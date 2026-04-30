// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use anyhow::{Context, Result};
use clap::Parser;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use std::io::{self, Read, Seek, SeekFrom, Write};
use tempfile::NamedTempFile;
use tokio::time::{Duration, sleep};
use zip::ZipArchive;

const MAX_RETRIES: u32 = 5;
const REQUEST_TIMEOUT_SECS: u64 = 120;
const USER_AGENT: &str = concat!("STITCH/", env!("CARGO_PKG_VERSION"));

/// Hard cap on bytes written by any single decompression (gzip or zip member).
/// Sized to comfortably exceed real-world feeds (largest current NVD year is ~1 GB
/// uncompressed) while still bounding decompression-bomb damage.
const MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Hard cap on bytes accepted from a single HTTP response. NVD year files are
/// the largest legitimate downloads (~100 MB gzipped); 2 GB leaves headroom.
const MAX_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Default URL for the ASD STIG zip. DISA versions this in the URL path, so
/// override with `--stig-url` when DISA cuts a new revision.
pub const DEFAULT_STIG_URL: &str =
    "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_ASD_V6R4_STIG.zip";

/// Copies bytes from `reader` to `writer`, refusing to write more than `limit`
/// bytes. Returns an error if the cap is reached, so a decompression bomb fails
/// fast rather than exhausting disk.
fn copy_capped<R: Read, W: Write>(reader: &mut R, writer: &mut W, limit: u64) -> Result<u64> {
    let mut capped = reader.take(limit + 1);
    let written = std::io::copy(&mut capped, writer).context("Failed during bounded copy")?;
    if written > limit {
        return Err(anyhow::anyhow!(
            "Refusing to write more than {limit} bytes (decompression bomb?)"
        ));
    }
    Ok(written)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Output database file path
    #[arg(short, long, default_value = "stitch.db")]
    pub output: String,

    /// Override the ASD STIG zip URL. Defaults to the V6R4 release on DISA's
    /// public site; override when DISA releases a new revision.
    #[arg(long, default_value = DEFAULT_STIG_URL)]
    pub stig_url: String,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

pub async fn decompress_gzip(input: &NamedTempFile, output: &mut NamedTempFile) -> Result<()> {
    let mut gz = GzDecoder::new(std::fs::File::open(input.path())?);
    copy_capped(&mut gz, output.as_file_mut(), MAX_DECOMPRESSED_BYTES)?;
    output.as_file_mut().sync_all()?;
    Ok(())
}

pub async fn download_file(
    url: &str,
    file: &mut NamedTempFile,
    silent: bool,
    prefix: String,
    args: &Args,
) -> Result<()> {
    let mut progress_bar: Option<ProgressBar> = None;

    let client = Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .user_agent(USER_AGENT)
        .build()
        .context("Failed to build HTTP client")?;

    if args.verbose {
        p(format!("Connecting to: {url}").as_str(), true);
    }

    let mut retries = 0;
    loop {
        // Reset the temp file before each attempt so partial writes don't accumulate.
        if retries > 0 {
            file.as_file_mut()
                .set_len(0)
                .context("Failed to truncate temp file for retry")?;
            file.as_file_mut()
                .seek(SeekFrom::Start(0))
                .context("Failed to seek temp file for retry")?;
        }

        let response = match client.get(url).send().await {
            Ok(res) => {
                let status = res.status();
                // Retry transient failures (5xx, 408, 429); fail fast on other 4xx
                // so a 404/410 doesn't get its HTML body written into the temp file
                // and parsed as XML/JSON later.
                let retryable = status.is_server_error()
                    || status == reqwest::StatusCode::REQUEST_TIMEOUT
                    || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
                if retryable {
                    retries += 1;
                    if retries < MAX_RETRIES {
                        p(format!("Download failed with status {status} (retry {retries}/{MAX_RETRIES}), retrying in 5 seconds...").as_str(), true);
                        sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                    return Err(anyhow::anyhow!(
                        "Failed to download {url}: Max retries exceeded."
                    ));
                }
                if !status.is_success() {
                    return Err(anyhow::anyhow!(
                        "Failed to download {url}: HTTP status {status}"
                    ));
                }
                res
            }
            Err(e) => {
                retries += 1;
                if retries < MAX_RETRIES {
                    p(
                        format!(
                            "Download failed: {e} (retry {retries}/{MAX_RETRIES}), retrying in 5 seconds..."
                        )
                        .as_str(),
                        true,
                    );
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
                return Err(anyhow::anyhow!(
                    "Failed to download {url}: Max retries exceeded. Last error: {e}"
                ));
            }
        };

        let total_size = response.content_length().unwrap_or(0);
        if args.verbose && total_size > 0 {
            p(format!("File size: {total_size} bytes").as_str(), true);
        }

        if !silent {
            let pb = ProgressBar::new(total_size);
            pb.set_style(
                #[allow(clippy::literal_string_with_formatting_args)]
                ProgressStyle::default_bar()
                    .template("{prefix} {bar:20.cyan/blue} {msg}")
                    .expect("Failed to create progress style"),
            );
            pb.set_prefix(prefix.clone());
            progress_bar = Some(pb);
        }

        let mut stream = response.bytes_stream();
        let mut downloaded: u64 = 0;
        let mut chunk_err: Option<anyhow::Error> = None;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    downloaded = downloaded.saturating_add(bytes.len() as u64);
                    if downloaded > MAX_DOWNLOAD_BYTES {
                        return Err(anyhow::anyhow!(
                            "Refusing to download more than {MAX_DOWNLOAD_BYTES} bytes from {url}"
                        ));
                    }
                    file.as_file_mut()
                        .write_all(&bytes)
                        .context("Failed to write chunk to file")?;
                    if !silent && let Some(pb) = &progress_bar {
                        pb.inc(bytes.len() as u64);
                        pb.set_message(format!("{}/{}B", pb.position(), &total_size));
                    }
                }
                Err(e) => {
                    chunk_err = Some(anyhow::anyhow!(e));
                    break;
                }
            }
        }

        if let Some(e) = chunk_err {
            if !silent && let Some(pb) = &progress_bar {
                pb.abandon();
            }
            progress_bar = None;
            retries += 1;
            if retries < MAX_RETRIES {
                p(
                    format!(
                        "Download interrupted: {e} (retry {retries}/{MAX_RETRIES}), retrying in 5 seconds..."
                    )
                    .as_str(),
                    true,
                );
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            return Err(anyhow::anyhow!(
                "Failed to download {url}: Max retries exceeded. Last error: {e}"
            ));
        }

        if !silent && let Some(pb) = &progress_bar {
            pb.finish_with_message(format!("✓ {}B", pb.position()));
            println!();
        }

        file.as_file_mut()
            .sync_all()
            .context("Failed to sync file to disk")?;

        return Ok(());
    }
}

pub fn extract_from_zip(
    zip_file: &NamedTempFile,
    xml_file: &mut NamedTempFile,
    ext: &str,
    args: &Args,
) -> Result<()> {
    let file = std::fs::File::open(zip_file.path()).context("Failed to open zip file")?;
    let mut archive = ZipArchive::new(file).context("Failed to read zip archive")?;

    if args.verbose {
        p("\nExtracting zip file…", false);
    }

    let mut extracted = false;
    let mut sample_names: Vec<String> = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            anyhow::anyhow!("Could not read file index {i} in the downloaded zip file: {e}")
        })?;
        let name = entry.name().to_string();
        if name.ends_with(ext) {
            copy_capped(&mut entry, xml_file.as_file_mut(), MAX_DECOMPRESSED_BYTES)
                .context(format!("Failed to extract {ext} file"))?;
            extracted = true;
            break;
        }
        if sample_names.len() < 5 {
            sample_names.push(name);
        }
    }

    if !extracted {
        return Err(anyhow::anyhow!(
            "Zip archive contained no entry ending in '{}' (saw: {})",
            ext,
            sample_names.join(", ")
        ));
    }

    Ok(())
}

/// Escapes SQL `LIKE` metacharacters (`%`, `_`, `\`) with a leading `\`.
///
/// Use this so a STIG/CCI/CWE ID containing a literal underscore can be used
/// as a `LIKE` pattern without the underscore being treated as a wildcard.
/// Pair with `LIKE ? ESCAPE '\'` (or `'\\'`) on the SQL side.
#[must_use]
pub fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' || c == '%' || c == '_' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

pub fn p(s: &str, newline: bool) {
    if newline {
        println!("{s}");
    } else {
        print!("{s}");
        // Ignore flush errors so a closed downstream pipe doesn't panic the build.
        let _ = io::stdout().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn args() -> Args {
        Args {
            output: "stitch.db".to_string(),
            stig_url: DEFAULT_STIG_URL.to_string(),
            verbose: false,
        }
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        {
            let mut zw = zip::ZipWriter::new(f.reopen().unwrap());
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        f
    }

    #[test]
    fn escape_like_escapes_metacharacters() {
        assert_eq!(escape_like("plain"), "plain");
        assert_eq!(escape_like("SV-12_345"), "SV-12\\_345");
        assert_eq!(escape_like("100%"), "100\\%");
        assert_eq!(escape_like("a\\b"), "a\\\\b");
        assert_eq!(escape_like("a_b%c\\"), "a\\_b\\%c\\\\");
    }

    #[test]
    fn extract_from_zip_picks_matching_extension() {
        let zip = make_zip(&[("readme.txt", b"hi"), ("data.xml", b"<x/>")]);
        let mut out = NamedTempFile::new().unwrap();
        extract_from_zip(&zip, &mut out, ".xml", &args()).unwrap();
        let got = std::fs::read(out.path()).unwrap();
        assert_eq!(got, b"<x/>");
    }

    #[test]
    fn extract_from_zip_skips_non_matching_then_extracts() {
        let zip = make_zip(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.xml", b"<c/>")]);
        let mut out = NamedTempFile::new().unwrap();
        extract_from_zip(&zip, &mut out, ".xml", &args()).unwrap();
        assert_eq!(std::fs::read(out.path()).unwrap(), b"<c/>");
    }

    #[test]
    fn extract_from_zip_no_match_returns_err() {
        let zip = make_zip(&[("a.txt", b"a"), ("b.json", b"{}")]);
        let mut out = NamedTempFile::new().unwrap();
        let err = extract_from_zip(&zip, &mut out, ".xml", &args()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no entry ending in '.xml'"), "got: {msg}");
        assert!(msg.contains("a.txt"), "should list seen names: {msg}");
    }
}
