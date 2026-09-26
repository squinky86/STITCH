// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::Parser;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use tempfile::NamedTempFile;
use tokio::time::{Duration, sleep};
use zip::ZipArchive;

const MAX_RETRIES: u32 = 5;
const REQUEST_TIMEOUT_SECS: u64 = 120;
const USER_AGENT: &str = concat!("STITCH/", env!("CARGO_PKG_VERSION"));
const MAX_ZIP_ENTRIES: usize = 10_000;

pub const MIB: u64 = 1024 * 1024;
pub const MAX_CWE_DOWNLOAD_BYTES: u64 = 128 * MIB;
pub const MAX_CWE_XML_BYTES: u64 = 512 * MIB;
pub const MAX_RMF_DOWNLOAD_BYTES: u64 = 128 * MIB;
pub const MAX_CCI_DOWNLOAD_BYTES: u64 = 128 * MIB;
pub const MAX_CCI_XML_BYTES: u64 = 256 * MIB;
pub const MAX_STIG_DOWNLOAD_BYTES: u64 = 128 * MIB;
pub const MAX_STIG_XML_BYTES: u64 = 256 * MIB;
pub const MAX_STIGWE_DOWNLOAD_BYTES: u64 = 16 * MIB;
pub const MAX_NVD_META_BYTES: u64 = 64 * 1024;
pub const MAX_NVD_GZIP_BYTES: u64 = 512 * MIB;
pub const MAX_NVD_JSON_BYTES: u64 = 1024 * MIB;

/// Default URL for the ASD STIG zip. DISA versions this in the URL path, so
/// override with `--stig-url` when DISA cuts a new revision.
pub const DEFAULT_STIG_URL: &str =
    "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_ASD_V6R4_STIG.zip";

#[derive(Debug, Clone)]
pub struct DownloadMetadata {
    pub requested_url: String,
    pub final_url: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub retrieved_at: String,
}

fn safe_url(url: &Url) -> String {
    let mut safe = url.clone();
    if safe.set_username("").is_err() || safe.set_password(None).is_err() {
        return format!("{}://<redacted>", safe.scheme());
    }
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

fn validated_https_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("Invalid download URL")?;
    if url.scheme() != "https" {
        bail!("Refusing non-HTTPS download URL: {}", safe_url(&url));
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("Credentials are not permitted in download URLs");
    }
    if url.host_str().is_none() {
        bail!("Download URL has no host");
    }
    Ok(url)
}

pub fn sha256_file(path: &std::path::Path) -> Result<String> {
    let file = std::fs::File::open(path).context("Failed to open file for hashing")?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).context("Failed to hash file")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

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

#[derive(Parser, Debug, Clone)]
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

pub async fn decompress_gzip(
    input: &NamedTempFile,
    output: &mut NamedTempFile,
    max_bytes: u64,
) -> Result<u64> {
    output.as_file_mut().set_len(0)?;
    output.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut gz = GzDecoder::new(std::fs::File::open(input.path())?);
    let written = copy_capped(&mut gz, output.as_file_mut(), max_bytes)?;
    output.as_file_mut().sync_all()?;
    Ok(written)
}

pub async fn download_file(
    url: &str,
    file: &mut NamedTempFile,
    silent: bool,
    prefix: String,
    args: &Args,
    reuse_bar: Option<&ProgressBar>,
    max_bytes: u64,
) -> Result<DownloadMetadata> {
    // When `reuse_bar` is provided, this download updates the caller's
    // persistent bar (resetting position/length/prefix on entry); the bar's
    // identity and place in any MultiProgress layout are preserved across
    // many calls. When None, we create and own a one-shot bar as before.
    let mut progress_bar: Option<ProgressBar> = None;

    let requested_url = validated_https_url(url)?;
    let safe_requested_url = safe_url(&requested_url);
    let client = Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .user_agent(USER_AGENT)
        .https_only(true)
        .build()
        .context("Failed to build HTTP client")?;

    if args.verbose {
        p(
            format!("Connecting to: {safe_requested_url}").as_str(),
            true,
        );
    }

    let mut retries = 0;
    loop {
        let current_size = file.as_file().metadata().map(|m| m.len()).unwrap_or(0);
        let mut req = client.get(requested_url.clone());

        if retries > 0 && current_size > 0 {
            req = req.header(reqwest::header::RANGE, format!("bytes={current_size}-"));
            if args.verbose {
                p(
                    format!("Resuming download from byte {current_size}").as_str(),
                    true,
                );
            }
            // Ensure the file cursor is at the end so we append.
            file.as_file_mut()
                .seek(SeekFrom::End(0))
                .context("Failed to seek temp file to end for resume")?;
        } else {
            // Reset the temp file before attempt so partial writes don't accumulate.
            file.as_file_mut()
                .set_len(0)
                .context("Failed to truncate temp file for retry")?;
            file.as_file_mut()
                .seek(SeekFrom::Start(0))
                .context("Failed to seek temp file for retry")?;
        }

        let response = match req.send().await {
            Ok(res) => {
                let status = res.status();
                if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
                    retries += 1;
                    if retries < MAX_RETRIES {
                        file.as_file_mut()
                            .set_len(0)
                            .context("Failed to reset temporary download file")?;
                        continue;
                    }
                    return Err(anyhow::anyhow!(
                        "Failed to download {safe_requested_url}: server rejected range request"
                    ));
                }
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
                        "Failed to download {safe_requested_url}: maximum retries exceeded"
                    ));
                }
                if !status.is_success() {
                    return Err(anyhow::anyhow!(
                        "Failed to download {safe_requested_url}: HTTP status {status}"
                    ));
                }
                res
            }
            Err(e) => {
                retries += 1;
                if retries < MAX_RETRIES {
                    p(
                        format!(
                            "Download failed: {} (retry {retries}/{MAX_RETRIES}), retrying in 5 seconds...",
                            e.without_url()
                        )
                        .as_str(),
                        true,
                    );
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
                return Err(anyhow::anyhow!(
                    "Failed to download {safe_requested_url}: maximum retries exceeded. Last error: {}",
                    e.without_url()
                ));
            }
        };

        let final_url = safe_url(response.url());
        if response.status() == reqwest::StatusCode::PARTIAL_CONTENT {
            let content_range = response
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .context("Resumed download omitted Content-Range")?
                .to_str()
                .context("Resumed download returned an invalid Content-Range")?;
            let expected_prefix = format!("bytes {current_size}-");
            if !content_range.starts_with(&expected_prefix) {
                bail!("Resumed download from {safe_requested_url} started at an unexpected offset");
            }
        }
        let content_length = response.content_length().unwrap_or(0);
        let mut current_offset = current_size;
        let total_size = if response.status() == reqwest::StatusCode::PARTIAL_CONTENT {
            current_offset.checked_add(content_length).ok_or_else(|| {
                anyhow::anyhow!("Download size overflow from {safe_requested_url}")
            })?
        } else {
            current_offset = 0;
            file.as_file_mut()
                .set_len(0)
                .context("Failed to truncate temp file on 200 OK")?;
            file.as_file_mut()
                .seek(SeekFrom::Start(0))
                .context("Failed to seek temp file on 200 OK")?;
            content_length
        };

        if total_size > max_bytes {
            bail!(
                "Refusing advertised download of {total_size} bytes from {safe_requested_url}; limit is {max_bytes} bytes"
            );
        }

        if args.verbose && total_size > 0 {
            p(format!("File size: {total_size} bytes").as_str(), true);
        }

        if !silent {
            let pb = if let Some(existing) = reuse_bar {
                // Re-point the caller's bar at this download. reset() also
                // clears elapsed time so ETA reflects the new transfer.
                existing.set_prefix(prefix.clone());
                existing.set_length(total_size);
                existing.set_message(String::new());
                if current_offset == 0 {
                    existing.reset();
                } else {
                    existing.set_position(current_offset);
                }
                existing.clone()
            } else {
                let pb = ProgressBar::new(total_size);
                pb.set_style(
                    #[allow(clippy::literal_string_with_formatting_args)]
                    ProgressStyle::default_bar()
                        .template("{prefix} {bar:20.cyan/blue} {msg}")
                        .expect("Failed to create progress style"),
                );
                pb.set_prefix(prefix.clone());
                pb.set_position(current_offset);
                pb
            };
            progress_bar = Some(pb);
        }

        let mut stream = response.bytes_stream();
        let mut downloaded: u64 = current_offset;
        let mut chunk_err: Option<anyhow::Error> = None;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    downloaded = downloaded.saturating_add(bytes.len() as u64);
                    if downloaded > max_bytes {
                        bail!(
                            "Refusing to download more than {max_bytes} bytes from {safe_requested_url}"
                        );
                    }
                    file.as_file_mut()
                        .write_all(&bytes)
                        .context("Failed to write chunk to file")?;
                    if !silent && let Some(pb) = &progress_bar {
                        pb.inc(bytes.len() as u64);
                        pb.set_message(format!("{}/{}B", pb.position(), total_size));
                    }
                }
                Err(e) => {
                    chunk_err = Some(anyhow::anyhow!(e.without_url()));
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
                "Failed to download {safe_requested_url}: maximum retries exceeded. Last error: {}",
                e
            ));
        }

        if !silent && let Some(pb) = &progress_bar {
            if reuse_bar.is_some() {
                // Caller owns the bar and will reset it for the next file.
                // Leave it at its final position with a tick so the slot
                // briefly shows completion before being reassigned.
                pb.set_message(format!("✓ {}B", pb.position()));
            } else {
                pb.finish_with_message(format!("✓ {}B", pb.position()));
                println!();
            }
        }

        file.as_file_mut()
            .sync_all()
            .context("Failed to sync file to disk")?;

        let size_bytes = file.as_file().metadata()?.len();
        let sha256 = sha256_file(file.path())?;
        return Ok(DownloadMetadata {
            requested_url: safe_requested_url,
            final_url,
            sha256,
            size_bytes,
            retrieved_at: Utc::now().to_rfc3339(),
        });
    }
}

pub fn extract_from_zip(
    zip_file: &NamedTempFile,
    xml_file: &mut NamedTempFile,
    ext: &str,
    args: &Args,
    max_bytes: u64,
) -> Result<u64> {
    let file = std::fs::File::open(zip_file.path()).context("Failed to open zip file")?;
    let mut archive = ZipArchive::new(file).context("Failed to read zip archive")?;
    if archive.len() > MAX_ZIP_ENTRIES {
        bail!(
            "Refusing zip archive with {} entries; limit is {MAX_ZIP_ENTRIES}",
            archive.len()
        );
    }

    xml_file.as_file_mut().set_len(0)?;
    xml_file.as_file_mut().seek(SeekFrom::Start(0))?;

    if args.verbose {
        p("\nExtracting zip file…", false);
    }

    let mut extracted_bytes = None;
    let mut sample_names: Vec<String> = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            anyhow::anyhow!("Could not read file index {i} in the downloaded zip file: {e}")
        })?;
        let name = entry.name().to_string();
        if name.ends_with(ext) {
            if entry.size() > max_bytes {
                bail!(
                    "Refusing zip member {name} with declared size {} bytes; limit is {max_bytes} bytes",
                    entry.size()
                );
            }
            let written = copy_capped(&mut entry, xml_file.as_file_mut(), max_bytes)
                .context(format!("Failed to extract {ext} file"))?;
            extracted_bytes = Some(written);
            break;
        }
        if sample_names.len() < 5 {
            sample_names.push(name);
        }
    }

    let Some(written) = extracted_bytes else {
        return Err(anyhow::anyhow!(
            "Zip archive contained no entry ending in '{}' (saw: {})",
            ext,
            sample_names.join(", ")
        ));
    };

    xml_file.as_file_mut().sync_all()?;
    Ok(written)
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

/// Build a multi-row `INSERT … VALUES (?,?,…),(?,?,…),…` clause.
/// `prefix` must end with `"VALUES "` (with the trailing space).
/// Used by the bulk loaders to amortize statement parse/plan cost across many rows.
#[must_use]
pub fn build_insert_sql(prefix: &str, rows: usize, cols: usize) -> String {
    debug_assert!(rows > 0 && cols > 0);
    let tuple_len = 2 + cols * 2;
    let mut sql = String::with_capacity(prefix.len() + rows * tuple_len);
    sql.push_str(prefix);
    for r in 0..rows {
        if r > 0 {
            sql.push(',');
        }
        sql.push('(');
        for c in 0..cols {
            if c > 0 {
                sql.push(',');
            }
            sql.push('?');
        }
        sql.push(')');
    }
    sql
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
        extract_from_zip(&zip, &mut out, ".xml", &args(), 1024).unwrap();
        let got = std::fs::read(out.path()).unwrap();
        assert_eq!(got, b"<x/>");
    }

    #[test]
    fn extract_from_zip_skips_non_matching_then_extracts() {
        let zip = make_zip(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.xml", b"<c/>")]);
        let mut out = NamedTempFile::new().unwrap();
        extract_from_zip(&zip, &mut out, ".xml", &args(), 1024).unwrap();
        assert_eq!(std::fs::read(out.path()).unwrap(), b"<c/>");
    }

    #[test]
    fn extract_from_zip_no_match_returns_err() {
        let zip = make_zip(&[("a.txt", b"a"), ("b.json", b"{}")]);
        let mut out = NamedTempFile::new().unwrap();
        let err = extract_from_zip(&zip, &mut out, ".xml", &args(), 1024).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no entry ending in '.xml'"), "got: {msg}");
        assert!(msg.contains("a.txt"), "should list seen names: {msg}");
    }

    #[test]
    fn extract_from_zip_enforces_member_limit() {
        let zip = make_zip(&[("data.xml", b"too large")]);
        let mut out = NamedTempFile::new().unwrap();
        let err = extract_from_zip(&zip, &mut out, ".xml", &args(), 3).unwrap_err();
        assert!(err.to_string().contains("limit is 3 bytes"));
    }

    #[test]
    fn download_urls_must_be_https_and_are_redacted() {
        let err = validated_https_url("http://example.com/feed?token=secret").unwrap_err();
        assert!(!err.to_string().contains("secret"));

        let parsed = validated_https_url("https://example.com/feed?token=secret#fragment").unwrap();
        assert_eq!(safe_url(&parsed), "https://example.com/feed");
    }
}
