// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use anyhow::{Context, Result};
use clap::Parser;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use std::io::{self, Write};
use tempfile::NamedTempFile;
use tokio::time::{Duration, sleep};
use zip::ZipArchive;

const MAX_RETRIES: u32 = 5;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Output database file path
    #[arg(short, long, default_value = "stitch.db")]
    pub output: String,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

pub async fn decompress_gzip(input: &NamedTempFile, output: &mut NamedTempFile) -> Result<()> {
    let mut gz = GzDecoder::new(std::fs::File::open(input.path())?);
    std::io::copy(&mut gz, output.as_file_mut())?;
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

    let client = Client::new();

    if args.verbose {
        p(format!("Connecting to: {}", url).as_str(), true);
    }

    let mut retries = 0;
    let response = loop {
        let response = client.get(url).send().await;

        match response {
            Ok(res) => {
                if res.status().is_server_error() {
                    retries += 1;
                    if retries < MAX_RETRIES {
                        p(format!("Download failed with status {} (retry {}/{}), retrying in 5 seconds...", res.status(), retries, MAX_RETRIES).as_str(), true);
                        sleep(Duration::from_secs(5)).await;
                        continue;
                    } else {
                        return Err(anyhow::anyhow!(
                            "Failed to download {}: Max retries exceeded.",
                            url
                        ));
                    }
                }
                break res;
            }
            Err(e) => {
                retries += 1;
                if retries < MAX_RETRIES {
                    p(
                        format!(
                            "Download failed: {} (retry {}/{}), retrying in 5 seconds...",
                            e, retries, MAX_RETRIES
                        )
                        .as_str(),
                        true,
                    );
                    sleep(Duration::from_secs(5)).await;
                    continue;
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to download {}: Max retries exceeded. Last error: {}",
                        url,
                        e
                    ));
                }
            }
        }
    };

    let total_size = response.content_length().unwrap_or(0);
    if args.verbose && total_size > 0 {
        p(format!("File size: {} bytes", total_size).as_str(), true);
    }

    if !silent {
        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{prefix} {bar:20.cyan/blue} {msg}")
                .expect("Failed to create progress style"),
        );

        pb.set_prefix(prefix);

        progress_bar = Some(pb);
    }

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read chunk")?;
        file.as_file_mut()
            .write_all(&chunk)
            .context("Failed to write chunk to file")?;
        if !silent {
            if let Some(pb) = &progress_bar {
                pb.inc(chunk.len() as u64);
                pb.set_message(format!("{}/{}B", pb.position(), &total_size));
            }
        }
    }

    if !silent {
        if let Some(pb) = &progress_bar {
            pb.finish_with_message(format!("✓ {}B", pb.position()));
            println!();
        }
    }

    file.as_file_mut()
        .sync_all()
        .context("Failed to sync file to disk")?;

    Ok(())
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

    for i in 0..archive.len() {
        match archive.by_index(i) {
            Ok(mut file) => {
                if file.name().ends_with(ext) {
                    std::io::copy(&mut file, xml_file.as_file_mut())
                        .context(format!("Failed to extract {} file", ext))?;
                    break;
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Could not extract file index {} in the downloaded zip file: {}",
                    i,
                    e
                ));
            }
        }
    }

    Ok(())
}

pub fn p(s: &str, newline: bool) {
    if newline {
        println!("{}", s);
    } else {
        print!("{}", s);
        io::stdout().flush().unwrap();
    }
}
