use reqwest::Client;
use flate2::read::GzDecoder;
use zip::ZipArchive;
use tempfile::NamedTempFile;
use anyhow::{Context, Result};
use clap::Parser;
use futures_util::{StreamExt};
use std::io::{self,Write};
use indicatif::{ProgressBar,ProgressStyle};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
	/// Output database file path
	#[arg(short, long, default_value = "rusktex.db")]
	pub output: String,

	/// Force download even if file exists
	#[arg(short, long)]
	pub force: bool,

	/// Verbose output
	#[arg(short, long)]
	pub verbose: bool,
}

pub async fn decompress_gzip(input: &mut NamedTempFile, output: &mut NamedTempFile) -> Result<()> {
    let mut gz = GzDecoder::new(std::fs::File::open(input.path())?);
    std::io::copy(&mut gz, output.as_file_mut())?;
    output.as_file_mut().sync_all()?;
    Ok(())
}

pub async fn download_file(url: &str, file: &mut NamedTempFile, silent: bool, prefix: String, postfix: String, args: &Args) -> Result<()> {
	let mut progress_bar: Option<ProgressBar> = None;
	
	let client = Client::new();

    if args.verbose {
        p(format!("Connecting to: {}", url).as_str(), true);
    }

    let response = client
        .get(url)
        .send()
        .await
        .context("Failed to download CWE XML")?;

    let total_size = response.content_length().unwrap_or(0);
    if args.verbose && total_size > 0 {
        p(format!("File size: {} bytes", total_size).as_str(), true);
    }

	if !silent {
		let pb = ProgressBar::new(total_size);
		pb.set_style(ProgressStyle::default_bar()
    	.template("{prefix} {bar:20.cyan/blue} {msg}")
    	.expect("Failed to create progress style"));

		pb.set_prefix(prefix);

		progress_bar = Some(pb);
	}

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read chunk")?;
        file.as_file_mut().write_all(&chunk)
            .context("Failed to write chunk to file")?;
		if !silent {
			if let Some(pb) = &progress_bar {
				pb.inc(chunk.len() as u64);
			}
		}
    }

	if !silent {
		if let Some(pb) = &progress_bar {
			pb.finish_with_message(postfix);
		}
	}
    
    file.as_file_mut().sync_all().context("Failed to sync file to disk")?;

    Ok(())
}

pub fn extract_from_zip(zip_file: &NamedTempFile, xml_file: &mut NamedTempFile, ext: &str, args: &Args) -> Result<()> {
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
                    i, e
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
