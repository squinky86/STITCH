use crate::common::{download_file,decompress_gzip,Args};

use anyhow::{Context, Result};
use chrono::{Utc, Datelike};
use rusqlite::{Connection};
use tokio::fs;
use tempfile::NamedTempFile;

pub async fn process_nvd(conn: &Connection, args: &Args) -> Result<()> {
	// NVD Data
	// Download and process NVD data
	println!("Obtaining and parsing NVD data:");
	let current_datetime = Utc::now();
	for year in 2002..current_datetime.year() {
		println!("\tProcessing NVD data for year {}:", year);
		let mut nvd_temp_json_gz = NamedTempFile::new()?;
		let mut nvd_temp_json = NamedTempFile::new()?;
		let nvd_url = format!("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{}.json.gz", year);
		print!("\t\tDownloading {} NVD JSON…", year);
		download_file(&nvd_url, &mut nvd_temp_json_gz, &args).await?;
		println!("✓");

		print!("\t\tDeflating {} NVD JSON…", year);
		decompress_gzip(&mut nvd_temp_json_gz, &mut nvd_temp_json).await?;
		println!("✓");

		print!("\t\tParsing {} NVD JSON data…", year);
		nvd_parse_and_populate_database(&mut nvd_temp_json, &conn).await?;
		println!("✓");
	}

    Ok(())
}

async fn nvd_parse_and_populate_database(json_file: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let json_content = fs::read_to_string(json_file.path())
        .await
        .context("Failed to read NVD JSON file")?;
    
    // TODO: Parse JSON and populate database
    
    
    Ok(())
}
