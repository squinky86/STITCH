use anyhow::{Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::Client;
use rusqlite::{params, Connection};
use std::io::Write;
use tokio::fs;
use zip::ZipArchive;
use tempfile::NamedTempFile;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Output database file path
	#[arg(short, long, default_value = "rusktex.db")]
	output: String,

	/// Force download even if file exists
	#[arg(short, long)]
	force: bool,

	/// Verbose output
	#[arg(short, long)]
	verbose: bool,
}

#[derive(Debug, Clone, Default)]
struct Weakness {
	id: u32,
	name: String,
	description: String,
	category: bool, // is a category?
	view: bool,     // is a view?
	extended_description: String,
	confidentiality: bool,
	integrity: bool,
	availability: bool,
}

#[derive(Debug, Clone)]
struct WeaknessRelationship {
	source_id: u32,
	target_id: u32,
	nature: String,
	view_id: u32,
}

#[derive(Debug, Clone, Default)]
struct RMFFamily {
	id: u32,
	abbr: String,
	name: String,
}

#[derive(Debug, Clone, Default)]
struct RMFControl {
	id: u32,
	RMFFamilyId: u32,
	number: String,
	name: String,
	description: String,
}

#[tokio::main]
async fn main() -> Result<()> {
	let args = Args::parse();

	//CWE Data
	const CWE_XML_URL: &str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip";
	let mut cwe_temp_zip = NamedTempFile::new()?;
	let mut cwe_temp_xml = NamedTempFile::new()?;

	//RMF Control Data
	const RMF_XML_URL: &str = "https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1_XML.xml";
	let mut rmf_temp_xml = NamedTempFile::new()?;

	println!("RuskTeX Database Builder v0.1.0");

	// Download the CWE XML file
    if cwe_temp_zip.path().exists() {
        print!("Downloading CWE XML file from MITRE…");
        download_file(&CWE_XML_URL, &mut cwe_temp_zip, &args).await?;
        println!("✓");

        print!("Extracting XML file…");
        extract_xml_from_zip(&cwe_temp_zip, &mut cwe_temp_xml, &args)?;
        println!("✓");
    } else {
        eprintln!("Unable to create temporary CWE file.");
        std::process::exit(1);
    }

	// Download the RMF XML file
	if rmf_temp_xml.path().exists() {
		print!("Downloading NIST RMF XML file from NIST…");
		download_file(&RMF_XML_URL, &mut rmf_temp_xml, &args).await?;
		println!("✓");
	} else {
		eprintln!("Unable to create temporary RMF file.");
		std::process::exit(1);
	}

	// Create database
	print!("Creating SQLite database:");
	let conn = create_database(&args.output)?;
	println!("SQLite database created ✓ ({})", args.output);

	// Parse CWE XML and populate database
	println!("Parsing CWE XML and populating database:");
	cwe_parse_and_populate_database(&mut cwe_temp_xml, &conn, &args).await?;

	// Parse RMF XML and populate database
	println!("Parsing NIST RMF XML and populating database:");
	rmf_parse_and_populate_database(&mut rmf_temp_xml, &conn, &args).await?;

	// Display summary
	display_database_summary(&conn)?;

	println!("\nCWE database build completed successfully: {}", args.output);
	Ok(())
}

async fn download_file(url: &str, file: &mut NamedTempFile, args: &Args) -> Result<()> {
    let client = Client::new();

    if args.verbose {
        println!("\nConnecting to: {}", url);
    }

    let response = client
        .get(url)
        .send()
        .await
        .context("Failed to download CWE XML")?;

    let total_size = response.content_length().unwrap_or(0);
    if args.verbose && total_size > 0 {
        println!("File size: {} bytes", total_size);
    }

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read chunk")?;
        file.as_file_mut().write_all(&chunk)
            .context("Failed to write chunk to file")?;
    }
    
    file.as_file_mut().sync_all().context("Failed to sync file to disk")?;

    Ok(())
}

fn extract_xml_from_zip(zip_file: &NamedTempFile, xml_file: &mut NamedTempFile, args: &Args) -> Result<()> {
    let file = std::fs::File::open(zip_file.path()).context("Failed to open zip file")?;
    let mut archive = ZipArchive::new(file).context("Failed to read zip archive")?;

    if args.verbose {
        println!("\nExtracting zip file...");
    }

    for i in 0..archive.len() {
        match archive.by_index(i) {
            Ok(mut file) => {
                if file.name().ends_with(".xml") {
                    std::io::copy(&mut file, xml_file.as_file_mut())
                        .context("Failed to extract XML file")?;
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

fn create_database(db_path: &str) -> Result<Connection> {
	let conn = Connection::open(db_path).context("Failed to create database")?;

	// Enable foreign key constraints
	conn.execute("PRAGMA foreign_keys = ON", [])?;

	// Create CWE Weakness table
	conn.execute(
		"CREATE TABLE IF NOT EXISTS Weakness (
id INTEGER NOT NULL UNIQUE PRIMARY KEY,
name TEXT NOT NULL,
description TEXT NOT NULL DEFAULT '',
extended_description TEXT NOT NULL DEFAULT '',
category BOOLEAN NOT NULL DEFAULT 0 CHECK(category IN (0, 1)),
view BOOLEAN NOT NULL DEFAULT 0 CHECK(view IN (0, 1)),
confidentiality BOOLEAN NOT NULL DEFAULT 0 CHECK(confidentiality IN (0, 1)),
integrity BOOLEAN NOT NULL DEFAULT 0 CHECK(integrity IN (0, 1)),
availability BOOLEAN NOT NULL DEFAULT 0 CHECK(availability IN (0, 1))
);",
		[],
	)
	.context("Failed to create Weakness table")?;

	// Create CWE relationships table
	conn.execute(
		"CREATE TABLE IF NOT EXISTS WeaknessRelationship (
id INTEGER PRIMARY KEY AUTOINCREMENT,
source_id INTEGER NOT NULL,
target_id INTEGER NOT NULL,
nature TEXT NOT NULL,
view_id INTEGER NOT NULL,
UNIQUE(source_id, target_id, nature, view_id),
FOREIGN KEY (source_id) REFERENCES Weakness(id),
FOREIGN KEY (target_id) REFERENCES Weakness(id),
FOREIGN KEY (view_id) REFERENCES Weakness(id)
);",
		[],
	)
	.context("Failed to create WeaknessRelationship table")?;

	// Create RMF Family table
	conn.execute(
		"CREATE TABLE IF NOT EXISTS RMFFamily (
id INTEGER PRIMARY KEY AUTOINCREMENT,
abbr TEXT NOT NULL UNIQUE,
name TEXT NOT NULL
);",
		[],
	)
	.context("Failed to create RMFFamily table")?;

	// Create RMF Control table
	conn.execute(
		"CREATE TABLE IF NOT EXISTS RMFControl (
id INTEGER PRIMARY KEY AUTOINCREMENT,
RMFFamilyId INTEGER NOT NULL,
number TEXT NOT NULL,
name TEXT NOT NULL,
description TEXT NOT NULL,
FOREIGN KEY (RMFFamilyId) REFERENCES RMFFamily(id)
);",
		[],
	)
	.context("Failed to create RMFControl table")?;

	// Create RMF CCI table
	conn.execute(
		"CREATE TABLE IF NOT EXISTS RMFCCI (
id INTEGER PRIMARY KEY UNIQUE,
RMFControlId INTEGER NOT NULL,
definition TEXT NOT NULL,
FOREIGN KEY (RMFControlId) REFERENCES RMFControl(id)
);",
		[],
	)
	.context("Failed to create RMFCCI table")?;

	Ok(conn)
}

async fn cwe_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection, args: &Args) -> Result<()> {
	let xml_content = fs::read_to_string(xml.path())
		.await
		.context("Failed to read XML file")?;

	let mut reader = Reader::from_str(&xml_content);
	reader.trim_text(true);

	let mut buf = Vec::new();
	let mut cwe_entries: Vec<Weakness> = Vec::new();
	let mut relationships: Vec<WeaknessRelationship> = Vec::new();

	let mut current_weakness: Option<Weakness> = None;
	let mut text_buffer = String::new();
	let mut current_element = String::new();
	let mut capture_text = false;

	loop {
		match reader.read_event_into(&mut buf) {
			Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e))=> {
				current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();

				match current_element.as_str() {
					"Weakness" | "Category" | "View" => {
						let mut weakness = Weakness::default();
						if current_element == "Category" {
							weakness.category = true;
						}
						if current_element == "View" {
							weakness.view = true;
						}

						// Parse attributes
						for attr in e.attributes() {
							let attr =
								attr.context("Failed to parse weakness attribute")?;
							let key = String::from_utf8_lossy(attr.key.as_ref());
							let value = String::from_utf8_lossy(&attr.value);

							match key.as_ref() {
								"ID" => {
									weakness.id = value.parse::<u32>().unwrap_or(0)
								}
								"Name" => weakness.name = value.to_string(),
								_ => {}
							}
						}
						current_weakness = Some(weakness);
					}
					"Description" | "Extended_Description" | "Scope" => {
						capture_text = true;
						text_buffer.clear();
					}
					"Related_Weakness" => {
						if let Some(weakness) = &current_weakness {
							let mut relationship = WeaknessRelationship {
								source_id: weakness.id,
								target_id: 0,
								nature: String::new(),
								view_id: 0,
							};

							for attr in e.attributes() {
								let attr = attr
									.context("Failed to parse relationship attribute")?;
								let key = String::from_utf8_lossy(attr.key.as_ref());
								let value = String::from_utf8_lossy(&attr.value);

								match key.as_ref() {
									"CWE_ID" => {
										relationship.target_id =
											value.parse::<u32>().unwrap_or(0)
									}
									"Nature" => relationship.nature = value.to_string(),
									"View_ID" => {
										relationship.view_id =
											value.parse::<u32>().unwrap_or(0)
									}
									_ => {}
								}
							}
							if relationship.target_id != 0
								&& !relationship.nature.is_empty()
							{
								relationships.push(relationship);
							}
						}
					}
					_ => {}
				}
			}
			Ok(Event::Text(e)) => {
				if capture_text {
					text_buffer.push_str(&e.unescape().unwrap_or_default());
				}
			}
			Ok(Event::End(ref e)) => {
				let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
				match tag_name.as_str() {
					"Weakness" | "Category" | "View" => {
						if let Some(weakness) = current_weakness.take() {
							if args.verbose {
								println!("Parsed: CWE-{}", weakness.id);
							}
							cwe_entries.push(weakness);
						}
					}
					"Description" => {
						if let Some(weakness) = current_weakness.as_mut() {
							weakness.description = text_buffer.trim().to_string();
						}
						capture_text = false;
					}
					"Extended_Description" => {
						if let Some(weakness) = current_weakness.as_mut() {
							weakness.extended_description =
								text_buffer.trim().to_string();
						}
						capture_text = false;
					}
					"Scope" => {
						if let Some(weakness) = current_weakness.as_mut() {
							match text_buffer.trim() {
								"Confidentiality" => weakness.confidentiality = true,
								"Integrity" => weakness.integrity = true,
								"Availability" => weakness.availability = true,
								_ => {}
							}
						}
						capture_text = false;
					}
					_ => {}
				}
				current_element.clear();
			}
			Ok(Event::Eof) => break,
			Err(e) => return Err(anyhow::anyhow!("XML parsing error: {}", e)),
			_ => {}
		}
		buf.clear();
	}

	cwe_insert_data_to_database(conn, &cwe_entries, &relationships)?;

	Ok(())
}

async fn rmf_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection, args: &Args) -> Result<()> {
    let xml_content = fs::read_to_string(xml.path())
        .await
        .context("Failed to read RMF XML file")?;
    let mut reader = Reader::from_str(&xml_content);
    reader.trim_text(true);

    let mut families: Vec<RMFFamily> = Vec::new();
    let mut controls: Vec<RMFControl> = Vec::new();
    let mut buf = Vec::new();
    
    let mut current_family: Option<RMFFamily> = None;
    let mut current_control: Option<RMFControl> = None;

	let mut text_buffer = String::new();
	let mut current_element = String::new();
	let mut capture_text = false;

	let mut tmp_family: String = String::new();
	let mut tmp_number: String = String::new();
	let mut tmp_title: String = String::new();
	let mut tmp_p: String = String::new();
    
	loop {
		match reader.read_event_into(&mut buf) {
			Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e))=> {
				current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();

				match current_element.as_str() {
					"family" | "number" | "title" | "p" => {
						capture_text = true;
						text_buffer.clear();
					}
					_ => {}
				}
			}
			Ok(Event::Text(e)) => {
				if capture_text {
					text_buffer.push_str(&e.unescape().unwrap_or_default());
				}
			}
			Ok(Event::End(ref e)) => {
				let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
				match tag_name.as_str() {
					"family" =>
					{
						tmp_family = text_buffer.trim().to_string();
					}
					"number" => {
						tmp_number = text_buffer.trim().to_string();
						let family = RMFFamily {
							id: 0,
							abbr: tmp_number.chars().take(2).collect(),
							name: tmp_family.clone()
						};
						if !families.iter().any(|f| f.abbr == family.abbr) {
							families.push(family);
						}
					}
					_ => {}
				}
				current_element.clear();
			}
			Ok(Event::Eof) => break,
			Err(e) => return Err(anyhow::anyhow!("RMF XML parsing error: {}", e)),
			_ => {}
		}
		buf.clear();
	}

    // Insert families
    if args.verbose {
        println!("Inserting {} RMF families...", families.len());
    }
    for family in families {
        conn.execute(
            "INSERT OR REPLACE INTO RMFFamily (abbr, name) VALUES (?1, ?2)",
            params![family.abbr, family.name],
        ).context("Failed to insert RMF family")?;
    }

    Ok(())
}

fn cwe_insert_data_to_database(
	conn: &Connection,
	entries: &[Weakness],
	relationships: &[WeaknessRelationship],
) -> Result<()> {
	// Insert CWE entries
	print!("\tInserting {} CWE entries…", entries.len());
	let mut tx = conn.unchecked_transaction()?;
	{
		let mut stmt = tx.prepare_cached(
			"INSERT OR REPLACE INTO Weakness 
             (id, name, description, extended_description, category, view, confidentiality, integrity, availability) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
		)?;

		for entry in entries {
			stmt.execute(params![
				entry.id,
				entry.name,
				entry.description,
				entry.extended_description,
				entry.category,
				entry.view,
				entry.confidentiality,
				entry.integrity,
				entry.availability
			])?;
		}
	}
	tx.commit()?;
	println!("✓");

	// Insert relationships
	print!("\tInserting {} relationships...", relationships.len());
	tx = conn.unchecked_transaction()?;
	{
		let mut stmt = tx.prepare_cached(
			"INSERT OR IGNORE INTO WeaknessRelationship 
             (source_id, target_id, nature, view_id) 
             VALUES (?1, ?2, ?3, ?4)",
		)?;

		for rel in relationships {
			stmt.execute(params![rel.source_id, rel.target_id, rel.nature, rel.view_id])?;
		}
	}
	tx.commit()?;
	println!("✓");

	Ok(())
}

fn display_database_summary(conn: &Connection) -> Result<()> {
	println!("\n=== Database Summary ===");

	// Count entries
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM Weakness")?;
	let entry_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("CWE Entries:   {}", entry_count);

	// Count relationships
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM WeaknessRelationship")?;
	let rel_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("Relationships: {}", rel_count);

	if rel_count > 0 {
		println!("\nRelationship Types:");
		let mut stmt = conn.prepare(
			"SELECT nature, COUNT(*) as count FROM WeaknessRelationship 
             GROUP BY nature ORDER BY count DESC",
		)?;
		let mut rows = stmt.query_map([], |row| {
			Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
		})?;

		while let Some(Ok((nature, count))) = rows.next() {
			println!("  - {}: {}", nature, count);
		}
	}

	Ok(())
}