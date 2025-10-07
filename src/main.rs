use anyhow::{Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::Client;
use rusqlite::{params, Connection};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tokio::fs;
use zip::ZipArchive;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Output database file path
	#[arg(short, long, default_value = "rusktex.db")]
	output: String,

	/// Force download even if file exists
	#[arg(short, long)]
	force: bool,

	/// Keep downloaded XML file
	#[arg(short, long)]
	keep_xml: bool,

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

const CWE_XML_URL: &str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip";
const TEMP_ZIP_FILE: &str = "cwec_latest.xml.zip";
const TEMP_XML_FILE: &str = "cwec_v4.18.xml";

#[tokio::main]
async fn main() -> Result<()> {
	let args = Args::parse();

	println!("RuskTeX Database Builder v0.1.0");

	// Download the CWE XML file
	if args.force || !Path::new(TEMP_XML_FILE).exists() {
		print!("Downloading CWE XML file from MITRE…");
		download_cwe_xml(&args).await?;
		println!("✓");

		print!("Extracting XML file…");
		extract_xml_from_zip(&args)?;
		println!("✓");
	} else {
		println!("Using existing XML file: {}", TEMP_XML_FILE);
	}

	// Create database
	print!("Creating SQLite database:");
	let conn = create_database(&args.output)?;
	println!("SQLite database created ✓ ({})", args.output);

	// Parse XML and populate database
	print!("Parsing CWE XML and populating database…");
	parse_and_populate_database(&conn, &args).await?;
	println!("✓");

	// Clean up temporary files
	if !args.keep_xml {
		print!("Cleaning temporary files…");
		let _ = std::fs::remove_file(TEMP_ZIP_FILE);
		let _ = std::fs::remove_file(TEMP_XML_FILE);
		println!("✓");
	}

	// Display summary
	display_database_summary(&conn)?;

	println!("\nCWE database build completed successfully: {}", args.output);
	Ok(())
}

async fn download_cwe_xml(args: &Args) -> Result<()> {
	let client = Client::new();

	if args.verbose {
		println!("\nConnecting to: {}", CWE_XML_URL);
	}

	let response = client
		.get(CWE_XML_URL)
		.send()
		.await
		.context("Failed to download CWE XML")?;

	let total_size = response.content_length().unwrap_or(0);
	if args.verbose && total_size > 0 {
		println!("File size: {} bytes", total_size);
	}

	let mut file =
		File::create(TEMP_ZIP_FILE).context("Failed to create temporary zip file")?;

	let mut stream = response.bytes_stream();
	while let Some(chunk) = stream.next().await {
		let chunk = chunk.context("Failed to read chunk")?;
		file.write_all(&chunk)
			.context("Failed to write chunk to file")?;
	}

	Ok(())
}

fn extract_xml_from_zip(args: &Args) -> Result<()> {
	let file = File::open(TEMP_ZIP_FILE).context("Failed to open zip file")?;
	let mut archive = ZipArchive::new(file).context("Failed to read zip archive")?;

	if let Some(mut file) = archive.by_name(TEMP_XML_FILE).ok() {
		if args.verbose {
			println!("\nExtracting: {}", file.name());
		}
		let mut xml_file =
			File::create(TEMP_XML_FILE).context("Failed to create XML file")?;
		std::io::copy(&mut file, &mut xml_file)
			.context("Failed to extract XML file")?;
	} else {
		return Err(anyhow::anyhow!(
			"Could not find '{}' in the downloaded zip file.", TEMP_XML_FILE
		));
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

	// Create relationships table
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

	Ok(conn)
}

async fn parse_and_populate_database(conn: &Connection, args: &Args) -> Result<()> {
	let xml_content = fs::read_to_string(TEMP_XML_FILE)
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

	insert_data_to_database(conn, &cwe_entries, &relationships)?;

	Ok(())
}

fn insert_data_to_database(
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