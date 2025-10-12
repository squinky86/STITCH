use crate::common::{download_file,extract_from_zip,Args};

use tempfile::NamedTempFile;
use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use rusqlite::{params, Connection};
use tokio::fs;
use indicatif::{ProgressBar,ProgressStyle};

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

pub async fn process_cwe(conn: &Connection, args: &Args) -> Result<()> {
    // Download and extract CWE XML
    let mut cwe_temp_zip = NamedTempFile::new()?;
    let mut cwe_temp_xml = NamedTempFile::new()?;
    download_file("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", &mut cwe_temp_zip, false, "Downloading CWE XML file from MITRE…".to_string(), "✓".to_string(), &args).await?;

    print!("Extracting CWE XML file…");
    extract_from_zip(&cwe_temp_zip, &mut cwe_temp_xml, ".xml", &args)?;
    println!("✓");

    // Parse and populate database
    cwe_parse_and_populate_database(&mut cwe_temp_xml, conn, args).await?;

    Ok(())
}

async fn cwe_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection, args: &Args) -> Result<()> {
	let xml_content = fs::read_to_string(xml.path())
		.await
		.context("Failed to read XML file")?;

	let mut reader = Reader::from_str(&xml_content);
	reader.config_mut().trim_text(true);

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
					text_buffer.push_str(&e.decode().unwrap_or_default());
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

fn cwe_insert_data_to_database(
	conn: &Connection,
	entries: &[Weakness],
	relationships: &[WeaknessRelationship],
) -> Result<()> {
	// Insert CWE entries
	let bar = ProgressBar::new(entries.len() as u64);
	let mut on: u32 = 0;
    bar.set_style(ProgressStyle::default_bar()
    	.template("{prefix} {bar:20.cyan/blue} {msg}")
    	.expect("Failed to create progress style"));
	bar.set_prefix("Inserting CWEs…");
	bar.set_message(format!("{}/{}", on, entries.len()));
	let mut tx = conn.unchecked_transaction()?;
	{
		let mut stmt = tx.prepare_cached(
			"INSERT OR REPLACE INTO Weakness 
             (id, name, description, extended_description, category, view, confidentiality, integrity, availability) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
		)?;

		for entry in entries {
			on += 1;
			bar.set_message(format!("{}/{}", on, entries.len()));
			bar.tick();
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
	bar.finish_with_message(format!("✓ ({})", entries.len()));

	// Insert relationships
	let bar2 = ProgressBar::new(relationships.len() as u64);
	on = 0;
    bar2.set_style(ProgressStyle::default_bar()
    	.template("{prefix} {bar:20.cyan/blue} {msg}")
    	.expect("Failed to create progress style"));
	bar2.set_prefix("Inserting CWE Relationshps…");
	bar2.set_message(format!("{}/{}", on, relationships.len()));
	tx = conn.unchecked_transaction()?;
	{
		let mut stmt = tx.prepare_cached(
			"INSERT OR IGNORE INTO WeaknessRelationship 
             (source_id, target_id, nature, view_id) 
             VALUES (?1, ?2, ?3, ?4)",
		)?;

		for rel in relationships {
			on += 1;
			bar2.set_message(format!("{}/{}", on, relationships.len()));
			bar2.tick();
			stmt.execute(params![rel.source_id, rel.target_id, rel.nature, rel.view_id])?;
		}
	}
	tx.commit()?;
	bar2.finish_with_message(format!("✓ ({})", relationships.len()));

	Ok(())
}
