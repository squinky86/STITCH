use crate::common::{download_file,Args};

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use rusqlite::{params, Connection};
use tokio::fs;
use tempfile::NamedTempFile;
use regex::Regex;

#[derive(Debug, Clone, Default)]
struct RMFFamily {
	id: u32,
	abbr: String,
	name: String,
}

#[derive(Debug, Clone, Default)]
struct RMFControl {
	id: u32,
	rmf_family_id: u32,
	number: String,
	name: String,
	description: String,
}

pub async fn process_rmf(conn: &Connection, args: &Args) -> Result<()> {
	//RMF Control Data
	let mut rmf_temp_xml = NamedTempFile::new()?;
    
    // Download RMF Data

    print!("Downloading RMF XML file from NIST…");
    let mut rmf_temp_xml = NamedTempFile::new()?;
    download_file("https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1_XML.xml", &mut rmf_temp_xml, &args).await?;
    println!("✓");

    // Parse RMF XML and populate database
	println!("Parsing NIST RMF XML and populating database:");
	rmf_parse_and_populate_database(&mut rmf_temp_xml, &conn).await?;

    Ok(())
}

async fn rmf_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let xml_content = fs::read_to_string(xml.path())
        .await
        .context("Failed to read RMF XML file")?;
    let mut reader = Reader::from_str(&xml_content);
    reader.trim_text(true);

    let mut families: Vec<RMFFamily> = Vec::new();
    let mut controls: Vec<RMFControl> = Vec::new();
    let mut buf = Vec::new();

	let mut text_buffer = String::new();
	let mut current_element = String::new();
	let mut capture_text = false;

	let mut tmp_family: String = String::new();
	let mut tmp_number: String = String::new();
	let mut tmp_title: String = String::new();
	let mut tmp_p: String = String::new();
	let mut tmp_e_number: String = String::new();
	let mut tmp_e_title: String = String::new();
	let mut tmp_e_p: String = String::new();
	let mut in_enhancements: bool = false;
    
	loop {
		match reader.read_event_into(&mut buf) {
			Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e))=> {
				current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();

				match current_element.as_str() {
					"family" | "description" | "number" | "title" | "p" => {
						capture_text = true;
						text_buffer.clear();
					}
					"control-enhancements" => {
						in_enhancements = true;
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
						let tmp_num2 = text_buffer.trim().to_string();
						// Regex that matches a NIST RMF control or enhancement (e.g., AC-03 or AC-03(1))
    					// ^\s*[A-Z]{2}-\d{1,2}(?:\(\d{1,2}\))?\s*$
						let re = Regex::new(r"^\s*[A-Z]{2}-\d{1,2}(?:\(\d{1,2}\))?\s*$").expect("Invalid Regex pattern");
						if re.is_match(&tmp_num2) {
							if in_enhancements {
								tmp_e_number = tmp_num2.clone();
							}
							else {
								tmp_number = tmp_num2.clone();
							}
							let family = RMFFamily {
								id: 0,
								abbr: tmp_num2.chars().take(2).collect(),
								name: tmp_family.clone()
							};
							if !families.iter().any(|f| f.abbr == family.abbr) {
								families.push(family);
							}
						}
						else {
							//we are in a line item within the description
							if in_enhancements {
								if tmp_e_p.len() > 0 {
									tmp_e_p.push_str("\n");
								}
								tmp_e_p.push_str(&tmp_num2.trim());
								tmp_e_p.push_str(" ");
							}
							else {
								if tmp_p.len() > 0 {
									tmp_p.push_str("\n");
								}
								tmp_p.push_str(&tmp_num2.trim());
								tmp_p.push_str(" ");
							}
						}
					}
					"title" => {
						if in_enhancements {
							tmp_e_title = text_buffer.trim().to_string();
						}
						else {
							tmp_title = text_buffer.trim().to_string();
						}
					}
					"description" => {
						if in_enhancements {
							tmp_e_p.push_str(&text_buffer.trim().to_string().replace("<p>", "").replace("</p>", "\n").trim());
						}
						else {
							tmp_p.push_str(&text_buffer.trim().to_string().replace("<p>", "").replace("</p>", "\n").trim());
						}
					}
					"control-enhancements" => {
						in_enhancements = false;
					}
					"controls:control" => {
						let c: RMFControl = RMFControl {
							id: 0,
							rmf_family_id: 0,
							number: tmp_number.clone(),
							name: tmp_title.clone(),
							description: tmp_p.clone()
						};
						controls.push(c);
						tmp_p = String::new();
					}
					"control-enhancement" => {
						let c: RMFControl = RMFControl {
							id: 0,
							rmf_family_id: 0,
							number: tmp_e_number.clone(),
							name: tmp_e_title.clone(),
							description: tmp_e_p.clone()
						};
						controls.push(c);
						tmp_e_p = String::new();
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

    // Insert RMF Families
    print!("\tInserting {} RMF Families…", families.len());
    for family in &families {
        conn.execute(
            "INSERT OR REPLACE INTO RMFFamily (abbr, name) VALUES (?1, ?2)",
            params![family.abbr, family.name],
        ).context("Failed to insert RMF Family")?;
    }
	println!("✓");

	// Insert RMF Controls
    print!("\tInserting {} RMF Controls…", controls.len());
    for control in &controls {
		let mut tmp_sql : String = String::new();
		tmp_sql.push_str("INSERT OR REPLACE INTO RMFControl (RMFFamilyId, number, name, description) VALUES ((SELECT id FROM RMFFamily WHERE abbr = $1), ?2, ?3, ?4)");
		conn.execute(
			&tmp_sql,
            params![&control.number.chars().take(2).collect::<String>(), control.number, control.name, control.description],
        ).context("Failed to insert RMF Control")?;
    }
	println!("✓");

    Ok(())
}