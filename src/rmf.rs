use crate::common::{download_file,p,Args};

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use rusqlite::{params, Connection};
use tokio::fs;
use tempfile::NamedTempFile;
use regex::Regex;
use indicatif::{ProgressBar,ProgressStyle};

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
struct RMFFamily {
	id: u32,
	abbr: String,
	name: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
struct RMFControl {
	id: u32,
	rmf_family_id: u32,
	number: String,
	name: String,
	description: String,
}

pub async fn process_rmf(conn: &Connection, args: &Args) -> Result<()> {
	// Download RMF Data
    let mut rmf_temp_xml = NamedTempFile::new()?;
    download_file("https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1_XML.xml", &mut rmf_temp_xml, false, "Downloading RMF XML file from NIST…".to_string(), &args).await?;

    // Parse RMF XML and populate database
	p("Parsing NIST RMF XML and populating database:", true);
	rmf_parse_and_populate_database(&mut rmf_temp_xml, &conn).await?;

    Ok(())
}

async fn rmf_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let xml_content = fs::read_to_string(xml.path())
        .await
        .context("Failed to read RMF XML file")?;
    let mut reader = Reader::from_str(&xml_content);
    reader.config_mut().trim_text(true);

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
					text_buffer.push_str(&e.decode().unwrap_or_default());
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
	let bar = ProgressBar::new(families.len() as u64);
	let mut on: u32 = 0;
    bar.set_style(ProgressStyle::default_bar()
    	.template("{prefix} {bar:20.cyan/blue} {msg}")
    	.expect("Failed to create progress style"));
	bar.set_prefix("\tInserting RMF Families…");
	bar.set_message(format!("{}/{}", on, families.len()));
    for family in &families {
		on += 1;
		bar.set_message(format!("{}/{}", on, families.len()));
		bar.inc(1);
        conn.execute(
            "INSERT OR REPLACE INTO RMFFamily (abbr, name) VALUES (?1, ?2)",
            params![family.abbr, family.name],
        ).context("Failed to insert RMF Family")?;
    }
	bar.finish_with_message(format!("✓ ({})", families.len()));
	println!();

	// Insert RMF Controls
	let bar2 = ProgressBar::new(controls.len() as u64);
	on = 0;
    bar2.set_style(ProgressStyle::default_bar()
    	.template("{prefix} {bar:20.cyan/blue} {msg}")
    	.expect("Failed to create progress style"));
	bar2.set_prefix("\tInserting RMF Controls…");
	bar2.set_message(format!("{}/{}", on, controls.len()));
    for control in &controls {
		on += 1;
		bar2.set_message(format!("{}/{}", on, controls.len()));
		bar2.inc(1);
		let mut tmp_sql : String = String::new();
		tmp_sql.push_str("INSERT OR REPLACE INTO RMFControl (RMFFamilyId, number, name, description) VALUES ((SELECT id FROM RMFFamily WHERE abbr = $1), ?2, ?3, ?4)");
		conn.execute(
			&tmp_sql,
            params![&control.number.chars().take(2).collect::<String>(), control.number, control.name, control.description],
        ).context("Failed to insert RMF Control")?;
    }
	bar2.finish_with_message(format!("✓ ({})", controls.len()));
	println!();

    Ok(())
}