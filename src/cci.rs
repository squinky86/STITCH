use crate::common::{download_file,extract_from_zip,p,Args};

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use rusqlite::{params, Connection};
use tokio::fs;
use tempfile::NamedTempFile;
use regex::Regex;
use once_cell::sync::Lazy;

pub async fn process_cci(conn: &Connection, args: &Args) -> Result<()> {
	// RMF CCI Data
	let mut cci_temp_zip = NamedTempFile::new()?;
	let mut cci_temp_xml = NamedTempFile::new()?;
    download_file("https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/CCI+List.zip", &mut cci_temp_zip, false, "Downloading CCI XML file from DISA…".to_string(), "✓".to_string(), &args).await?;

    p("Extracting CCI XML file…", false);
    extract_from_zip(&cci_temp_zip, &mut cci_temp_xml, ".xml", &args)?;
    p("✓", true);

    // Parse CCI XML and populate database
	p("Parsing DISA CCI XML and populating database…", false);
	cci_parse_and_populate_database(&mut cci_temp_xml, &conn).await?;
	p("✓", true);

    Ok(())
}

fn extract_control_identifier(input: &str) -> Option<String> {
    // Regex to match the base control and optional single parenthetical enhancement
	static BASE_CONTROL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^([A-Z]{2,3}-\d{1,2}(?:\(\d{1,2}\))?)").unwrap()
    });
	// Regex to match and capture zero-padded enhancements like (01), (02), etc.
    static ZERO_PADDED_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\(0(\d)\)$").unwrap()
    });
    
    // Find the match
    let captures = BASE_CONTROL_RE.captures(input)?;
    
    // Extract the content of the first capturing group (index 1)
    let control_part = captures.get(1)?.as_str().to_string();

    if let Some(captures) = ZERO_PADDED_RE.captures(&control_part) {
        // If it matches (0N), replace the end of the string with (N)
        let digit = captures.get(1).unwrap().as_str();
        let stripped_control = control_part.strip_suffix(&captures.get(0).unwrap().as_str()).unwrap();
        return Some(format!("{}({})", stripped_control, digit));
    }
    
    Some(control_part)
}

async fn cci_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let xml_content = fs::read_to_string(xml.path())
        .await
        .context("Failed to read CCI XML file")?;

    let mut reader = Reader::from_str(&xml_content);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut current_element = String::new();
    let mut current_cci_id: u32 = 0;
    let mut current_definition = String::new();
    let mut current_references = Vec::new();
	let mut current_v4_references = Vec::new();
    let mut capture_text = false;
    let mut text_buffer = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match current_element.as_str() {
                    "cci_item" => {
                        // Get the CCI ID from the id attribute
                        for attr in e.attributes() {
                            let attr = attr.context("Failed to parse CCI attribute")?;
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value);

                            if key == "id" {
								let tmp_cci = value.trim_start_matches("CCI-");
                                current_cci_id = tmp_cci.parse::<u32>()
                                    .context("Failed to parse CCI ID")?;
                            }
                        }
                    }
                    "definition" => {
                        capture_text = true;
                        text_buffer.clear();
                    }
                    "reference" => {
                        let mut ref_title = String::new();
                        let mut ref_index = String::new();
                        
                        // Get the reference title and index attributes
                        for attr in e.attributes() {
                            let attr = attr.context("Failed to parse reference attribute")?;
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value);

                            match key.as_ref() {
                                "title" => ref_title = value.to_string(),
                                "index" => ref_index = value.to_string(),
                                _ => {}
                            }
                        }
                        
                        // Only collect 800-53 Rev 5 references
                        if ref_title == "NIST SP 800-53 Revision 5" {
                            current_references.push(ref_index.clone());
                        }

						// Only collect Rev 4 references when Rev 5 mappings don't exist
                        if ref_title == "NIST SP 800-53 Revision 4" {
                            current_v4_references.push(ref_index.clone());
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
                    "definition" => {
                        current_definition = text_buffer.trim().to_string();
                        capture_text = false;
                    }
                    "cci_item" => {
                        // For each 800-53r5 reference, insert a CCI record
						if current_references.len() == 0 && current_v4_references.len() > 0 {
							current_references.append(&mut current_v4_references);
						}
                        for control_number in &current_references {
							let tmp_control_number = extract_control_identifier(control_number);
                            // Get the RMFControl ID for this control number
                            let mut stmt = conn.prepare(
                                "SELECT id FROM RMFControl WHERE number = ?"
                            )?;
                            
                            if let Ok(control_id) = stmt.query_row([tmp_control_number], |row| row.get::<_, i64>(0)) {
                                // Insert the CCI
                                conn.execute(
                                    "INSERT OR REPLACE INTO RMFCCI (id, RMFControlId, definition) VALUES (?1, ?2, ?3)",
                                    params![current_cci_id, control_id, current_definition],
                                ).context("Failed to insert CCI")?;
                            }
                        }

                        // Reset for next CCI
                        current_cci_id = 0;
                        current_definition.clear();
                        current_references.clear();
						current_v4_references.clear();
                    }
                    _ => {}
                }
                current_element.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("CCI XML parsing error: {}", e)),
            _ => {}
        }
        buf.clear();
    }

    Ok(())
}
