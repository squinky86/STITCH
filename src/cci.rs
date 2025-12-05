// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use crate::common::{download_file,extract_from_zip,p,Args};

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use rusqlite::{params, Connection};
use tokio::fs;
use tempfile::NamedTempFile;
use regex::Regex;
use lazy_static::lazy_static;
use indicatif::{ProgressBar,ProgressStyle};

// Use lazy_static to compile the regex only once for efficiency.
lazy_static! {
    // This regex is designed to capture the RMF components.
    //
    // Breakdown:
    // ^                - Anchor to the start of the string.
    // ([A-Z]{2})      - Capture Group 1: The RMF Family (exactly two uppercase letters).
    // \s*-\s* - A hyphen, allowing for surrounding whitespace (e.g., "AC - 1").
    // (\d+)            - Capture Group 2: The RMF Control Number (one or more digits, e.g., "1", "03").
    // (?: ... )?       - An optional, non-capturing group for the enhancement.
    //   \s* - Allows for whitespace between the control number and the parenthesis.
    //   \(             - A literal opening parenthesis.
    //   \s* - Allows for whitespace inside the parenthesis (e.g., "( 1 )").
    //   (\d+)          - Capture Group 3: The Enhancement Number (one or more digits, e.g., "1", "04").
    //   \s* - Allows for whitespace before the closing parenthesis.
    //   \)             - A literal closing parenthesis.
    static ref RMF_REGEX: Regex = Regex::new(
        r"^([A-Z]{2})\s*-\s*(\d+)(?:\s*\(\s*(\d+)\s*\))?"
    ).unwrap();
}

pub async fn process_cci(conn: &Connection, args: &Args) -> Result<()> {
	// RMF CCI Data
	let mut cci_temp_zip = NamedTempFile::new()?;
	let mut cci_temp_xml = NamedTempFile::new()?;
    download_file("https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/CCI+List.zip", &mut cci_temp_zip, false, "Downloading CCI XML file from DISA…".to_string(), args).await?;

    p("Extracting CCI XML file…", false);
    extract_from_zip(&cci_temp_zip, &mut cci_temp_xml, ".xml", &args)?;
    p("✓", true);

    // Parse CCI XML and populate database
	cci_parse_and_populate_database(&mut cci_temp_xml, &conn).await?;

    Ok(())
}

fn extract_control_identifier(input: &str) -> String {
    // RMF_REGEX.captures() attempts to match the regex at the beginning of the string.
    if let Some(caps) = RMF_REGEX.captures(input) {
        // --- Get RMF Family (Group 1) ---
        // We can unwrap() because a successful match guarantees Group 1 exists.
        let family = caps.get(1).unwrap().as_str();

        // --- Get RMF Control Number (Group 2) ---
        // We also know Group 2 is guaranteed to exist.
        let control_num_str = caps.get(2).unwrap().as_str();
        
        // Parse the string to a number (e.g., u32). This beautifully
        // handles normalization (e.g., "03" becomes 3).
        // We can unwrap() the parse because the regex (\d+) guarantees it's a valid number.
        let control_num: u32 = control_num_str.parse().unwrap();

        // Start building the result string using the normalized number.
        let mut result = format!("{}-{}", family, control_num);

        // --- Get Optional RMF Enhancement (Group 3) ---
        // Group 3 is optional, so we must check if it was captured.
        if let Some(enhancement_match) = caps.get(3) {
            let enhancement_str = enhancement_match.as_str();
            
            // Parse to normalize the enhancement number (e.g., "01" becomes 1).
            let enhancement_num: u32 = enhancement_str.parse().unwrap();
            
            // Append the formatted enhancement directly to the result string.
            result.push_str(&format!("({})", enhancement_num));
        }

        // Return the final, formatted string.
        result
    } else {
        // If the regex did not match the start of the string, return an empty string.
        String::new()
    }
}

async fn cci_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let bar = ProgressBar::new(4349); // estimated number of CCIs
	let mut on: u32 = 0;
    bar.set_style(ProgressStyle::default_bar()
    	.template("{prefix} {bar:20.cyan/blue} {msg}")
    	.expect("Failed to create progress style"));
	bar.set_prefix("Parsing CCIs…");
	bar.set_message(format!("{}/4349?", on));
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
								on += 1;
								bar.set_message(format!("{}/4349?", on));
								bar.inc(1);
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

	bar.finish_with_message(format!("✓ ({})", on));

    Ok(())
}
