// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use crate::common::{
    Args, MAX_CCI_DOWNLOAD_BYTES, MAX_CCI_XML_BYTES, download_file, extract_from_zip, p,
};
use crate::db::record_source;
use std::fmt::Write as _;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use quick_xml::Reader;
use quick_xml::events::Event;
use regex::Regex;
use rusqlite::{Connection, params};
use std::sync::OnceLock;
use tempfile::NamedTempFile;
use tokio::fs;

// Use OnceLock to compile the regex only once for efficiency.
static RMF_REGEX: OnceLock<Regex> = OnceLock::new();

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
fn get_rmf_regex() -> &'static Regex {
    RMF_REGEX.get_or_init(|| Regex::new(r"^([A-Z]{2})\s*-\s*(\d+)(?:\s*\(\s*(\d+)\s*\))?").unwrap())
}

pub async fn process_cci(conn: &Connection, args: &Args) -> Result<()> {
    // RMF CCI Data
    let mut cci_temp_zip = NamedTempFile::new()?;
    let mut cci_temp_xml = NamedTempFile::new()?;
    let metadata = download_file(
        "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/CCI_List.zip",
        &mut cci_temp_zip,
        false,
        "Downloading CCI XML file from DISA…".to_string(),
        args,
        None,
        MAX_CCI_DOWNLOAD_BYTES,
    )
    .await?;

    p("Extracting CCI XML file…", false);
    extract_from_zip(
        &cci_temp_zip,
        &mut cci_temp_xml,
        ".xml",
        args,
        MAX_CCI_XML_BYTES,
    )?;
    p("✓", true);

    // Parse CCI XML and populate database
    cci_parse_and_populate_database(&cci_temp_xml, conn).await?;
    record_source(conn, "CCI", &metadata, None, None)?;

    Ok(())
}

fn extract_control_identifier(input: &str) -> String {
    // The regex matches `\d+`, which can produce digit runs that overflow u32
    // (e.g., "AC-9999999999"). On overflow we return an empty string so the
    // caller treats the row as unrecognized rather than panicking the build.
    let Some(caps) = get_rmf_regex().captures(input) else {
        return String::new();
    };
    let family = caps.get(1).map_or("", |m| m.as_str());
    let Some(control_num_str) = caps.get(2).map(|m| m.as_str()) else {
        return String::new();
    };
    let Ok(control_num) = control_num_str.parse::<u32>() else {
        return String::new();
    };

    let mut result = format!("{family}-{control_num}");

    if let Some(enhancement_match) = caps.get(3) {
        let Ok(enhancement_num) = enhancement_match.as_str().parse::<u32>() else {
            return String::new();
        };
        write!(result, "({enhancement_num})").unwrap();
    }

    result
}

async fn cci_parse_and_populate_database(xml: &NamedTempFile, conn: &Connection) -> Result<()> {
    let bar = ProgressBar::new(4349); // estimated number of CCIs
    let mut on: u32 = 0;
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{prefix} {bar:20.cyan/blue} {msg}")
            .expect("Failed to create progress style"),
    );
    bar.set_prefix("Parsing CCIs…");
    bar.set_message(format!("{on}/4349?"));
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
            Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
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
                                current_cci_id =
                                    tmp_cci.parse::<u32>().context("Failed to parse CCI ID")?;
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
            Ok(Event::Text(e)) if capture_text => {
                text_buffer.push_str(&e.decode().unwrap_or_default());
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
                        if current_references.is_empty() && !current_v4_references.is_empty() {
                            current_references.append(&mut current_v4_references);
                        }
                        for control_number in &current_references {
                            let tmp_control_number = extract_control_identifier(control_number);
                            // Get the RMFControl ID for this control number
                            let mut stmt =
                                conn.prepare("SELECT id FROM RMFControl WHERE number = ?")?;

                            if let Ok(control_id) =
                                stmt.query_row([tmp_control_number], |row| row.get::<_, i64>(0))
                            {
                                // Insert the CCI
                                on += 1;
                                bar.set_message(format!("{on}/4349?"));
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
            Err(e) => return Err(anyhow::anyhow!("CCI XML parsing error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if on == 0 {
        anyhow::bail!("CCI feed contained no usable revision 5 mappings");
    }
    bar.finish_with_message(format!("✓ ({on})"));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::extract_control_identifier;

    #[test]
    fn extract_control_identifier_round_trip() {
        let cases: &[(&str, &str)] = &[
            ("AC-1", "AC-1"),
            ("AC-03", "AC-3"),
            ("AC-3 (1)", "AC-3(1)"),
            ("ac-3", ""),              // wrong case → no match
            ("AC-3(1)(2)", "AC-3(1)"), // only first enhancement captured
            ("", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(
                extract_control_identifier(input),
                *expected,
                "extract_control_identifier({input:?})",
            );
        }
    }

    #[test]
    fn extract_control_identifier_overflow_returns_empty() {
        // The regex matches arbitrarily long digit runs; overflow must not panic.
        assert_eq!(extract_control_identifier("AC-9999999999"), "");
        assert_eq!(extract_control_identifier("AC-1(9999999999)"), "");
    }
}
