// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use crate::common::{Args, build_insert_sql, download_file, extract_from_zip, p};

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use quick_xml::Reader;
use quick_xml::events::Event;
use rusqlite::{Connection, params_from_iter, types::Value};
use tempfile::NamedTempFile;
use tokio::fs;

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct Weakness {
    pub id: u32,
    pub name: String,
    pub abstraction: String,
    pub description: String,
    pub category: bool, // is a category?
    pub view: bool,     // is a view?
    pub extended_description: String,
    pub confidentiality: bool,
    pub integrity: bool,
    pub availability: bool,
}

#[derive(Debug, Clone)]
pub struct WeaknessRelationship {
    pub source_id: u32,
    pub target_id: u32,
    pub nature: String,
    pub view_id: u32,
}

pub async fn process_cwe(conn: &Connection, args: &Args) -> Result<()> {
    // Download and extract CWE XML
    let mut cwe_temp_zip = NamedTempFile::new()?;
    let mut cwe_temp_xml = NamedTempFile::new()?;
    download_file(
        "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        &mut cwe_temp_zip,
        false,
        "Downloading CWE XML file from MITRE…".to_string(),
        args,
        None,
    )
    .await?;

    p("Extracting CWE XML file…", false);
    extract_from_zip(&cwe_temp_zip, &mut cwe_temp_xml, ".xml", args)?;
    p("✓", true);

    // Parse and populate database
    cwe_parse_and_populate_database(&cwe_temp_xml, conn, args).await?;

    Ok(())
}

async fn cwe_parse_and_populate_database(
    xml: &NamedTempFile,
    conn: &Connection,
    args: &Args,
) -> Result<()> {
    let xml_content = fs::read_to_string(xml.path())
        .await
        .context("Failed to read XML file")?;

    let (cwe_entries, relationships) = parse_cwe_xml(&xml_content, args.verbose)?;
    cwe_insert_data_to_database(conn, &cwe_entries, &relationships)?;
    Ok(())
}

/// Parses a CWE XML document string into in-memory `Weakness` and `WeaknessRelationship` rows.
///
/// The async DB-loading wrapper calls this after reading the file; tests use
/// it directly with inline fixture XML.
pub fn parse_cwe_xml(
    xml_content: &str,
    verbose: bool,
) -> Result<(Vec<Weakness>, Vec<WeaknessRelationship>)> {
    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut cwe_entries: Vec<Weakness> = Vec::new();
    let mut relationships: Vec<WeaknessRelationship> = Vec::new();

    let mut current_weakness: Option<Weakness> = None;
    let mut text_buffer = String::new();
    let mut current_element = String::new();
    let mut capture_text = false;

    let mut has_other: bool = false;
    let mut has_scope: bool = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
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
                            let attr = attr.context("Failed to parse weakness attribute")?;
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value);

                            match key.as_ref() {
                                "Abstraction" => {
                                    weakness.abstraction = value.to_string();
                                }
                                "ID" => weakness.id = value.parse::<u32>().unwrap_or(0),
                                "Name" => weakness.name = value.to_string(),
                                _ => {}
                            }
                        }
                        current_weakness = Some(weakness);
                    }
                    "Description" | "Extended_Description" | "Scope" | "Impact" => {
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
                                let attr =
                                    attr.context("Failed to parse relationship attribute")?;
                                let key = String::from_utf8_lossy(attr.key.as_ref());
                                let value = String::from_utf8_lossy(&attr.value);

                                match key.as_ref() {
                                    "CWE_ID" => {
                                        relationship.target_id = value.parse::<u32>().unwrap_or(0);
                                    }
                                    "Nature" => relationship.nature = value.to_string(),
                                    "View_ID" => {
                                        relationship.view_id = value.parse::<u32>().unwrap_or(0);
                                    }
                                    _ => {}
                                }
                            }
                            if relationship.target_id != 0 && !relationship.nature.is_empty() {
                                relationships.push(relationship);
                            }
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
                    "Weakness" | "Category" | "View" => {
                        if let Some(mut weakness) = current_weakness.take() {
                            if verbose {
                                p(format!("Parsed: CWE-{}", weakness.id).as_str(), true);
                            }
                            //If it is a class not mapped to any impact, assume it maps to all impacts.
                            //Only apply this fallback if no scope was defined at all;
                            //CWEs that explicitly list non-CIA scopes (e.g., "Other") are intentionally without CIA impact.
                            if weakness.abstraction == "Class"
                                && !weakness.confidentiality
                                && !weakness.integrity
                                && !weakness.availability
                                && !has_scope
                            {
                                weakness.confidentiality = true;
                                weakness.integrity = true;
                                weakness.availability = true;
                            }
                            cwe_entries.push(weakness);
                            has_other = false;
                            has_scope = false;
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
                            weakness.extended_description = text_buffer.trim().to_string();
                        }
                        capture_text = false;
                    }
                    "Scope" => {
                        has_scope = true;
                        if let Some(weakness) = current_weakness.as_mut() {
                            match text_buffer.trim() {
                                "Confidentiality" => weakness.confidentiality = true,
                                "Integrity" | "Accountability" | "Non-Repudiation" => {
                                    weakness.integrity = true;
                                }
                                "Availability" => weakness.availability = true,
                                "Access Control" => {
                                    weakness.confidentiality = true;
                                    weakness.integrity = true;
                                }
                                "Authentication" | "Authorization" => {
                                    weakness.confidentiality = true;
                                    weakness.integrity = true;
                                    weakness.availability = true;
                                }
                                "Other" => has_other = true,
                                _ => {}
                            }
                        }
                        capture_text = false;
                    }
                    "Impact" => {
                        if let Some(weakness) = current_weakness.as_mut()
                            && has_other
                            && text_buffer.trim() == "Varies by Context"
                        {
                            weakness.confidentiality = true;
                            weakness.integrity = true;
                            weakness.availability = true;
                        }
                        has_other = false;
                        capture_text = false;
                    }
                    _ => {}
                }
                current_element.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parsing error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    Ok((cwe_entries, relationships))
}

// Chunk sizes chosen to stay well under SQLite's default 32766 host-parameter
// limit while keeping the per-statement parse/plan cost amortized over many
// rows. 1000 weakness rows = 10000 params; 2000 relationship rows = 8000 params.
const WEAKNESS_BATCH: usize = 1000;
const RELATIONSHIP_BATCH: usize = 2000;

fn cwe_insert_data_to_database(
    conn: &Connection,
    entries: &[Weakness],
    relationships: &[WeaknessRelationship],
) -> Result<()> {
    // Insert CWE entries
    let bar = ProgressBar::new(entries.len() as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{prefix} {bar:20.cyan/blue} {msg}")
            .expect("Failed to create progress style"),
    );
    bar.set_prefix("Inserting CWEs…");
    bar.set_message(format!("0/{}", entries.len()));
    let mut tx = conn.unchecked_transaction()?;
    {
        for chunk in entries.chunks(WEAKNESS_BATCH) {
            let sql = build_insert_sql(
                "INSERT OR REPLACE INTO Weakness \
                 (id, name, abstraction, description, extended_description, \
                  category, view, confidentiality, integrity, availability) VALUES ",
                chunk.len(),
                10,
            );
            let mut values: Vec<Value> = Vec::with_capacity(chunk.len() * 10);
            for entry in chunk {
                values.push(Value::Integer(i64::from(entry.id)));
                values.push(Value::Text(entry.name.clone()));
                values.push(Value::Text(entry.abstraction.clone()));
                values.push(Value::Text(entry.description.clone()));
                values.push(Value::Text(entry.extended_description.clone()));
                values.push(Value::Integer(i64::from(entry.category)));
                values.push(Value::Integer(i64::from(entry.view)));
                values.push(Value::Integer(i64::from(entry.confidentiality)));
                values.push(Value::Integer(i64::from(entry.integrity)));
                values.push(Value::Integer(i64::from(entry.availability)));
            }
            tx.execute(&sql, params_from_iter(values.iter()))?;
            bar.inc(chunk.len() as u64);
            bar.set_message(format!("{}/{}", bar.position(), entries.len()));
        }
    }
    tx.commit()?;
    bar.finish_with_message(format!("✓ ({})", entries.len()));
    println!();

    // Insert relationships
    let bar2 = ProgressBar::new(relationships.len() as u64);
    bar2.set_style(
        ProgressStyle::default_bar()
            .template("{prefix} {bar:20.cyan/blue} {msg}")
            .expect("Failed to create progress style"),
    );
    bar2.set_prefix("Inserting CWE Relationships…");
    bar2.set_message(format!("0/{}", relationships.len()));
    tx = conn.unchecked_transaction()?;
    {
        for chunk in relationships.chunks(RELATIONSHIP_BATCH) {
            let sql = build_insert_sql(
                "INSERT OR IGNORE INTO WeaknessRelationship \
                 (source_id, target_id, nature, view_id) VALUES ",
                chunk.len(),
                4,
            );
            let mut values: Vec<Value> = Vec::with_capacity(chunk.len() * 4);
            for rel in chunk {
                values.push(Value::Integer(i64::from(rel.source_id)));
                values.push(Value::Integer(i64::from(rel.target_id)));
                values.push(Value::Text(rel.nature.clone()));
                values.push(Value::Integer(i64::from(rel.view_id)));
            }
            tx.execute(&sql, params_from_iter(values.iter()))?;
            bar2.inc(chunk.len() as u64);
            bar2.set_message(format!("{}/{}", bar2.position(), relationships.len()));
        }
    }
    tx.commit()?;
    bar2.finish_with_message(format!("✓ ({})", relationships.len()));
    println!();

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> (Vec<Weakness>, Vec<WeaknessRelationship>) {
        parse_cwe_xml(xml, false).expect("parse_cwe_xml failed")
    }

    fn find(entries: &[Weakness], id: u32) -> &Weakness {
        entries.iter().find(|w| w.id == id).expect("CWE not found")
    }

    const FIXTURE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog>
  <Weaknesses>
    <Weakness ID="100" Name="Class no scope" Abstraction="Class">
      <Description>desc</Description>
    </Weakness>
    <Weakness ID="200" Name="Other varies" Abstraction="Base">
      <Description>desc</Description>
      <Common_Consequences>
        <Consequence>
          <Scope>Other</Scope>
          <Impact>Varies by Context</Impact>
        </Consequence>
      </Common_Consequences>
    </Weakness>
    <Weakness ID="300" Name="Confidentiality only" Abstraction="Base">
      <Description>desc</Description>
      <Common_Consequences>
        <Consequence>
          <Scope>Confidentiality</Scope>
        </Consequence>
      </Common_Consequences>
    </Weakness>
    <Weakness ID="400" Name="Authentication scope" Abstraction="Base">
      <Description>desc</Description>
      <Common_Consequences>
        <Consequence>
          <Scope>Authentication</Scope>
        </Consequence>
      </Common_Consequences>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="100" View_ID="1000" />
      </Related_Weaknesses>
    </Weakness>
  </Weaknesses>
  <Views>
    <View ID="1000" Name="Research view" Abstraction="View">
      <Description>view</Description>
    </View>
  </Views>
</Weakness_Catalog>"#;

    #[test]
    fn class_with_no_scope_defaults_to_all_cia() {
        let (entries, _) = parse(FIXTURE);
        let w = find(&entries, 100);
        assert!(w.confidentiality && w.integrity && w.availability);
    }

    #[test]
    fn other_scope_with_varies_by_context_sets_all_cia() {
        let (entries, _) = parse(FIXTURE);
        let w = find(&entries, 200);
        assert!(w.confidentiality && w.integrity && w.availability);
    }

    #[test]
    fn explicit_confidentiality_scope_only_sets_c() {
        let (entries, _) = parse(FIXTURE);
        let w = find(&entries, 300);
        assert!(w.confidentiality && !w.integrity && !w.availability);
    }

    #[test]
    fn authentication_scope_sets_all_cia() {
        let (entries, _) = parse(FIXTURE);
        let w = find(&entries, 400);
        assert!(w.confidentiality && w.integrity && w.availability);
    }

    #[test]
    fn related_weakness_emits_relationship_row() {
        let (_, rels) = parse(FIXTURE);
        let r = rels
            .iter()
            .find(|r| r.source_id == 400)
            .expect("expected relationship from 400");
        assert_eq!(r.target_id, 100);
        assert_eq!(r.nature, "ChildOf");
        assert_eq!(r.view_id, 1000);
    }

    #[test]
    fn parser_output_inserts_into_in_memory_db() {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::apply_schema(&conn).unwrap();
        let (entries, rels) = parse(FIXTURE);
        cwe_insert_data_to_database(&conn, &entries, &rels).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM Weakness", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 5);
        let rel_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM WeaknessRelationship", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(rel_count, 1);
    }
}
