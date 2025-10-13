use crate::common::{download_file,p,Args};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use tokio::fs;
use tempfile::NamedTempFile;
use serde::Deserialize;
use std::collections::HashMap;
use indicatif::{ProgressBar,ProgressStyle};

//store data of YAML parsing
#[derive(Debug, Deserialize)]
struct Mappings {
    stig_to_cwe: HashMap<String, STIGToCWE>,
    cwe_to_stig: HashMap<String, CWEToSTIG>,
}

#[derive(Debug, Deserialize)]
struct STIGToCWE {
    cwe_ids: Vec<MappingWithDefault>,
}

#[derive(Debug, Deserialize)]
struct CWEToSTIG {
    stig_ids: Vec<MappingWithDefault>,
}

#[derive(Debug, Deserialize)]
struct MappingWithDefault {
    id: String,
    default: bool,
}

pub async fn process_stigwe(conn: &Connection, args: &Args) -> Result<()> {
	// STIG↔CWE Data
    let mut stigwe_temp_yaml = NamedTempFile::new()?;
	download_file("https://raw.githubusercontent.com/squinky86/STIGWE/refs/heads/main/mappings/mappings.yaml", &mut stigwe_temp_yaml, false, "Downloading STIGWE YAML file…".to_string(), "✓".to_string(), &args).await?;

    // Parse STIGWE YAML and populate database
	p("Parsing STIGWE YAML and populating database:", true);
	stigwe_parse_and_populate_database(&mut stigwe_temp_yaml, &conn).await?;

    Ok(())
}

async fn stigwe_parse_and_populate_database(yaml: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let yaml_content = fs::read_to_string(yaml.path())
        .await
        .context("Failed to read YAML file")?;

    let mappings: Mappings = serde_yaml::from_str(&yaml_content)
        .context("Failed to parse YAML content")?;

	// Update STIGCheck CWEId where default mapping exists
	let bar = ProgressBar::new(mappings.stig_to_cwe.len() as u64);
	let mut on: u32 = 0;
    bar.set_style(ProgressStyle::default_bar()
    	.template("{prefix} {bar:20.cyan/blue} {msg}")
    	.expect("Failed to create progress style"));
	bar.set_prefix("\tInserting STIG→CWE mappings…");
	bar.set_message(format!("{}/{}", on, mappings.stig_to_cwe.len()));
	for (stig_id, mapping) in &mappings.stig_to_cwe {
		on += 1;
		bar.set_message(format!("{}/{}", on, mappings.stig_to_cwe.len()));
        bar.inc(1);
		for cwe_mapping in &mapping.cwe_ids {
            if cwe_mapping.default {
                let cwe_id = cwe_mapping.id.trim_start_matches("CWE-")
                    .parse::<u32>()
                    .context("Failed to parse CWE ID")?;
                
				conn.execute(
                    "UPDATE STIGCheck 
                     SET CWEId = ?1 
                     WHERE DISAId LIKE ?2 
                     AND CWEId IS NULL",
					params![cwe_id, format!("{}%", stig_id)],
                )?;
            }
        }
    }
	bar.finish_with_message(format!("✓ ({})", mappings.stig_to_cwe.len()));
	println!();

	// Process CWE to STIG mappings
	let bar2 = ProgressBar::new(mappings.cwe_to_stig.len() as u64);
	on = 0;
    bar2.set_style(ProgressStyle::default_bar()
    	.template("{prefix} {bar:20.cyan/blue} {msg}")
    	.expect("Failed to create progress style"));
	bar2.set_prefix("\tInserting CWE→STIG mappings…");
	bar2.set_message(format!("{}/{}", on, mappings.cwe_to_stig.len()));
	for (cwe_id, mapping) in &mappings.cwe_to_stig {
		on += 1;
		bar2.set_message(format!("{}/{}", on, mappings.cwe_to_stig.len()));
        bar2.inc(1);
		for stig_mapping in &mapping.stig_ids {
            if stig_mapping.default {
                let cwe_num = cwe_id.trim_start_matches("CWE-")
                    .parse::<u32>()
                    .context("Failed to parse CWE ID")?;
                
                conn.execute(
                    "UPDATE Weakness 
                     SET STIGCheckId = (
                         SELECT id 
                         FROM STIGCheck 
                         WHERE DISAId LIKE ?1
                         LIMIT 1
                     )
                     WHERE id = ?2",
                    params![format!("{}%", stig_mapping.id), cwe_num],
                )?;
            }
        }
    }
	bar2.finish_with_message(format!("✓ ({})", mappings.cwe_to_stig.len()));
	println!();

    Ok(())
}
