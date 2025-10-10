mod common;
mod cwe;
mod rmf;

use crate::common::{decompress_gzip,download_file,extract_xml_from_zip,Args};
use crate::cwe::process_cwe;
use crate::rmf::process_rmf;
use anyhow::{Context, Result};
use chrono::{Utc, Datelike};
use clap::Parser;
use quick_xml::events::Event;
use quick_xml::Reader;
use rusqlite::{params, Connection};
use tokio::fs;
use tempfile::NamedTempFile;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
struct STIG {
    id: u32,
    classification: String,
    description: String,
    name: String, 
    version: String,
}

#[derive(Debug, Clone, Default)]
struct STIGCheck {
    id: u32,
    check_content: String,
    check_system: String,
    disa_id: String,
    documentable: bool,
    false_negatives: String,
    false_positives: String,
    fix_text: String,
    ia_controls: String,
    mitigation_control: String,
    mitigations: String,
    potential_impacts: String,
    reference: String,
    responsibility: String,
    stig_id: u32,
    severity: String,
    severity_override_guidance: String,
    third_party_tools: String,
    title: String,
    vuln_group_id: String,
    vuln_id: String,
    version: String,
    vuln_discussion: String,
    weight: f64,
}

async fn nvd_parse_and_populate_database(json_file: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let json_content = fs::read_to_string(json_file.path())
        .await
        .context("Failed to read NVD JSON file")?;
    
    // TODO: Parse JSON and populate database
    
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
	let args = Args::parse();

	//RMF CCI Data
	const CCI_XML_URL: &str = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/CCI+List.zip";
	let mut cci_temp_zip = NamedTempFile::new()?;
	let mut cci_temp_xml = NamedTempFile::new()?;

	//STIG Data
	const STIG_XML_URL: &str = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_ASD_V6R3_STIG.zip";
	let mut stig_temp_zip = NamedTempFile::new()?;
	let mut stig_temp_xml = NamedTempFile::new()?;

	//CWE and STIG mapping
	const STIGWE_YAML_URL: &str = "https://raw.githubusercontent.com/squinky86/STIGWE/refs/heads/main/mappings/mappings.yaml";
	let mut stigwe_temp_yaml = NamedTempFile::new()?;

	println!("RuskTeX Database Builder v0.1.0");

	//DB Structure
	print!("Creating SQLite database:");
	let conn = create_database(&args.output)?;
	println!("SQLite database created ✓ ({})", args.output);

	//CWE Data
	process_cwe(&conn, &args).await?;

	//RMF Data
	process_rmf(&conn, &args).await?;

	// Download the CCI XML file
	if cci_temp_zip.path().exists() {
		print!("Downloading CCI XML file from DISA…");
        download_file(&CCI_XML_URL, &mut cci_temp_zip, &args).await?;
        println!("✓");

        print!("Extracting CCI XML file…");
        extract_xml_from_zip(&cci_temp_zip, &mut cci_temp_xml, &args)?;
        println!("✓");
    } else {
        eprintln!("Unable to create temporary CCI file.");
        std::process::exit(1);
	}

	// Download the STIG XML file
	if stig_temp_zip.path().exists() {
		print!("Downloading STIG XML file from DISA…");
        download_file(&STIG_XML_URL, &mut stig_temp_zip, &args).await?;
        println!("✓");

        print!("Extracting STIG XML file…");
        extract_xml_from_zip(&stig_temp_zip, &mut stig_temp_xml, &args)?;
        println!("✓");
    } else {
        eprintln!("Unable to create temporary STIG file.");
        std::process::exit(1);
	}

	// Download the STIGWE YAML file
	if stigwe_temp_yaml.path().exists() {
		print!("Downloading STIGWE YAML file…");
		download_file(&STIGWE_YAML_URL, &mut stigwe_temp_yaml, &args).await?;
		println!("✓");
	} else {
		eprintln!("Unable to create temporary STIGWE YAML file.");
		std::process::exit(1);
	}

	//Parse CCI XML and populate database
	print!("Parsing DISA CCI XML and populating database…");
	cci_parse_and_populate_database(&mut cci_temp_xml, &conn).await?;
	println!("✓");

	// Parse STIG XML and populate database
	print!("Parsing DISA STIG XML and populating database…");
	stig_parse_and_populate_database(&mut stig_temp_xml, &conn).await?;
	println!("✓");

	// Parse STIGWE YAML and populate database
	println!("Parsing STIGWE YAML and populating database:");
	stigwe_parse_and_populate_database(&mut stigwe_temp_yaml, &conn).await?;

	// Download and process NVD data
	println!("Obtaining and parsing NVD data:");
	let current_datetime = Utc::now();
	for year in 2002..current_datetime.year() {
		println!("\tProcessing NVD data for year {}:", year);
		let mut nvd_temp_json_gz = NamedTempFile::new()?;
		let mut nvd_temp_json = NamedTempFile::new()?;
		let nvd_url = format!("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{}.json.gz", year);
		print!("\t\tDownloading {} NVD JSON…", year);
		download_file(&nvd_url, &mut nvd_temp_json_gz, &args).await?;
		println!("✓");

		print!("\t\tDeflating {} NVD JSON…", year);
		decompress_gzip(&mut nvd_temp_json_gz, &mut nvd_temp_json).await?;
		println!("✓");

		print!("\t\tParsing {} NVD JSON data…", year);
		nvd_parse_and_populate_database(&mut nvd_temp_json, &conn).await?;
		println!("✓");
	}

	// Display summary
	display_database_summary(&conn)?;

	println!("\nCWE database build completed successfully: {}", args.output);
	Ok(())
}

fn create_database(db_path: &str) -> Result<Connection> {
	// Delete the database file if it exists
	if std::path::Path::new(db_path).exists() {
		std::fs::remove_file(db_path).context("Failed to delete existing database file")?;
	}
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
availability BOOLEAN NOT NULL DEFAULT 0 CHECK(availability IN (0, 1)),
STIGCheckId INTEGER,
FOREIGN KEY(STIGCheckId) REFERENCES STIGCheck(id)
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

	conn.execute(
		"CREATE TABLE IF NOT EXISTS STIG (
id INTEGER PRIMARY KEY AUTOINCREMENT,
classification TEXT,
description TEXT,
name TEXT,
version TEXT
);",
		[],
	)
	.context("Failed to create STIG table")?;

	conn.execute(
		"CREATE TABLE IF NOT EXISTS STIGCheck (
id INTEGER PRIMARY KEY AUTOINCREMENT,
CheckContent TEXT,
CheckSys TEXT,
DISAId TEXT,
Documentable INTEGER NOT NULL DEFAULT 0,
FalseNegatives TEXT,
FalsePositives TEXT,
FixText TEXT,
IAControls TEXT,
MitigationControl TEXT,
Mitigations TEXT,
PotentialImpacts TEXT,
Reference TEXT,
Responsibility TEXT,
STIGId INTEGER NOT NULL,
Severity TEXT,
SeverityOverrideGuidance TEXT,
ThirdPartyTools TEXT,
Title TEXT,
VULNGroupId TEXT,
VULNId TEXT,
Version TEXT,
VulnDiscussion TEXT,
Weight NUMERIC NOT NULL DEFAULT 10.0,
CWEId INTEGER,
FOREIGN KEY(CWEId) REFERENCES Weakness(id),
FOREIGN KEY(STIGId) REFERENCES STIG(id) ON DELETE CASCADE
);",
		[],
	)
	.context("Failed to create STIG table")?;

	conn.execute(
		"CREATE TABLE IF NOT EXISTS MapSTIGCheckCCI (
STIGCheckId INTEGER,
CCIId INTEGER,
PRIMARY KEY(STIGCheckId,CCIId),
FOREIGN KEY(STIGCheckId) REFERENCES STIGCheck(id) ON DELETE CASCADE,
FOREIGN KEY(CCIId) REFERENCES RMFCCI(id)
);",
		[],
	)
	.context("Failed to create MapSTIGCheckCCI table")?;

	conn.execute(
		"CREATE TABLE IF NOT EXISTS Vulnerability (
id INTEGER PRIMARY KEY AUTOINCREMENT,
NVDId TEXT,
Description TEXT,
attackVector TEXT,
attackComplexity TEXT,
attackRequirements TEXT,
privilegesRequired TEXT,
userInteraction TEXT,
vulnConfidentialityImpact TEXT,
vulnIntegrityImpact TEXT,
vulnAvailabilityImpact TEXT,
subConfidentialityImpact TEXT,
subIntegrityImpact TEXT,
subAvailabilityImpact TEXT,
exploitMaturity TEXT,
confidentialityRequirement TEXT,
integrityRequirement TEXT,
availabilityRequirement TEXT,
modifiedAttackVector TEXT,
modifiedAttackComplexity TEXT,
modifiedAttackRequirements TEXT,
modifiedPrivilegesRequired TEXT,
modifiedUserInteraction TEXT,
modifiedVulnConfidentialityImpact TEXT,
modifiedVulnIntegrityImpact TEXT,
modifiedVulnAvailabilityImpact TEXT,
modifiedSubConfidentialityImpact TEXT,
modifiedSubIntegrityImpact TEXT,
modifiedSubAvailabilityImpact TEXT,
Safety TEXT,
Automatable TEXT,
Recovery TEXT,
valueDensity TEXT,
vulnerabilityResponseEffort TEXT,
providerUrgency TEXT
);",
		[],
	)
	.context("Failed to create NVD table")?;

	conn.execute(
		"CREATE TABLE IF NOT EXISTS MapVulnerabilityWeakness (
VulnerabilityId INTEGER,
WeaknessId INTEGER,
PRIMARY KEY(VulnerabilityId,WeaknessId),
FOREIGN KEY(VulnerabilityId) REFERENCES Vulnerability(id) ON DELETE CASCADE,
FOREIGN KEY(WeaknessId) REFERENCES Weakness(id)
);",
		[],
	)
	.context("Failed to create MapNVDWeakness table")?;

	Ok(conn)
}

fn extract_control_identifier(input: &str) -> Option<String> {
    // Regex to match the base control and optional single parenthetical enhancement
    // NOTE: This captures (03) as (03). See further notes for (3)
    let re = Regex::new(r"^([A-Z]{2,3}-\d{1,2}(?:\(\d{1,2}\))?)").unwrap();
    
    // Find the match
    let captures = re.captures(input)?;
    
    // Extract the content of the first capturing group (index 1)
    let control_part = captures.get(1)?.as_str().to_string();

    // --- Optional: Post-Processing to remove leading zero if (0N) is present ---
    if let Some(captures) = Regex::new(r"\(0(\d)\)$").unwrap().captures(&control_part) {
        // If it matches (0N), replace the end of the string with (N)
        let digit = captures.get(1).unwrap().as_str();
        let stripped_control = control_part.strip_suffix(&captures.get(0).unwrap().as_str()).unwrap();
        return Some(format!("{}({})", stripped_control, digit));
    }
    // --------------------------------------------------------------------------

    Some(control_part)
}

async fn cci_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let xml_content = fs::read_to_string(xml.path())
        .await
        .context("Failed to read CCI XML file")?;

    let mut reader = Reader::from_str(&xml_content);
    reader.trim_text(true);

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
                    text_buffer.push_str(&e.unescape().unwrap_or_default());
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

async fn stig_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let xml_content = fs::read_to_string(xml.path())
        .await
        .context("Failed to read STIG XML file")?;

    let mut reader = Reader::from_str(&xml_content);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut text_buffer = String::new();
    let mut current_element = String::new();
    let mut capture_text = false;

	let mut in_rule = false;
	let mut in_ident_cci = false;

	let mut tcheck_content = String::new();
    let mut tcheck_system = String::new();
    let mut tdisa_id  = String::new();
    let mut tdocumentable = false;
    let mut tfalse_negatives  = String::new();
    let mut tfalse_positives  = String::new();
    let mut tfix_text  = String::new();
    let mut tia_controls  = String::new();
    let mut tmitigation_control  = String::new();
    let mut tmitigations  = String::new();
    let mut tpotential_impacts  = String::new();
    let mut treference  = String::new();
    let mut tresponsibility  = String::new();
    let mut tseverity  = String::new();
    let mut tseverity_override_guidance  = String::new();
    let mut tthird_party_tools  = String::new();
    let mut ttitle  = String::new();
    let mut tvuln_group_id  = String::new();
    let mut tvuln_id  = String::new();
    let mut tversion  = String::new();
    let mut tvuln_discussion  = String::new();
    let mut tweight: f64 = 10.0;
	let mut tccis: Vec<u32> = Vec::new();

    // Insert STIG record first to get its ID
    let stig_id = conn.execute(
        "INSERT INTO STIG (classification, description, name, version) VALUES (?1, ?2, ?3, ?4)",
        params![
            "UNCLASSIFIED", // Default classification
            "Application Security and Development STIG",
            "ASD STIG",
            "V6R3"
        ],
    )?;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match current_element.as_str() {
                    "check" => {
						for attr in e.attributes() {
                            let attr = attr.context("Failed to parse STIG check attribute")?;
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value);

                            if key == "system" {
								tcheck_system = value.to_string();
                            }
                        }
					}
					"Group" => {
                        for attr in e.attributes() {
                            let attr = attr.context("Failed to parse STIG group attribute")?;
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value);

                            if key == "id" {
								tvuln_id = value.to_string();
                            }
                        }
                    }
					"ident" => {
						for attr in e.attributes() {
                            let attr = attr.context("Failed to parse ident attribute")?;
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value);

                            if key == "system" {
								if value == "http://cyber.mil/cci" {
									in_ident_cci = true;
									capture_text = true;
									text_buffer.clear();
								}
                            }
                        }
					}
					"Rule" => {
						in_rule = true;
						for attr in e.attributes() {
                            let attr = attr.context("Failed to parse rule attribute")?;
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value);

							match key.as_ref() {
								"id" => {
									tdisa_id = value.to_string();
								}
								"weight" => {
									tweight = value.parse::<f64>().unwrap_or(10.0);
								}
								"severity" => {
									tseverity = value.to_string();
								}
								_ => {}
							}
                        }
					}
					"title" | "description" | "fixtext" | "check-content" | "version" => {
						capture_text = true;
						text_buffer.clear();
					}
                    _ => {
                    }
                }
            }
			/*Ok(Event::Empty(ref e)) => {
                current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match current_element.as_str() {
					"fix" => {
						if in_rule {
							for attr in e.attributes() {
								let attr = attr.context("Failed to parse CCI attribute")?;
								let key = String::from_utf8_lossy(attr.key.as_ref());
								let value = String::from_utf8_lossy(&attr.value);

								if key == "id" {
									tfix
								}
							}
						}
					}
				}
			}*/
            Ok(Event::Text(e)) => {
                if capture_text {
                    text_buffer.push_str(&e.unescape().unwrap_or_default());
                }
            }
            Ok(Event::End(ref e)) => {
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match tag_name.as_str() {
                    "title" => {
						if in_rule {
							ttitle = text_buffer.trim().to_string();
						}
						else {
							tvuln_group_id = text_buffer.trim().to_string();
						}
					}
					"ident" => {
						if in_rule {
							if in_ident_cci {
								let tcci_str = text_buffer.trim_start_matches("CCI-").to_string();
								if tcci_str.len() > 0 {
									tccis.push(tcci_str.parse::<u32>().unwrap_or(0));
								}
								in_ident_cci = false;
							}
						}
					}
					"description" => {
						if in_rule {
							// Create a new Reader for the embedded XML content
							let mut tbuf = text_buffer.trim().to_string();
							//fix extraneous xml tags in the description
							tbuf = tbuf.replace("<", "&lt;").replace(">", "&gt;");
							//fix actual xml tags in description
							tbuf = tbuf
									.replace("&lt;VulnDiscussion&gt;", "<VulnDiscussion>")
									.replace("&lt;/VulnDiscussion&gt;", "</VulnDiscussion>")
									.replace("&lt;FalseNegatives&gt;", "<FalseNegatives>")
									.replace("&lt;/FalseNegatives&gt;", "</FalseNegatives>")
									.replace("&lt;FalsePositives&gt;", "<FalsePositives>")
									.replace("&lt;/FalsePositives&gt;", "</FalsePositives>")
									.replace("&lt;Documentable&gt;", "<Documentable>")
									.replace("&lt;/Documentable&gt;", "</Documentable>")
									.replace("&lt;Mitigations&gt;", "<Mitigations>")
									.replace("&lt;/Mitigations&gt;", "</Mitigations>")
									.replace("&lt;PotentialImpacts&gt;", "<PotentialImpacts>")
									.replace("&lt;/PotentialImpacts&gt;", "</PotentialImpacts>")
									.replace("&lt;ThirdPartyTools&gt;", "<ThirdPartyTools>")
									.replace("&lt;/ThirdPartyTools&gt;", "</ThirdPartyTools>")
									.replace("&lt;MitigationControl&gt;", "<MitigationControl>")
									.replace("&lt;/MitigationControl&gt;", "</MitigationControl>")
									.replace("&lt;Severity&gt;", "<Severity>")
									.replace("&lt;/Severity&gt;", "</Severity>")
									.replace("&lt;SeverityOverrideGuidance&gt;", "<SeverityOverrideGuidance>")
									.replace("&lt;/SeverityOverrideGuidance&gt;", "</SeverityOverrideGuidance>")
									.replace("&lt;CheckContent&gt;", "<CheckContent>")
									.replace("&lt;/CheckContent&gt;", "</CheckContent>")
									.replace("&lt;CheckSystem&gt;", "<CheckSystem>")
									.replace("&lt;/CheckSystem&gt;", "</CheckSystem>")
									.replace("&lt;IAControls&gt;", "<IAControls>")
									.replace("&lt;/IAControls&gt;", "</IAControls>")
									.replace("&lt;Responsibility&gt;", "<Responsibility>")
									.replace("&lt;/Responsibility&gt;", "</Responsibility>")
									.replace("&lt;References&gt;", "<References>")
									.replace("&lt;/References&gt;", "</References>");
							let mut desc_reader = Reader::from_str(&tbuf);
							desc_reader.trim_text(true);
							
							let mut desc_buf = Vec::new();
							let mut desc_text = String::new();
							let mut desc_capture = false;
					
							loop {
								match desc_reader.read_event_into(&mut desc_buf) {
									Ok(Event::Start(ref e)) => {
										desc_capture = true;
										desc_text.clear();
									}
									Ok(Event::Text(e)) => {
										if desc_capture {
											desc_text.push_str(&e.unescape().unwrap_or_default());
										}
									}
									Ok(Event::End(ref e)) => {
										let end_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
										match end_tag.as_str() {
											"VulnDiscussion" => tvuln_discussion = desc_text.trim().to_string(),
											"FalseNegatives" => tfalse_negatives = desc_text.trim().to_string(),
											"FalsePositives" => tfalse_positives = desc_text.trim().to_string(),
											"Documentable" => tdocumentable = desc_text.trim().eq_ignore_ascii_case("true"),
											"Mitigations" => tmitigations = desc_text.trim().to_string(),
											"PotentialImpacts" => tpotential_impacts = desc_text.trim().to_string(),
											"ThirdPartyTools" => tthird_party_tools = desc_text.trim().to_string(),
											"MitigationControl" => tmitigation_control = desc_text.trim().to_string(),
											"Severity" => tseverity = desc_text.trim().to_string(),
											"SeverityOverrideGuidance" => tseverity_override_guidance = desc_text.trim().to_string(),
											"CheckContent" => tcheck_content = desc_text.trim().to_string(),
											"CheckSystem" => tcheck_system = desc_text.trim().to_string(),
											"IAControls" => tia_controls = desc_text.trim().to_string(),
											"Responsibility" => tresponsibility = desc_text.trim().to_string(),
											"References" => treference = desc_text.trim().to_string(),
											_ => {}
										}
										desc_capture = false;
									}
									Ok(Event::Eof) => break,
									Err(e) => {
										eprintln!("Error parsing description XML: {}", e);
										break;
									}
									_ => {}
								}
								desc_buf.clear();
							}
						}
					}
					"Rule" => {
                        in_rule = false;
                        // Insert the check into database
                        conn.execute(
                            "INSERT INTO STIGCheck (
                                CheckContent, CheckSys, DISAId, Documentable, 
                                FalseNegatives, FalsePositives, FixText, IAControls,
                                MitigationControl, Mitigations, PotentialImpacts,
                                Reference, Responsibility, STIGId, Severity,
                                SeverityOverrideGuidance, ThirdPartyTools, Title,
                                VULNGroupId, VULNId, Version, VulnDiscussion, Weight
                            ) VALUES (
                                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23
                            )",
                            params![
                                tcheck_content,
                                tcheck_system,
                                tdisa_id,
                                tdocumentable,
                                tfalse_negatives,
                                tfalse_positives,
                                tfix_text,
                                tia_controls,
                                tmitigation_control,
                                tmitigations,
                                tpotential_impacts,
                                treference,
                                tresponsibility,
                                stig_id,
                                tseverity,
                                tseverity_override_guidance,
                                tthird_party_tools,
                                ttitle,
                                tvuln_group_id,
                                tvuln_id,
                                tversion,
                                tvuln_discussion,
                                tweight
                            ],
                        )?;
						let check_id = conn.last_insert_rowid();
						
						// Insert CCI mappings
						for cci_id in &tccis {
							if *cci_id != 0 {
								conn.execute(
									"INSERT INTO MapSTIGCheckCCI (STIGCheckId, CCIId) 
									SELECT ?1, ?2 
									WHERE EXISTS (SELECT 1 FROM RMFCCI WHERE id = ?2)",
									params![check_id, cci_id],
								)?;
							}
						}
						
						// Clear the CCIs collection
						tccis.clear();
                    }
					"fixtext" => {
						if in_rule {
							tfix_text = text_buffer.trim().to_string();
						}
					}
					"check-content" => {
						if in_rule {
							tcheck_content = text_buffer.trim().to_string();
						}
					}
					"version" => {
						if in_rule {
							tversion = text_buffer.trim().to_string();
						}
					}
                    _ => {}
                }
                capture_text = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("STIG XML parsing error: {}", e)),
            _ => {}
        }
        buf.clear();
    }

    Ok(())
}

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

async fn stigwe_parse_and_populate_database(yaml: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let yaml_content = fs::read_to_string(yaml.path())
        .await
        .context("Failed to read YAML file")?;

    let mappings: Mappings = serde_yaml::from_str(&yaml_content)
        .context("Failed to parse YAML content")?;

	print!("\tInserting {} STIG→CWE mappings…", mappings.stig_to_cwe.len());
    // Update STIGCheck CWEId where default mapping exists
    for (stig_id, mapping) in mappings.stig_to_cwe.iter() {
        for cwe_mapping in mapping.cwe_ids.iter() {
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
	println!("✓");

	print!("\tInserting {} CWE→STIG mappings…", mappings.cwe_to_stig.len());
    // Process CWE to STIG mappings
    for (cwe_id, mapping) in mappings.cwe_to_stig.iter() {
        for stig_mapping in mapping.stig_ids.iter() {
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
	println!("✓");

    Ok(())
}

fn display_database_summary(conn: &Connection) -> Result<()> {
	println!("\n=== Database Summary ===");

	// Count entries
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM Weakness")?;
	let entry_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("CWE Entries: {}", entry_count);

	// Count relationships
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM WeaknessRelationship")?;
	let rel_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("Relationships: {}", rel_count);

	if rel_count > 0 {
		println!("Relationship Types:");
		let mut stmt = conn.prepare(
			"SELECT nature, COUNT(*) as count FROM WeaknessRelationship 
             GROUP BY nature ORDER BY count DESC",
		)?;
		let mut rows = stmt.query_map([], |row| {
			Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
		})?;

		while let Some(Ok((nature, count))) = rows.next() {
			println!("\t{}: {}", nature, count);
		}
	}

	// Count RMF Families
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFFamily")?;
	let fam_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("RMF Families: {}", fam_count);

	// Count RMF Controls
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFControl")?;
	let control_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("RMF Controls: {}", control_count);

	// Count RMF CCIs
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFCCI")?;
	let cci_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("RMF CCIs: {}", cci_count);

	// Count STIGs
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIG")?;
	let stig_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("STIGs: {}", stig_count);

	// Count STIG Checks
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIGCheck")?;
	let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("STIG Checks: {}", check_count);

	// Count STIG Checks
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM MapSTIGCheckCCI")?;
	let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("STIG Check to CCI Mappings: {}", check_count);

	// Count Mappings
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIGCheck WHERE CWEId IS NOT NULL")?;
    let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
    println!("STIG→CWE Mappings: {}", check_count);

    let mut stmt = conn.prepare("SELECT COUNT(*) FROM Weakness WHERE STIGCheckId IS NOT NULL")?;
    let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
    println!("CWE→STIG Mappings: {}", check_count);

	Ok(())
}