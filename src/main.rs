use anyhow::{Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::Client;
use rusqlite::{params, Connection};
use std::io::Write;
use tokio::fs;
use zip::ZipArchive;
use tempfile::NamedTempFile;
use regex::Regex;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Output database file path
	#[arg(short, long, default_value = "rusktex.db")]
	output: String,

	/// Force download even if file exists
	#[arg(short, long)]
	force: bool,

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
    ident: String,
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

#[tokio::main]
async fn main() -> Result<()> {
	let args = Args::parse();

	//CWE Data
	const CWE_XML_URL: &str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip";
	let mut cwe_temp_zip = NamedTempFile::new()?;
	let mut cwe_temp_xml = NamedTempFile::new()?;

	//RMF Control Data
	const RMF_XML_URL: &str = "https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1_XML.xml";
	let mut rmf_temp_xml = NamedTempFile::new()?;

	//RMF CCI Data
	const CCI_XML_URL: &str = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/CCI+List.zip";
	let mut cci_temp_zip = NamedTempFile::new()?;
	let mut cci_temp_xml = NamedTempFile::new()?;

	//STIG Data
	const STIG_XML_URL: &str = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_ASD_V6R3_STIG.zip";
	let mut stig_temp_zip = NamedTempFile::new()?;
	let mut stig_temp_xml = NamedTempFile::new()?;

	println!("RuskTeX Database Builder v0.1.0");

	// Download the CWE XML file
    if cwe_temp_zip.path().exists() {
        print!("Downloading CWE XML file from MITRE…");
        download_file(&CWE_XML_URL, &mut cwe_temp_zip, &args).await?;
        println!("✓");

        print!("Extracting CWE XML file…");
        extract_xml_from_zip(&cwe_temp_zip, &mut cwe_temp_xml, &args)?;
        println!("✓");
    } else {
        eprintln!("Unable to create temporary CWE file.");
        std::process::exit(1);
    }

	// Download the RMF XML file
	if rmf_temp_xml.path().exists() {
		print!("Downloading NIST RMF XML file from NIST…");
		download_file(&RMF_XML_URL, &mut rmf_temp_xml, &args).await?;
		println!("✓");
	} else {
		eprintln!("Unable to create temporary RMF file.");
		std::process::exit(1);
	}

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

	// Create database
	print!("Creating SQLite database:");
	let conn = create_database(&args.output)?;
	println!("SQLite database created ✓ ({})", args.output);

	// Parse CWE XML and populate database
	println!("Parsing CWE XML and populating database:");
	cwe_parse_and_populate_database(&mut cwe_temp_xml, &conn, &args).await?;

	// Parse RMF XML and populate database
	println!("Parsing NIST RMF XML and populating database:");
	rmf_parse_and_populate_database(&mut rmf_temp_xml, &conn).await?;

	//Parse CCI XML and populate database
	println!("Parsing DISA CCI XML and populating database:");
	cci_parse_and_populate_database(&mut cci_temp_xml, &conn).await?;

	// Parse STIG XML and populate database
	println!("Parsing DISA STIG XML and populating database:");
	stig_parse_and_populate_database(&mut stig_temp_xml, &conn).await?;

	// Display summary
	display_database_summary(&conn)?;

	println!("\nCWE database build completed successfully: {}", args.output);
	Ok(())
}

async fn download_file(url: &str, file: &mut NamedTempFile, args: &Args) -> Result<()> {
    let client = Client::new();

    if args.verbose {
        println!("\nConnecting to: {}", url);
    }

    let response = client
        .get(url)
        .send()
        .await
        .context("Failed to download CWE XML")?;

    let total_size = response.content_length().unwrap_or(0);
    if args.verbose && total_size > 0 {
        println!("File size: {} bytes", total_size);
    }

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read chunk")?;
        file.as_file_mut().write_all(&chunk)
            .context("Failed to write chunk to file")?;
    }
    
    file.as_file_mut().sync_all().context("Failed to sync file to disk")?;

    Ok(())
}

fn extract_xml_from_zip(zip_file: &NamedTempFile, xml_file: &mut NamedTempFile, args: &Args) -> Result<()> {
    let file = std::fs::File::open(zip_file.path()).context("Failed to open zip file")?;
    let mut archive = ZipArchive::new(file).context("Failed to read zip archive")?;

    if args.verbose {
        println!("\nExtracting zip file...");
    }

    for i in 0..archive.len() {
        match archive.by_index(i) {
            Ok(mut file) => {
                if file.name().ends_with(".xml") {
                    std::io::copy(&mut file, xml_file.as_file_mut())
                        .context("Failed to extract XML file")?;
                    break;
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Could not extract file index {} in the downloaded zip file: {}", 
                    i, e
                ));
            }
        }
    }

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
availability BOOLEAN NOT NULL DEFAULT 0 CHECK(availability IN (0, 1))
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
Ident TEXT,
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
STIGCheckID INTEGER,
CCIId INTEGER,
PRIMARY KEY(STIGCheckId,CCIId),
FOREIGN KEY(CCIId) REFERENCES RMFCCI(id),
FOREIGN KEY(STIGCheckID) REFERENCES STIGCheck(id)
);",
		[],
	)
	.context("Failed to create STIG table")?;

	Ok(conn)
}

async fn cwe_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection, args: &Args) -> Result<()> {
	let xml_content = fs::read_to_string(xml.path())
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

	cwe_insert_data_to_database(conn, &cwe_entries, &relationships)?;

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
    print!("\tInserting {} RMF Controls", controls.len());
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
								let tmp_cci = value.trim_start_matches(['C', 'I', '-']);
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
                            current_references.push(ref_index);
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

	let mut tcheck_content = String::new();
    let mut tcheck_system = String::new();
    let mut tdisa_id  = String::new();
    let mut tdocumentable = false;
    let mut tfalse_negatives  = String::new();
    let mut tfalse_positives  = String::new();
    let mut tfix_text  = String::new();
    let mut tia_controls  = String::new();
    let mut tident  = String::new();
    let mut tmitigation_control  = String::new();
    let mut tmitigations  = String::new();
    let mut tpotential_impacts  = String::new();
    let mut treference  = String::new();
    let mut tresponsibility  = String::new();
    let mut tstig_id: u32 = 0;
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
                    "Group" => {
                        for attr in e.attributes() {
                            let attr = attr.context("Failed to parse CCI attribute")?;
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
									capture_text = true;
									text_buffer.clear();
								}
                            }
                        }
					}
					"Rule" => {
						in_rule = true;
						for attr in e.attributes() {
                            let attr = attr.context("Failed to parse ident attribute")?;
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
					"title" | "description" | "fixtext" | "check-content" => {
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
							let tcci_str = text_buffer.trim().to_string();
							if tcci_str.len() > 0 {
								tccis.push(tcci_str.parse::<u32>().unwrap_or(0));
							}
						}
					}
					"description" => {
						if in_rule {
							// Create a new Reader for the embedded XML content
							let tBuf = text_buffer.replace("&gt;", ">").replace("&lt;", "<");
							let mut desc_reader = Reader::from_str(&tBuf);
							desc_reader.trim_text(true);
							
							let mut desc_buf = Vec::new();
							let mut desc_text = String::new();
							let mut desc_element = String::new();
							let mut desc_capture = false;
					
							loop {
								match desc_reader.read_event_into(&mut desc_buf) {
									Ok(Event::Start(ref e)) => {
										desc_element = String::from_utf8_lossy(e.name().as_ref()).to_string();
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
                                Ident, MitigationControl, Mitigations, PotentialImpacts,
                                Reference, Responsibility, STIGId, Severity,
                                SeverityOverrideGuidance, ThirdPartyTools, Title,
                                VULNGroupId, VULNId, Version, VulnDiscussion, Weight
                            ) VALUES (
                                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24
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
                                tident,
                                tmitigation_control,
                                tmitigations,
                                tpotential_impacts,
                                treference,
                                tresponsibility,
                                1,
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

fn cwe_insert_data_to_database(
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
	print!("\tInserting {} relationships…", relationships.len());
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

	// Count RMF Families
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFFamily")?;
	let fam_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("RMF Families:   {}", fam_count);

	// Count RMF Controls
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFControl")?;
	let control_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("RMF Controls:   {}", control_count);

	// Count RMF CCIs
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFCCI")?;
	let cci_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("RMF CCIs:   {}", cci_count);

	// Count STIGs
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIG")?;
	let stig_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("STIGs: {}", stig_count);

	// Count STIG Checks
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIGCheck")?;
	let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("STIG Checks: {}", check_count);

	Ok(())
}