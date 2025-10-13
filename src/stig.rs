use crate::common::{download_file,extract_from_zip,p,Args};

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use rusqlite::{params, Connection};
use tokio::fs;
use tempfile::NamedTempFile;

pub async fn process_stig(conn: &Connection, args: &Args) -> Result<()> {
    let mut stig_temp_zip = NamedTempFile::new()?;
	let mut stig_temp_xml = NamedTempFile::new()?;
    download_file("https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_ASD_V6R3_STIG.zip", &mut stig_temp_zip, false, "Downloading STIG XML file from DISA…".to_string(), "✓".to_string(), &args).await?;

    p("Extracting STIG XML file…", false);
    extract_from_zip(&stig_temp_zip, &mut stig_temp_xml, ".xml", &args)?;
    p("✓", true);

    // Parse STIG XML and populate database
	p("Parsing DISA STIG XML and populating database…", false);
	stig_parse_and_populate_database(&mut stig_temp_xml, &conn).await?;
	p("✓", true);

    Ok(())
}

async fn stig_parse_and_populate_database(xml: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let xml_content = fs::read_to_string(xml.path())
        .await
        .context("Failed to read STIG XML file")?;

    let mut reader = Reader::from_str(&xml_content);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut text_buffer = String::new();
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
                let current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();
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
            Ok(Event::Text(e)) => {
                if capture_text {
                    text_buffer.push_str(&e.decode().unwrap_or_default());
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
							desc_reader.config_mut().trim_text(true);
							
							let mut desc_buf = Vec::new();
							let mut desc_text = String::new();
							let mut desc_capture = false;
					
							loop {
								match desc_reader.read_event_into(&mut desc_buf) {
									Ok(Event::Start(_)) => {
										desc_capture = true;
										desc_text.clear();
									}
									Ok(Event::Text(e)) => {
										if desc_capture {
											desc_text.push_str(&e.decode().unwrap_or_default());
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