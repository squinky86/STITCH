// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use crate::common::{Args, download_file, extract_from_zip, p};

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use tokio::fs;

/// Public database structures
#[derive(Debug)]
pub struct Stig {
    pub id: u32,
    pub title: String,
    pub version: String,
    pub stig_id: String,
    pub release: String,
    pub identifier: String,
}

#[derive(Debug)]
pub struct StigCheck {
    pub id: u32,
    pub check_content: String,
    pub check_sys: String,
    pub disa_id: String,
    pub documentable: bool,
    pub false_negatives: String,
    pub false_positives: String,
    pub fix_text: String,
    pub ia_controls: String,
    pub mitigation_control: String,
    pub mitigations: String,
    pub potential_impacts: String,
    pub reference: String,
    pub responsibility: String,
    pub stig_id: u32,
    pub severity: String,
    pub severity_override_guidance: String,
    pub third_party_tools: String,
    pub title: String,
    pub vuln_group_id: String,
    pub vuln_id: String,
    pub version: String,
    pub vuln_discussion: String,
    pub weight: f32,
    pub cwe_id: u32,
    pub legacy_ids: String,
}

/// Root element of a STIG XML file
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "Benchmark")]
pub struct Benchmark {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    pub title: String,

    pub description: String,

    pub version: String,

    pub status: Option<String>,

    #[serde(rename = "plain-text")]
    pub plain_texts: Vec<PlainText>,

    #[serde(rename = "front-matter")]
    pub front_matter: Option<String>,

    #[serde(rename = "rear-matter")]
    pub rear_matter: Option<String>,

    #[serde(rename = "Group", default)]
    pub groups: Vec<Group>,
}

/// A group of related security requirements
#[derive(Debug, Deserialize, Serialize)]
pub struct Group {
    #[serde(rename = "@id")]
    pub id: String,

    pub title: String,

    pub description: Option<String>,

    #[serde(rename = "Rule", default)]
    pub rules: Vec<Rule>,
}

/// A specific security rule/requirement
#[derive(Debug, Deserialize, Serialize)]
pub struct Rule {
    #[serde(rename = "@id")]
    pub id: String,

    #[serde(rename = "@severity")]
    pub severity: String,

    #[serde(rename = "@weight")]
    pub weight: f32,

    pub version: String,

    pub title: String,

    pub description: String,

    #[serde(rename = "ident", default)]
    pub idents: Vec<Ident>,

    pub check: Option<Check>,

    pub fixtext: Option<FixText>,

    pub fix: Option<Fix>,

    pub reference: Reference,
}

/// A specific security rule/requirement
#[derive(Debug, Deserialize, Serialize)]
pub struct Reference {
    pub title: String,

    pub publisher: String,

    #[serde(rename = "type")]
    pub type_: String,

    pub subject: String,

    pub identifier: String,
}

/// Identifier for a rule (CCI, Legacy ID, etc.)
#[derive(Debug, Deserialize, Serialize)]
pub struct Ident {
    #[serde(rename = "@system")]
    pub system: String,

    #[serde(rename = "$value")]
    pub value: String,
}

/// Identifier for Release, Generator, and Tooling
#[derive(Debug, Deserialize, Serialize)]
pub struct PlainText {
    #[serde(rename = "@id")]
    pub id: String,

    #[serde(rename = "$value")]
    pub value: String,
}

/// Check information for verifying compliance
#[derive(Debug, Deserialize, Serialize)]
pub struct Check {
    #[serde(rename = "@system")]
    pub system: String,

    #[serde(rename = "check-content-ref")]
    pub check_content_ref: Option<CheckContentRef>,

    #[serde(rename = "check-content")]
    pub check_content: Option<String>,
}

/// Reference to external check content
#[derive(Debug, Deserialize, Serialize)]
pub struct CheckContentRef {
    #[serde(rename = "@href")]
    pub href: Option<String>,

    #[serde(rename = "@name")]
    pub name: Option<String>,
}

/// Instructions for fixing a non-compliant finding
#[derive(Debug, Deserialize, Serialize)]
pub struct FixText {
    #[serde(rename = "@fixref")]
    pub fixref: Option<String>,

    #[serde(rename = "$value")]
    pub value: String,
}

/// Automated fix information
#[derive(Debug, Deserialize, Serialize)]
pub struct Fix {
    #[serde(rename = "@id")]
    pub id: Option<String>,

    #[serde(rename = "$value")]
    pub value: Option<String>,
}

/// Parsed description fields from the rule description
#[derive(Debug, Default)]
pub struct ParsedDescription {
    pub vuln_discussion: Option<String>,
    pub false_positives: Option<String>,
    pub false_negatives: Option<String>,
    pub documentable: Option<String>,
    pub mitigations: Option<String>,
    pub security_override_guidance: Option<String>,
    pub severity_override_guidance: Option<String>,
    pub potential_impacts: Option<String>,
    pub mitigation_control: Option<String>,
    pub ia_controls: Option<String>,
    pub responsibility: Option<String>,
    pub third_party_tools: Option<String>,
}

impl Benchmark {
    /// Get release info
    pub fn release_info(&self) -> Vec<&str> {
        self.plain_texts
            .iter()
            .filter(|i| i.id == "release-info")
            .map(|i| i.value.as_str())
            .collect()
    }
}

impl Rule {
    /// Parse the embedded XML-like tags in the description field
    pub fn parse_description(&self) -> ParsedDescription {
        let desc = &self.description;

        ParsedDescription {
            vuln_discussion: extract_tag_content(desc, "VulnDiscussion"),
            false_positives: extract_tag_content(desc, "FalsePositives"),
            false_negatives: extract_tag_content(desc, "FalseNegatives"),
            documentable: extract_tag_content(desc, "Documentable"),
            mitigations: extract_tag_content(desc, "Mitigations"),
            security_override_guidance: extract_tag_content(desc, "SecurityOverrideGuidance"),
            severity_override_guidance: extract_tag_content(desc, "SeverityOverrideGuidance"),
            potential_impacts: extract_tag_content(desc, "PotentialImpacts"),
            mitigation_control: extract_tag_content(desc, "MitigationControl"),
            ia_controls: extract_tag_content(desc, "IAControls"),
            responsibility: extract_tag_content(desc, "Responsibility"),
            third_party_tools: extract_tag_content(desc, "ThirdPartyTools"),
        }
    }

    /// Get the severity category (CAT I, II, or III)
    pub fn severity_category(&self) -> &str {
        match self.severity.as_str() {
            "high" => "CAT I",
            "medium" => "CAT II",
            "low" => "CAT III",
            _ => "Unknown",
        }
    }

    /// Get CCI identifiers
    pub fn cci_idents(&self) -> Vec<&str> {
        self.idents
            .iter()
            .filter(|i| {
                i.system == "http://iase.disa.mil/cci" || i.system == "http://cyber.mil/cci"
            })
            .map(|i| i.value.as_str())
            .collect()
    }

    /// Get legacy identifier
    pub fn legacy_ids(&self) -> Vec<&str> {
        self.idents
            .iter()
            .filter(|i| i.system == "http://cyber.mil/legacy")
            .map(|i| i.value.as_str())
            .collect()
    }
}

/// Extract content between XML-like tags in a string
fn extract_tag_content(text: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);

    if let Some(start_pos) = text.find(&start_tag) {
        let content_start = start_pos + start_tag.len();
        if let Some(end_pos) = text[content_start..].find(&end_tag) {
            let content = &text[content_start..content_start + end_pos];
            if !content.trim().is_empty() {
                return Some(content.to_string());
            }
        }
    }
    None
}

/// Parse a STIG XML file from a string
pub fn parse_stig_xml(xml_content: &str) -> Result<Benchmark, quick_xml::DeError> {
    quick_xml::de::from_str(xml_content)
}

/// Parse a STIG XML file from a reader
pub fn parse_stig_xml_reader<R: std::io::BufRead>(
    reader: R,
) -> Result<Benchmark, quick_xml::DeError> {
    quick_xml::de::from_reader(reader)
}

pub async fn process_stig(conn: &Connection, args: &Args) -> Result<()> {
    let mut stig_temp_zip = NamedTempFile::new()?;
    let mut stig_temp_xml = NamedTempFile::new()?;
    download_file(
        "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_ASD_V6R4_STIG.zip",
        &mut stig_temp_zip,
        false,
        "Downloading STIG XML file from DISA…".to_string(),
        args,
    )
    .await?;

    p("Extracting STIG XML file…", false);
    extract_from_zip(&stig_temp_zip, &mut stig_temp_xml, ".xml", args)?;
    p("✓", true);

    // Parse STIG XML and populate database
    stig_parse_and_populate_database(&stig_temp_xml, conn).await?;

    Ok(())
}

async fn stig_parse_and_populate_database(
    xml: &NamedTempFile,
    conn: &Connection,
) -> Result<()> {
    let xml_content = fs::read_to_string(xml.path())
        .await
        .context("Failed to read STIG XML file")?;

    let reader = std::io::Cursor::new(xml_content);
    let bar = ProgressBar::new(100);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{prefix} {bar:20.cyan/blue} {msg}")
            .expect("Failed to create progress style"),
    );
    bar.set_prefix("Inserting STIG Checks…");
    let benchmark = parse_stig_xml_reader(reader)?;
    let total_rules = benchmark
        .groups
        .iter()
        .map(|group| group.rules.len() as u64)
        .sum();
    bar.set_length(total_rules);
    let mut on: u32 = 0;
    bar.set_message(format!("{}/{}", on, total_rules));

    //create the new STIG
    let _ = conn.execute(
		"INSERT INTO STIG (title, version, stigId, release, identifier) VALUES (?1, ?2, ?3, ?4, ?5)",
		params![
			benchmark.title,
			benchmark.version,
			benchmark.id.clone().unwrap_or_default(),
			benchmark.release_info().first().ok_or_else(|| anyhow::anyhow!("Missing release info"))?,
			benchmark.groups.first().ok_or_else(|| anyhow::anyhow!("Missing group"))?.rules.first().ok_or_else(|| anyhow::anyhow!("Missing rule"))?.reference.identifier.clone()
		],
	);
    let stig_id = conn.last_insert_rowid();

    // Now iterate through the groups and rules to insert them
    for group in &benchmark.groups {
        for rule in &group.rules {
            let check = rule
                .check
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing check for rule {}", rule.id))?;
            let desc = rule.parse_description();
            on += 1;
            bar.set_message(format!("{}/{}", on, total_rules));
            bar.inc(1);
            conn.execute(
                "INSERT INTO STIGCheck (
					CheckContent, CheckSys, DISAId, Documentable, 
					FalseNegatives, FalsePositives, FixText, IAControls,
					MitigationControl, Mitigations, PotentialImpacts,
					Reference, Responsibility, STIGId, Severity,
					SeverityOverrideGuidance, ThirdPartyTools, Title,
					VULNGroupId, VULNId, Version, VulnDiscussion, Weight, LegacyIds
				) VALUES (
					?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
					?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24
				)",
                params![
                    check
                        .check_content
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing check-content"))?
                        .clone(),
                    check.system,
                    rule.id,
                    desc.documentable
                        .ok_or_else(|| anyhow::anyhow!("Missing Documentable"))?
                        == "true",
                    desc.false_negatives,
                    desc.false_positives,
                    rule.fixtext
                        .as_ref()
                        .map_or_else(|| "".to_string(), |f| f.value.clone()),
                    desc.ia_controls,
                    desc.mitigation_control,
                    desc.mitigations,
                    desc.potential_impacts,
                    rule.reference.identifier,
                    desc.responsibility,
                    stig_id,
                    rule.severity,
                    desc.severity_override_guidance,
                    desc.third_party_tools,
                    rule.title,
                    group.title,
                    group.id,
                    rule.version,
                    desc.vuln_discussion,
                    rule.weight,
                    rule.legacy_ids().join(",")
                ],
            )?;
            let check_id = conn.last_insert_rowid();
            for cci_id_str in rule.cci_idents() {
                if let Ok(cci_id) = cci_id_str.trim_start_matches("CCI-").parse::<u32>() {
                    if cci_id != 0 {
                        conn.execute(
							"INSERT INTO MapSTIGCheckCCI (STIGCheckId, CCIId) SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM RMFCCI WHERE id = ?2)",
							params![check_id, cci_id],
						)?;
                    }
                }
            }
        }
    }

    bar.finish_with_message(format!("✓ ({})", total_rules));
    Ok(())
}
