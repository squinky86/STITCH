use crate::common::{download_file,decompress_gzip,Args};

use anyhow::{Context, Result};
use chrono::{Utc, Datelike};
use rusqlite::{Connection,params};
use tokio::fs;
use tempfile::NamedTempFile;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCveFeed {
    pub results_per_page: i64,
    pub start_index: i64,
    pub total_results: i64,
    pub format: String,
    pub version: String,
    pub timestamp: String,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub cve: Cve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    pub id: String,
    pub source_identifier: Option<String>,
    pub published: String,
    pub last_modified: String,
    pub vuln_status: String,
    pub descriptions: Vec<Description>,
    pub metrics: Metrics,
    pub weaknesses: Option<Vec<Weakness>>,
    pub configurations: Option<Vec<Configuration>>,
    pub references: Vec<Reference>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    #[serde(rename = "cvssMetricV2")]
    pub cvss_metric_v2: Option<Vec<CvssMetricV2>>,
    #[serde(rename = "cvssMetricV30")]
    pub cvss_metric_v30: Option<Vec<CvssMetricV30>>,
    #[serde(rename = "cvssMetricV31")]
    pub cvss_metric_v31: Option<Vec<CvssMetricV31>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetricV2 {
    pub source: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub cvss_data: CvssData,
    pub base_severity: String,
    pub exploitability_score: f64,
    pub impact_score: f64,
    pub ac_insuf_info: Option<bool>,
    pub obtain_all_privilege: bool,
    pub obtain_user_privilege: bool,
    pub obtain_other_privilege: bool,
    pub user_interaction_required: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssData {
    pub version: String,
    pub vector_string: String,
    pub access_vector: String,
    pub access_complexity: String,
    pub authentication: String,
    pub confidentiality_impact: String,
    pub integrity_impact: String,
    pub availability_impact: String,
    pub base_score: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetricV30 {
    pub source: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub cvss_data: CvssDataV3,
    pub exploitability_score: f64,
    pub impact_score: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetricV31 {
    pub source: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub cvss_data: CvssDataV3,
    pub exploitability_score: f64,
    pub impact_score: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssDataV3 {
    pub version: String,
    pub vector_string: String,
    pub attack_vector: String,
    pub attack_complexity: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub scope: String,
    pub confidentiality_impact: String,
    pub integrity_impact: String,
    pub availability_impact: String,
    pub base_score: f64,
    pub base_severity: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Weakness {
    pub source: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub description: Vec<Description>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub nodes: Vec<Node>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub operator: String,
    pub negate: bool,
    pub cpe_match: Vec<CpeMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    pub match_criteria_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    pub url: String,
    pub source: String,
    pub tags: Option<Vec<String>>,
}

pub async fn process_nvd(conn: &Connection, args: &Args) -> Result<()> {
	// NVD Data
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

    Ok(())
}

async fn nvd_parse_and_populate_database(json_file: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let json_content = fs::read_to_string(json_file.path())
        .await
        .context("Failed to read NVD JSON file")?;
    
    let feed: NvdCveFeed = serde_json::from_str(&json_content).unwrap();

    for v in feed.vulnerabilities {
        let cve = &v.cve;

        let description = cve.descriptions
            .iter()
            .find(|d| d.lang == "en")
            .map_or("No description found.", |d| d.value.as_str());

        conn.execute(
            "INSERT INTO Vulnerability (
                NVDId,
                Description,
                attackVector,
                attackComplexity,
                attackRequirements,
                privilegesRequired,
                userInteraction,
                vulnConfidentialityImpact,
                vulnIntegrityImpact,
                vulnAvailabilityImpact,
                subConfidentialityImpact,
                subIntegrityImpact,
                subAvailabilityImpact,
                exploitMaturity,
                confidentialityRequirement,
                integrityRequirement,
                availabilityRequirement,
                modifiedAttackVector,
                modifiedAttackComplexity,
                modifiedAttackRequirements,
                modifiedPrivilegesRequired,
                modifiedUserInteraction,
                modifiedVulnConfidentialityImpact,
                modifiedVulnIntegrityImpact,
                modifiedVulnAvailabilityImpact,
                modifiedSubConfidentialityImpact,
                modifiedSubIntegrityImpact,
                modifiedSubAvailabilityImpact,
                Safety,
                Automatable,
                Recovery,
                valueDensity,
                vulnerabilityResponseEffort,
                providerUrgency
            ) VALUES (
                ?1,
                ?2,
                ?3,
                ?4,
                ?5,
                ?6,
                ?7,
                ?8,
                ?9,
                ?10,
                ?11,
                ?12,
                ?13,
                ?14,
                ?15,
                ?16,
                ?17,
                ?18,
                ?19,
                ?20,
                ?21,
                ?22,
                ?23,
                ?24,
                ?25,
                ?26,
                ?27,
                ?28,
                ?29,
                ?30,
                ?31,
                ?32,
                ?33,
                ?34
            )",
            params![
                cve.id,
                description,
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                ""
            ],
        )?;
    }
    
    Ok(())
}
