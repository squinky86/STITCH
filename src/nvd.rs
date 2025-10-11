use crate::common::{download_file,decompress_gzip,Args};

use anyhow::{Context, Result};
use chrono::{Utc, Datelike};
use rusqlite::{Connection,params};
use tokio::fs;
use tempfile::NamedTempFile;
use serde::Deserialize;
use indicatif::{ProgressBar,ProgressStyle};

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
	#[serde(rename = "cvssMetricV40")]
	pub cvss_metric_v40: Option<Vec<CvssMetricV40>>,
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
pub struct CvssMetricV40 {
    pub source: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub cvss_data: CvssDataV40,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssDataV40 {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
    pub base_severity: String,
	pub attack_vector: String,
	pub attack_complexity: String,
	pub attack_requirements: String,
	pub privileges_required: String,
	pub user_interaction: String,
	pub vuln_confidentiality_impact: String,
	pub vuln_integrity_impact: String,
	pub vuln_availability_impact: String,
	pub sub_confidentiality_impact: String,
	pub sub_integrity_impact: String,
	pub sub_availability_impact: String,
	pub exploit_maturity: String,
	pub confidentiality_requirement: String,
	pub integrity_requirement: String,
	pub availability_requirement: String,
	pub modified_attack_vector: String,
	pub modified_attack_complexity: String,
	pub modified_attack_requirements: String,
	pub modified_privileges_required: String,
	pub modified_user_interaction: String,
	pub modified_vuln_confidentiality_impact: String,
	pub modified_vuln_integrity_impact: String,
	pub modified_vuln_availability_impact: String,
	pub modified_sub_confidentiality_impact: String,
	pub modified_sub_integrity_impact: String,
	pub modified_sub_availability_impact: String,
	pub safety: String,
	pub automatable: String,
	pub recovery: String,
	pub value_density: String,
	pub vulnerability_response_effort: String,
	pub provider_urgency: String,
}

impl CvssDataV40 {
	pub fn new() -> Self {
		Self {
			version: String::new(),
			vector_string: String::new(),
			base_score: 0.0,
			base_severity: String::new(),
			attack_vector: String::new(),
			attack_complexity: String::new(),
			attack_requirements: String::new(),
			privileges_required: String::new(),
			user_interaction: String::new(),
			vuln_confidentiality_impact: String::new(),
			vuln_integrity_impact: String::new(),
			vuln_availability_impact: String::new(),
			sub_confidentiality_impact: String::new(),
			sub_integrity_impact: String::new(),
			sub_availability_impact: String::new(),
			exploit_maturity: String::new(),
			confidentiality_requirement: String::new(),
			integrity_requirement: String::new(),
			availability_requirement: String::new(),
			modified_attack_vector: String::new(),
			modified_attack_complexity: String::new(),
			modified_attack_requirements: String::new(),
			modified_privileges_required: String::new(),
			modified_user_interaction: String::new(),
			modified_vuln_confidentiality_impact: String::new(),
			modified_vuln_integrity_impact: String::new(),
			modified_vuln_availability_impact: String::new(),
			modified_sub_confidentiality_impact: String::new(),
			modified_sub_integrity_impact: String::new(),
			modified_sub_availability_impact: String::new(),
			safety: String::new(),
			automatable: String::new(),
			recovery: String::new(),
			value_density: String::new(),
			vulnerability_response_effort: String::new(),
			provider_urgency: String::new(),
		}
	}
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

		nvd_parse_and_populate_database(&mut nvd_temp_json, year, &conn).await?;
	}

    Ok(())
}

async fn nvd_parse_and_populate_database(json_file: &mut NamedTempFile, year: i32, conn: &Connection) -> Result<()> {
    let json_content = fs::read_to_string(json_file.path())
        .await
        .context("Failed to read NVD JSON file")?;
    
    let feed: NvdCveFeed = serde_json::from_str(&json_content).unwrap();

	let bar = ProgressBar::new(feed.total_results as u64);
    bar.set_style(ProgressStyle::default_bar()
    	.template("{prefix} {bar:20.cyan/blue} {msg}")
    	.expect("Failed to create progress style"));
	bar.set_prefix(format!("\t\tProcessing {} JSON…", year));
	for v in feed.vulnerabilities {
        let cve = &v.cve;

		//store cvss data to insert into database
		let mut cvss_v4 = CvssDataV40::new();
		
		if let Some(cvss_metrics) = &cve.metrics.cvss_metric_v40 {
			if !cvss_metrics.is_empty() {
				cvss_v4 = cvss_metrics[0].cvss_data.clone();
			}
		}
		else if let Some(cvss_metrics) = &cve.metrics.cvss_metric_v31 {
			if !cvss_metrics.is_empty() {
				//convert v3.1 to v4.0
			}
		}
		else if let Some(cvss_metrics) = &cve.metrics.cvss_metric_v30 {
			if !cvss_metrics.is_empty() {
				//convert v3.0 to v4.0
			}
		}
		else if let Some(cvss_metrics) = &cve.metrics.cvss_metric_v2 {
			if !cvss_metrics.is_empty() {
				//convert v2.0 to v4.0
			}
		}

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
                cvss_v4.attack_vector,
				cvss_v4.attack_complexity,
				cvss_v4.attack_requirements,
				cvss_v4.privileges_required,
				cvss_v4.user_interaction,
				cvss_v4.vuln_confidentiality_impact,
				cvss_v4.vuln_integrity_impact,
				cvss_v4.vuln_availability_impact,
				cvss_v4.sub_confidentiality_impact,
				cvss_v4.sub_integrity_impact,
				cvss_v4.sub_availability_impact,
				cvss_v4.exploit_maturity,
				cvss_v4.confidentiality_requirement,
				cvss_v4.integrity_requirement,
				cvss_v4.availability_requirement,
				cvss_v4.modified_attack_vector,
				cvss_v4.modified_attack_complexity,
				cvss_v4.modified_attack_requirements,
				cvss_v4.modified_privileges_required,
				cvss_v4.modified_user_interaction,
				cvss_v4.modified_vuln_confidentiality_impact,
				cvss_v4.modified_vuln_integrity_impact,
				cvss_v4.modified_vuln_availability_impact,
				cvss_v4.modified_sub_confidentiality_impact,
				cvss_v4.modified_sub_integrity_impact,
				cvss_v4.modified_sub_availability_impact,
				cvss_v4.safety,
				cvss_v4.automatable,
				cvss_v4.recovery,
				cvss_v4.value_density,
				cvss_v4.vulnerability_response_effort,
				cvss_v4.provider_urgency
            ],
        )?;
		let check_id = conn.last_insert_rowid();
		let mut inserted: Vec<i32> = Vec::new();
        if let Some(weaknesses) = &cve.weaknesses {
            for weakness in weaknesses {
                for description in weakness.description.iter().filter(|d| d.lang == "en" && d.value.starts_with("CWE-")) {
                    let tmp_weakness = description.value.trim_start_matches("CWE-").parse::<i32>().unwrap();
					if !inserted.contains(&tmp_weakness) {
						conn.execute(
                    	    "INSERT INTO MapVulnerabilityWeakness (VulnerabilityId, WeaknessId) VALUES (?1, ?2)",
                    	    params![check_id, tmp_weakness],
                    	)?;
						inserted.push(tmp_weakness);
					}
                }
            }
        }

		bar.inc(1);
    }

	bar.finish_with_message(format!("✓ ({})", feed.total_results));
    
    Ok(())
}
