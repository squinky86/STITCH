// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use crate::common::{Args, decompress_gzip, download_file, p};

use anyhow::{Context, Result};
use chrono::{Datelike, Utc};
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, params};
use serde::Deserialize;
use tempfile::NamedTempFile;
use tokio::fs;

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetricV40 {
    pub source: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub cvss_data: CvssDataV40,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    #[serde(rename = "Safety")]
    pub safety: String,
    #[serde(rename = "Automatable")]
    pub automatable: String,
    #[serde(rename = "Recovery")]
    pub recovery: String,
    pub value_density: String,
    pub vulnerability_response_effort: String,
    pub provider_urgency: String,
}

impl Default for CvssDataV40 {
    fn default() -> Self {
        Self::new()
    }
}

impl CvssDataV40 {
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: String::new(),
            vector_string: String::new(),
            base_score: 0.0,
            base_severity: String::new(),
            attack_vector: "NETWORK".to_string(),
            attack_complexity: "LOW".to_string(),
            attack_requirements: "NONE".to_string(),
            privileges_required: "NONE".to_string(),
            user_interaction: "NONE".to_string(),
            vuln_confidentiality_impact: "HIGH".to_string(),
            vuln_integrity_impact: "HIGH".to_string(),
            vuln_availability_impact: "HIGH".to_string(),
            sub_confidentiality_impact: "HIGH".to_string(),
            sub_integrity_impact: "HIGH".to_string(),
            sub_availability_impact: "HIGH".to_string(),
            exploit_maturity: "NOT_DEFINED".to_string(),
            confidentiality_requirement: "NOT_DEFINED".to_string(),
            integrity_requirement: "NOT_DEFINED".to_string(),
            availability_requirement: "NOT_DEFINED".to_string(),
            modified_attack_vector: "NOT_DEFINED".to_string(),
            modified_attack_complexity: "NOT_DEFINED".to_string(),
            modified_attack_requirements: "NOT_DEFINED".to_string(),
            modified_privileges_required: "NOT_DEFINED".to_string(),
            modified_user_interaction: "NOT_DEFINED".to_string(),
            modified_vuln_confidentiality_impact: "NOT_DEFINED".to_string(),
            modified_vuln_integrity_impact: "NOT_DEFINED".to_string(),
            modified_vuln_availability_impact: "NOT_DEFINED".to_string(),
            modified_sub_confidentiality_impact: "NOT_DEFINED".to_string(),
            modified_sub_integrity_impact: "NOT_DEFINED".to_string(),
            modified_sub_availability_impact: "NOT_DEFINED".to_string(),
            safety: "NOT_DEFINED".to_string(),
            automatable: "NOT_DEFINED".to_string(),
            recovery: "NOT_DEFINED".to_string(),
            value_density: "NOT_DEFINED".to_string(),
            vulnerability_response_effort: "NOT_DEFINED".to_string(),
            provider_urgency: "NOT_DEFINED".to_string(),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Weakness {
    pub source: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub description: Vec<Description>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub nodes: Option<Vec<Node>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub operator: String,
    pub negate: bool,
    pub cpe_match: Vec<CpeMatch>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    pub match_criteria_id: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    pub url: String,
    pub source: String,
    pub tags: Option<Vec<String>>,
}

/// Apply a CVSS v3.x record onto a v4 record using the published mapping
/// from `doc/scoring.md`. Operates on the inner `CvssDataV3` so it covers
/// both v3.0 and v3.1 metrics.
pub fn apply_v3_to_v4(cvss_v4: &mut CvssDataV40, v3: &CvssDataV3) {
    cvss_v4.attack_vector = if v3.attack_vector == "ADJACENT_NETWORK" {
        "ADJACENT".to_string()
    } else {
        v3.attack_vector.clone()
    };
    cvss_v4.attack_complexity.clone_from(&v3.attack_complexity);
    cvss_v4
        .privileges_required
        .clone_from(&v3.privileges_required);
    cvss_v4.user_interaction = if v3.user_interaction == "REQUIRED" {
        "ACTIVE".to_string()
    } else {
        v3.user_interaction.clone()
    };

    if v3.scope == "CHANGED" {
        cvss_v4
            .sub_confidentiality_impact
            .clone_from(&v3.confidentiality_impact);
        cvss_v4
            .sub_integrity_impact
            .clone_from(&v3.integrity_impact);
        cvss_v4
            .sub_availability_impact
            .clone_from(&v3.availability_impact);
    } else {
        cvss_v4.sub_confidentiality_impact = "NONE".to_string();
        cvss_v4.sub_integrity_impact = "NONE".to_string();
        cvss_v4.sub_availability_impact = "NONE".to_string();
    }

    cvss_v4
        .vuln_confidentiality_impact
        .clone_from(&v3.confidentiality_impact);
    cvss_v4
        .vuln_integrity_impact
        .clone_from(&v3.integrity_impact);
    cvss_v4
        .vuln_availability_impact
        .clone_from(&v3.availability_impact);
}

/// Apply a CVSS v2 record onto a v4 record using the published mapping
/// from `doc/scoring.md`.
pub fn apply_v2_to_v4(cvss_v4: &mut CvssDataV40, v2: &CvssMetricV2) {
    cvss_v4.attack_vector = match v2.cvss_data.access_vector.as_str() {
        "NETWORK" => "NETWORK".to_string(),
        "ADJACENT_NETWORK" => "ADJACENT".to_string(),
        "LOCAL" => "LOCAL".to_string(),
        _ => "NOT_DEFINED".to_string(),
    };
    match v2.cvss_data.access_complexity.as_str() {
        "LOW" => {
            cvss_v4.attack_complexity = "LOW".to_string();
            cvss_v4.attack_requirements = "NONE".to_string();
        }
        "MEDIUM" => {
            cvss_v4.attack_complexity = "LOW".to_string();
            cvss_v4.attack_requirements = "PRESENT".to_string();
        }
        _ => {
            cvss_v4.attack_complexity = "HIGH".to_string();
            cvss_v4.attack_requirements = "PRESENT".to_string();
        }
    }
    cvss_v4.privileges_required = match v2.cvss_data.authentication.as_str() {
        "NONE" => "NONE".to_string(),
        "SINGLE" => "LOW".to_string(),
        _ => "HIGH".to_string(),
    };
    cvss_v4.vuln_confidentiality_impact = match v2.cvss_data.confidentiality_impact.as_str() {
        "NONE" => "NONE".to_string(),
        "PARTIAL" => "LOW".to_string(),
        _ => "HIGH".to_string(),
    };
    cvss_v4.vuln_integrity_impact = match v2.cvss_data.integrity_impact.as_str() {
        "NONE" => "NONE".to_string(),
        "PARTIAL" => "LOW".to_string(),
        _ => "HIGH".to_string(),
    };
    cvss_v4.vuln_availability_impact = match v2.cvss_data.availability_impact.as_str() {
        "NONE" => "NONE".to_string(),
        "PARTIAL" => "LOW".to_string(),
        _ => "HIGH".to_string(),
    };
    if v2.obtain_all_privilege {
        cvss_v4.sub_confidentiality_impact = "HIGH".to_string();
        cvss_v4.sub_integrity_impact = "HIGH".to_string();
        cvss_v4.sub_availability_impact = "HIGH".to_string();
    } else if v2.obtain_user_privilege || v2.obtain_other_privilege {
        cvss_v4.sub_confidentiality_impact = "LOW".to_string();
        cvss_v4.sub_integrity_impact = "LOW".to_string();
        cvss_v4.sub_availability_impact = "LOW".to_string();
    } else {
        cvss_v4.sub_confidentiality_impact = "NONE".to_string();
        cvss_v4.sub_integrity_impact = "NONE".to_string();
        cvss_v4.sub_availability_impact = "NONE".to_string();
    }

    if let Some(ui_required) = v2.user_interaction_required {
        cvss_v4.user_interaction = if ui_required {
            "ACTIVE".to_string()
        } else {
            "NONE".to_string()
        };
    }
}

pub async fn process_nvd(conn: &Connection, args: &Args) -> Result<()> {
    // NVD Data
    p("Obtaining and parsing NVD data:", true);
    let current_datetime = Utc::now();
    for year in 2002..=current_datetime.year() {
        p(
            format!("\tProcessing NVD data for year {year}:")
                .to_string()
                .as_ref(),
            true,
        );
        let mut nvd_temp_json_gz = NamedTempFile::new()?;
        let mut nvd_temp_json = NamedTempFile::new()?;
        let nvd_url = format!("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz");
        download_file(
            &nvd_url,
            &mut nvd_temp_json_gz,
            false,
            format!("\t\tDownloading {year} NVD JSON…"),
            args,
        )
        .await?;

        p(
            format!("\t\tDeflating {year} NVD JSON…")
                .to_string()
                .as_ref(),
            false,
        );
        decompress_gzip(&nvd_temp_json_gz, &mut nvd_temp_json).await?;
        p("✓", true);

        nvd_parse_and_populate_database(&nvd_temp_json, year, conn).await?;
    }

    Ok(())
}

async fn nvd_parse_and_populate_database(
    json_file: &NamedTempFile,
    year: i32,
    conn: &Connection,
) -> Result<()> {
    let json_content = fs::read_to_string(json_file.path())
        .await
        .context("Failed to read NVD JSON file")?;

    let feed: NvdCveFeed = serde_json::from_str(&json_content)
        .context(format!("Failed to parse NVD JSON for year {year}"))?;

    #[allow(clippy::cast_sign_loss)]
    let bar = ProgressBar::new(feed.total_results as u64);
    let mut on: u32 = 0;
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{prefix} {bar:20.cyan/blue} {msg}")
            .expect("Failed to create progress style"),
    );
    bar.set_prefix(format!("\t\tProcessing {year} JSON…"));
    bar.set_message(format!("{}/{}", on, feed.total_results));
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare_cached(
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
				safety,
				automatable,
				providerUrgency,
				recovery,
				valueDensity,
				vulnerabilityResponseEffort,
				scoreVersion
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
				?34,
				?35
			)",
        )?;

        let mut stmt2 = tx.prepare_cached(
            "INSERT INTO MapVulnerabilityWeakness (VulnerabilityId, WeaknessId, `Primary`) VALUES (?1, ?2, ?3)",
        )?;

        for v in feed.vulnerabilities {
            on += 1;
            bar.set_message(format!("{}/{}", on, feed.total_results));
            let cve = &v.cve;

            //store cvss data to insert into database
            let mut cvss_v4 = CvssDataV40::new();
            let mut score_version: u32 = 0;

            if let Some(cvss_metrics) = &cve.metrics.cvss_metric_v40
                && !cvss_metrics.is_empty()
            {
                for cvss_metric in cvss_metrics {
                    if cvss_metric.type_ == "Primary" {
                        cvss_v4 = cvss_metric.cvss_data.clone();
                        score_version = 4;
                        break;
                    }
                }
            }

            if score_version == 0
                && let Some(cvss_metrics) = &cve.metrics.cvss_metric_v31
            {
                for cvss_metric in cvss_metrics {
                    if cvss_metric.type_ == "Primary" {
                        score_version = 3;
                        apply_v3_to_v4(&mut cvss_v4, &cvss_metric.cvss_data);
                        break;
                    }
                }
            }

            if score_version == 0
                && let Some(cvss_metrics) = &cve.metrics.cvss_metric_v30
            {
                for cvss_metric in cvss_metrics {
                    if cvss_metric.type_ == "Primary" {
                        score_version = 3;
                        apply_v3_to_v4(&mut cvss_v4, &cvss_metric.cvss_data);
                        break;
                    }
                }
            }

            if score_version == 0
                && let Some(cvss_metrics) = &cve.metrics.cvss_metric_v2
                && !cvss_metrics.is_empty()
            {
                for cvss_metric in cvss_metrics {
                    if cvss_metric.type_ == "Primary" {
                        score_version = 2;
                        apply_v2_to_v4(&mut cvss_v4, cvss_metric);
                        break;
                    }
                }
            }

            let description = cve
                .descriptions
                .iter()
                .find(|d| d.lang == "en")
                .map_or("No description found.", |d| d.value.as_str());

            stmt.execute(params![
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
                cvss_v4.provider_urgency,
                cvss_v4.recovery,
                cvss_v4.value_density,
                cvss_v4.vulnerability_response_effort,
                score_version
            ])?;
            let vuln_id = tx.last_insert_rowid();
            let mut inserted: Vec<i32> = Vec::new();
            if let Some(weaknesses) = &cve.weaknesses {
                for weakness in weaknesses {
                    for description in weakness
                        .description
                        .iter()
                        .filter(|d| d.lang == "en" && d.value.starts_with("CWE-"))
                    {
                        if let Ok(tmp_weakness) =
                            description.value.trim_start_matches("CWE-").parse::<i32>()
                            && !inserted.contains(&tmp_weakness)
                        {
                            stmt2.execute(params![
                                vuln_id,
                                tmp_weakness,
                                weakness.type_ == "Primary"
                            ])?;
                            inserted.push(tmp_weakness);
                        }
                    }
                }
            }

            bar.inc(1);
        }
    }

    tx.commit()?;
    bar.finish_with_message(format!("✓ ({})", feed.total_results));
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v3(scope: &str, av: &str, ui: &str) -> CvssDataV3 {
        CvssDataV3 {
            version: "3.1".into(),
            vector_string: String::new(),
            attack_vector: av.into(),
            attack_complexity: "LOW".into(),
            privileges_required: "NONE".into(),
            user_interaction: ui.into(),
            scope: scope.into(),
            confidentiality_impact: "HIGH".into(),
            integrity_impact: "LOW".into(),
            availability_impact: "NONE".into(),
            base_score: 0.0,
            base_severity: String::new(),
        }
    }

    #[test]
    fn v3_to_v4_unchanged_scope_clears_subsequent_impacts() {
        let mut out = CvssDataV40::new();
        apply_v3_to_v4(&mut out, &v3("UNCHANGED", "NETWORK", "NONE"));
        assert_eq!(out.attack_vector, "NETWORK");
        assert_eq!(out.vuln_confidentiality_impact, "HIGH");
        assert_eq!(out.vuln_integrity_impact, "LOW");
        assert_eq!(out.vuln_availability_impact, "NONE");
        // Scope=UNCHANGED → subsequent system impacts go to NONE
        assert_eq!(out.sub_confidentiality_impact, "NONE");
        assert_eq!(out.sub_integrity_impact, "NONE");
        assert_eq!(out.sub_availability_impact, "NONE");
        // Default user_interaction passes through.
        assert_eq!(out.user_interaction, "NONE");
    }

    #[test]
    fn v3_to_v4_changed_scope_propagates_to_subsequent_impacts() {
        let mut out = CvssDataV40::new();
        apply_v3_to_v4(&mut out, &v3("CHANGED", "NETWORK", "NONE"));
        assert_eq!(out.sub_confidentiality_impact, "HIGH");
        assert_eq!(out.sub_integrity_impact, "LOW");
        assert_eq!(out.sub_availability_impact, "NONE");
    }

    #[test]
    fn v3_to_v4_adjacent_network_renamed_to_adjacent() {
        let mut out = CvssDataV40::new();
        apply_v3_to_v4(&mut out, &v3("UNCHANGED", "ADJACENT_NETWORK", "NONE"));
        assert_eq!(out.attack_vector, "ADJACENT");
    }

    #[test]
    fn v3_to_v4_required_user_interaction_becomes_active() {
        let mut out = CvssDataV40::new();
        apply_v3_to_v4(&mut out, &v3("UNCHANGED", "NETWORK", "REQUIRED"));
        assert_eq!(out.user_interaction, "ACTIVE");
    }

    #[allow(clippy::too_many_arguments)]
    fn v2(
        av: &str,
        ac: &str,
        au: &str,
        c: &str,
        i: &str,
        a: &str,
        all: bool,
        user: bool,
        other: bool,
        ui: Option<bool>,
    ) -> CvssMetricV2 {
        CvssMetricV2 {
            source: String::new(),
            type_: "Primary".into(),
            cvss_data: CvssData {
                version: "2.0".into(),
                vector_string: String::new(),
                access_vector: av.into(),
                access_complexity: ac.into(),
                authentication: au.into(),
                confidentiality_impact: c.into(),
                integrity_impact: i.into(),
                availability_impact: a.into(),
                base_score: 0.0,
            },
            base_severity: String::new(),
            exploitability_score: 0.0,
            impact_score: 0.0,
            ac_insuf_info: None,
            obtain_all_privilege: all,
            obtain_user_privilege: user,
            obtain_other_privilege: other,
            user_interaction_required: ui,
        }
    }

    #[test]
    fn v2_to_v4_low_complexity_no_auth_no_ui_required() {
        let mut out = CvssDataV40::new();
        apply_v2_to_v4(
            &mut out,
            &v2(
                "NETWORK",
                "LOW",
                "NONE",
                "PARTIAL",
                "PARTIAL",
                "NONE",
                false,
                false,
                false,
                Some(false),
            ),
        );
        assert_eq!(out.attack_vector, "NETWORK");
        assert_eq!(out.attack_complexity, "LOW");
        assert_eq!(out.attack_requirements, "NONE");
        assert_eq!(out.privileges_required, "NONE");
        assert_eq!(out.vuln_confidentiality_impact, "LOW");
        assert_eq!(out.vuln_integrity_impact, "LOW");
        assert_eq!(out.vuln_availability_impact, "NONE");
        assert_eq!(out.sub_confidentiality_impact, "NONE");
        assert_eq!(out.user_interaction, "NONE");
    }

    #[test]
    fn v2_to_v4_medium_complexity_promotes_attack_requirements() {
        let mut out = CvssDataV40::new();
        apply_v2_to_v4(
            &mut out,
            &v2(
                "LOCAL", "MEDIUM", "SINGLE", "COMPLETE", "COMPLETE", "COMPLETE", false, false,
                false, None,
            ),
        );
        assert_eq!(out.attack_complexity, "LOW");
        assert_eq!(out.attack_requirements, "PRESENT");
        assert_eq!(out.privileges_required, "LOW");
        assert_eq!(out.vuln_confidentiality_impact, "HIGH");
    }

    #[test]
    fn v2_to_v4_obtain_all_privilege_sets_subsequent_high() {
        let mut out = CvssDataV40::new();
        apply_v2_to_v4(
            &mut out,
            &v2(
                "NETWORK", "LOW", "NONE", "NONE", "NONE", "NONE", true, false, false, None,
            ),
        );
        assert_eq!(out.sub_confidentiality_impact, "HIGH");
        assert_eq!(out.sub_integrity_impact, "HIGH");
        assert_eq!(out.sub_availability_impact, "HIGH");
    }

    #[test]
    fn v2_to_v4_obtain_user_or_other_sets_subsequent_low() {
        let mut out = CvssDataV40::new();
        apply_v2_to_v4(
            &mut out,
            &v2(
                "NETWORK", "LOW", "NONE", "NONE", "NONE", "NONE", false, true, false, None,
            ),
        );
        assert_eq!(out.sub_confidentiality_impact, "LOW");
    }

    #[test]
    fn v2_to_v4_adjacent_network_renamed() {
        let mut out = CvssDataV40::new();
        apply_v2_to_v4(
            &mut out,
            &v2(
                "ADJACENT_NETWORK",
                "LOW",
                "NONE",
                "NONE",
                "NONE",
                "NONE",
                false,
                false,
                false,
                None,
            ),
        );
        assert_eq!(out.attack_vector, "ADJACENT");
    }

    #[test]
    fn v2_to_v4_user_interaction_required_true_becomes_active() {
        let mut out = CvssDataV40::new();
        apply_v2_to_v4(
            &mut out,
            &v2(
                "NETWORK",
                "LOW",
                "NONE",
                "NONE",
                "NONE",
                "NONE",
                false,
                false,
                false,
                Some(true),
            ),
        );
        assert_eq!(out.user_interaction, "ACTIVE");
    }
}
