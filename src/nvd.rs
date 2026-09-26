// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use crate::common::{
    Args, DownloadMetadata, MAX_NVD_GZIP_BYTES, MAX_NVD_JSON_BYTES, MAX_NVD_META_BYTES,
    build_insert_sql, decompress_gzip, download_file, p, sha256_file,
};
use crate::db::record_source;

use anyhow::{Context, Result, bail};
use chrono::{Datelike, Utc};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use rusqlite::{Connection, params_from_iter, types::Value};
use serde::Deserialize;
use serde::de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::fmt;
use std::io::{BufReader, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::sync::mpsc;

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

#[derive(Debug, Clone)]
struct NvdMeta {
    size: u64,
    gzip_size: u64,
    sha256: String,
}

fn parse_nvd_meta(file: &NamedTempFile) -> Result<NvdMeta> {
    let mut content = String::new();
    file.reopen()?.read_to_string(&mut content)?;
    let mut size = None;
    let mut gzip_size = None;
    let mut zip_size = None;
    let mut sha256 = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "size" => {
                let parsed = value
                    .trim()
                    .parse::<u64>()
                    .context("Invalid NVD metadata size")?;
                if size.replace(parsed).is_some() {
                    bail!("NVD metadata repeated the size field");
                }
            }
            "gzSize" => {
                let parsed = value
                    .trim()
                    .parse::<u64>()
                    .context("Invalid NVD metadata gzip size")?;
                if gzip_size.replace(parsed).is_some() {
                    bail!("NVD metadata repeated the gzSize field");
                }
            }
            "zipSize" => {
                let parsed = value
                    .trim()
                    .parse::<u64>()
                    .context("Invalid NVD metadata zip size")?;
                if zip_size.replace(parsed).is_some() {
                    bail!("NVD metadata repeated the zipSize field");
                }
            }
            "sha256" if sha256.is_some() => {
                bail!("NVD metadata repeated the sha256 field");
            }
            "sha256" => sha256 = Some(value.trim().to_ascii_lowercase()),
            _ => {}
        }
    }

    let metadata = NvdMeta {
        size: size.context("NVD metadata omitted uncompressed size")?,
        gzip_size: gzip_size
            .or(zip_size)
            .context("NVD metadata omitted gzip size")?,
        sha256: sha256.context("NVD metadata omitted SHA-256")?,
    };
    if metadata.size == 0 || metadata.size > MAX_NVD_JSON_BYTES {
        bail!(
            "NVD metadata declared invalid JSON size {} (limit {})",
            metadata.size,
            MAX_NVD_JSON_BYTES
        );
    }
    if metadata.gzip_size == 0 || metadata.gzip_size > MAX_NVD_GZIP_BYTES {
        bail!(
            "NVD metadata declared invalid gzip size {} (limit {})",
            metadata.gzip_size,
            MAX_NVD_GZIP_BYTES
        );
    }
    if metadata.sha256.len() != 64 || !metadata.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("NVD metadata contained an invalid SHA-256 digest");
    }
    Ok(metadata)
}

#[derive(Debug)]
struct NvdFeedSummary {
    results_per_page: i64,
    start_index: i64,
    total_results: i64,
    format: String,
    version: String,
    timestamp: String,
    vulnerability_count: u64,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "camelCase")]
enum FeedField {
    ResultsPerPage,
    StartIndex,
    TotalResults,
    Format,
    Version,
    Timestamp,
    Vulnerabilities,
    #[serde(other)]
    Other,
}

struct NvdFeedSeed<'a, F> {
    on_vulnerability: &'a mut F,
}

impl<'de, F> DeserializeSeed<'de> for NvdFeedSeed<'_, F>
where
    F: FnMut(Vulnerability) -> Result<()>,
{
    type Value = NvdFeedSummary;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(NvdFeedVisitor {
            on_vulnerability: self.on_vulnerability,
        })
    }
}

struct NvdFeedVisitor<'a, F> {
    on_vulnerability: &'a mut F,
}

impl<'de, F> Visitor<'de> for NvdFeedVisitor<'_, F>
where
    F: FnMut(Vulnerability) -> Result<()>,
{
    type Value = NvdFeedSummary;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an NVD CVE feed object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut results_per_page = None;
        let mut start_index = None;
        let mut total_results = None;
        let mut format = None;
        let mut version = None;
        let mut timestamp = None;
        let mut vulnerability_count = None;

        while let Some(field) = map.next_key::<FeedField>()? {
            match field {
                FeedField::ResultsPerPage => {
                    if results_per_page.replace(map.next_value()?).is_some() {
                        return Err(A::Error::duplicate_field("resultsPerPage"));
                    }
                }
                FeedField::StartIndex => {
                    if start_index.replace(map.next_value()?).is_some() {
                        return Err(A::Error::duplicate_field("startIndex"));
                    }
                }
                FeedField::TotalResults => {
                    if total_results.replace(map.next_value()?).is_some() {
                        return Err(A::Error::duplicate_field("totalResults"));
                    }
                }
                FeedField::Format => {
                    if format.replace(map.next_value()?).is_some() {
                        return Err(A::Error::duplicate_field("format"));
                    }
                }
                FeedField::Version => {
                    if version.replace(map.next_value()?).is_some() {
                        return Err(A::Error::duplicate_field("version"));
                    }
                }
                FeedField::Timestamp => {
                    if timestamp.replace(map.next_value()?).is_some() {
                        return Err(A::Error::duplicate_field("timestamp"));
                    }
                }
                FeedField::Vulnerabilities => {
                    if vulnerability_count.is_some() {
                        return Err(A::Error::duplicate_field("vulnerabilities"));
                    }
                    vulnerability_count = Some(map.next_value_seed(VulnerabilityListSeed {
                        on_vulnerability: self.on_vulnerability,
                    })?);
                }
                FeedField::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(NvdFeedSummary {
            results_per_page: results_per_page
                .ok_or_else(|| A::Error::missing_field("resultsPerPage"))?,
            start_index: start_index.ok_or_else(|| A::Error::missing_field("startIndex"))?,
            total_results: total_results.ok_or_else(|| A::Error::missing_field("totalResults"))?,
            format: format.ok_or_else(|| A::Error::missing_field("format"))?,
            version: version.ok_or_else(|| A::Error::missing_field("version"))?,
            timestamp: timestamp.ok_or_else(|| A::Error::missing_field("timestamp"))?,
            vulnerability_count: vulnerability_count
                .ok_or_else(|| A::Error::missing_field("vulnerabilities"))?,
        })
    }
}

struct VulnerabilityListSeed<'a, F> {
    on_vulnerability: &'a mut F,
}

impl<'de, F> DeserializeSeed<'de> for VulnerabilityListSeed<'_, F>
where
    F: FnMut(Vulnerability) -> Result<()>,
{
    type Value = u64;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(VulnerabilityListVisitor {
            on_vulnerability: self.on_vulnerability,
        })
    }
}

struct VulnerabilityListVisitor<'a, F> {
    on_vulnerability: &'a mut F,
}

impl<'de, F> Visitor<'de> for VulnerabilityListVisitor<'_, F>
where
    F: FnMut(Vulnerability) -> Result<()>,
{
    type Value = u64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of NVD vulnerabilities")
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut count = 0_u64;
        while let Some(vulnerability) = sequence.next_element::<Vulnerability>()? {
            (self.on_vulnerability)(vulnerability).map_err(A::Error::custom)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| A::Error::custom("NVD vulnerability count overflow"))?;
        }
        Ok(count)
    }
}

fn parse_nvd_feed<R, F>(reader: R, on_vulnerability: &mut F) -> Result<NvdFeedSummary>
where
    R: Read,
    F: FnMut(Vulnerability) -> Result<()>,
{
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let summary = NvdFeedSeed { on_vulnerability }
        .deserialize(&mut deserializer)
        .context("Failed to parse NVD JSON")?;
    deserializer.end().context("Trailing data in NVD JSON")?;
    Ok(summary)
}

fn validate_nvd_feed(summary: &NvdFeedSummary, year: i32) -> Result<()> {
    let count = i64::try_from(summary.vulnerability_count)
        .context("NVD vulnerability count cannot fit in database")?;
    if count == 0 || summary.total_results != count || summary.results_per_page != count {
        bail!(
            "NVD {year} feed count mismatch: parsed {count}, resultsPerPage {}, totalResults {}",
            summary.results_per_page,
            summary.total_results
        );
    }
    if summary.start_index != 0
        || summary.format != "NVD_CVE"
        || summary.version != "2.0"
        || summary.timestamp.trim().is_empty()
    {
        bail!("NVD {year} feed metadata failed semantic validation");
    }
    Ok(())
}

fn valid_cve_id(id: &str) -> bool {
    let mut parts = id.split('-');
    matches!(parts.next(), Some("CVE"))
        && parts
            .next()
            .is_some_and(|part| part.len() == 4 && part.bytes().all(|byte| byte.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|part| part.len() >= 4 && part.bytes().all(|byte| byte.is_ascii_digit()))
        && parts.next().is_none()
}

struct NvdDownload {
    year: i32,
    gzip_file: NamedTempFile,
    download: DownloadMetadata,
    metadata: NvdMeta,
}

/// Keep only two compressed feeds in flight and one queued. Parsing is
/// streaming, so the loader's memory use no longer grows with a feed year.
const NVD_DOWNLOAD_CONCURRENCY: usize = 2;

pub async fn process_nvd(conn: &Connection, args: &Args) -> Result<()> {
    // Slot model: exactly NVD_DOWNLOAD_CONCURRENCY + 1 progress bars exist
    // for the duration of this step. The first N are persistent "download
    // slots" — N worker tasks each own one slot bar and reuse it across
    // every year they download. The last bar is the overall sequential
    // processor that increments as downloaded years are inserted.
    //
    // Workers pull years off a shared atomic counter (cheaper than a mutex
    // around a queue when items are just integers and there's no fairness
    // requirement). Completed downloads are sent over a bounded mpsc channel
    // to the consumer running on the main task — Connection is !Send so the
    // consumer must stay here.
    p("Obtaining and parsing NVD data:", true);
    let current_year = Utc::now().year();
    let years: Vec<i32> = (2002..=current_year).rev().collect();
    let total_years = years.len();

    // Cap redraws so the per-chunk byte updates don't flood scrollback.
    let mp = MultiProgress::with_draw_target(ProgressDrawTarget::stderr_with_hz(4));

    let bar_style = ProgressStyle::default_bar()
        .template("{prefix} {bar:20.cyan/blue} {msg}")
        .expect("Failed to create progress style");

    // Pre-create the N slot bars FIRST so they occupy the top of the layout.
    // Each starts in an idle state; the worker that owns it will set the
    // length/prefix on its first download.
    let slot_bars: Vec<ProgressBar> = (0..NVD_DOWNLOAD_CONCURRENCY)
        .map(|_| {
            let pb = mp.add(ProgressBar::new(0));
            pb.set_style(bar_style.clone());
            pb.set_prefix("\t(idle)");
            pb.set_message("waiting…");
            pb
        })
        .collect();

    // The overall processing bar sits at the bottom of the layout.
    let proc_bar = mp.add(ProgressBar::new(total_years as u64));
    proc_bar.set_style(bar_style);
    proc_bar.set_prefix("Processing NVD years…");
    proc_bar.set_message(format!("0/{total_years}"));
    proc_bar.enable_steady_tick(Duration::from_millis(250));

    // Shared work dispatch: an atomic index into the years vec.
    let years = Arc::new(years);
    let next_year = Arc::new(AtomicUsize::new(0));
    let args_arc = Arc::new(args.clone());

    // Bounded so a fast network can't run the consumer out of disk: peak
    // gz holdings ≈ N (one per worker mid-download) + channel capacity.
    let (tx, mut rx) = mpsc::channel::<Result<NvdDownload>>(1);
    let mut workers = Vec::with_capacity(NVD_DOWNLOAD_CONCURRENCY);

    // Spawn one worker per slot. Each worker owns its slot bar for its
    // entire lifetime, draining the year queue and reusing the bar.
    for slot_bar in slot_bars {
        let years = years.clone();
        let next_year = next_year.clone();
        let tx = tx.clone();
        let args = args_arc.clone();
        workers.push(tokio::spawn(async move {
            loop {
                let idx = next_year.fetch_add(1, Ordering::Relaxed);
                if idx >= years.len() {
                    // No work left; freeze the slot in a clean state but
                    // leave it on screen so the layout stays stable.
                    slot_bar.set_prefix("\t(done)");
                    slot_bar.set_message(String::new());
                    slot_bar.set_length(0);
                    slot_bar.set_position(0);
                    break;
                }
                let year = years[idx];
                let result: Result<NvdDownload> = async {
                    let base_url = format!(
                        "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
                    );
                    let mut meta_file = NamedTempFile::new()?;
                    let meta_url =
                        format!("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.meta");
                    download_file(
                        &meta_url,
                        &mut meta_file,
                        true,
                        String::new(),
                        &args,
                        None,
                        MAX_NVD_META_BYTES,
                    )
                    .await?;
                    let metadata = parse_nvd_meta(&meta_file)?;

                    let mut gz_file = NamedTempFile::new()?;
                    let download = download_file(
                        &base_url,
                        &mut gz_file,
                        false,
                        format!("\tDownloading {year} NVD JSON…"),
                        &args,
                        Some(&slot_bar),
                        metadata.gzip_size,
                    )
                    .await?;
                    if download.size_bytes != metadata.gzip_size {
                        bail!(
                            "NVD {year} gzip size mismatch: downloaded {}, metadata declared {}",
                            download.size_bytes,
                            metadata.gzip_size
                        );
                    }
                    Ok(NvdDownload {
                        year,
                        gzip_file: gz_file,
                        download,
                        metadata,
                    })
                }
                .await;
                let failed = result.is_err();
                if tx.send(result).await.is_err() {
                    // Consumer dropped rx — typically because of an earlier
                    // error elsewhere. Stop pulling new years.
                    break;
                }
                if failed {
                    break;
                }
            }
        }));
    }
    // Drop our handle so the channel closes once every worker exits.
    drop(tx);

    // Consumer: one year at a time, in completion order.
    let mut completed: u64 = 0;
    let mut processing_error = None;
    while let Some(item) = rx.recv().await {
        let item = match item {
            Ok(item) => item,
            Err(error) => {
                processing_error = Some(error);
                break;
            }
        };
        let year = item.year;
        let mut json_file = NamedTempFile::new()?;
        let json_size = match decompress_gzip(&item.gzip_file, &mut json_file, item.metadata.size)
            .await
        {
            Ok(size) => size,
            Err(error) => {
                processing_error = Some(error.context(format!("Failed to decompress NVD {year}")));
                break;
            }
        };
        if json_size != item.metadata.size {
            processing_error = Some(anyhow::anyhow!(
                "NVD {year} JSON size mismatch: decompressed {json_size}, metadata declared {}",
                item.metadata.size
            ));
            break;
        }
        let json_hash = match sha256_file(json_file.path()) {
            Ok(hash) => hash,
            Err(error) => {
                processing_error = Some(error.context(format!("Failed to hash NVD {year}")));
                break;
            }
        };
        if json_hash != item.metadata.sha256 {
            processing_error = Some(anyhow::anyhow!(
                "NVD {year} SHA-256 mismatch: downloaded content did not match NIST metadata"
            ));
            break;
        }
        // Free the gz immediately — only the decompressed JSON matters now.
        drop(item.gzip_file);
        if let Err(error) = nvd_parse_and_populate_database(&json_file, year, conn) {
            processing_error = Some(error);
            break;
        }
        if let Err(error) = record_source(
            conn,
            &format!("NVD-{year}"),
            &item.download,
            Some(&item.metadata.sha256),
            Some(item.metadata.size),
        ) {
            processing_error = Some(error);
            break;
        }
        completed += 1;
        proc_bar.set_position(completed);
        proc_bar.set_message(format!("{completed}/{total_years} (last: {year})"));
    }
    drop(rx);

    for worker in workers {
        if let Err(join_error) = worker.await
            && processing_error.is_none()
        {
            processing_error = Some(anyhow::anyhow!("NVD download worker failed: {join_error}"));
        }
    }
    if let Some(error) = processing_error {
        proc_bar.abandon_with_message("failed");
        return Err(error);
    }
    if completed != total_years as u64 {
        bail!("NVD load ended after {completed} of {total_years} years");
    }

    proc_bar.finish_with_message(format!("✓ ({total_years} years)"));
    // MultiProgress is about to drop; one newline so subsequent stdout
    // doesn't share a line with the final bar render.
    println!();
    Ok(())
}

fn nvd_parse_and_populate_database(
    json_file: &NamedTempFile,
    year: i32,
    conn: &Connection,
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    {
        // Resolve each row's CVSS metrics + child CWE list up-front, then flush
        // in chunks. 35 columns × 500 rows = 17500 host params, well under
        // SQLite's default 32766 limit. Multi-row INSERT amortizes parse/plan
        // cost vs. row-at-a-time execute().
        const VULN_BATCH: usize = 500;
        const VULN_COLS: usize = 35;
        const MAP_BATCH: usize = 5000;
        const MAP_COLS: usize = 3;

        let vuln_prefix = "INSERT INTO Vulnerability (\
            NVDId,Description,attackVector,attackComplexity,attackRequirements,\
            privilegesRequired,userInteraction,vulnConfidentialityImpact,\
            vulnIntegrityImpact,vulnAvailabilityImpact,subConfidentialityImpact,\
            subIntegrityImpact,subAvailabilityImpact,exploitMaturity,\
            confidentialityRequirement,integrityRequirement,availabilityRequirement,\
            modifiedAttackVector,modifiedAttackComplexity,modifiedAttackRequirements,\
            modifiedPrivilegesRequired,modifiedUserInteraction,\
            modifiedVulnConfidentialityImpact,modifiedVulnIntegrityImpact,\
            modifiedVulnAvailabilityImpact,modifiedSubConfidentialityImpact,\
            modifiedSubIntegrityImpact,modifiedSubAvailabilityImpact,\
            safety,automatable,providerUrgency,recovery,valueDensity,\
            vulnerabilityResponseEffort,scoreVersion) VALUES ";
        let map_prefix =
            "INSERT INTO MapVulnerabilityWeakness (VulnerabilityId, WeaknessId, `Primary`) VALUES ";

        // Pre-build the full-batch SQL once; the trailing partial chunk gets
        // its own SQL string.
        let full_vuln_sql = build_insert_sql(vuln_prefix, VULN_BATCH, VULN_COLS);

        // Per-vuln pending child rows: (cwe_id, primary). The vulnerability
        // rowid is unknown until after the parent multi-row INSERT runs and
        // last_insert_rowid() reports the highest assigned id.
        struct Pending {
            children: Vec<(i32, bool)>,
        }
        let mut buf_values: Vec<Value> = Vec::with_capacity(VULN_BATCH * VULN_COLS);
        let mut pending: Vec<Pending> = Vec::with_capacity(VULN_BATCH);
        let mut map_values: Vec<Value> = Vec::with_capacity(MAP_BATCH * MAP_COLS);

        // Flushes the parent batch, then the (now-resolvable) child batch.
        // Declared as a closure-like inline section via a helper macro would
        // be cleaner, but the borrow checker is happier with an explicit fn-
        // style block we re-enter at end-of-loop and final-flush.
        let flush_vulns = |tx: &rusqlite::Transaction<'_>,
                           buf_values: &mut Vec<Value>,
                           pending: &mut Vec<Pending>,
                           map_values: &mut Vec<Value>,
                           full_sql: &str|
         -> Result<()> {
            if pending.is_empty() {
                return Ok(());
            }
            let n = pending.len();
            let sql_storage;
            let sql: &str = if n == VULN_BATCH {
                full_sql
            } else {
                sql_storage = build_insert_sql(vuln_prefix, n, VULN_COLS);
                &sql_storage
            };
            tx.execute(sql, params_from_iter(buf_values.iter()))?;
            let last_id = tx.last_insert_rowid();
            // SQLite assigns sequential rowids within a single multi-row INSERT
            // when no explicit id is provided and AUTOINCREMENT is in effect.
            #[allow(clippy::cast_possible_wrap)]
            let first_id = last_id - (n as i64) + 1;

            for (offset, p) in pending.drain(..).enumerate() {
                #[allow(clippy::cast_possible_wrap)]
                let vuln_id = first_id + offset as i64;
                for (cwe_id, is_primary) in p.children {
                    map_values.push(Value::Integer(vuln_id));
                    map_values.push(Value::Integer(i64::from(cwe_id)));
                    map_values.push(Value::Integer(i64::from(is_primary)));
                    if map_values.len() >= MAP_BATCH * MAP_COLS {
                        let rows = map_values.len() / MAP_COLS;
                        let map_sql = build_insert_sql(map_prefix, rows, MAP_COLS);
                        tx.execute(&map_sql, params_from_iter(map_values.iter()))?;
                        map_values.clear();
                    }
                }
            }
            buf_values.clear();
            Ok(())
        };

        let summary = {
            let mut insert_vulnerability = |v: Vulnerability| -> Result<()> {
                let cve = &v.cve;
                if !valid_cve_id(&cve.id) {
                    bail!(
                        "NVD {year} feed contained invalid CVE identifier: {}",
                        cve.id
                    );
                }

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

                buf_values.push(Value::Text(cve.id.clone()));
                buf_values.push(Value::Text(description.to_string()));
                buf_values.push(Value::Text(cvss_v4.attack_vector));
                buf_values.push(Value::Text(cvss_v4.attack_complexity));
                buf_values.push(Value::Text(cvss_v4.attack_requirements));
                buf_values.push(Value::Text(cvss_v4.privileges_required));
                buf_values.push(Value::Text(cvss_v4.user_interaction));
                buf_values.push(Value::Text(cvss_v4.vuln_confidentiality_impact));
                buf_values.push(Value::Text(cvss_v4.vuln_integrity_impact));
                buf_values.push(Value::Text(cvss_v4.vuln_availability_impact));
                buf_values.push(Value::Text(cvss_v4.sub_confidentiality_impact));
                buf_values.push(Value::Text(cvss_v4.sub_integrity_impact));
                buf_values.push(Value::Text(cvss_v4.sub_availability_impact));
                buf_values.push(Value::Text(cvss_v4.exploit_maturity));
                buf_values.push(Value::Text(cvss_v4.confidentiality_requirement));
                buf_values.push(Value::Text(cvss_v4.integrity_requirement));
                buf_values.push(Value::Text(cvss_v4.availability_requirement));
                buf_values.push(Value::Text(cvss_v4.modified_attack_vector));
                buf_values.push(Value::Text(cvss_v4.modified_attack_complexity));
                buf_values.push(Value::Text(cvss_v4.modified_attack_requirements));
                buf_values.push(Value::Text(cvss_v4.modified_privileges_required));
                buf_values.push(Value::Text(cvss_v4.modified_user_interaction));
                buf_values.push(Value::Text(cvss_v4.modified_vuln_confidentiality_impact));
                buf_values.push(Value::Text(cvss_v4.modified_vuln_integrity_impact));
                buf_values.push(Value::Text(cvss_v4.modified_vuln_availability_impact));
                buf_values.push(Value::Text(cvss_v4.modified_sub_confidentiality_impact));
                buf_values.push(Value::Text(cvss_v4.modified_sub_integrity_impact));
                buf_values.push(Value::Text(cvss_v4.modified_sub_availability_impact));
                buf_values.push(Value::Text(cvss_v4.safety));
                buf_values.push(Value::Text(cvss_v4.automatable));
                buf_values.push(Value::Text(cvss_v4.provider_urgency));
                buf_values.push(Value::Text(cvss_v4.recovery));
                buf_values.push(Value::Text(cvss_v4.value_density));
                buf_values.push(Value::Text(cvss_v4.vulnerability_response_effort));
                buf_values.push(Value::Integer(i64::from(score_version)));

                let mut children: Vec<(i32, bool)> = Vec::new();
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
                                children.push((tmp_weakness, weakness.type_ == "Primary"));
                                inserted.push(tmp_weakness);
                            }
                        }
                    }
                }
                pending.push(Pending { children });

                if pending.len() >= VULN_BATCH {
                    flush_vulns(
                        &tx,
                        &mut buf_values,
                        &mut pending,
                        &mut map_values,
                        &full_vuln_sql,
                    )?;
                }
                Ok(())
            };

            let reader = BufReader::new(
                json_file
                    .reopen()
                    .context("Failed to reopen NVD JSON file")?,
            );
            parse_nvd_feed(reader, &mut insert_vulnerability)
                .with_context(|| format!("Failed to parse NVD JSON for year {year}"))?
        };
        validate_nvd_feed(&summary, year)?;

        flush_vulns(
            &tx,
            &mut buf_values,
            &mut pending,
            &mut map_values,
            &full_vuln_sql,
        )?;
        if !map_values.is_empty() {
            let rows = map_values.len() / MAP_COLS;
            let map_sql = build_insert_sql(map_prefix, rows, MAP_COLS);
            tx.execute(&map_sql, params_from_iter(map_values.iter()))?;
        }
    }

    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn nvd_feed_streams_vulnerabilities_and_validates_counts() {
        let json = br#"{
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-01-01T00:00:00.000",
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2025-1234",
                    "published": "2025-01-01",
                    "lastModified": "2025-01-01",
                    "vulnStatus": "Analyzed",
                    "descriptions": [],
                    "metrics": {},
                    "references": []
                }
            }]
        }"#;
        let mut ids = Vec::new();
        let summary = parse_nvd_feed(json.as_slice(), &mut |entry: Vulnerability| {
            ids.push(entry.cve.id);
            Ok(())
        })
        .unwrap();
        validate_nvd_feed(&summary, 2025).unwrap();
        assert_eq!(ids, ["CVE-2025-1234"]);
    }

    #[test]
    fn streamed_nvd_feed_populates_database() {
        let json = br#"{
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-01-01T00:00:00.000",
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2025-1234",
                    "published": "2025-01-01",
                    "lastModified": "2025-01-01",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "fixture"}],
                    "metrics": {},
                    "references": []
                }
            }]
        }"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json).unwrap();
        file.flush().unwrap();
        let conn = Connection::open_in_memory().unwrap();
        crate::db::apply_schema(&conn).unwrap();

        nvd_parse_and_populate_database(&file, 2025, &conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM Vulnerability", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn nvd_metadata_requires_valid_hash_and_bounded_sizes() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "size:123\ngzSize:45\nsha256:{}", "a".repeat(64)).unwrap();
        let metadata = parse_nvd_meta(&file).unwrap();
        assert_eq!(metadata.size, 123);
        assert_eq!(metadata.gzip_size, 45);
        assert_eq!(metadata.sha256, "a".repeat(64));

        let mut duplicate = NamedTempFile::new().unwrap();
        writeln!(
            duplicate,
            "size:123\nsize:456\ngzSize:45\nsha256:{}",
            "a".repeat(64)
        )
        .unwrap();
        assert!(parse_nvd_meta(&duplicate).is_err());
    }

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
