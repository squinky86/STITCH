// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use stitch::{nvd::CvssDataV40, stig::Stig, stig::StigCheck};

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use clap::Parser;
use cvss::v3::Base;
use cvss::v4::Vector;
use rusqlite::{Connection, Row, params};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};
use uuid::Uuid;

/// Minimum number of CVEs that must be associated with a CWE before a score
/// is emitted. Below this, no score is produced. See `doc/scoring.md` §4.2.1.
const MINIMUM_CVES_TO_SCORE: usize = 5;

/// Minimum CVE pool size that lets a step short-circuit further data-gathering
/// within the current round. See `doc/scoring.md` §4.2.1.
const MINIMUM_CVES_TO_COMPLETE_ROUND: usize = 50;

fn get_controls_from_controls(controls: Vec<String>, db_path: &str) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database file: {}", db_path))?;

    let placeholders = controls.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let query_controls = format!(
        "
		SELECT DISTINCT
			c.number as control_number,
			c.name as control_name,
			c.description as control_description,
			f.abbr as family_abbreviation,
			f.name as family_name,
			c.id as control_id
		FROM RMFCCI rc
		JOIN RMFControl c ON rc.RMFControlId = c.id
		JOIN RMFFamily f ON c.RMFFamilyId = f.id
		WHERE c.number IN ({})",
        placeholders
    );

    // Prepare statement to find all CCIs for a given control
    let mut stmt_ccis = conn.prepare("SELECT id FROM RMFCCI WHERE RMFControlId = ?1")?;

    let mut stmt_controls = conn.prepare(&query_controls)?;

    let mut unique_controls: HashMap<u32, serde_json::Value> = HashMap::new();

    let rows = stmt_controls.query_map(rusqlite::params_from_iter(controls), |row: &Row| {
        let control_number: String = row.get(0)?;
        let control_name: String = row.get(1)?;
        let control_desc: String = row.get(2)?;
        let family_abbr: String = row.get(3)?;
        let family_name: String = row.get(4)?;
        let control_id: u32 = row.get(5)?;

        Ok((
            control_id,
            json!({
                "control": control_number,
                "name": control_name,
                "description": control_desc,
                "family": {
                    "abbreviation": family_abbr,
                    "name": family_name
                }
            }),
        ))
    })?;

    for (control_id, control_json) in rows.flatten() {
        // Add to map. If already present, it's just ignored.
        unique_controls.entry(control_id).or_insert(control_json);
    }

    let mut output_controls: Vec<serde_json::Value> = Vec::new();

    for (control_id, mut control_json) in unique_controls {
        // Find all CCIs for this control_id
        let cci_rows = stmt_ccis.query_map([control_id], |row| {
            let cci_id: u32 = row.get(0)?;
            Ok(json!(format!("CCI-{:06}", cci_id)))
        })?;

        // Collect the CCIs into a JSON array
        let cci_list: Vec<serde_json::Value> = cci_rows.filter_map(Result::ok).collect();

        // Add the control_id and cci_list to the JSON object
        if let Some(obj) = control_json.as_object_mut() {
            obj.insert("control_id".to_string(), json!(control_id));
            obj.insert("ccis".to_string(), json!(cci_list));
        }

        output_controls.push(control_json);
    }

    let result = json!({
        "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "controls": output_controls // This is now an array of controls, each with its own CCI list
    });

    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}

fn get_controls_from_ccis(ccis: Vec<u32>, db_path: &str) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database file: {}", db_path))?;

    // Prepare statement to find controls for a single CCI
    let query_controls = "
		SELECT DISTINCT
			c.number as control_number,
			c.name as control_name,
			c.description as control_description,
			f.abbr as family_abbreviation,
			f.name as family_name,
			c.id as control_id
		FROM RMFCCI rc
		JOIN RMFControl c ON rc.RMFControlId = c.id
		JOIN RMFFamily f ON c.RMFFamilyId = f.id
		WHERE rc.id = ?1";

    let mut stmt_controls = conn.prepare(query_controls)?;

    // Prepare statement to find all CCIs for a given control
    let placeholders = ccis.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql_ccis = format!(
        "SELECT id FROM RMFCCI WHERE RMFControlId = ?1 AND id IN ({})",
        placeholders
    );
    let mut stmt_ccis = conn.prepare(&sql_ccis)?;

    let mut unique_controls: HashMap<u32, serde_json::Value> = HashMap::new();

    for cci_id in &ccis {
        let rows = stmt_controls.query_map([cci_id], |row: &Row| {
            let control_number: String = row.get(0)?;
            let control_name: String = row.get(1)?;
            let control_desc: String = row.get(2)?;
            let family_abbr: String = row.get(3)?;
            let family_name: String = row.get(4)?;
            let control_id: u32 = row.get(5)?;

            Ok((
                control_id,
                json!({
                    "control": control_number,
                    "name": control_name,
                    "description": control_desc,
                    "family": {
                        "abbreviation": family_abbr,
                        "name": family_name
                    }
                }),
            ))
        })?;

        for (control_id, control_json) in rows.flatten() {
            // Add to map. If already present, it's just ignored.
            unique_controls.entry(control_id).or_insert(control_json);
        }
    }

    let mut output_controls: Vec<serde_json::Value> = Vec::new();

    for (control_id, mut control_json) in unique_controls {
        // Find all CCIs for this control_id
        let mut tmp_params: Vec<u32> = Vec::new();
        tmp_params.push(control_id);
        tmp_params.append(&mut ccis.clone());
        let cci_rows = stmt_ccis.query_map(rusqlite::params_from_iter(tmp_params), |row| {
            let cci_id: u32 = row.get(0)?;
            Ok(json!(format!("CCI-{:06}", cci_id)))
        })?;

        // Collect the CCIs into a JSON array
        let cci_list: Vec<serde_json::Value> = cci_rows.filter_map(Result::ok).collect();

        // Add the control_id and cci_list to the JSON object
        if let Some(obj) = control_json.as_object_mut() {
            obj.insert("control_id".to_string(), json!(control_id));
            obj.insert("ccis".to_string(), json!(cci_list));
        }

        output_controls.push(control_json);
    }

    let result = json!({
        "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "controls": output_controls // This is now an array of controls, each with its own CCI list
    });

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn mean_impact(iter: impl Iterator<Item = String>, affects: bool) -> String {
    if !affects {
        return String::from("NONE");
    }
    let scores: Vec<u32> = iter
        .map(|s| match s.as_str() {
            "LOW" => 1,
            "HIGH" => 3,
            _ => 0,
        })
        .collect();

    let score: u32 = scores.iter().sum();

    let count = scores.len();

    // Handle the division by zero case for an empty iterator
    if count == 0 {
        return String::from("NONE");
    }

    let average = (score as f32) / (count as f32);

    if average < 0.33 {
        return String::from("NONE");
    } else if average < 2.0 {
        return String::from("LOW");
    }

    String::from("HIGH")
}

/// Calculates the mode (most frequent value) of a sequence of items.
fn mode(iter: impl Iterator<Item = String>, list: Vec<String>) -> String {
    // Step 0: Set the initial HashMaps
    let mut counts: HashMap<String, usize> = HashMap::new();
    for item in &list {
        counts.insert((&item).to_string(), 0);
    }

    // Step 1: Count the frequency of each item from the iterator.
    // A HashMap is used to store items and their corresponding counts.
    for item in iter {
        *counts.entry(item).or_insert(0) += 1;
    }

    // Handle the edge case of an empty iterator. Since the function must
    // return a String, we'll return an empty one.
    if counts.is_empty() {
        return String::new();
    }

    // Step 2: Find the maximum frequency.
    // The .unwrap() is safe here because we've already handled the empty case.
    let max_freq = *counts.values().max().unwrap();

    // Step 3: Collect all items that have the maximum frequency.
    // We use into_iter() to take ownership of the strings from the map.
    let modes: Vec<String> = counts
        .into_iter()
        .filter(|(_, count)| *count == max_freq)
        .map(|(item, _)| item)
        .collect();

    // Step 4: Determine the result.
    if modes.len() == 1 {
        // If there is a single unique mode, return it.
        // .into_iter().next().unwrap() efficiently moves the String out of the Vec.
        return modes.into_iter().next().unwrap();
    } else {
        // If there is a tie, use the provided list to resolve it.
        // For performance, convert the modes into a HashSet for quick lookups.
        let mode_set: Vec<String> = modes.into_iter().collect();

        // Iterate through the tie-breaker list.
        for item in &list {
            if mode_set.contains(item) {
                return (&item).to_string();
            }
        }
    }

    //should not get here
    String::from("N/A")
}

/// Maps a CVSS metric's full name to its single-letter abbreviation.
fn map_metric(metric: &str) -> Result<&'static str> {
    match metric {
        // Attack Vector (AV)
        "NETWORK" => Ok("N"),
        "ADJACENT" => Ok("A"),
        "LOCAL" => Ok("L"),
        "PHYSICAL" => Ok("P"),

        // Attack Complexity (AC) & Privileges Required (PR) & Impacts (VC, VI, etc.)
        "HIGH" => Ok("H"),
        "LOW" => Ok("L"),

        // Attack Requirements (AT)
        "PRESENT" => Ok("P"),
        "NONE" => Ok("N"),

        // User Interaction (UI)
        "ACTIVE" => Ok("A"),
        "PASSIVE" => Ok("P"),

        // Exploit Maturity (E)
        "NOT_DEFINED" => Ok("X"),
        "ATTACKED" => Ok("A"),
        "PROOF_OF_CONCEPT" => Ok("P"),
        "UNREPORTED" => Ok("U"),

        // Safety (S)
        "NEGLIGIBLE" => Ok("N"),

        // Automatable (AU)
        "YES" => Ok("Y"),
        "NO" => Ok("N"),

        // Provider Urgency (U)
        "RED" => Ok("RED"),
        "AMBER" => Ok("AMBER"),
        "GREEN" => Ok("GREEN"),
        "CLEAR" => Ok("CLEAR"),

        // Recovery (R)
        "AUTOMATIC" => Ok("A"),
        "USER" => Ok("U"),
        "IRRECOVERABLE" => Ok("I"),

        // Value Density (V)
        "DIFFUSE" => Ok("D"),
        "CONCENTRATED" => Ok("C"),

        // Vulnerability Response Effort (RE)
        "MODERATE" => Ok("M"),

        // C, I, and A Requirements (CR, IR, AR)
        "MEDIUM" => Ok("M"),

        // Modified Subsequent System Impacts
        "SAFETY" => Ok("S"),

        _ => Err(anyhow::anyhow!("Unknown CVSS metric value: {}", metric)),
    }
}

/// A tool to calculate CVSS scores from a vector string or a CVE identifier.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The CVSS vector string (e.g., "CVSS:4.0/AV:N/AC:L...") or a CVE ID (e.g., "CVE-2021-44228")
    input: String,

    /// Path to the STITCH database file
    #[arg(short, long, default_value = "stitch.db")]
    db: String,

    /// Verbose output of how the scoring is done
    #[arg(short, long)]
    pub verbose: bool,

    /// Export STIG checks as a CKLB JSON file (input should be comma-separated SV IDs)
    #[arg(short = 's', long)]
    pub cklb: bool,

    /// Export JSON of the RMF control information associated with a list of comma-separated CCIs
    #[arg(short = 'c', long)]
    pub ccis: bool,

    /// Export JSON of the RMF control information associated with a list of comma-separated RMF controls
    #[arg(short = 'r', long)]
    pub controls: bool,
}

fn export_stig_json(stig_ids: &str, db_path: &str) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database file: {}", db_path))?;

    // Lowercase both sides at comparison time. The previous
    // `replace("ULE", "ule").replace("R", "r")` normalization was a footgun:
    // any stray uppercase `R` in the ID body got silently lower-cased too.
    let ids: Vec<String> = stig_ids.split(',').map(str::to_ascii_lowercase).collect();

    let mut stmt_stig =
        conn.prepare("SELECT id, title, version, stigId, release, identifier FROM STIG")?;
    let stig_iterator = stmt_stig.query_map([], |row: &Row| {
        Ok(Stig {
            id: row.get(0)?,
            title: row.get(1)?,
            version: row.get(2)?,
            stig_id: row.get(3)?,
            release: row.get(4)?,
            identifier: row.get(5)?,
        })
    })?;

    let stigs: Vec<Stig> = stig_iterator.collect::<Result<Vec<Stig>, _>>()?;

    let mut result_stigs: Vec<serde_json::Value> = Vec::new();

    for stig in stigs {
        let stig_uuid = Uuid::new_v4().to_string();
        let mut result_checks: Vec<serde_json::Value> = Vec::new();

        let mut stmt_check = conn.prepare(
            "SELECT
					id,
					CheckContent,
					CheckSys,
					DISAId,
					Documentable,
					FalseNegatives,
					FalsePositives,
					FixText,
					IAControls,
					MitigationControl,
					Mitigations,
					PotentialImpacts,
					Reference,
					Responsibility,
					Severity,
					SeverityOverrideGuidance,
					ThirdPartyTools,
					Title,
					VULNGroupId,
					VULNId,
					Version,
					VulnDiscussion,
					Weight,
					CWEId,
					LegacyIds
				FROM STIGCheck
				WHERE STIGId = ?1",
        )?;

        let stigchecks: Vec<StigCheck> = stmt_check
            .query_map([stig.id], |row| {
                Ok(StigCheck {
                    id: row.get::<_, u32>(0)?,
                    check_content: row.get::<_, String>(1)?,
                    check_sys: row.get::<_, String>(2)?,
                    disa_id: row.get::<_, String>(3)?,
                    documentable: row.get::<_, Option<bool>>(4)?.unwrap_or_default(),
                    false_negatives: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    false_positives: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                    fix_text: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
                    ia_controls: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
                    mitigation_control: row.get::<_, Option<String>>(9)?.unwrap_or_default(),
                    mitigations: row.get::<_, Option<String>>(10)?.unwrap_or_default(),
                    potential_impacts: row.get::<_, Option<String>>(11)?.unwrap_or_default(),
                    reference: row.get::<_, Option<String>>(12)?.unwrap_or_default(),
                    responsibility: row.get::<_, Option<String>>(13)?.unwrap_or_default(),
                    stig_id: stig.id,
                    severity: row.get::<_, String>(14)?,
                    severity_override_guidance: row
                        .get::<_, Option<String>>(15)?
                        .unwrap_or_default(),
                    third_party_tools: row.get::<_, Option<String>>(16)?.unwrap_or_default(),
                    title: row.get::<_, String>(17)?,
                    vuln_group_id: row.get::<_, String>(18)?,
                    vuln_id: row.get::<_, String>(19)?,
                    version: row.get::<_, String>(20)?,
                    vuln_discussion: row.get::<_, Option<String>>(21)?.unwrap_or_default(),
                    weight: row.get::<_, f32>(22)?,
                    cwe_id: row.get::<_, u32>(23)?,
                    legacy_ids: row.get::<_, String>(24)?,
                })
            })?
            .filter_map(std::result::Result::ok)
            .collect(); // *** This is the crucial step: collecting the iterator into a Vec;

        for stigcheck in stigchecks {
            let mut legacy_ids: Vec<serde_json::Value> = Vec::new();
            for lid in stigcheck.legacy_ids.split(",") {
                legacy_ids.push(json!(lid));
            }

            let mut stmt_ccis =
                conn.prepare("SELECT CCIId FROM MapSTIGCheckCCI WHERE STIGCheckId = ?1")?;

            let ccis: Vec<serde_json::Value> = stmt_ccis
                .query_map([stigcheck.id], |row| {
                    Ok(json!(format!("CCI-{:06}", row.get::<_, u32>(0)?)))
                })?
                .filter_map(std::result::Result::ok)
                .collect();

            let disa_id_lc = stigcheck.disa_id.to_ascii_lowercase();
            let (status, finding_details) = if ids.iter().any(|id| disa_id_lc.starts_with(id)) {
                ("open".to_string(), "|organization| identified findings against this check.".to_string())
            } else {
                ("not_reviewed".to_string(), String::new())
            };

            let check = json!({
                "uuid": Uuid::new_v4().to_string(),
                "stig_uuid": stig_uuid,
                "target_key": null,
                "stig_ref": null,
                "group_id": stigcheck.vuln_id,
                "rule_id": stigcheck.disa_id.replace("_rule", ""),
                "rule_id_src": stigcheck.disa_id,
                "weight": format!("{:1}", stigcheck.weight),
                "classification": "Unclassified",
                "severity": stigcheck.severity,
                "rule_version": stigcheck.version,
                "group_title": stigcheck.title,
                "rule_title": stigcheck.title,
                "fix_text": stigcheck.fix_text,
                "false_positives": stigcheck.false_positives,
                "false_negatives": stigcheck.false_negatives,
                "discussion": stigcheck.vuln_discussion,
                "check_content": stigcheck.check_content,
                "documentable": stigcheck.documentable.to_string(),
                "mitigations": stigcheck.mitigations,
                "potential_impacts": stigcheck.potential_impacts,
                "third_party_tools": stigcheck.third_party_tools,
                "mitigation_control": stigcheck.mitigation_control,
                "responsibility": stigcheck.responsibility,
                "security_override_guidance": stigcheck.severity_override_guidance,
                "ia_controls": stigcheck.ia_controls,
                "check_content_ref": {
                    "href": format!("{}.xml", stig.stig_id),
                    "name": "M"
                },
                "legacy_ids": legacy_ids,
                "ccis": ccis,
                "group_tree": [
                    {
                        "id": stigcheck.vuln_id,
                        "title": stigcheck.vuln_group_id,
                        "description": "<GroupDescription></GroupDescription>"
                    }
                ],
                "createdAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "updatedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "STIGUuid": stig_uuid,
                "status": status,
                "overrides": {},
                "comments": "",
                "finding_details": finding_details,
                "srg_id": stigcheck.vuln_group_id
            });
            result_checks.push(check);
        }

        let result_stig = json!({
            "stig_name": stig.title,
            "display_name": stig.title.replace("Security Technical Implementation Guide", "").replace("Security Requirements Guide", ""),
            "stig_id": stig.stig_id,
            "release_info": stig.release,
            "version": stig.version,
            "uuid": stig_uuid,
            "reference_identifier": stig.identifier,
            "size": result_checks.len(),
            "rules": result_checks
        });

        result_stigs.push(result_stig);
    }

    let json = json!({
        "title": "|projName| Checklist",
        "id": Uuid::new_v4().to_string(),

        "stigs": result_stigs,
        "active": true,
        "mode": 1,
        "has_path": false,
        "target_data": {
            "target_type": "Computing",
            "host_name": "|projName|",
            "ip_address": "",
            "mac_address": "",
            "fqdn": "",
            "comments": "",
            "role": "None",
            "is_web_database": false,
            "technology_area": "",
            "web_db_site": "",
            "web_db_instance": "",
            "classification": null
        },
        "cklb_version": "1.0",
        "cklb_generator": "STITCH 0.1.0"
    });

    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let input = args.input.trim().to_uppercase();

    if args.cklb {
        if input.starts_with("SV-") {
            export_stig_json(&input, &args.db)?;
        } else {
            export_stig_json("", &args.db)?;
        }
    } else if args.ccis {
        let ccis: Vec<u32> = input
            .split(",")
            .map(|s| {
                s.to_ascii_uppercase()
                    .trim_start_matches("CCI-")
                    .parse::<u32>()
                    .unwrap_or(0)
            })
            .filter(|&id| id != 0)
            .collect();

        _ = get_controls_from_ccis(ccis, &args.db);
    } else if args.controls {
        let controls: Vec<String> = input.split(",").map(|s| s.to_ascii_uppercase()).collect();

        _ = get_controls_from_controls(controls, &args.db);
    } else if input.starts_with("CVSS:") {
        score_from_vector(&input, &args)?;
    } else if input.starts_with("CVE-") {
        score_from_cve(&input, &args.db, &args)?;
    } else if input.starts_with("CWE-") {
        score_from_cwe(&input, &args.db, &args)?;
    } else if input.starts_with("CWES") {
        score_cwes(&args.db, &args)?;
    } else if input.starts_with("SV-") {
        score_from_stig(&input, &args.db, &args)?;
    } else {
        anyhow::bail!(
            "Input must be a valid CVSS vector string (starting with 'CVSS:') or a CVE identifier (starting with 'CVE-') or a CWE (starting with 'CWE-')."
        );
    }

    Ok(())
}

/// Calculates and prints the score from a given CVSS vector string.
fn score_from_vector(vector: &str, args: &Args) -> Result<()> {
    if args.verbose {
        println!(); // Add a blank line for better formatting
    }

    if vector.starts_with("CVSS:4.0") {
        let base = Vector::from_str(vector).context("Failed to parse CVSS 4.0 vector string")?;
        if args.verbose {
            println!("CVSS 4.0 Vector: {}", vector);
            println!("Qualitative Severity: {}", base.score().severity());
            println!("Base Score: {:.1}", base.score().value());
        } else {
            println!("{:.1}", base.score().value());
        }
    } else if vector.starts_with("CVSS:3.1") || vector.starts_with("CVSS:3.0") {
        let base = Base::from_str(vector).context("Failed to parse CVSS 3.x vector string")?;
        if args.verbose {
            println!("CVSS 3.x Vector: {}", vector);
            println!("Qualitative Severity: {}", base.severity());
            println!("Base Score: {:.1}", base.score().value());
        } else {
            println!("{:.1}", base.score().value());
        }
    } else {
        anyhow::bail!("Unsupported CVSS version. Only 3.0, 3.1, and 4.0 are supported.");
    }
    Ok(())
}

/// Looks up a CVE in the database, constructs a CVSS 4.0 vector, and calculates the score.
fn score_from_cve(cve_id: &str, db_path: &str, args: &Args) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database file: {}", db_path))?;

    let mut stmt = conn.prepare(
        "SELECT
            id,
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
			providerUrgency,
			Recovery,
			valueDensity,
			vulnerabilityResponseEffort,
			scoreVersion
        FROM Vulnerability
        WHERE NVDId = ?1",
    )?;

    // Query the database for the CVE's metrics
    let cve_data = stmt
        .query_row(params![cve_id.to_uppercase()], |row| {
            Ok((
                row.get::<_, u32>(0)?,     // id
                row.get::<_, String>(1)?,  // AV
                row.get::<_, String>(2)?,  // AC
                row.get::<_, String>(3)?,  // AT
                row.get::<_, String>(4)?,  // PR
                row.get::<_, String>(5)?,  // UI
                row.get::<_, String>(6)?,  // VC
                row.get::<_, String>(7)?,  // VI
                row.get::<_, String>(8)?,  // VA
                row.get::<_, String>(9)?,  // SC
                row.get::<_, String>(10)?, // SI
                row.get::<_, String>(11)?, // SA
                row.get::<_, String>(12)?, // E
                row.get::<_, String>(13)?, // CR
                row.get::<_, String>(14)?, // IR
                row.get::<_, String>(15)?, // AR
                row.get::<_, String>(16)?, // MAV
                row.get::<_, String>(17)?, // MAC
                row.get::<_, String>(18)?, // MAT
                row.get::<_, String>(19)?, // MPR
                row.get::<_, String>(20)?, // MUI
                row.get::<_, String>(21)?, // MVC
                row.get::<_, String>(22)?, // MVI
                row.get::<_, String>(23)?, // MVA
                row.get::<_, String>(24)?, // MSC
                row.get::<_, String>(25)?, // MSI
                row.get::<_, String>(26)?, // MSA
                row.get::<_, String>(27)?, // S
                row.get::<_, String>(28)?, // AU
                row.get::<_, String>(29)?, // U
                row.get::<_, String>(30)?, // R
                row.get::<_, String>(31)?, // V
                row.get::<_, String>(32)?, // RE
                row.get::<_, u32>(33)?,    // score version
            ))
        })
        .with_context(|| format!("Could not find CVE '{}' in the database.", cve_id))?;

    // Map the database's full metric names to their CVSS 4.0 single-letter abbreviations
    let vector_string = format!(
        "CVSS:4.0/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/VC:{}/VI:{}/VA:{}/SC:{}/SI:{}/SA:{}", // /CR:{}/IR:{}/AR:{}/MAV:{}/MAC:{}/MAT:{}/MPR:{}/MUI:{}/MVC:{}/MVI:{}/MVA:{}/MSC:{}/MSI:{}/MSA:{}/S:{}/AU:{}/U:{}/R:{}/V:{}/RE:{}",
        map_metric(&cve_data.1)?,
        map_metric(&cve_data.2)?,
        map_metric(&cve_data.3)?,
        map_metric(&cve_data.4)?,
        map_metric(&cve_data.5)?,
        map_metric(&cve_data.6)?,
        map_metric(&cve_data.7)?,
        map_metric(&cve_data.8)?,
        map_metric(&cve_data.9)?,
        map_metric(&cve_data.10)?,
        map_metric(&cve_data.11)?,
        /*map_metric(&cve_data.12)?,
        map_metric(&cve_data.13)?,
        map_metric(&cve_data.14)?,
        map_metric(&cve_data.15)?,
        map_metric(&cve_data.16)?,
        map_metric(&cve_data.17)?,
        map_metric(&cve_data.18)?,
        map_metric(&cve_data.19)?,
        map_metric(&cve_data.20)?,
        map_metric(&cve_data.21)?,
        map_metric(&cve_data.22)?,
        map_metric(&cve_data.23)?,
        map_metric(&cve_data.24)?,
        map_metric(&cve_data.25)?,
        map_metric(&cve_data.26)?,
        map_metric(&cve_data.27)?,
        map_metric(&cve_data.28)?,
        map_metric(&cve_data.29)?,
        map_metric(&cve_data.30)?,
        map_metric(&cve_data.31)?,
        map_metric(&cve_data.32)?*/
    );

    if args.verbose {
        println!(
            "Found CVE: {} using CVSS Version {}. Constructing CVSS 4.0 vector from database: {}.",
            cve_id, cve_data.33, vector_string
        );
    }

    let cwe_data: Vec<CWEDetails> = {
        let mut stmt_cwe = conn.prepare(
            "SELECT
				Weakness.id,
                Weakness.name,
                abstraction,
                category,
                view,
                confidentiality,
                integrity,
                availability,
                DISAId,
                Severity,
                number,
                RMFCCI.id
            FROM Weakness JOIN STIGCheck ON STIGCheck.id = Weakness.STIGCheckId
            JOIN MapSTIGCheckCCI ON STIGCheck.id = MapSTIGCheckCCI.STIGCheckId
            JOIN RMFCCI ON MapSTIGCheckCCI.CCIId = RMFCCI.id
            JOIN RMFControl ON RMFCCI.RMFControlId = RMFControl.id
            WHERE Weakness.id IN (SELECT WeaknessId FROM MapVulnerabilityWeakness WHERE VulnerabilityId = ?1 ORDER BY `Primary` DESC)",
        )?;

        let cwe_data_elements = stmt_cwe.query_map(params![cve_data.0], |row| {
            let id = row.get::<_, u32>(0);
            let name = row.get::<_, Option<String>>(1);
            let abstraction = row.get::<_, Option<String>>(2);
            let category = row.get::<_, bool>(3);
            let view = row.get::<_, bool>(4);
            let confidentiality = row.get::<_, bool>(5);
            let integrity = row.get::<_, bool>(6);
            let availability = row.get::<_, bool>(7);
            let disaid = row.get::<_, Option<String>>(8);
            let severity = row.get::<_, Option<String>>(9);
            let control = row.get::<_, Option<String>>(10);
            let cci = row.get::<_, u32>(11);
            Ok(CWEDetails {
                id: id?,
                name: name?.unwrap_or_default(),
                abstraction: abstraction?.unwrap_or_default(),
                category: category?,
                view: view?,
                confidentiality: confidentiality?,
                integrity: integrity?,
                availability: availability?,
                disaid: disaid?.unwrap_or_default(),
                severity: severity?.unwrap_or_default(),
                control: control?.unwrap_or_default(),
                cci: format!("CCI-{}", cci?),
            })
        })?;

        let mut success_count = 0;
        let mut error_count = 0;
        let cwe_data_result: Vec<CWEDetails> = cwe_data_elements
            .filter_map(|r| match r {
                Ok(v) => { success_count += 1; Some(v) },
                Err(_e) => { error_count += 1; /*eprintln!("DEBUG: Row error: {}", e);*/ None },
            })
            .collect();
        //eprintln!("DEBUG: CWE query returned {} successes, {} errors, total rows = {}", success_count, error_count, cwe_data_result.len());

        cwe_data_result
    };

    let details: CWEDetails = if cwe_data.is_empty() {
        CWEDetails {
            id: 710,
            name: "Improper Adherence to Coding Standards".to_string(),
            abstraction: "Pillar".to_string(),
            category: false,
            view: false,
            confidentiality: false,
            integrity: false,
            availability: false,
            disaid: "SV-222653r961863_rule".to_string(),
            severity: "low".to_string(),
            control: "SA-15".to_string(),
            cci: "CCI-3233".to_string(),
        }
    } else {
        cwe_data.first().unwrap().clone()
    };

    print!(
        "{},\"{}\",{},{},{},{},\"{}\",\"{}\",",
        details.id,
        details.name,
        details.abstraction,
        vector_string,
        details.disaid,
        details.severity,
        details.control,
        details.cci
    );
    score_from_vector(&vector_string, args)?;

    Ok(())
}

fn score_cwes(db_path: &str, args: &Args) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database file: {}", db_path))?;

    let mut stmt = conn.prepare(
        "SELECT
			id,
			name,
            category,
			view
        FROM Weakness",
    )?;

    let cwes = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,    //id
                row.get::<_, String>(1)?, //name
                row.get::<_, bool>(2)?,   //category
                row.get::<_, bool>(3)?,   //view
            ))
        })
        .with_context(|| "Could not get CWEs from the database.".to_string())?;

    if !args.verbose {
        println!("CWE,Title,Abstraction,Vector,ASD STIG,STIG Severity,Control,CCI,Score");
    }

    for cwe in cwes {
        let cwe = cwe?;
        let cwe_id = format!("CWE-{}", cwe.0);
        if args.verbose {
            println!("\n=== Scoring {} {} ===", cwe_id, cwe.1);
        }
        if cwe.2 {
            if args.verbose {
                println!("Categories cannot be scored.");
            }
            continue;
        }

        if cwe.3 {
            if args.verbose {
                println!("Views cannot be scored.");
            }
            continue;
        }

        if cwe.1.starts_with("DEPRECATED") {
            if args.verbose {
                println!("Deprecated CWEs cannot be scored.");
            }
            continue;
        }

        score_from_cwe(&cwe_id, db_path, args)?;
    }

    Ok(())
}

/// Fetches CVSS information for vulnerabilities given a weakness ID and score version.
fn get_cve_data_by_weakness(
    conn: &Connection,
    score_version: u32,
    weakness_id: u32,
) -> Result<Vec<CvssDataV40>> {
    let mut stmt = conn.prepare(
        "SELECT
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
		NVDId
    FROM Vulnerability 
    WHERE id IN (SELECT VulnerabilityId FROM MapVulnerabilityWeakness WHERE WeaknessId = ?2 AND `Primary` = 1)
		AND scoreVersion = ?1",
    )?;

    let cve_iter = stmt.query_map(params![score_version, weakness_id], |row| {
        Ok(CvssDataV40 {
            attack_vector: row.get(0)?,
            attack_complexity: row.get(1)?,
            attack_requirements: row.get(2)?,
            privileges_required: row.get(3)?,
            user_interaction: row.get(4)?,
            vuln_confidentiality_impact: row.get(5)?,
            vuln_integrity_impact: row.get(6)?,
            vuln_availability_impact: row.get(7)?,
            sub_confidentiality_impact: row.get(8)?,
            sub_integrity_impact: row.get(9)?,
            sub_availability_impact: row.get(10)?,
            exploit_maturity: row.get(11)?,
            confidentiality_requirement: row.get(12)?,
            integrity_requirement: row.get(13)?,
            availability_requirement: row.get(14)?,
            modified_attack_vector: row.get(15)?,
            modified_attack_complexity: row.get(16)?,
            modified_attack_requirements: row.get(17)?,
            modified_privileges_required: row.get(18)?,
            modified_user_interaction: row.get(19)?,
            modified_vuln_confidentiality_impact: row.get(20)?,
            modified_vuln_integrity_impact: row.get(21)?,
            modified_vuln_availability_impact: row.get(22)?,
            modified_sub_confidentiality_impact: row.get(23)?,
            modified_sub_integrity_impact: row.get(24)?,
            modified_sub_availability_impact: row.get(25)?,
            safety: row.get(26)?,
            automatable: row.get(27)?,
            provider_urgency: row.get(28)?,
            recovery: row.get(29)?,
            value_density: row.get(30)?,
            vulnerability_response_effort: row.get(31)?,
            // --- Hardcoded values from your original example ---
            version: format!("{}.0", score_version),
            base_score: 0.0,
            base_severity: "".to_string(),
            vector_string: row.get(32)?,
        })
    })?;

    // Collect the results into a Vec.
    let results = cve_iter.collect::<Result<Vec<CvssDataV40>, rusqlite::Error>>()?;

    Ok(results)
}

/// Fetches child CWEs given a weakness ID in a given View.
fn get_child_cwes(conn: &Connection, weakness_id: u32, view_id: u32) -> Result<Vec<u32>> {
    let mut stmt = conn.prepare(
        "SELECT source_id FROM WeaknessRelationship WHERE target_id = ?1 AND view_id = ?2",
    )?;

    let cwe_iter = stmt.query_map(params![weakness_id, view_id], |row| row.get(0))?;

    // Collect the results into a Vec.
    let results = cwe_iter.collect::<Result<Vec<u32>, rusqlite::Error>>()?;

    Ok(results)
}

/// Fetches parent CWEs given a weakness ID in a given View.
fn get_parent_cwes(conn: &Connection, weakness_id: u32, view_id: u32) -> Result<Vec<u32>> {
    let mut stmt = conn.prepare(
        "SELECT target_id FROM WeaknessRelationship WHERE source_id = ?1 AND view_id = ?2",
    )?;

    let cwe_iter = stmt.query_map(params![weakness_id, view_id], |row| row.get(0))?;

    // Collect the results into a Vec.
    let results = cwe_iter.collect::<Result<Vec<u32>, rusqlite::Error>>()?;

    Ok(results)
}

#[derive(Debug, Clone)]
struct CWEDetails {
    id: u32,
    name: String,
    abstraction: String,
    category: bool,
    view: bool,
    confidentiality: bool,
    integrity: bool,
    availability: bool,
    disaid: String,
    severity: String,
    control: String,
    cci: String,
}

/// Looks up a CVE in the database, constructs a CVSS 4.0 vector, and calculates the score.
fn score_from_stig(stig_id: &str, db_path: &str, args: &Args) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database file: {}", db_path))?;

    // Use case-insensitive LIKE with the prefix escaped, so a literal `_` in
    // the rule ID is matched as `_` not as a single-char wildcard, and the
    // user can type the ID in either case.
    let stig_id_pattern = stitch::common::escape_like(stig_id);

    let stig_data: Vec<CWEDetails> = {
        let mut stmt_stig = conn.prepare(
            "SELECT
			Weakness.id,
			Weakness.name,
			abstraction,
            category,
			view,
			confidentiality,
			integrity,
			availability,
			DISAId,
			Severity,
			number,
			RMFCCI.id
        FROM STIGCheck JOIN Weakness ON Weakness.id = STIGCheck.CWEId
		JOIN MapSTIGCheckCCI ON STIGCheck.id = MapSTIGCheckCCI.STIGCheckId
		JOIN RMFCCI ON MapSTIGCheckCCI.CCIId = RMFCCI.id
		JOIN RMFControl ON RMFCCI.RMFControlId = RMFControl.id
        WHERE STIGCheck.DISAId LIKE (?1 || '%') ESCAPE '\\' COLLATE NOCASE",
        )?;

        let stig_data_elements = stmt_stig.query_map(params![stig_id_pattern], |row| {
            Ok(CWEDetails {
                id: row.get::<_, u32>(0)?,               //id
                name: row.get::<_, Option<String>>(1)?.unwrap_or_default(),      //name
                abstraction: row.get::<_, Option<String>>(2)?.unwrap_or_default(), //abstraction
                category: row.get::<_, bool>(3)?,        //category
                view: row.get::<_, bool>(4)?,            //view
                confidentiality: row.get::<_, bool>(5)?, //confidentiality
                integrity: row.get::<_, bool>(6)?,       //integrity
                availability: row.get::<_, bool>(7)?,    //availability
                disaid: row.get::<_, Option<String>>(8)?.unwrap_or_default(), //DISAId
                severity: row.get::<_, Option<String>>(9)?.unwrap_or_default(), //severity
                control: row.get::<_, Option<String>>(10)?.unwrap_or_default(),      //RMF Control
                cci: row.get::<_, u32>(11)?.to_string(), //CCI
            })
        })?;

        let stig_data_result: rusqlite::Result<Vec<CWEDetails>> = stig_data_elements.collect();

        stig_data_result.with_context(|| "No records found in the database.")?
    }; // `stmt_cwe` and `cwe_data_elements` are dropped here, releasing the borrow on `conn`.

    score_from(conn, stig_data, args)
}

/// Looks up a CVE in the database, constructs a CVSS 4.0 vector, and calculates the score.
fn score_from_cwe(cwe_id: &str, db_path: &str, args: &Args) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database file: {}", db_path))?;

    let cwe_num_id: u32 = cwe_id.to_uppercase().trim_start_matches("CWE-").parse()?;

    let cwe_data: Vec<CWEDetails> = {
        let mut stmt_cwe = conn.prepare(
            "SELECT
				Weakness.id,
                Weakness.name,
                abstraction,
                category,
                view,
                confidentiality,
                integrity,
                availability,
                DISAId,
                Severity,
                number,
                RMFCCI.id
            FROM Weakness JOIN STIGCheck ON STIGCheck.id = Weakness.STIGCheckId
            JOIN MapSTIGCheckCCI ON STIGCheck.id = MapSTIGCheckCCI.STIGCheckId
            JOIN RMFCCI ON MapSTIGCheckCCI.CCIId = RMFCCI.id
            JOIN RMFControl ON RMFCCI.RMFControlId = RMFControl.id
            WHERE Weakness.id = ?1",
        )?;

        let cwe_data_elements = stmt_cwe.query_map(params![cwe_num_id], |row| {
            Ok(CWEDetails {
                id: row.get::<_, u32>(0)?,               //id
                name: row.get::<_, Option<String>>(1)?.unwrap_or_default(),      //name
                abstraction: row.get::<_, Option<String>>(2)?.unwrap_or_default(), //abstraction
                category: row.get::<_, bool>(3)?,        //category
                view: row.get::<_, bool>(4)?,            //view
                confidentiality: row.get::<_, bool>(5)?, //confidentiality
                integrity: row.get::<_, bool>(6)?,       //integrity
                availability: row.get::<_, bool>(7)?,    //availability
                disaid: row.get::<_, Option<String>>(8)?.unwrap_or_default(), //DISAId
                severity: row.get::<_, Option<String>>(9)?.unwrap_or_default(), //severity
                control: row.get::<_, Option<String>>(10)?.unwrap_or_default(),      //RMF Control
                cci: row.get::<_, u32>(11)?.to_string(), //CCI
            })
        })?;

        let cwe_data_result: rusqlite::Result<Vec<CWEDetails>> = cwe_data_elements.collect();

        cwe_data_result.with_context(|| "No records found in the database.")?
    }; // `stmt_cwe` and `cwe_data_elements` are dropped here, releasing the borrow on `conn`.

    score_from(conn, cwe_data, args)
}

/// Looks up a CVE in the database, constructs a CVSS 4.0 vector, and calculates the score.
fn score_from(conn: Connection, mut cwe_data: Vec<CWEDetails>, args: &Args) -> Result<()> {
    if cwe_data.is_empty() {
        eprintln!("Invalid CWE data provided");
        return Ok(());
    }

    let (cwe_data_flatened, rest_of_data) = cwe_data
        .split_first_mut()
        .expect("cwe_data vector should not be empty at this point.");

    cwe_data_flatened.cci.insert_str(0, "CCI-");

    for element in rest_of_data.iter_mut() {
        if !cwe_data_flatened.control.contains(&element.control) {
            cwe_data_flatened.control.push(',');
            cwe_data_flatened.control.push_str(&element.control);
        }
        cwe_data_flatened.cci.push(',');
        cwe_data_flatened.cci.push_str(&element.cci)
    }

    if args.verbose {
        println!("Found CWE: CWE-{}", cwe_data_flatened.id);
    }

    if cwe_data_flatened.category {
        if args.verbose {
            println!("Categories cannot be scored.");
        }
        return Ok(());
    }

    if cwe_data_flatened.view {
        if args.verbose {
            println!("Views cannot be scored.");
        }
        return Ok(());
    }

    if cwe_data_flatened.name.starts_with("DEPRECATED") {
        if args.verbose {
            println!("Deprecated CWEs cannot be scored.");
        }
        return Ok(());
    }

    // ROUND 1: Direct NVD Scores
    if args.verbose {
        println!("Starting Round 1 Scoring.");
    }

    // ROUND 1.1: Direct CVSS 4.0 scores
    // Find direct instances of this CWE in the Vulnerability table

    let mut cves: Vec<CvssDataV40> = get_cve_data_by_weakness(&conn, 4, cwe_data_flatened.id)?;

    if args.verbose {
        println!("1.1: Found {} CVSS 4.0 CVEs.", cves.len());
    }

    // ROUND 1.2: Conversion of direct CVSS 3.0 and 3.1 scores
    if cves.len() < MINIMUM_CVES_TO_COMPLETE_ROUND {
        let tmp_cves: Vec<CvssDataV40> = get_cve_data_by_weakness(&conn, 3, cwe_data_flatened.id)?;

        if args.verbose {
            println!("1.2: Found {} CVSS 3 and 3.1 CVEs.", tmp_cves.len());
        }
        cves.extend(tmp_cves);
    }

    // ROUND 1.3: Conversion of direct CVSS 2.0 scores
    if cves.len() < MINIMUM_CVES_TO_COMPLETE_ROUND {
        let tmp_cves: Vec<CvssDataV40> = get_cve_data_by_weakness(&conn, 2, cwe_data_flatened.id)?;
        if args.verbose {
            println!("1.3: Found {} CVSS 2.0 CVEs.", tmp_cves.len());
        }
        cves.extend(tmp_cves);
    }

    let mut processed_cwes: HashSet<u32> = HashSet::new();

    // ROUND 2: Progeny CWEs of View 1000
    // Iterate one generation at a time until there are enough CVEs to score.
    if cves.len() < MINIMUM_CVES_TO_SCORE {
        if args.verbose {
            println!("Starting Round 2 Scoring.");
        }
        let mut next_generation_cwes: Vec<u32> = get_child_cwes(&conn, cwe_data_flatened.id, 1000)?;
        next_generation_cwes.sort();
        next_generation_cwes.dedup();
        next_generation_cwes.retain(|x| !processed_cwes.contains(x));

        while !next_generation_cwes.is_empty() {
            // ROUND 2.1: Child CWEs of View 1000 CVSS 4.0 scores
            for child in &next_generation_cwes {
                let tmp_cves: Vec<CvssDataV40> = get_cve_data_by_weakness(&conn, 4, *child)?;
                if args.verbose {
                    println!("2.1: Found {} CVSS 4.0 CVEs.", tmp_cves.len());
                }
                cves.extend(tmp_cves);
            }

            if cves.len() < MINIMUM_CVES_TO_COMPLETE_ROUND {
                // ROUND 2.2: Child CWEs of View 1000 CVSS 3.1 and 3.0 scores
                for child in &next_generation_cwes {
                    let tmp_cves: Vec<CvssDataV40> = get_cve_data_by_weakness(&conn, 3, *child)?;
                    if args.verbose {
                        println!("2.2: Found {} CVSS 3.0 and 3.1 CVEs.", tmp_cves.len());
                    }
                    cves.extend(tmp_cves);
                }
            }

            if cves.len() < MINIMUM_CVES_TO_COMPLETE_ROUND {
                // ROUND 2.3: Child CWEs of View 1000 CVSS 2 scores
                for child in &next_generation_cwes {
                    let tmp_cves: Vec<CvssDataV40> = get_cve_data_by_weakness(&conn, 2, *child)?;
                    if args.verbose {
                        println!("2.3: Found {} CVSS 2 CVEs.", tmp_cves.len());
                    }
                    cves.extend(tmp_cves);
                }
            }

            // Iterate the next round of children if there are any
            processed_cwes.extend(next_generation_cwes.clone());
            if cves.len() < MINIMUM_CVES_TO_SCORE {
                let mut tmp_next_generation_cwes: Vec<u32> = Vec::new();
                for n in &next_generation_cwes {
                    let child_cwes: Vec<u32> = get_child_cwes(&conn, *n, 1000)?;
                    tmp_next_generation_cwes.extend(child_cwes);
                }
                tmp_next_generation_cwes.sort();
                tmp_next_generation_cwes.dedup();
                tmp_next_generation_cwes.retain(|x| !processed_cwes.contains(x));
                next_generation_cwes = tmp_next_generation_cwes;
            } else {
                next_generation_cwes.clear();
            }
        }
    }

    // ROUND 3: Ancestor and Cousin CWEs of View 1000.
    // For each ancestor generation: process the ancestors themselves (steps
    // 3.1-3.3); if still short of MINIMUM_CVES_TO_SCORE, process those
    // ancestors' children (cousins of the original CWE) at steps 3.4-3.6.
    // Then iterate one generation deeper.
    if cves.len() < MINIMUM_CVES_TO_SCORE {
        if args.verbose {
            println!("Starting Round 3 Scoring.");
        }
        let mut prev_generation_cwes: Vec<u32> =
            get_parent_cwes(&conn, cwe_data_flatened.id, 1000)?;
        prev_generation_cwes.sort();
        prev_generation_cwes.dedup();
        prev_generation_cwes.retain(|x| !processed_cwes.contains(x));

        while !prev_generation_cwes.is_empty() {
            // ROUND 3.1: Parent/Ancestor CWEs of View 1000 CVSS 4.0 scores
            for parent in &prev_generation_cwes {
                let tmp_cves: Vec<CvssDataV40> = get_cve_data_by_weakness(&conn, 4, *parent)?;
                if args.verbose {
                    println!("3.1: Found {} CVSS 4.0 CVEs.", tmp_cves.len());
                }
                cves.extend(tmp_cves);
            }

            if cves.len() < MINIMUM_CVES_TO_COMPLETE_ROUND {
                // ROUND 3.2: Parent/Ancestor CWEs of View 1000 CVSS 3.1 and 3.0 scores
                for parent in &prev_generation_cwes {
                    let tmp_cves: Vec<CvssDataV40> = get_cve_data_by_weakness(&conn, 3, *parent)?;
                    if args.verbose {
                        println!("3.2: Found {} CVSS 3.0 and 3.1 CVEs.", tmp_cves.len());
                    }
                    cves.extend(tmp_cves);
                }
            }

            if cves.len() < MINIMUM_CVES_TO_COMPLETE_ROUND {
                // ROUND 3.3: Parent/Ancestor CWEs of View 1000 CVSS 2 scores
                for parent in &prev_generation_cwes {
                    let tmp_cves: Vec<CvssDataV40> = get_cve_data_by_weakness(&conn, 2, *parent)?;
                    if args.verbose {
                        println!("3.3: Found {} CVSS 2 CVEs.", tmp_cves.len());
                    }
                    cves.extend(tmp_cves);
                }
            }

            processed_cwes.extend(prev_generation_cwes.clone());

            if cves.len() < MINIMUM_CVES_TO_SCORE {
                let mut sibling_cwes: Vec<u32> = Vec::new();
                // ROUND 3.4: Cousin CWEs of View 1000 CVSS 4.0 scores
                for parent in &prev_generation_cwes {
                    sibling_cwes.extend(get_child_cwes(&conn, *parent, 1000)?);
                    sibling_cwes.sort();
                    sibling_cwes.dedup();
                    sibling_cwes.retain(|x| !processed_cwes.contains(x));
                }

                processed_cwes.extend(sibling_cwes.clone());

                for sibling in &sibling_cwes {
                    let tmp_cves: Vec<CvssDataV40> = get_cve_data_by_weakness(&conn, 4, *sibling)?;
                    if args.verbose {
                        println!("3.4: Found {} CVSS 4.0 CVEs.", tmp_cves.len());
                    }
                    cves.extend(tmp_cves);
                }

                if cves.len() < MINIMUM_CVES_TO_COMPLETE_ROUND {
                    // ROUND 3.5: Cousin CWEs of View 1000 CVSS 3.0 and 3.1 scores
                    for sibling in &sibling_cwes {
                        let tmp_cves: Vec<CvssDataV40> =
                            get_cve_data_by_weakness(&conn, 3, *sibling)?;
                        if args.verbose {
                            println!("3.5: Found {} CVSS 3.0 and 3.1 CVEs.", tmp_cves.len());
                        }
                        cves.extend(tmp_cves);
                    }
                }

                if cves.len() < MINIMUM_CVES_TO_COMPLETE_ROUND {
                    // ROUND 3.6: Cousin CWEs of View 1000 CVSS 2.0 scores
                    for sibling in sibling_cwes {
                        let tmp_cves: Vec<CvssDataV40> =
                            get_cve_data_by_weakness(&conn, 2, sibling)?;
                        if args.verbose {
                            println!("3.6: Found {} CVSS 2.0 CVEs.", tmp_cves.len());
                        }
                        cves.extend(tmp_cves);
                    }
                }
            }

            // Iterate the next round of ancestors if there are any
            if cves.len() < MINIMUM_CVES_TO_SCORE {
                let mut tmp_prev_generation_cwes: Vec<u32> = Vec::new();
                for p in &prev_generation_cwes {
                    let parent_cwes: Vec<u32> = get_parent_cwes(&conn, *p, 1000)?;
                    tmp_prev_generation_cwes.extend(parent_cwes);
                }
                tmp_prev_generation_cwes.sort();
                tmp_prev_generation_cwes.dedup();
                tmp_prev_generation_cwes.retain(|x| !processed_cwes.contains(x));
                prev_generation_cwes = tmp_prev_generation_cwes;
            } else {
                prev_generation_cwes.clear();
            }
        }
    }

    if cves.len() < MINIMUM_CVES_TO_SCORE {
        if args.verbose {
            println!(
                "Unable to score with fewer than {} CVEs.",
                MINIMUM_CVES_TO_SCORE
            );
        } else {
            println!(
                "{},\"{}\",{},N/A,{},{},\"{}\",\"{}\",{:.1}",
                cwe_data_flatened.id,
                cwe_data_flatened.name,
                cwe_data_flatened.abstraction,
                cwe_data_flatened.disaid,
                cwe_data_flatened.severity,
                cwe_data_flatened.control,
                cwe_data_flatened.cci,
                0.0
            );
        }
        return Ok(());
    }

    if args.verbose {
        println!("Scoring with {} CVEs in memory.", cves.len());
        // List CVEs used in scoring
        let mut tmp_cves: Vec<String> = cves.iter().map(|c| c.vector_string.clone()).collect();
        tmp_cves.sort();
        for cve in &tmp_cves {
            println!("CVE: {}", cve);
        }
    }

    let temp_cvss4 = CvssDataV40 {
        attack_vector: mode(
            cves.iter().map(|c| c.attack_vector.clone()),
            vec![
                "NETWORK".to_string(),
                "ADJACENT".to_string(),
                "LOCAL".to_string(),
                "PHYSICAL".to_string(),
            ],
        ),
        attack_complexity: mode(
            cves.iter().map(|c| c.attack_complexity.clone()),
            vec!["LOW".to_string(), "HIGH".to_string()],
        ),
        attack_requirements: mode(
            cves.iter().map(|c| c.attack_requirements.clone()),
            vec!["NONE".to_string(), "PRESENT".to_string()],
        ),
        privileges_required: mode(
            cves.iter().map(|c| c.privileges_required.clone()),
            vec!["NONE".to_string(), "LOW".to_string(), "HIGH".to_string()],
        ),
        user_interaction: mode(
            cves.iter().map(|c| c.user_interaction.clone()),
            vec![
                "NONE".to_string(),
                "PASSIVE".to_string(),
                "ACTIVE".to_string(),
            ],
        ),
        vuln_confidentiality_impact: mean_impact(
            cves.iter().map(|c| c.vuln_confidentiality_impact.clone()),
            cwe_data_flatened.confidentiality,
        ),
        vuln_integrity_impact: mean_impact(
            cves.iter().map(|c| c.vuln_integrity_impact.clone()),
            cwe_data_flatened.integrity,
        ),
        vuln_availability_impact: mean_impact(
            cves.iter().map(|c| c.vuln_availability_impact.clone()),
            cwe_data_flatened.availability,
        ),
        sub_confidentiality_impact: mean_impact(
            cves.iter().map(|c| c.sub_confidentiality_impact.clone()),
            true,
        ),
        sub_integrity_impact: mean_impact(
            cves.iter().map(|c| c.sub_integrity_impact.clone()),
            true,
        ),
        sub_availability_impact: mean_impact(
            cves.iter().map(|c| c.sub_availability_impact.clone()),
            true,
        ),
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
        provider_urgency: "NOT_DEFINED".to_string(),
        recovery: "NOT_DEFINED".to_string(),
        value_density: "NOT_DEFINED".to_string(),
        vulnerability_response_effort: "NOT_DEFINED".to_string(),
        // Environmental metrics and modified metrics are obtained from the program, not from the NVD.
        /*exploit_maturity: mode(cves.iter().map(|c| c.exploit_maturity.clone()), vec!["ATTACKED".to_string(), "PROOF_OF_CONCEPT".to_string(), "UNREPORTED".to_string(), "NOT_DEFINED".to_string()]),
        confidentiality_requirement: mode(cves.iter().map(|c| c.confidentiality_requirement.clone()), vec!["HIGH".to_string(), "MEDIUM".to_string(), "LOW".to_string(), "NOT_DEFINED".to_string()]),
        integrity_requirement: mode(cves.iter().map(|c| c.integrity_requirement.clone()), vec!["HIGH".to_string(), "MEDIUM".to_string(), "LOW".to_string(), "NOT_DEFINED".to_string()]),
        availability_requirement: mode(cves.iter().map(|c| c.availability_requirement.clone()), vec!["HIGH".to_string(), "MEDIUM".to_string(), "LOW".to_string(), "NOT_DEFINED".to_string()]),
        modified_attack_vector: mode(cves.iter().map(|c| c.modified_attack_vector.clone()), vec!["NETWORK".to_string(), "ADJACENT".to_string(), "LOCAL".to_string(), "PHYSICAL".to_string(), "NOT_DEFINED".to_string()]),
        modified_attack_complexity: mode(cves.iter().map(|c| c.modified_attack_complexity.clone()), vec!["LOW".to_string(), "HIGH".to_string(), "NOT_DEFINED".to_string()]),
        modified_attack_requirements: mode(cves.iter().map(|c| c.modified_attack_requirements.clone()), vec!["NONE".to_string(), "PRESENT".to_string(), "NOT_DEFINED".to_string()]),
        modified_privileges_required: mode(cves.iter().map(|c| c.modified_privileges_required.clone()), vec!["NONE".to_string(), "LOW".to_string(), "HIGH".to_string(), "NOT_DEFINED".to_string()]),
        modified_user_interaction: mode(cves.iter().map(|c| c.modified_user_interaction.clone()), vec!["NONE".to_string(), "PASSIVE".to_string(), "ACTIVE".to_string(), "NOT_DEFINED".to_string()]),
        modified_vuln_confidentiality_impact: mode(cves.iter().map(|c| c.modified_vuln_confidentiality_impact.clone()), vec!["HIGH".to_string(), "LOW".to_string(), "NONE".to_string(), "NOT_DEFINED".to_string()]),
        modified_vuln_integrity_impact: mode(cves.iter().map(|c| c.modified_vuln_integrity_impact.clone()), vec!["HIGH".to_string(), "LOW".to_string(), "NONE".to_string(), "NOT_DEFINED".to_string()]),
        modified_vuln_availability_impact: mode(cves.iter().map(|c| c.modified_vuln_availability_impact.clone()), vec!["HIGH".to_string(), "LOW".to_string(), "NONE".to_string(), "NOT_DEFINED".to_string()]),
        modified_sub_confidentiality_impact: mode(cves.iter().map(|c| c.modified_sub_confidentiality_impact.clone()), vec!["HIGH".to_string(), "LOW".to_string(), "NONE".to_string(), "NOT_DEFINED".to_string()]),
        modified_sub_integrity_impact: mode(cves.iter().map(|c| c.modified_sub_integrity_impact.clone()), vec!["HIGH".to_string(), "LOW".to_string(), "NONE".to_string(), "NOT_DEFINED".to_string()]),
        modified_sub_availability_impact: mode(cves.iter().map(|c| c.modified_sub_availability_impact.clone()), vec!["HIGH".to_string(), "LOW".to_string(), "NONE".to_string(), "NOT_DEFINED".to_string()]),
        safety: mode(cves.iter().map(|c| c.safety.clone()), vec!["PRESENT".to_string(), "NEGLIGIBLE".to_string(), "NOT_DEFINED".to_string()]),
        automatable: mode(cves.iter().map(|c| c.automatable.clone()), vec!["YES".to_string(), "NO".to_string(), "NOT_DEFINED".to_string()]),
        provider_urgency: mode(cves.iter().map(|c| c.provider_urgency.clone()), vec!["RED".to_string(), "AMBER".to_string(), "GREEN".to_string(), "CLEAR".to_string(), "NOT_DEFINED".to_string()]),
        recovery: mode(cves.iter().map(|c| c.recovery.clone()), vec!["AUTOMATIC".to_string(), "USER".to_string(), "IRRECOVERABLE".to_string(), "NOT_DEFINED".to_string()]),
        value_density: mode(cves.iter().map(|c| c.value_density.clone()), vec!["DIFFUSE".to_string(), "CONCENTRATED".to_string(), "NOT_DEFINED".to_string()]),
        vulnerability_response_effort: mode(cves.iter().map(|c| c.vulnerability_response_effort.clone()), vec!["LOW".to_string(), "MODERATE".to_string(), "HIGH".to_string(), "NOT_DEFINED".to_string()]),*/
        version: "4".to_string(),
        base_score: 0.0,
        base_severity: "".to_string(),
        vector_string: "".to_string(),
    };

    if args.verbose {
        println!("\nCVSS Vector Analysis (Mode):");
        println!("  Attack Vector: {}", temp_cvss4.attack_vector);
        println!("  Attack Complexity: {}", temp_cvss4.attack_complexity);
        println!("  Attack Requirements: {}", temp_cvss4.attack_requirements);
        println!("  Privileges Required: {}", temp_cvss4.privileges_required);
        println!("  User Interaction: {}", temp_cvss4.user_interaction);
        println!(
            "  Vulnerable Confidentiality Impact: {}",
            temp_cvss4.vuln_confidentiality_impact
        );
        println!(
            "  Vulnerable Integrity Impact: {}",
            temp_cvss4.vuln_integrity_impact
        );
        println!(
            "  Vulnerable Availability Impact: {}",
            temp_cvss4.vuln_availability_impact
        );
        println!(
            "  Subsystem Confidentiality Impact: {}",
            temp_cvss4.sub_confidentiality_impact
        );
        println!(
            "  Subsystem Integrity Impact: {}",
            temp_cvss4.sub_integrity_impact
        );
        println!(
            "  Subsystem Availability Impact: {}",
            temp_cvss4.sub_availability_impact
        );
        println!("  Exploit Maturity: {}", temp_cvss4.exploit_maturity);
        println!(
            "  Confidentiality Requirement: {}",
            temp_cvss4.confidentiality_requirement
        );
        println!(
            "  Integrity Requirement: {}",
            temp_cvss4.integrity_requirement
        );
        println!(
            "  Availability Requirement: {}",
            temp_cvss4.availability_requirement
        );
        println!(
            "  Modified Attack Vector: {}",
            temp_cvss4.modified_attack_vector
        );
        println!(
            "  Modified Attack Complexity: {}",
            temp_cvss4.modified_attack_complexity
        );
        println!(
            "  Modified Attack Requirements: {}",
            temp_cvss4.modified_attack_requirements
        );
        println!(
            "  Modified Privileges Required: {}",
            temp_cvss4.modified_privileges_required
        );
        println!(
            "  Modified User Interaction: {}",
            temp_cvss4.modified_user_interaction
        );
        println!(
            "  Modified Vulnerable Confidentiality Impact: {}",
            temp_cvss4.modified_vuln_confidentiality_impact
        );
        println!(
            "  Modified Vulnerable Integrity Impact: {}",
            temp_cvss4.modified_vuln_integrity_impact
        );
        println!(
            "  Modified Vulnerable Availability Impact: {}",
            temp_cvss4.modified_vuln_availability_impact
        );
        println!(
            "  Modified Subsystem Confidentiality Impact: {}",
            temp_cvss4.modified_sub_confidentiality_impact
        );
        println!(
            "  Modified Subsystem Integrity Impact: {}",
            temp_cvss4.modified_sub_integrity_impact
        );
        println!(
            "  Modified Subsystem Availability Impact: {}",
            temp_cvss4.modified_sub_availability_impact
        );
        println!("  Safety: {}", temp_cvss4.safety);
        println!("  Automatable: {}", temp_cvss4.automatable);
        println!("  Provider Urgency: {}", temp_cvss4.provider_urgency);
        println!("  Recovery: {}", temp_cvss4.recovery);
        println!("  Value Density: {}", temp_cvss4.value_density);
        println!(
            "  Vulnerability Response Effort: {}",
            temp_cvss4.vulnerability_response_effort
        );
    }

    let vector_string = format!(
        "CVSS:4.0/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/VC:{}/VI:{}/VA:{}/SC:{}/SI:{}/SA:{}", // /E:{}/CR:{}/IR:{}/AR:{}/MAV:{}/MAC:{}/MAT:{}/MPR:{}/MUI:{}/MVC:{}/MVI:{}/MVA:{}/MSC:{}/MSI:{}/MSA:{}/S:{}/AU:{}/U:{}/R:{}/V:{}/RE:{}",
        map_metric(&temp_cvss4.attack_vector)?,
        map_metric(&temp_cvss4.attack_complexity)?,
        map_metric(&temp_cvss4.attack_requirements)?,
        map_metric(&temp_cvss4.privileges_required)?,
        map_metric(&temp_cvss4.user_interaction)?,
        map_metric(&temp_cvss4.vuln_confidentiality_impact)?,
        map_metric(&temp_cvss4.vuln_integrity_impact)?,
        map_metric(&temp_cvss4.vuln_availability_impact)?,
        map_metric(&temp_cvss4.sub_confidentiality_impact)?,
        map_metric(&temp_cvss4.sub_integrity_impact)?,
        map_metric(&temp_cvss4.sub_availability_impact)?,
        /*map_metric(&temp_cvss4.exploit_maturity)?
        map_metric(&temp_cvss4.confidentiality_requirement)?,
        map_metric(&temp_cvss4.integrity_requirement)?,
        map_metric(&temp_cvss4.availability_requirement)?,
        map_metric(&temp_cvss4.modified_attack_vector)?,
        map_metric(&temp_cvss4.modified_attack_complexity)?,
        map_metric(&temp_cvss4.modified_attack_requirements)?,
        map_metric(&temp_cvss4.modified_privileges_required)?,
        map_metric(&temp_cvss4.modified_user_interaction)?,
        map_metric(&temp_cvss4.modified_vuln_confidentiality_impact)?,
        map_metric(&temp_cvss4.modified_vuln_integrity_impact)?,
        map_metric(&temp_cvss4.modified_vuln_availability_impact)?,
        map_metric(&temp_cvss4.modified_sub_confidentiality_impact)?,
        map_metric(&temp_cvss4.modified_sub_integrity_impact)?,
        map_metric(&temp_cvss4.modified_sub_availability_impact)?,
        map_metric(&temp_cvss4.safety)?,
        map_metric(&temp_cvss4.automatable)?,
        map_metric(&temp_cvss4.provider_urgency)?,
        map_metric(&temp_cvss4.recovery)?,
        map_metric(&temp_cvss4.value_density)?,
        map_metric(&temp_cvss4.vulnerability_response_effort)?*/
    );

    if args.verbose {
        println!("Scoring VS: {}", vector_string);
        println!("Abstraction: {}", cwe_data_flatened.abstraction);
    } else {
        print!(
            "{},\"{}\",{},{},{},{},\"{}\",\"{}\",",
            cwe_data_flatened.id,
            cwe_data_flatened.name,
            cwe_data_flatened.abstraction,
            vector_string,
            cwe_data_flatened.disaid,
            cwe_data_flatened.severity,
            cwe_data_flatened.control,
            cwe_data_flatened.cci
        );
    }

    score_from_vector(&vector_string, args)?;

    Ok(())
}
