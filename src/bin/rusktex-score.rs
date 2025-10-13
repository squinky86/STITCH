// src/bin/rusktex-score.rs

use anyhow::{Context, Result};
use clap::Parser;
use cvss::v3::Base;
use cvss::v4::Vector;
use rusqlite::{params, Connection};
use std::str::FromStr;

/// A tool to calculate CVSS scores from a vector string or a CVE identifier.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The CVSS vector string (e.g., "CVSS:4.0/AV:N/AC:L...") or a CVE ID (e.g., "CVE-2021-44228")
    input: String,

    /// Path to the RuskTeX database file
    #[arg(short, long, default_value = "rusktex.db")]
    db: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let input = args.input.trim();

    // Determine if the input is a vector string or a CVE identifier
    if input.starts_with("CVSS:") {
        score_from_vector(input)?;
    } else if input.to_uppercase().starts_with("CVE-") {
        score_from_cve(&args.input, &args.db)?;
    } else {
        anyhow::bail!("Input must be a valid CVSS vector string (starting with 'CVSS:') or a CVE identifier (starting with 'CVE-').");
    }

    Ok(())
}

/// Calculates and prints the score from a given CVSS vector string.
fn score_from_vector(vector: &str) -> Result<()> {
    println!(); // Add a blank line for better formatting
    if vector.starts_with("CVSS:4.0") {
        let vector = Vector::from_str(vector).context("Failed to parse CVSS 4.0 vector string")?;
        println!("CVSS 4.0 Vector: {}", vector);
        println!("Qualitative Severity: {}", vector.score().severity());
        println!("Base Score: {:.1}", vector.score().value());
    } else if vector.starts_with("CVSS:3.1") || vector.starts_with("CVSS:3.0") {
        let base = Base::from_str(vector).context("Failed to parse CVSS 3.x vector string")?;
        println!("CVSS 3.x Vector: {}", base);
        println!("Qualitative Severity: {}", base.severity());
        println!("Base Score: {:.1}", base.score().value());
    } else {
        anyhow::bail!("Unsupported CVSS version. Only 3.0, 3.1, and 4.0 are supported.");
    }
    Ok(())
}

/// Looks up a CVE in the database, constructs a CVSS 4.0 vector, and calculates the score.
fn score_from_cve(cve_id: &str, db_path: &str) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database file: {}", db_path))?;

    let mut stmt = conn.prepare(
        "SELECT
            attackVector, attackComplexity, attackRequirements, privilegesRequired,
            userInteraction, vulnConfidentialityImpact, vulnIntegrityImpact,
            vulnAvailabilityImpact, subConfidentialityImpact, subIntegrityImpact,
            subAvailabilityImpact, scoreVersion
         FROM Vulnerability
         WHERE NVDId = ?1",
    )?;

    // Query the database for the CVE's metrics
    let cve_data = stmt.query_row(params![cve_id.to_uppercase()], |row| {
        Ok((
            row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
            row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?,
            row.get::<_, String>(6)?, row.get::<_, String>(7)?, row.get::<_, String>(8)?,
            row.get::<_, String>(9)?, row.get::<_, String>(10)?, row.get::<_, u32>(11)?,
        ))
    }).with_context(|| format!("Could not find CVE '{}' in the database.", cve_id))?;

    // Map the database's full metric names to their CVSS 4.0 single-letter abbreviations
    let vector_string = format!(
        "CVSS:4.0/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/VC:{}/VI:{}/VA:{}/SC:{}/SI:{}/SA:{}",
        map_metric(&cve_data.0)?, map_metric(&cve_data.1)?, map_metric(&cve_data.2)?,
        map_metric(&cve_data.3)?, map_metric(&cve_data.4)?, map_metric(&cve_data.5)?,
        map_metric(&cve_data.6)?, map_metric(&cve_data.7)?, map_metric(&cve_data.8)?,
        map_metric(&cve_data.9)?, map_metric(&cve_data.10)?
    );

    println!("Found CVE: {} using CVSS Version {}. Constructing CVSS 4.0 vector from database: {}.", cve_id, cve_data.11, vector_string);
    score_from_vector(&vector_string)?;

    Ok(())
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
        // User Interaction (UI)
        "ACTIVE" => Ok("A"),
        // Universal "None" value for multiple metric types
        "NONE" => Ok("N"),
        _ => Err(anyhow::anyhow!("Unknown CVSS metric value: {}", metric)),
    }
}
