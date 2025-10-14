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
			scoreVersion
         FROM Vulnerability
         WHERE NVDId = ?1",
    )?;

    // Query the database for the CVE's metrics
    let cve_data = stmt.query_row(params![cve_id.to_uppercase()], |row| {
        Ok((
            row.get::<_, String>(0)?, //AV
			row.get::<_, String>(1)?, //AC
			row.get::<_, String>(2)?, //AT
            row.get::<_, String>(3)?, //PR
			row.get::<_, String>(4)?, //UI
			row.get::<_, String>(5)?, //VC
            row.get::<_, String>(6)?, //VI
			row.get::<_, String>(7)?, //VA
			row.get::<_, String>(8)?, //SC
            row.get::<_, String>(9)?, //SI
			row.get::<_, String>(10)?, //SA
			row.get::<_, String>(11)?, //E
			row.get::<_, String>(12)?, //CR
			row.get::<_, String>(13)?, //IR
			row.get::<_, String>(14)?, //AR
			row.get::<_, String>(15)?, // MAV
			row.get::<_, String>(16)?, // MAC
			row.get::<_, String>(17)?, // MAT
			row.get::<_, String>(18)?, // MPR
			row.get::<_, String>(19)?, // MUI
			row.get::<_, String>(20)?, // MVC
			row.get::<_, String>(21)?, // MVI
			row.get::<_, String>(22)?, // MVA
			row.get::<_, String>(23)?, // MSC
			row.get::<_, String>(24)?, // MSI
			row.get::<_, String>(25)?, // MSA
			row.get::<_, u32>(26)?,
        ))
    }).with_context(|| format!("Could not find CVE '{}' in the database.", cve_id))?;

    // Map the database's full metric names to their CVSS 4.0 single-letter abbreviations
    let vector_string = format!(
        "CVSS:4.0/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/VC:{}/VI:{}/VA:{}/SC:{}/SI:{}/SA:{}/E:{}/CR:{}/IR:{}/AR:{}/MAV:{}/MAC:{}/MAT:{}/MPR:{}/MUI:{}/MVC:{}/MVI:{}/MVA:{}/MSC:{}/MSI:{}/MSA:{}",
        map_metric(&cve_data.0)?,
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
		map_metric(&cve_data.12)?,
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
		map_metric(&cve_data.25)?
    );

    println!("Found CVE: {} using CVSS Version {}. Constructing CVSS 4.0 vector from database: {}.", cve_id, cve_data.26, vector_string);
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
		"NONE" => Ok("N"),
		
		// Privileges Required (PR):
		//     High handled in AC
		//     LOW handled in AC
		//     NONE handled in AT

		// User Interaction (UI)
        "ACTIVE" => Ok("A"),
		"PASSIVE" => Ok("P"),
		//    NONE handled in AT

		// Vulnerable System Confidentiality, Integrity, and Availability
		//     High handled in AC
		//     LOW handled in AC
		//     NONE handled in AT

		// Exploit Maturity (E)
		"NOT_DEFINED" => Ok("X"),
		"ATTACKED" => Ok("A"),
		"PROOF_OF_CONCEPT" => Ok("P"),
		"UNREPORTED" => Ok("U"),

        _ => Err(anyhow::anyhow!("Unknown CVSS metric value: {}", metric)),
    }
}
