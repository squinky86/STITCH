mod common;
mod cwe;
mod rmf;
mod cci;
mod stig;

use crate::common::{decompress_gzip,download_file,Args};
use crate::cwe::process_cwe;
use crate::rmf::process_rmf;
use crate::stig::process_stig;
use crate::cci::process_cci;
use anyhow::{Context, Result};
use chrono::{Utc, Datelike};
use clap::Parser;
use rusqlite::{params, Connection};
use tokio::fs;
use tempfile::NamedTempFile;
use serde::Deserialize;
use std::collections::HashMap;

async fn nvd_parse_and_populate_database(json_file: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let json_content = fs::read_to_string(json_file.path())
        .await
        .context("Failed to read NVD JSON file")?;
    
    // TODO: Parse JSON and populate database
    
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
	let args = Args::parse();

	//CWE and STIG mapping
	const STIGWE_YAML_URL: &str = "https://raw.githubusercontent.com/squinky86/STIGWE/refs/heads/main/mappings/mappings.yaml";
	let mut stigwe_temp_yaml = NamedTempFile::new()?;

	println!("RuskTeX Database Builder v0.1.0");

	//DB Structure
	print!("Creating SQLite database:");
	let conn = create_database(&args.output)?;
	println!("SQLite database created ✓ ({})", args.output);

	//CWE Data
	process_cwe(&conn, &args).await?;

	//RMF Data
	process_rmf(&conn, &args).await?;

	process_cci(&conn, &args).await?;

	//STIG Data
	process_stig(&conn, &args).await?;

	// Download the STIGWE YAML file
	if stigwe_temp_yaml.path().exists() {
		print!("Downloading STIGWE YAML file…");
		download_file(&STIGWE_YAML_URL, &mut stigwe_temp_yaml, &args).await?;
		println!("✓");
	} else {
		eprintln!("Unable to create temporary STIGWE YAML file.");
		std::process::exit(1);
	}

	// Parse STIGWE YAML and populate database
	println!("Parsing STIGWE YAML and populating database:");
	stigwe_parse_and_populate_database(&mut stigwe_temp_yaml, &conn).await?;

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

	// Display summary
	display_database_summary(&conn)?;

	println!("\nCWE database build completed successfully: {}", args.output);
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
availability BOOLEAN NOT NULL DEFAULT 0 CHECK(availability IN (0, 1)),
STIGCheckId INTEGER,
FOREIGN KEY(STIGCheckId) REFERENCES STIGCheck(id)
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
STIGCheckId INTEGER,
CCIId INTEGER,
PRIMARY KEY(STIGCheckId,CCIId),
FOREIGN KEY(STIGCheckId) REFERENCES STIGCheck(id) ON DELETE CASCADE,
FOREIGN KEY(CCIId) REFERENCES RMFCCI(id)
);",
		[],
	)
	.context("Failed to create MapSTIGCheckCCI table")?;

	conn.execute(
		"CREATE TABLE IF NOT EXISTS Vulnerability (
id INTEGER PRIMARY KEY AUTOINCREMENT,
NVDId TEXT,
Description TEXT,
attackVector TEXT,
attackComplexity TEXT,
attackRequirements TEXT,
privilegesRequired TEXT,
userInteraction TEXT,
vulnConfidentialityImpact TEXT,
vulnIntegrityImpact TEXT,
vulnAvailabilityImpact TEXT,
subConfidentialityImpact TEXT,
subIntegrityImpact TEXT,
subAvailabilityImpact TEXT,
exploitMaturity TEXT,
confidentialityRequirement TEXT,
integrityRequirement TEXT,
availabilityRequirement TEXT,
modifiedAttackVector TEXT,
modifiedAttackComplexity TEXT,
modifiedAttackRequirements TEXT,
modifiedPrivilegesRequired TEXT,
modifiedUserInteraction TEXT,
modifiedVulnConfidentialityImpact TEXT,
modifiedVulnIntegrityImpact TEXT,
modifiedVulnAvailabilityImpact TEXT,
modifiedSubConfidentialityImpact TEXT,
modifiedSubIntegrityImpact TEXT,
modifiedSubAvailabilityImpact TEXT,
Safety TEXT,
Automatable TEXT,
Recovery TEXT,
valueDensity TEXT,
vulnerabilityResponseEffort TEXT,
providerUrgency TEXT
);",
		[],
	)
	.context("Failed to create NVD table")?;

	conn.execute(
		"CREATE TABLE IF NOT EXISTS MapVulnerabilityWeakness (
VulnerabilityId INTEGER,
WeaknessId INTEGER,
PRIMARY KEY(VulnerabilityId,WeaknessId),
FOREIGN KEY(VulnerabilityId) REFERENCES Vulnerability(id) ON DELETE CASCADE,
FOREIGN KEY(WeaknessId) REFERENCES Weakness(id)
);",
		[],
	)
	.context("Failed to create MapNVDWeakness table")?;

	Ok(conn)
}

//store data of YAML parsing
#[derive(Debug, Deserialize)]
struct Mappings {
    stig_to_cwe: HashMap<String, STIGToCWE>,
    cwe_to_stig: HashMap<String, CWEToSTIG>,
}

#[derive(Debug, Deserialize)]
struct STIGToCWE {
    cwe_ids: Vec<MappingWithDefault>,
}

#[derive(Debug, Deserialize)]
struct CWEToSTIG {
    stig_ids: Vec<MappingWithDefault>,
}

#[derive(Debug, Deserialize)]
struct MappingWithDefault {
    id: String,
    default: bool,
}

async fn stigwe_parse_and_populate_database(yaml: &mut NamedTempFile, conn: &Connection) -> Result<()> {
    let yaml_content = fs::read_to_string(yaml.path())
        .await
        .context("Failed to read YAML file")?;

    let mappings: Mappings = serde_yaml::from_str(&yaml_content)
        .context("Failed to parse YAML content")?;

	print!("\tInserting {} STIG→CWE mappings…", mappings.stig_to_cwe.len());
    // Update STIGCheck CWEId where default mapping exists
    for (stig_id, mapping) in mappings.stig_to_cwe.iter() {
        for cwe_mapping in mapping.cwe_ids.iter() {
            if cwe_mapping.default {
                let cwe_id = cwe_mapping.id.trim_start_matches("CWE-")
                    .parse::<u32>()
                    .context("Failed to parse CWE ID")?;
                
				conn.execute(
                    "UPDATE STIGCheck 
                     SET CWEId = ?1 
                     WHERE DISAId LIKE ?2 
                     AND CWEId IS NULL",
					params![cwe_id, format!("{}%", stig_id)],
                )?;
            }
        }
    }
	println!("✓");

	print!("\tInserting {} CWE→STIG mappings…", mappings.cwe_to_stig.len());
    // Process CWE to STIG mappings
    for (cwe_id, mapping) in mappings.cwe_to_stig.iter() {
        for stig_mapping in mapping.stig_ids.iter() {
            if stig_mapping.default {
                let cwe_num = cwe_id.trim_start_matches("CWE-")
                    .parse::<u32>()
                    .context("Failed to parse CWE ID")?;
                
                conn.execute(
                    "UPDATE Weakness 
                     SET STIGCheckId = (
                         SELECT id 
                         FROM STIGCheck 
                         WHERE DISAId LIKE ?1
                         LIMIT 1
                     )
                     WHERE id = ?2",
                    params![format!("{}%", stig_mapping.id), cwe_num],
                )?;
            }
        }
    }
	println!("✓");

    Ok(())
}

fn display_database_summary(conn: &Connection) -> Result<()> {
	println!("\n=== Database Summary ===");

	// Count entries
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM Weakness")?;
	let entry_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("CWE Entries: {}", entry_count);

	// Count relationships
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM WeaknessRelationship")?;
	let rel_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("Relationships: {}", rel_count);

	if rel_count > 0 {
		println!("Relationship Types:");
		let mut stmt = conn.prepare(
			"SELECT nature, COUNT(*) as count FROM WeaknessRelationship 
             GROUP BY nature ORDER BY count DESC",
		)?;
		let mut rows = stmt.query_map([], |row| {
			Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
		})?;

		while let Some(Ok((nature, count))) = rows.next() {
			println!("\t{}: {}", nature, count);
		}
	}

	// Count RMF Families
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFFamily")?;
	let fam_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("RMF Families: {}", fam_count);

	// Count RMF Controls
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFControl")?;
	let control_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("RMF Controls: {}", control_count);

	// Count RMF CCIs
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFCCI")?;
	let cci_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("RMF CCIs: {}", cci_count);

	// Count STIGs
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIG")?;
	let stig_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("STIGs: {}", stig_count);

	// Count STIG Checks
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIGCheck")?;
	let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("STIG Checks: {}", check_count);

	// Count STIG Checks
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM MapSTIGCheckCCI")?;
	let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
	println!("STIG Check to CCI Mappings: {}", check_count);

	// Count Mappings
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIGCheck WHERE CWEId IS NOT NULL")?;
    let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
    println!("STIG→CWE Mappings: {}", check_count);

    let mut stmt = conn.prepare("SELECT COUNT(*) FROM Weakness WHERE STIGCheckId IS NOT NULL")?;
    let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
    println!("CWE→STIG Mappings: {}", check_count);

	Ok(())
}