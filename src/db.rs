use crate::common::p;

use rusqlite::Connection;
use anyhow::{Context, Result};

pub fn create_database(db_path: &str) -> Result<Connection> {
    p("Creating SQLite database…", false);
    
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

    p(format!("✓ ({})", db_path).to_string().as_ref(), true);

	Ok(conn)
}

pub fn display_database_summary(conn: &Connection) -> Result<()> {
	p("\n=== Database Summary ===", true);

	// Count entries
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM Weakness")?;
	let entry_count: i64 = stmt.query_row([], |row| row.get(0))?;
	p(format!("CWE Entries: {}", entry_count).to_string().as_ref(), true);

	// Count relationships
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM WeaknessRelationship")?;
	let rel_count: i64 = stmt.query_row([], |row| row.get(0))?;
	p(format!("Relationships: {}", rel_count).to_string().as_ref(), true);

	if rel_count > 0 {
		p("Relationship Types:", true);
		let mut stmt = conn.prepare(
			"SELECT nature, COUNT(*) as count FROM WeaknessRelationship 
             GROUP BY nature ORDER BY count DESC",
		)?;
		let mut rows = stmt.query_map([], |row| {
			Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
		})?;

		while let Some(Ok((nature, count))) = rows.next() {
			p(format!("\t{}: {}", nature, count).to_string().as_ref(), true);;
		}
	}

	// Count RMF Families
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFFamily")?;
	let fam_count: i64 = stmt.query_row([], |row| row.get(0))?;
	p(format!("RMF Families: {}", fam_count).to_string().as_ref(), true);

	// Count RMF Controls
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFControl")?;
	let control_count: i64 = stmt.query_row([], |row| row.get(0))?;
	p(format!("RMF Controls: {}", control_count).to_string().as_ref(), true);

	// Count RMF CCIs
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM RMFCCI")?;
	let cci_count: i64 = stmt.query_row([], |row| row.get(0))?;
	p(format!("RMF CCIs: {}", cci_count).to_string().as_ref(), true);

	// Count STIGs
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIG")?;
	let stig_count: i64 = stmt.query_row([], |row| row.get(0))?;
	p(format!("STIGs: {}", stig_count).to_string().as_ref(), true);

	// Count STIG Checks
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIGCheck")?;
	let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
	p(format!("STIG Checks: {}", check_count).to_string().as_ref(), true);

	// Count STIG Checks
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM MapSTIGCheckCCI")?;
	let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
	p(format!("STIG Check to CCI Mappings: {}", check_count).to_string().as_ref(), true);

	// Count Mappings
	let mut stmt = conn.prepare("SELECT COUNT(*) FROM STIGCheck WHERE CWEId IS NOT NULL")?;
    let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
    p(format!("STIG→CWE Mappings: {}", check_count).to_string().as_ref(), true);

    let mut stmt = conn.prepare("SELECT COUNT(*) FROM Weakness WHERE STIGCheckId IS NOT NULL")?;
    let check_count: i64 = stmt.query_row([], |row| row.get(0))?;
    p(format!("CWE→STIG Mappings: {}", check_count).to_string().as_ref(), true);

	Ok(())
}
