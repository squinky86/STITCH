// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use crate::common::{DownloadMetadata, p};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OpenFlags, config::DbConfig, params};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

const DATABASE_SCHEMA_VERSION: i64 = 2;

pub struct DatabaseBuild {
    conn: Option<Connection>,
    temp_file: Option<NamedTempFile>,
    destination: PathBuf,
}

impl DatabaseBuild {
    pub fn connection(&self) -> &Connection {
        self.conn
            .as_ref()
            .expect("database build connection is available until publication")
    }

    pub fn publish(mut self) -> Result<()> {
        let conn = self
            .conn
            .take()
            .context("Database build was already published")?;

        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .context("Failed to run SQLite integrity check")?;
        if integrity != "ok" {
            bail!("Refusing to publish corrupt database: {integrity}");
        }

        let foreign_key_error: Option<(String, i64)> = {
            let mut statement = conn.prepare("PRAGMA foreign_key_check")?;
            let mut rows = statement.query([])?;
            if let Some(row) = rows.next()? {
                Some((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            } else {
                None
            }
        };
        if let Some((table, rowid)) = foreign_key_error {
            bail!("Refusing to publish database with foreign-key violation in {table} row {rowid}");
        }

        conn.execute(
            "UPDATE BuildMetadata SET status = 'complete', completedAt = ?1 WHERE id = 1",
            params![Utc::now().to_rfc3339()],
        )?;
        conn.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);
             PRAGMA synchronous = FULL;",
        )?;
        let journal_mode: String =
            conn.query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("delete") {
            bail!("Failed to finalize SQLite journal before publication");
        }
        drop(conn);

        let temp_file = self
            .temp_file
            .take()
            .context("Database build temporary file is unavailable")?;
        temp_file
            .as_file()
            .sync_all()
            .context("Failed to sync completed database")?;
        temp_file.persist(&self.destination).map_err(|error| {
            anyhow::anyhow!(
                "Failed to atomically publish database to {}: {}",
                self.destination.display(),
                error.error
            )
        })?;

        #[cfg(unix)]
        {
            let parent = self
                .destination
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .context("Failed to sync database output directory")?;
        }
        Ok(())
    }
}

pub fn create_database(db_path: &str) -> Result<DatabaseBuild> {
    p("Creating SQLite database…", false);

    let destination = PathBuf::from(db_path);
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        bail!(
            "Database output directory does not exist: {}",
            parent.display()
        );
    }
    if destination.file_name().is_none() {
        bail!("Database output path must name a file");
    }

    // NamedTempFile creates a new file with exclusive-create semantics in the
    // destination directory. SQLite opens that already-created inode with
    // NOFOLLOW, and the finished database replaces the destination atomically.
    let temp_file =
        NamedTempFile::new_in(parent).context("Failed to create secure temporary database file")?;
    let conn = Connection::open_with_flags(
        temp_file.path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .context("Failed to create temporary database")?;
    apply_schema(&conn)?;
    conn.execute(
        "INSERT INTO BuildMetadata
         (id, schemaVersion, applicationVersion, status, startedAt)
         VALUES (1, ?1, ?2, 'building', ?3)",
        params![
            DATABASE_SCHEMA_VERSION,
            env!("CARGO_PKG_VERSION"),
            Utc::now().to_rfc3339()
        ],
    )?;
    p(format!("✓ ({db_path})").as_ref(), true);
    Ok(DatabaseBuild {
        conn: Some(conn),
        temp_file: Some(temp_file),
        destination,
    })
}

pub fn record_source(
    conn: &Connection,
    source_name: &str,
    metadata: &DownloadMetadata,
    declared_sha256: Option<&str>,
    declared_size_bytes: Option<u64>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO SourceMetadata
         (sourceName, requestedUrl, finalUrl, sha256, sizeBytes, retrievedAt,
          declaredSha256, declaredSizeBytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            source_name,
            metadata.requested_url,
            metadata.final_url,
            metadata.sha256,
            i64::try_from(metadata.size_bytes).context("Downloaded source is too large")?,
            metadata.retrieved_at,
            declared_sha256,
            declared_size_bytes
                .map(i64::try_from)
                .transpose()
                .context("Declared source size is too large")?
        ],
    )?;
    Ok(())
}

pub fn open_database_read_only(db_path: &str) -> Result<Connection> {
    let metadata = std::fs::symlink_metadata(db_path)
        .with_context(|| format!("Failed to inspect database file: {db_path}"))?;
    if metadata.file_type().is_symlink() {
        bail!("Refusing to open database through a symlink: {db_path}");
    }
    if !metadata.is_file() {
        bail!("Database path is not a regular file: {db_path}");
    }

    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .with_context(|| format!("Failed to open database file: {db_path}"))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    conn.execute_batch("PRAGMA query_only = ON; PRAGMA foreign_keys = ON;")?;
    let (schema_version, status): (i64, String) = conn
        .query_row(
            "SELECT schemaVersion, status FROM BuildMetadata WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("Database has no valid build-completion marker; rebuild it with stitch")?;
    if schema_version != DATABASE_SCHEMA_VERSION || status != "complete" {
        bail!(
            "Database is incomplete or uses an unsupported schema (version {schema_version}, status {status}); rebuild it with stitch"
        );
    }
    Ok(conn)
}

/// Applies the full STITCH schema (tables, FKs, pragmas) to an open Connection.
/// Used by `create_database` and by tests that want an in-memory DB.
pub fn apply_schema(conn: &Connection) -> Result<()> {
    // Enable foreign key constraints and tune SQLite for bulk-load throughput.
    // WAL + synchronous=NORMAL is durable across application crashes (only at
    // risk on OS crash / power loss) and dramatically reduces fsyncs during the
    // multi-million-row NVD ingest. cache_size is in KiB when negative, so
    // -65536 = 64 MiB. mmap_size enables memory-mapped reads up to 256 MiB.
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA cache_size = -65536;
         PRAGMA temp_store = MEMORY;
         PRAGMA mmap_size = 268435456;",
    )
    .context("Failed to apply SQLite pragmas")?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS BuildMetadata (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            schemaVersion INTEGER NOT NULL,
            applicationVersion TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('building', 'complete')),
            startedAt TEXT NOT NULL,
            completedAt TEXT
         );
         CREATE TABLE IF NOT EXISTS SourceMetadata (
            sourceName TEXT PRIMARY KEY,
            requestedUrl TEXT NOT NULL,
            finalUrl TEXT NOT NULL,
            sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
            sizeBytes INTEGER NOT NULL CHECK(sizeBytes >= 0),
            retrievedAt TEXT NOT NULL,
            declaredSha256 TEXT CHECK(declaredSha256 IS NULL OR length(declaredSha256) = 64),
            declaredSizeBytes INTEGER CHECK(declaredSizeBytes IS NULL OR declaredSizeBytes >= 0)
         );",
    )
    .context("Failed to create database metadata tables")?;

    // Create CWE Weakness table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS Weakness (
id INTEGER NOT NULL UNIQUE PRIMARY KEY,
name TEXT NOT NULL,
abstraction TEXT NOT NULL,
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
title TEXT,
version TEXT,
stigId TEXT,
release TEXT,
identifier TEXT
);",
        [],
    )
    .context("Failed to create STIG table")?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS STIGCheck (
id INTEGER PRIMARY KEY AUTOINCREMENT,
CheckContent TEXT,
CheckSys TEXT,
CheckContentRefHref TEXT,
CheckContentRefName TEXT,
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
GroupDescription TEXT,
VULNId TEXT,
Version TEXT,
VulnDiscussion TEXT,
Weight NUMERIC NOT NULL DEFAULT 10.0,
CWEId INTEGER,
LegacyIds TEXT,
FOREIGN KEY(CWEId) REFERENCES Weakness(id),
FOREIGN KEY(STIGId) REFERENCES STIG(id) ON DELETE CASCADE
);",
        [],
    )
    .context("Failed to create STIGCheck table")?;

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
NVDId TEXT NOT NULL UNIQUE,
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
safety TEXT,
automatable TEXT,
providerUrgency TEXT,
recovery TEXT,
valueDensity TEXT,
vulnerabilityResponseEffort TEXT,
scoreVersion INTEGER NOT NULL DEFAULT 0 CHECK(scoreVersion IN (0, 2, 3, 4))
);",
        [],
    )
    .context("Failed to create NVD table")?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS MapVulnerabilityWeakness (
VulnerabilityId INTEGER,
WeaknessId INTEGER,
`Primary` INTEGER NOT NULL DEFAULT 1,
PRIMARY KEY(VulnerabilityId,WeaknessId,`Primary`),
FOREIGN KEY(VulnerabilityId) REFERENCES Vulnerability(id) ON DELETE CASCADE,
FOREIGN KEY(WeaknessId) REFERENCES Weakness(id)
);",
        [],
    )
    .context("Failed to create MapNVDWeakness table")?;

    // Indexes for stitch-score query patterns. The existing UNIQUE/PRIMARY KEY
    // constraints index the leftmost columns; these cover the reverse-direction
    // and non-leading-column lookups that scoring performs in tight loops.
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_wr_target_view ON WeaknessRelationship(target_id, view_id);
         CREATE INDEX IF NOT EXISTS idx_wr_source_view ON WeaknessRelationship(source_id, view_id);
         CREATE INDEX IF NOT EXISTS idx_mvw_weakness ON MapVulnerabilityWeakness(WeaknessId);
         CREATE INDEX IF NOT EXISTS idx_mscc_cci ON MapSTIGCheckCCI(CCIId);
         CREATE INDEX IF NOT EXISTS idx_stigcheck_cwe ON STIGCheck(CWEId);",
    )
    .context("Failed to create query indexes")?;

    Ok(())
}

pub fn display_database_summary(conn: &Connection) -> Result<()> {
    p("\n=== Database Summary ===", true);

    // Count entries
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM Weakness")?;
    let mut tmp_count: i64 = stmt.query_row([], |row| row.get(0))?;
    p(format!("CWE Entries: {tmp_count}").as_ref(), true);

    // Count relationships
    stmt = conn.prepare("SELECT COUNT(*) FROM WeaknessRelationship")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("Relationships: {tmp_count}").as_ref(), true);

    if tmp_count > 0 {
        p("Relationship Types:", true);
        stmt = conn.prepare(
            "SELECT nature, COUNT(*) as count FROM WeaknessRelationship 
             GROUP BY nature ORDER BY count DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;

        for row in rows {
            let (nature, count) = row?;
            p(format!("\t{nature}: {count}").to_string().as_ref(), true);
        }
    }

    // Count RMF Families
    stmt = conn.prepare("SELECT COUNT(*) FROM RMFFamily")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("RMF Families: {tmp_count}").as_ref(), true);

    // Count RMF Controls
    stmt = conn.prepare("SELECT COUNT(*) FROM RMFControl")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("RMF Controls: {tmp_count}").as_ref(), true);

    // Count RMF CCIs
    stmt = conn.prepare("SELECT COUNT(*) FROM RMFCCI")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("RMF CCIs: {tmp_count}").as_ref(), true);

    // Count STIGs
    stmt = conn.prepare("SELECT COUNT(*) FROM STIG")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("STIGs: {tmp_count}").as_ref(), true);

    // Count STIG Checks
    stmt = conn.prepare("SELECT COUNT(*) FROM STIGCheck")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("STIG Checks: {tmp_count}").as_ref(), true);

    stmt = conn.prepare("SELECT COUNT(*) FROM Vulnerability")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("CVEs: {tmp_count}").as_ref(), true);

    stmt = conn.prepare("SELECT COUNT(*) FROM Weakness")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("CWEs: {tmp_count}").as_ref(), true);

    stmt = conn.prepare("SELECT COUNT(*) FROM Weakness WHERE view = TRUE")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("\tViews: {tmp_count}").as_ref(), true);

    stmt = conn.prepare("SELECT COUNT(*) FROM Weakness WHERE category = TRUE")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("\tCategories: {tmp_count}").as_ref(), true);

    stmt = conn.prepare("SELECT COUNT(*) FROM Weakness WHERE view = FALSE AND category = FALSE")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("\tRegular: {tmp_count}").as_ref(), true);

    // Count STIG Checks
    stmt = conn.prepare("SELECT COUNT(*) FROM MapSTIGCheckCCI")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(
        format!("STIG Check to CCI Mappings: {tmp_count}").as_ref(),
        true,
    );

    // Count Mappings
    stmt = conn.prepare("SELECT COUNT(*) FROM STIGCheck WHERE CWEId IS NOT NULL")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("STIG→CWE Mappings: {tmp_count}").as_ref(), true);

    stmt = conn.prepare("SELECT COUNT(*) FROM Weakness WHERE STIGCheckId IS NOT NULL")?;
    tmp_count = stmt.query_row([], |row| row.get(0))?;
    p(format!("CWE→STIG Mappings: {tmp_count}").as_ref(), true);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_build_preserves_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("stitch.db");
        std::fs::write(&destination, b"existing database").unwrap();

        let build = create_database(destination.to_str().unwrap()).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing database");
        drop(build);
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing database");
    }

    #[test]
    fn scorer_rejects_old_schema_with_rebuild_instructions() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("stitch.db");
        let database = create_database(destination.to_str().unwrap()).unwrap();
        database
            .connection()
            .execute(
                "UPDATE BuildMetadata SET schemaVersion = 1 WHERE id = 1",
                [],
            )
            .unwrap();
        database.publish().unwrap();
        let error = open_database_read_only(destination.to_str().unwrap()).unwrap_err();
        assert!(error.to_string().contains("rebuild it with stitch"));
    }

    #[test]
    fn published_database_is_complete_and_read_only() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("stitch.db");
        create_database(destination.to_str().unwrap())
            .unwrap()
            .publish()
            .unwrap();

        let conn = open_database_read_only(destination.to_str().unwrap()).unwrap();
        let status: String = conn
            .query_row("SELECT status FROM BuildMetadata WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(status, "complete");
        assert!(conn.execute("DELETE FROM BuildMetadata", []).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn scorer_rejects_database_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("stitch.db");
        create_database(destination.to_str().unwrap())
            .unwrap()
            .publish()
            .unwrap();
        let link = directory.path().join("database-link.db");
        symlink(&destination, &link).unwrap();
        assert!(open_database_read_only(link.to_str().unwrap()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn publication_replaces_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        let destination = directory.path().join("stitch.db");
        std::fs::write(&victim, b"do not overwrite").unwrap();
        symlink(&victim, &destination).unwrap();

        create_database(destination.to_str().unwrap())
            .unwrap()
            .publish()
            .unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"do not overwrite");
        assert!(
            !std::fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        open_database_read_only(destination.to_str().unwrap()).unwrap();
    }
}
