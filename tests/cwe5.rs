use std::{collections::BTreeSet, io::Read, path::Path, process::Command};

use rusqlite::{Connection, params, types::Value};
use stitch::{
    cwe::import_cwe_xml,
    db::{apply_schema, create_database},
    stig::import_stig_xml,
    stigwe::import_stigwe_yaml,
};

// Expected defaults from STIGWE's CWE 5.0 update. CWE-1468 is a view.
const NEW_CWE_DEFAULTS: &[(u32, &str)] = &[
    (1461, "SV-222648"),
    (1462, "SV-222580"),
    (1463, "SV-222389"),
    (1464, "SV-222549"),
    (1465, "SV-222578"),
    (1466, "SV-222520"),
    (1467, "SV-222582"),
    (1469, "SV-222400"),
    (1470, "SV-222556"),
    (1471, "SV-222605"),
    (1472, "SV-222545"),
    (1473, "SV-222553"),
    (1474, "SV-222605"),
    (1475, "SV-222395"),
    (1476, "SV-222667"),
];

const CHANGED_STIG_DEFAULTS: &[(&str, u32)] = &[
    ("SV-222389", 1463),
    ("SV-222390", 1463),
    ("SV-222391", 1464),
    ("SV-222392", 223),
    ("SV-222400", 1469),
    ("SV-222403", 1472),
    ("SV-222404", 1472),
    ("SV-222549", 1464),
    ("SV-222564", 1464),
    ("SV-222566", 1463),
    ("SV-222568", 404),
    ("SV-222578", 1465),
    ("SV-222582", 1467),
];

fn check_defaults(conn: &Connection) {
    for (cwe, stig) in NEW_CWE_DEFAULTS {
        let actual: String = conn
            .query_row(
                "SELECT s.DISAId FROM Weakness w JOIN STIGCheck s ON s.id = w.STIGCheckId WHERE w.id = ?1",
                [cwe], |row| row.get(0),
            ).unwrap();
        assert!(
            actual.starts_with(&format!("{stig}r")),
            "CWE-{cwe}: {actual}"
        );
    }
    for (stig, cwe) in CHANGED_STIG_DEFAULTS {
        let actual: u32 = conn
            .query_row(
                "SELECT CWEId FROM STIGCheck WHERE DISAId LIKE ?1",
                [format!("{stig}r%")],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(actual, *cwe, "{stig}");
    }
    assert_eq!(
        conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, u32>(0)
        })
        .unwrap(),
        0
    );
}

fn score(db: &Path, identifier: &str, verbose: bool) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stitch-score"));
    command.arg("--db").arg(db).arg(identifier);
    if verbose {
        command.arg("--verbose");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{identifier}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn insert_scored_cves(conn: &Connection, weakness_id: u32) {
    let columns: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('Vulnerability') WHERE type = 'TEXT'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for n in 1..=5 {
        let values: Vec<Value> = columns
            .iter()
            .map(|name| {
                Value::Text(match name.as_str() {
                    "NVDId" => format!("CVE-2026-{n:04}"),
                    "attackVector" => "NETWORK".into(),
                    "attackComplexity" => "LOW".into(),
                    "attackRequirements"
                    | "privilegesRequired"
                    | "userInteraction"
                    | "subConfidentialityImpact"
                    | "subIntegrityImpact"
                    | "subAvailabilityImpact" => "NONE".into(),
                    "vulnConfidentialityImpact"
                    | "vulnIntegrityImpact"
                    | "vulnAvailabilityImpact" => "HIGH".into(),
                    _ => "NOT_DEFINED".into(),
                })
            })
            .collect();
        let sql = format!(
            "INSERT INTO Vulnerability ({}, scoreVersion) VALUES ({}, 4)",
            columns.join(","),
            vec!["?"; columns.len()].join(",")
        );
        conn.execute(&sql, rusqlite::params_from_iter(values))
            .unwrap();
        conn.execute(
            "INSERT INTO MapVulnerabilityWeakness (VulnerabilityId, WeaknessId) VALUES (?1, ?2)",
            params![conn.last_insert_rowid(), weakness_id],
        )
        .unwrap();
    }
}

#[test]
fn cwe_v5_mappings_and_scoring_work_together() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cwe5.db");
    let build = create_database(db.to_str().unwrap()).unwrap();
    let conn = build.connection();
    import_cwe_xml(include_str!("fixtures/cwe_v5_excerpt.xml"), conn, false).unwrap();

    conn.execute_batch("INSERT INTO STIG (id, title) VALUES (1, 'Fixture');
        INSERT INTO RMFFamily (id, abbr, name) VALUES (1, 'AC', 'Fixture');
        INSERT INTO RMFControl (id, RMFFamilyId, number, name, description) VALUES (1, 1, 'AC-12', 'Fixture', 'Fixture');
        INSERT INTO RMFCCI (id, RMFControlId, definition) VALUES (1, 1, 'Fixture');").unwrap();
    let stigs: BTreeSet<_> = NEW_CWE_DEFAULTS
        .iter()
        .map(|(_, stig)| stig)
        .chain(CHANGED_STIG_DEFAULTS.iter().map(|(stig, _)| stig))
        .collect();
    for stig in stigs {
        conn.execute(
            "INSERT INTO STIGCheck (STIGId, DISAId, Severity) VALUES (1, ?1, 'medium')",
            [format!("{stig}r1_rule")],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO MapSTIGCheckCCI (STIGCheckId, CCIId) VALUES (?1, 1)",
            [conn.last_insert_rowid()],
        )
        .unwrap();
    }
    import_stigwe_yaml(include_str!("fixtures/stigwe_cwe_v5_excerpt.yaml"), conn).unwrap();
    check_defaults(conn);

    // Five synthetic CVEs on the new session-management class exercise ancestor
    // fallback for CWE-1463 and its STIG, without depending on NVD's live scores.
    insert_scored_cves(conn, 1462);
    // Give non-scoreable entries a mapping so the CLI reaches its type checks.
    conn.execute("UPDATE Weakness SET STIGCheckId = (SELECT STIGCheckId FROM Weakness WHERE id = 1463) WHERE id IN (613, 1451, 1468)", []).unwrap();
    build.publish().unwrap();

    let cwe = score(&db, "CWE-1463", false);
    assert_eq!(cwe, score(&db, "SV-222389", false));
    let record = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(cwe.as_bytes())
        .records()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(&record[0], "1463");
    assert_eq!(
        &record[3],
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
    );
    assert!(record[8].parse::<f64>().unwrap() > 0.0);
    // CWE-1464 is a Base with no declared scopes. Missing catalog data must
    // not suppress the impacts from the same ancestor's CVE evidence.
    let invalidation = score(&db, "CWE-1464", false);
    let record = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(invalidation.as_bytes())
        .records()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        &record[3],
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    );
    assert!(record[8].parse::<f64>().unwrap() > 0.0);
    assert!(score(&db, "CWE-1463", true).contains("3.1: Found 5 CVSS 4.0 CVEs."));
    assert!(score(&db, "CWE-613", true).contains("Deprecated CWEs cannot be scored."));
    assert!(score(&db, "CWE-1451", true).contains("Groupings/categories cannot be scored."));
    assert!(score(&db, "CWE-1468", true).contains("Views cannot be scored."));
}

#[test]
fn cwe_379_override_restores_scoring_through_its_former_grandparent() {
    check_temporary_file_override(
        379,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    );
}

#[test]
fn cwe_378_override_restores_scoring_through_its_former_grandparent() {
    check_temporary_file_override(
        378,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    );
}

fn check_temporary_file_override(cwe: u32, expected_vector: &str) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("temporary-files.db");
    let build = create_database(db.to_str().unwrap()).unwrap();
    let conn = build.connection();
    import_cwe_xml(
        include_str!("fixtures/cwe_temporary_files_excerpt.xml"),
        conn,
        false,
    )
    .unwrap();
    conn.execute_batch(
        "INSERT INTO STIG (id, title) VALUES (1, 'Fixture');
         INSERT INTO STIGCheck (id, STIGId, DISAId, Severity)
             VALUES (1, 1, 'SV-222393r1_rule', 'medium');
         INSERT INTO RMFFamily (id, abbr, name) VALUES (1, 'AC', 'Fixture');
         INSERT INTO RMFControl (id, RMFFamilyId, number, name, description)
             VALUES (1, 1, 'AC-16', 'Fixture', 'Fixture');
         INSERT INTO RMFCCI (id, RMFControlId, definition) VALUES (1, 1, 'Fixture');
         INSERT INTO MapSTIGCheckCCI (STIGCheckId, CCIId) VALUES (1, 1);",
    )
    .unwrap();
    conn.execute("UPDATE STIGCheck SET CWEId = ?1 WHERE id = 1", [cwe])
        .unwrap();
    conn.execute("UPDATE Weakness SET STIGCheckId = 1 WHERE id = ?1", [cwe])
        .unwrap();
    insert_scored_cves(conn, 668);
    // Secondary direct mappings must not bypass the existing evidence policy.
    conn.execute(
        "INSERT INTO MapVulnerabilityWeakness (VulnerabilityId, WeaknessId, `Primary`)
         SELECT id, ?1, 0 FROM Vulnerability;",
        [cwe],
    )
    .unwrap();
    build.publish().unwrap();

    let identifier = format!("CWE-{cwe}");
    let output = score(&db, &identifier, false);
    let record = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(output.as_bytes())
        .records()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(&record[0], cwe.to_string());
    assert_eq!(&record[3], expected_vector);
    assert!(record[8].parse::<f64>().unwrap() > 0.0);
    assert_eq!(output, score(&db, "SV-222393", false));
    assert!(score(&db, &identifier, true).contains("3.1: Found 5 CVSS 4.0 CVEs."));

    // Removing just the local edge reproduces the original N/A failure.
    Connection::open(&db)
        .unwrap()
        .execute(
            "DELETE FROM WeaknessRelationship
         WHERE source_id = ?1 AND target_id = 668 AND nature = 'ChildOf' AND view_id = 1000",
            [cwe],
        )
        .unwrap();
    assert!(score(&db, &identifier, false).contains("\"N/A\""));
}

fn zip_xml(path: &str) -> String {
    let mut archive = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
    let name = archive
        .file_names()
        .map(Result::unwrap)
        .find(|name| name.ends_with(".xml"))
        .unwrap()
        .into_owned();
    let mut xml = String::new();
    archive
        .by_name(&name)
        .unwrap()
        .read_to_string(&mut xml)
        .unwrap();
    xml
}

#[test]
#[ignore = "requires STITCH_CWE_V5_ZIP, STITCH_ASD_V6R5_ZIP, and STITCH_STIGWE_YAML"]
fn full_cwe_v5_and_stigwe_catalogs() {
    let cwe = zip_xml(&std::env::var("STITCH_CWE_V5_ZIP").unwrap());
    let stig = zip_xml(&std::env::var("STITCH_ASD_V6R5_ZIP").unwrap());
    let mappings = std::fs::read_to_string(std::env::var("STITCH_STIGWE_YAML").unwrap()).unwrap();
    let conn = Connection::open_in_memory().unwrap();
    apply_schema(&conn).unwrap();
    import_cwe_xml(&cwe, &conn, false).unwrap();
    import_stig_xml(stig.as_bytes(), &conn).unwrap();
    import_stigwe_yaml(&mappings, &conn).unwrap();
    check_defaults(&conn);
    for (query, expected) in [
        ("SELECT count(*) FROM Weakness", 1477),
        ("SELECT count(*) FROM Weakness WHERE category = 1", 431),
        ("SELECT count(*) FROM Weakness WHERE view = 1", 62),
        (
            "SELECT count(*) FROM Weakness WHERE category = 0 AND view = 0 AND name NOT LIKE 'DEPRECATED%'",
            956,
        ),
        // 1,622 source relationships plus the two temporary-file overrides.
        ("SELECT count(*) FROM WeaknessRelationship", 1624),
        (
            "SELECT count(*) FROM WeaknessRelationship WHERE source_id IN (378, 379) AND target_id = 668 AND nature = 'ChildOf' AND view_id = 1000",
            2,
        ),
        ("SELECT count(*) FROM STIGCheck", 286),
        ("SELECT count(*) FROM STIGCheck WHERE CWEId IS NULL", 0),
        (
            "SELECT count(*) FROM Weakness WHERE category = 0 AND view = 0 AND name NOT LIKE 'DEPRECATED%' AND STIGCheckId IS NULL",
            0,
        ),
    ] {
        assert_eq!(
            conn.query_row(query, [], |row| row.get::<_, u32>(0))
                .unwrap(),
            expected,
            "{query}"
        );
    }
    let overlap: String = conn
        .query_row(
            "SELECT nature FROM WeaknessRelationship WHERE source_id = ?1 AND target_id = ?2",
            params![1476, 1264],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(overlap, "Overlaps");
}
