use std::{collections::BTreeSet, path::Path, process::Command};

use rusqlite::{params, types::Value};
use stitch::db::create_database;

struct TestCve {
    number: u32,
    weaknesses: &'static [u32],
    version: u32,
    attack_vector: &'static str,
    confidentiality: &'static str,
}

impl TestCve {
    fn new(number: u32, weaknesses: &'static [u32]) -> Self {
        Self {
            number,
            weaknesses,
            version: 4,
            attack_vector: "NETWORK",
            confidentiality: "HIGH",
        }
    }
}

fn fixture(
    relationships: &[(u32, u32)],
    cves: &[TestCve],
) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("evidence.db");
    let build = create_database(db.to_str().unwrap()).unwrap();
    let conn = build.connection();
    conn.execute_batch(
        "INSERT INTO STIG (id, title) VALUES (1, 'Fixture');
         INSERT INTO STIGCheck (id, STIGId, DISAId, Severity)
             VALUES (1, 1, 'SV-1r1_rule', 'medium');
         INSERT INTO RMFFamily (id, abbr, name) VALUES (1, 'AC', 'Fixture');
         INSERT INTO RMFControl (id, RMFFamilyId, number, name, description)
             VALUES (1, 1, 'AC-1', 'Fixture', 'Fixture');
         INSERT INTO RMFCCI (id, RMFControlId, definition) VALUES (1, 1, 'Fixture');
         INSERT INTO MapSTIGCheckCCI (STIGCheckId, CCIId) VALUES (1, 1);
         INSERT INTO Weakness (id, name, abstraction, view)
             VALUES (1000, 'Hierarchy', '', 1);",
    )
    .unwrap();
    let weaknesses: BTreeSet<u32> = std::iter::once(1)
        .chain(
            relationships
                .iter()
                .flat_map(|&(child, parent)| [child, parent]),
        )
        .chain(cves.iter().flat_map(|cve| cve.weaknesses.iter().copied()))
        .collect();
    for id in weaknesses {
        conn.execute(
            "INSERT INTO Weakness
             (id, name, abstraction, confidentiality, integrity, availability, STIGCheckId)
             VALUES (?1, 'Fixture', 'Base', 1, 1, 1, 1)",
            [id],
        )
        .unwrap();
    }
    for &(child, parent) in relationships {
        conn.execute(
            "INSERT INTO WeaknessRelationship (source_id, target_id, nature, view_id)
             VALUES (?1, ?2, 'ChildOf', 1000)",
            params![child, parent],
        )
        .unwrap();
    }
    let columns: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('Vulnerability') WHERE type = 'TEXT'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let insert = format!(
        "INSERT INTO Vulnerability ({}, scoreVersion) VALUES ({}, ?)",
        columns.join(","),
        vec!["?"; columns.len()].join(",")
    );
    for cve in cves {
        let mut values: Vec<Value> = columns
            .iter()
            .map(|column| {
                Value::Text(match column.as_str() {
                    "NVDId" => format!("CVE-2026-{:05}", cve.number),
                    "attackVector" => cve.attack_vector.into(),
                    "attackComplexity" => "LOW".into(),
                    "vulnConfidentialityImpact" => cve.confidentiality.into(),
                    "attackRequirements"
                    | "privilegesRequired"
                    | "userInteraction"
                    | "vulnIntegrityImpact"
                    | "vulnAvailabilityImpact"
                    | "subConfidentialityImpact"
                    | "subIntegrityImpact"
                    | "subAvailabilityImpact" => "NONE".into(),
                    _ => "NOT_DEFINED".into(),
                })
            })
            .collect();
        values.push(Value::Integer(cve.version.into()));
        conn.execute(&insert, rusqlite::params_from_iter(values))
            .unwrap();
        let vulnerability_id = conn.last_insert_rowid();
        for weakness in cve.weaknesses {
            conn.execute(
                "INSERT INTO MapVulnerabilityWeakness (VulnerabilityId, WeaknessId)
                 VALUES (?1, ?2)",
                params![vulnerability_id, weakness],
            )
            .unwrap();
        }
    }
    build.publish().unwrap();
    (dir, db)
}

fn score(db: &Path, verbose: bool) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stitch-score"));
    command.arg("--db").arg(db).arg("CWE-1");
    if verbose {
        command.arg("--verbose");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn vector(db: &Path) -> String {
    let output = score(db, false);
    csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(output.as_bytes())
        .records()
        .next()
        .unwrap()
        .unwrap()[3]
        .to_string()
}

fn assert_evidence(db: &Path, expected: std::ops::RangeInclusive<u32>) {
    let output = score(db, true);
    let ids: Vec<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("CVE: "))
        .collect();
    let expected: Vec<_> = expected.map(|id| format!("CVE-2026-{id:05}")).collect();
    assert_eq!(ids, expected, "{output}");
    assert!(output.contains(&format!("Scoring with {} CVEs in memory.", ids.len())));
}

#[test]
fn starting_cwe_cannot_supply_its_direct_evidence_again_as_a_sibling() {
    let cves: Vec<_> = (1..=4).map(|id| TestCve::new(id, &[1])).collect();
    let (_dir, db) = fixture(&[(1, 2)], &cves);
    assert_eq!(vector(&db), "N/A");
}

#[test]
fn sibling_mappings_cannot_turn_four_cves_into_enough_evidence() {
    let cves: Vec<_> = (1..=4).map(|id| TestCve::new(id, &[3, 4])).collect();
    let (_dir, db) = fixture(&[(1, 2), (3, 2), (4, 2)], &cves);
    assert_eq!(vector(&db), "N/A");
}

#[test]
fn duplicate_evidence_does_not_prevent_searching_the_next_ancestor() {
    let cves = [
        TestCve::new(1, &[1, 3]),
        TestCve::new(2, &[2]),
        TestCve::new(3, &[3]),
        TestCve::new(4, &[3]),
        TestCve::new(5, &[5]),
    ];
    let (_dir, db) = fixture(&[(1, 2), (3, 2), (2, 5)], &cves);
    assert_evidence(&db, 1..=5);
}

#[test]
fn duplicate_mappings_do_not_trigger_the_fifty_cve_cutoff() {
    // Exercise the cutoff within descendant, ancestor, and cousin steps.
    for relationships in [
        vec![(2, 1), (3, 1)],
        vec![(1, 2), (1, 3)],
        vec![(1, 4), (2, 4), (3, 4)],
    ] {
        let mut cves: Vec<_> = (1..=25).map(|id| TestCve::new(id, &[2, 3])).collect();
        cves.extend((26..=50).map(|id| TestCve {
            version: 3,
            ..TestCve::new(id, &[2])
        }));
        // Fifty unique CVEs after the v3 step must still skip the v2 step.
        cves.push(TestCve {
            version: 2,
            ..TestCve::new(51, &[2])
        });
        let (_dir, db) = fixture(&relationships, &cves);
        assert_evidence(&db, 1..=50);
    }
}

#[test]
fn repeated_mappings_do_not_weight_modes_or_impacts_more_than_once() {
    let mut cves: Vec<_> = (1..=2).map(|id| TestCve::new(id, &[2, 3])).collect();
    // These three distinct CVEs intentionally have identical metrics. Identity
    // is the CVE ID, not the metric vector. With equal weighting, LOCAL wins
    // 3:2 and confidentiality averages (3 + 3 + 1 + 1 + 1) / 5 = 1.8 (LOW).
    cves.extend((3..=5).map(|id| TestCve {
        attack_vector: "LOCAL",
        confidentiality: "LOW",
        ..TestCve::new(id, &[2])
    }));
    let (_dir, db) = fixture(&[(2, 1), (3, 1)], &cves);
    assert_eq!(
        vector(&db),
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
    );
    assert_evidence(&db, 1..=5);
}

#[test]
fn a_relationship_cycle_cannot_reuse_the_starting_cwes_evidence() {
    let cves: Vec<_> = (1..=4).map(|id| TestCve::new(id, &[1])).collect();
    let (_dir, db) = fixture(&[(1, 2), (2, 1)], &cves);
    assert_eq!(vector(&db), "N/A");
}
