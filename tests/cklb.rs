use std::{collections::BTreeSet, io::Read, process::Command};

use rusqlite::params;
use serde_json::{Value, json};
use stitch::{
    db::create_database,
    stig::{import_stig_xml, parse_stig_xml},
};

const V6R5_EXCERPT: &str = include_str!("fixtures/asd_v6r5_excerpt.xml");

/// Exercise XML ingestion, database publication, and the real CKLB CLI together.
fn export_and_check(
    xml: &str,
    expected_rule_count: usize,
    requested_ids: &str,
    selected_groups: &[&str],
) -> Value {
    let benchmark = parse_stig_xml(xml).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let db_path = directory.path().join("stitch.db");
    let database = create_database(db_path.to_str().unwrap()).unwrap();
    let conn = database.connection();

    // Supply the CCI catalog entries needed by this benchmark. Deliberately do
    // not supply CWE mappings: exporting a checklist must not depend on them.
    conn.execute_batch(
        "INSERT INTO RMFFamily (id, abbr, name) VALUES (1, 'IA', 'Test family');
         INSERT INTO RMFControl (id, RMFFamilyId, number, name, description)
         VALUES (1, 1, 'IA-5', 'Test control', 'Test control');",
    )
    .unwrap();
    for rule in benchmark.groups.iter().flat_map(|group| &group.rules) {
        for cci in rule.cci_idents() {
            let id = cci.trim_start_matches("CCI-").parse::<u32>().unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO RMFCCI (id, RMFControlId, definition)
                 VALUES (?1, 1, 'Test CCI')",
                params![id],
            )
            .unwrap();
        }
    }
    import_stig_xml(xml.as_bytes(), conn).unwrap();
    database.publish().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_stitch-score"))
        .args(["--db", db_path.to_str().unwrap(), "--cklb"])
        .arg(requested_ids)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "CKLB export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let checklist: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(checklist["cklb_version"], "1.0");
    let stigs = checklist["stigs"].as_array().unwrap();
    assert_eq!(stigs.len(), 1);
    let stig = &stigs[0];
    assert_eq!(stig["stig_name"], benchmark.title);
    assert_eq!(stig["stig_id"], "Application_Security_Development_STIG");
    assert_eq!(stig["version"], "6");
    assert_eq!(
        stig["release_info"],
        "Release: 5 Benchmark Date: 30 Sep 2026"
    );
    assert_eq!(stig["reference_identifier"], "4093");
    assert_eq!(stig["size"], expected_rule_count);
    let rules = stig["rules"].as_array().unwrap();
    assert_eq!(rules.len(), expected_rule_count);
    let source_rule_count: usize = benchmark.groups.iter().map(|group| group.rules.len()).sum();
    assert_eq!(rules.len(), source_rule_count);

    let mut uuids = BTreeSet::new();
    for group in &benchmark.groups {
        for source in &group.rules {
            let rule = rules
                .iter()
                .find(|rule| rule["rule_id_src"] == source.id)
                .unwrap_or_else(|| panic!("Missing rule {}", source.id));
            let desc = source.parse_description();
            let check = source.check.as_ref().unwrap();
            let check_ref = check.check_content_ref.as_ref().unwrap();
            let expected = json!({
                "group_id": group.id,
                "rule_id": source.id.strip_suffix("_rule").unwrap(),
                "group_title": group.title,
                "rule_title": source.title,
                "rule_version": source.version,
                "severity": source.severity,
                "weight": source.weight.to_string(),
                "reference_identifier": source.reference.identifier,
                "fix_text": source.fixtext.as_ref().map(|fix| fix.value.as_str()).unwrap_or_default(),
                "check_content": check.check_content.as_deref().unwrap(),
                "check_content_ref": { "href": check_ref.href, "name": check_ref.name },
                "group_tree": [{
                    "id": group.id,
                    "title": group.title,
                    "description": group.description.as_deref().unwrap_or_default()
                }],
                "discussion": desc.vuln_discussion.unwrap_or_default(),
                "documentable": desc.documentable.unwrap(),
                "false_positives": desc.false_positives.unwrap_or_default(),
                "false_negatives": desc.false_negatives.unwrap_or_default(),
                "mitigations": desc.mitigations.unwrap_or_default(),
                "potential_impacts": desc.potential_impacts.unwrap_or_default(),
                "third_party_tools": desc.third_party_tools.unwrap_or_default(),
                "mitigation_control": desc.mitigation_control.unwrap_or_default(),
                "responsibility": desc.responsibility.unwrap_or_default(),
                "security_override_guidance": desc.severity_override_guidance.unwrap_or_default(),
                "ia_controls": desc.ia_controls.unwrap_or_default(),
                "legacy_ids": source.legacy_ids()
            });
            for (field, value) in expected.as_object().unwrap() {
                assert_eq!(&rule[field], value, "{}: {field}", source.id);
            }

            let ccis: BTreeSet<_> = rule["ccis"]
                .as_array()
                .unwrap()
                .iter()
                .map(|cci| cci.as_str().unwrap())
                .collect();
            assert_eq!(ccis, source.cci_idents().into_iter().collect());
            assert_eq!(rule["stig_uuid"], stig["uuid"]);
            assert_eq!(rule["STIGUuid"], stig["uuid"]);
            assert_eq!(rule["srg_id"], group.title);
            let uuid = rule["uuid"].as_str().unwrap();
            uuid::Uuid::parse_str(uuid).unwrap();
            assert!(uuids.insert(uuid));

            let selected = selected_groups.contains(&group.id.as_str());
            assert_eq!(
                rule["status"],
                if selected { "open" } else { "not_reviewed" }
            );
            assert_eq!(
                rule["finding_details"].as_str().unwrap().is_empty(),
                !selected
            );
        }
    }

    // A full obsolete revision must not silently select a different revision.
    let stale = Command::new(env!("CARGO_BIN_EXE_stitch-score"))
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "--cklb",
            "SV-222545r1043190_rule",
        ])
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert!(stale.stdout.is_empty());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("No database record found"));

    checklist
}

#[test]
fn asd_v6r5_cklb_preserves_benchmark_content() {
    let checklist = export_and_check(
        V6R5_EXCERPT,
        3,
        " SV-222545 , sv-222434R1263534_RULE ",
        &["V-222545", "V-222434"],
    );
    let rules = checklist["stigs"][0]["rules"].as_array().unwrap();
    let password = rules
        .iter()
        .find(|rule| rule["group_id"] == "V-222545")
        .unwrap();
    assert_eq!(password["rule_id_src"], "SV-222545r1263524_rule");
    assert_eq!(password["rule_version"], "APSC-DV-001770");
    assert_eq!(
        password["rule_title"],
        "The application must enforce a 180-day maximum password lifetime restriction."
    );
    assert_eq!(
        password["fix_text"],
        "Configure the application to have a maximum password lifetime of 180 days."
    );
    assert!(
        password["check_content"]
            .as_str()
            .unwrap()
            .contains("after 180 days")
    );
    assert_eq!(
        password["check_content_ref"]["href"],
        "Application_Security_and_Development_STIG.xml"
    );
}

#[test]
fn cklb_preserves_custom_metadata_and_empty_legacy_ids() {
    let xml = V6R5_EXCERPT
        .replace(
            "Application_Security_and_Development_STIG.xml",
            "custom-checks.xml",
        )
        .replace("name=\"M\"", "name=\"Custom\"")
        .replace(
            "&lt;GroupDescription&gt;&lt;/GroupDescription&gt;",
            "&lt;GroupDescription&gt;Source description&lt;/GroupDescription&gt;",
        )
        .replace(
            "<ident system=\"http://cyber.mil/legacy\">SV-84811</ident>",
            "",
        )
        .replace(
            "<ident system=\"http://cyber.mil/legacy\">V-70189</ident>",
            "",
        );
    let checklist = export_and_check(&xml, 3, "SV-222545,SV-222434", &["V-222545", "V-222434"]);
    let no_legacy = checklist["stigs"][0]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["group_id"] == "V-265634")
        .unwrap();
    assert_eq!(no_legacy["legacy_ids"], json!([]));
}

#[test]
#[ignore = "requires the full DISA archive in STITCH_ASD_V6R5_ZIP"]
fn asd_v6r5_full_archive() {
    let path = std::env::var_os("STITCH_ASD_V6R5_ZIP")
        .expect("Set STITCH_ASD_V6R5_ZIP to the supplied U_ASD_V6R5_STIG.zip");
    let file = std::fs::File::open(path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let mut xml = String::new();
    archive
        .by_name("U_ASD_V6R5_Manual_STIG/U_ASD_STIG_V6R5_Manual-xccdf.xml")
        .unwrap()
        .read_to_string(&mut xml)
        .unwrap();
    export_and_check(
        &xml,
        286,
        "SV-265634r1117183,SV-222614r1117151",
        &["V-265634", "V-222614"],
    );
}
