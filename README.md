# STITCH - Scoring Tool for Integrated Threat and Compliance Heuristics

STITCH, the Scoring Tool for Integrated Threat and Compliance Heuristics, is a Rust command-line tool that maps CWEs, CVEs, ASD STIG Rules, and RMF Controls to generate a CVSS version 4.0 score estimation.

STITCH is derived from the Public Domain "JFAC Scoring Procedure," a scoring estimation program vetted by the Joint Federated Assurance Center (JFAC).

The current scoring process is documented in [doc/scoring.md](doc/scoring.md).

## Acknowledgements

This software was developed, in whole or in part, under U.S. Government Contract No. ending in 24-F-B013 with the U.S. Army Combat Capabilities Development Command Aviation & Missile Center. For the full contract number, please contact the author(s) of this software.

Any opinions, findings, and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the U.S. Army or the Department of Defense.

## Installation

### Prerequisites
- Rust (1.96+)
- Internet connection (for downloading CWE, NVD, STIG, RMF, and Mapping data)

### Build from source
```bash
git clone <repository-url>
cd STITCH
cargo build --locked --release
```

## Usage

### Building the database (`stitch`)

The default ASD benchmark is **Application Security and Development Version: 6
Release: 5** (V6R5, benchmark date 30 Sep 2026), with STIGWE mappings pinned to
the [CWE 5.0 / V6R5 update](https://github.com/squinky86/STIGWE/commit/4a52cc1596d2eeec7df9fd9943d63ef71da6ebe5).

The builder reads MITRE's latest CWE catalog, including **CWE 5.0 / schema 8.0**.
Schema 8 `Grouping` entries use the existing database `category` flag and are
excluded from scoring, as are legacy categories, views, and deprecated entries.
Parent/child scoring traversal follows only `ChildOf` relationships in View
1000; relationships such as `Overlaps` are stored but do not establish ancestry.
The [manual CWE overrides](#manual-cwe-overrides) repair the disconnected
ancestry of CWE-378 and CWE-379 and allow CVE-derived impacts for missing scopes
such as CWE-1464's.

Rebuild existing databases to pick up CWE 5.0 and the updated STIGWE defaults.
For example, `SV-222389` now maps to `CWE-1463` instead of the deprecated
`CWE-613`. Updating the binaries alone does not refresh an existing database.

```bash
# Build database with default settings (writes to ./stitch.db)
./target/release/stitch

# Specify output file
./target/release/stitch --output my.db

# Verbose output
./target/release/stitch --verbose

# Override the ASD STIG download URL (e.g., when DISA cuts a new revision)
./target/release/stitch --stig-url https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_ASD_V6R5_STIG.zip
```

#### Options
- `-o, --output <FILE>`: Output database file path (default: `stitch.db`).
- `--stig-url <URL>`: Override the ASD STIG zip URL. HTTPS is required.
- `-v, --verbose`: Enable verbose output.
- `-h, --help`: Show help information.

### Scoring (`stitch-score`)

`stitch-score` dispatches on the first positional argument; the prefix selects the operation. Run `stitch-score --help` for the full list.

The scorer accepts databases completed by the current builder and opens them
read-only. Rebuild databases created by an older STITCH release so they include
the completion and source-provenance metadata.

```bash
# Score a CVSS vector directly (no database needed)
./target/release/stitch-score 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'

# Score by CVE
./target/release/stitch-score CVE-2021-44228

# Score by CWE
./target/release/stitch-score CWE-89

# Score by STIG rule (full or prefix)
./target/release/stitch-score SV-222387r960735_rule

# Score every CWE in the database (CSV to stdout)
./target/release/stitch-score CWES

# Export the complete STIG as CKLB JSON, marking the listed rules open
# Stable SV IDs select the current revision from the database.
./target/release/stitch-score -s SV-222387,SV-222545 > checklist.cklb

# Look up RMF control info by CCI(s)
./target/release/stitch-score -c CCI-000001,CCI-000002

# Look up RMF control info by control number(s)
./target/release/stitch-score -r AC-1,AU-2

# Verbose mode changes the output format from a single number / CSV row
# to a step-by-step trace of how the score was constructed.
./target/release/stitch-score -v CWE-89
```

CSV output uses standard quoting and prefixes cells that spreadsheet programs
could otherwise interpret as formulas.

CKLB exports use the benchmark and rule metadata stored in the database. Rebuild
existing databases with the updated `stitch` before exporting V6R5 checklists;
upgrading `stitch-score` alone does not update benchmark content. The current
schema also preserves the XCCDF check references and group descriptions. A V6R5
export identifies password-lifetime rule `SV-222545r1263524_rule` and its 180-day
maximum, along with `Release: 5 Benchmark Date: 30 Sep 2026`.

CKLB field names, types, and default mode follow the supplied CKLB 1.0 reference
exported by STIG Viewer. `group_id` and `group_id_src` contain the vulnerability ID;
`group_title` and `rule_title` contain the descriptive rule title. The SRG ID
remains in `srg_id` and `group_tree[].title`. Exports use `stig_uuid` for the
parent link, decimal strings such as `"10.0"` for weights, and trimmed STIG
display names, without additional STITCH-specific fields.

The benchmark identity **Application Security and Development Version: 6
Release: 5** is stored in separate CKLB fields, as in STIG Viewer:

| Field | Value |
| --- | --- |
| `display_name` | `Application Security and Development` |
| `version` | `6` |
| `release_info` | `Release: 5 Benchmark Date: 30 Sep 2026` |

`stig_name` retains the full official title, `Application Security and Development
Security Technical Implementation Guide`.

## Manual CWE overrides

STITCH applies the following local corrections when importing CWE data. These
are STITCH scoring decisions, not relationships or impact declarations supplied
by MITRE. Rebuild the database with the updated builder to apply them; updating
only `stitch-score` does not change an existing database.

### CWE-378 and CWE-379: restore the scoring ancestry

[CWE-378 — Creation of Temporary File With Insecure Permissions](https://cwe.mitre.org/data/definitions/378.html)
and
[CWE-379 — Creation of Temporary File in Directory with Insecure Permissions](https://cwe.mitre.org/data/definitions/379.html)
still point to CWE-377 in CWE 5.0, although that release deprecated CWE-377 and
removed its parent relationships. This disconnects both weaknesses from the
ancestor CVEs used to estimate their scores. In the October 29, 2026 database,
their direct CVE mappings are all secondary and therefore excluded by the
scoring policy.

STITCH adds `CWE-378 ChildOf CWE-668` and `CWE-379 ChildOf CWE-668` in View 1000,
retaining their original relationships to CWE-377. CWE-668, "Exposure of
Resource to Wrong Sphere," was their former grandparent and covers exposing
a temporary file through insecure file permissions (CWE-378) or directory
permissions (CWE-379). Both become children of CWE-668 under CWE-664.

Each override applies independently, only when that weakness's sole View-1000
`ChildOf` parent is the deprecated CWE-377, the weakness and CWE-668 are active,
and View 1000 is present. An existing edge is not duplicated, and a different
ancestry supplied by the source catalog takes precedence. The primary-CVE
filter, five-CVE minimum, and each weakness's declared impact scopes remain
in effect.

### CWE-1464: preserve impacts when the catalog omits scopes

[CWE-1464 — Improper Session Invalidation](https://cwe.mitre.org/data/definitions/1464.html)
is a Base weakness whose CWE 5.0 entry declares no impact scopes. Treating that
omission as no Confidentiality, Integrity, or Availability impact produced a
false zero score.

STITCH allows all three impact dimensions for any weakness with **no declared
scopes**, then derives their values from the selected CVEs. This generalizes
the earlier Class-only fallback to include CWE-1464; it does not assign a fixed
score or force high impacts. Explicitly declared scopes retain their meaning,
and categories/groupings and views do not receive this fallback. A weakness
still needs enough qualifying CVEs to receive a vector.

The implementation and regression tests are in `src/cwe.rs` and `tests/cwe5.rs`.

## Data integrity

Database builds use HTTPS-only downloads, per-feed size limits, and SHA-256
source records in the `SourceMetadata` table. NVD feeds are checked against
NIST's published size and SHA-256 metadata. A build is written to a secure
temporary file and replaces the requested output atomically only after SQLite
integrity and foreign-key checks pass. If a download or parser fails, an
existing output database remains unchanged.

## Example Queries

Once the database is built, you can query it with any SQLite tool.

### Find all weaknesses related to SQL Injection
```sql
SELECT id, name, description
FROM Weakness
WHERE name LIKE '%SQL%' OR description LIKE '%SQL injection%';
```

### Get all child weaknesses of a specific CWE (View 1000)
```sql
SELECT child.id, child.name, r.nature
FROM WeaknessRelationship r
JOIN Weakness child ON child.id = r.source_id
WHERE r.target_id = 89 AND r.nature = 'ChildOf' AND r.view_id = 1000;
```

## Dependencies

- `tokio` - Async runtime
- `reqwest` - HTTP client for downloading
- `rusqlite` - SQLite interface
- `quick-xml` - XML parsing
- `clap` - Command line parsing
- `anyhow` - Error handling
- `zip` - Archive extraction
- `tempfile` - Temporary file handling
- `serde` - JSON, XML, and YAML mapping
- `serde_yaml2` - serde YAML interface
- `serde_json` - serde JSON interface
- `csv` - safe CSV serialization
- `sha2` - source integrity hashing
- `futures-util` - common containers
- `regex` - regular expression handling
- `chrono` - access system clock
- `flate2` - file decompression
- `indicatif` - progress bars
- `cvss` - CVSS 4.0 scoring
- `uuid` - UUIDs for STIG generation

## Contributing

Please submit pull requests or issues.

The CKLB integration tests include matching V6R5 XCCDF and STIG Viewer CKLB
excerpts and run offline with `cargo test --locked --all-targets`. The CKLB
fixture comes from STIG Viewer's `empty.cklb`, with only the rule list and size
reduced to the three XCCDF fixture rules. Tests compare all field names, types,
and benchmark content, allowing per-export IDs, target names, selected findings,
line endings, and CCI/legacy-ID ordering to differ. To also compare all 286 rules
in the original DISA archive through database ingestion and CKLB export:

```bash
STITCH_ASD_V6R5_ZIP=../STIGWE/U_ASD_V6R5_STIG.zip \
  cargo test --locked --test cklb asd_v6r5_full_archive -- --ignored
```

Set `STITCH_ASD_V6R5_CKLB=/path/to/empty.cklb` as well to compare the complete
export with a STIG Viewer reference for that benchmark.

CWE 5.0 tests include catalog and STIGWE excerpts, cover schema 7 compatibility,
and exercise the new default mappings through database ingestion and scoring.
To validate the complete CWE 5.0 catalog and STIGWE mappings against ASD V6R5:

```bash
STITCH_CWE_V5_ZIP=/path/to/cwec_v5.0.xml.zip \
STITCH_ASD_V6R5_ZIP=../STIGWE/U_ASD_V6R5_STIG.zip \
STITCH_STIGWE_YAML=../STIGWE/mappings/mappings.yaml \
  cargo test --locked --test cwe5 full_cwe_v5_and_stigwe_catalogs -- --ignored
```

## Copyright and License

Copyright (c) 2025 Jon Hood

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Note**: This tool is not affiliated with MITRE Corporation.
