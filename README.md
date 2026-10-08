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

The default ASD benchmark is **V6R5** (Release 5, benchmark date 30 Sep 2026),
with STIGWE mappings pinned to the corresponding V6R5 update.

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

The CKLB integration tests include a small V6R5 XCCDF excerpt and run offline
with `cargo test --locked --all-targets`. To also compare all 286 rules in the
original DISA archive through database ingestion and CKLB export:

```bash
STITCH_ASD_V6R5_ZIP=../STIGWE/U_ASD_V6R5_STIG.zip \
  cargo test --locked --test cklb asd_v6r5_full_archive -- --ignored
```

## Copyright and License

Copyright (c) 2025 Jon Hood

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Note**: This tool is not affiliated with MITRE Corporation.
