# STITCH - Scoring Tool for Integrated Threat and Compliance Heuristics

STITCH, the Scoring Tool for Integrated Threat and Compliance Heuristics, is a Rust command-line tool that maps CWEs, CVEs, ASD STIG Rules, and RMF Controls to generate a CVSS version 4.0 score estimation.

STITCH is derived from the Public Domain "JFAC Scoring Procedure," a scoring estimation program vetted by the Joint Federated Assurance Center (JFAC).

The current scoring process is documented in [doc/scoring.md](doc/scoring.md).

## Acknowledgements

This software was developed, in whole or in part, under U.S. Government Contract No. ending in 24-F-B013 with the U.S. Army Combat Capabilities Development Command Aviation & Missile Center. For the full contract number, please contact the author(s) of this software.

Any opinions, findings, and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the U.S. Army or the Department of Defense.

## Installation

### Prerequisites
- Rust (1.88+)
- Internet connection (for downloading CWE, NVD, STIG, RMF, and Mapping data)

### Build from source
```bash
git clone <repository-url>
cd STITCH
cargo build --release
```

## Usage

### Building the database (`stitch`)

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
- `--stig-url <URL>`: Override the ASD STIG zip URL.
- `-v, --verbose`: Enable verbose output.
- `-h, --help`: Show help information.

### Scoring (`stitch-score`)

`stitch-score` dispatches on the first positional argument; the prefix selects the operation. Run `stitch-score --help` for the full list.

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

# Export STIG checks for a comma-separated list of rule IDs as CKLB JSON
./target/release/stitch-score -s SV-222387r960735_rule,SV-222388r1043182_rule

# Look up RMF control info by CCI(s)
./target/release/stitch-score -c CCI-000001,CCI-000002

# Look up RMF control info by control number(s)
./target/release/stitch-score -r AC-1,AU-2

# Verbose mode changes the output format from a single number / CSV row
# to a step-by-step trace of how the score was constructed.
./target/release/stitch-score -v CWE-89
```

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
- `futures-util` - common containers
- `regex` - regular expression handling
- `chrono` - access system clock
- `flate2` - file decompression
- `indicatif` - progress bars
- `once_cell` - lazy loading of values
- `cvss` - CVSS 4.0 scoring
- `lazy_static` - lazy loading of regexes
- `uuid` - UUIDs for STIG generation

## Contributing

Please submit pull requests or issues.

## Copyright and License

Copyright (c) 2025 Jon Hood

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Note**: This tool is not affiliated with MITRE Corporation.
