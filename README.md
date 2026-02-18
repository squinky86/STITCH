# STITCH - Scoring Tool for Integrated Threat and Compliance Heuristics

STITCH, the Scoring Tool for Integrated Threat and Compliance Heuristics, is a Rust command-line tool that maps CWEs, CVEs, ASD STIG Rules, and RMF Controls to generate a CVSS version 4.0 score estimation.

STITCH is derived from the Public Domain "JFAC Scoring Procedure," a scoring estimation program vetted by the Joint Federated Assurance Center (JFAC).

The current scoring process is documented in [doc/scoring.md](doc/scoring.md).

## Acknowledgements

This software was developed, in whole or in part, under U.S. Government Contract No. ending in 24-F-B013 with the U.S. Army, DEVCOM AvMC. For the full contract number, please contact the author(s) of this software.

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

### Basic usage
```bash
# Build database with default settings
./target/release/stitch

# Specify output file
./target/release/stitch --output my_cwe.db

# Verbose output
./target/release/stitch --verbose

# Score a specific CWE
./target/release/stitch-score CWE-119
```

### Command-line options
- `-o, --output <FILE>`: Output database file path (default: cwe_database.db)
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Show help information

## Example Queries

Once the database is built, you can query it with any SQLite tool:

### Find all weaknesses related to SQL Injection
```sql
SELECT e.id, e.name, e.description 
FROM Weakness e
WHERE e.name LIKE '%SQL%' OR e.description LIKE '%SQL injection%';
```

### Get all child weaknesses of a specific CWE
```sql
SELECT target.id, target.name, r.nature
FROM Weakness r
JOIN WeaknessRelationship target ON r.target_id = target.id
WHERE r.source_id = '89' AND r.nature = 'ChildOf';
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
- `openssl` - set to vendor mode as a subdependency for static building

## Contributing

Please submit pull requests or issues.

## Copyright and License

Copyright (c) 2025 Jon Hood

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Note**: This tool is not affiliated with MITRE Corporation.
