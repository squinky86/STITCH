# RuskTeX

A Rust command-line tool that maps CWEs, CVEs, ASD STIG Rules, and RMF Controls

RuskTeX derives its name from an internal tool called "RiskTeX" which was used to generate LaTeX-formatted risk reports with previous CVSS versions.

## Installation

### Prerequisites
- Rust (1.85+)
- Internet connection (for downloading CWE data)

### Build from source
```bash
git clone <repository-url>
cd RuskTeX
cargo build --release
```

## Usage

### Basic usage
```bash
# Build database with default settings
./target/release/RuskTeX

# Specify output file
./target/release/RuskTeX --output my_cwe.db

# Verbose output
./target/release/RuskTeX --verbose

# Force re-download even if XML exists
./target/release/RuskTeX --force
```

### Command-line options
- `-o, --output <FILE>`: Output database file path (default: cwe_database.db)
- `-f, --force`: Force download even if XML file exists
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

## Error Handling

The tool includes comprehensive error handling for:
- Network connectivity issues
- XML parsing errors
- Database creation/insertion errors
- File system errors

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Note**: This tool is not affiliated with MITRE Corporation. It simply provides a convenient way to work with their publicly available CWE data.
