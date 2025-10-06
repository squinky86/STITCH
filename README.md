# CWE Database Builder

A Rust command-line tool that downloads the latest Common Weakness Enumeration (CWE) XML data from MITRE and builds a comprehensive SQLite database with weakness entries and their relationships.

## Features

- 🚀 **Automatic Download**: Downloads the latest CWE XML data from MITRE automatically
- 🗄️ **SQLite Database**: Creates a well-structured SQLite database with proper indexing
- 🔗 **Relationship Mapping**: Stores CWE relationships including nature and view context
- 📊 **Comprehensive Schema**: Supports weaknesses, categories, views, and their relationships
- ⚡ **Fast Processing**: Efficient XML parsing and database operations
- 🛠️ **Command Line Interface**: Easy to use with various options

## Database Schema

The tool creates four main tables:

### `cwe_entries` (Main CWE Weaknesses)
- `id` - CWE identifier (e.g., "79", "89", "200")
- `name` - Weakness name
- `description` - Main description
- `extended_description` - Additional details (optional)
- `abstraction` - Abstraction level (Class, Base, Variant, etc.)
- `structure` - Structure type
- `status` - Status (Draft, Stable, etc.)

### `cwe_relationships` (Mapping Table)
- `source_id` - Source CWE ID
- `target_id` - Target CWE ID
- `nature` - Relationship nature (ChildOf, ParentOf, MemberOf, etc.)
- `view_id` - View context (optional)

### `cwe_categories`
- `id` - Category identifier
- `name` - Category name
- `description` - Category description
- `status` - Status

### `cwe_views`
- `id` - View identifier
- `name` - View name
- `description` - View description
- `status` - Status

## Installation

### Prerequisites
- Rust (1.70+)
- Internet connection (for downloading CWE data)

### Build from source
```bash
git clone <repository-url>
cd cwe-database-builder
cargo build --release
```

## Usage

### Basic usage
```bash
# Build database with default settings
./target/release/cwe_database_builder

# Specify output file
./target/release/cwe_database_builder --output my_cwe.db

# Verbose output
./target/release/cwe_database_builder --verbose

# Force re-download even if XML exists
./target/release/cwe_database_builder --force

# Keep XML files after processing
./target/release/cwe_database_builder --keep-xml
```

### Command-line options
- `-o, --output <FILE>`: Output database file path (default: cwe_database.db)
- `-f, --force`: Force download even if XML file exists
- `-k, --keep-xml`: Keep downloaded XML file after processing
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Show help information

## Example Queries

Once the database is built, you can query it with any SQLite tool:

### Find all weaknesses related to SQL Injection
```sql
SELECT e.id, e.name, e.description 
FROM cwe_entries e
WHERE e.name LIKE '%SQL%' OR e.description LIKE '%SQL injection%';
```

### Get all child weaknesses of a specific CWE
```sql
SELECT target.id, target.name, r.nature
FROM cwe_relationships r
JOIN cwe_entries target ON r.target_id = target.id
WHERE r.source_id = '89' AND r.nature = 'ChildOf';
```

### Find relationships by nature
```sql
SELECT source.name as source_name, 
       target.name as target_name, 
       r.nature, 
       r.view_id
FROM cwe_relationships r
JOIN cwe_entries source ON r.source_id = source.id
JOIN cwe_entries target ON r.target_id = target.id
WHERE r.nature = 'ParentOf'
ORDER BY source.name;
```

### Count relationships by type
```sql
SELECT nature, COUNT(*) as count 
FROM cwe_relationships 
GROUP BY nature 
ORDER BY count DESC;
```

## Data Source

This tool downloads data from:
- **URL**: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
- **Format**: MITRE CWE XML Schema
- **Updates**: The tool always downloads the latest version

## Dependencies

- `tokio` - Async runtime
- `reqwest` - HTTP client for downloading
- `rusqlite` - SQLite interface
- `quick-xml` - XML parsing
- `clap` - Command line parsing
- `anyhow` - Error handling
- `zip` - Archive extraction

## Performance

- **Download**: ~2-10MB compressed XML file
- **Processing**: Typical processing time is under 30 seconds
- **Database Size**: Final database is typically 15-25MB
- **Memory Usage**: Low memory footprint with streaming XML parsing

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

## Acknowledgments

- MITRE Corporation for maintaining the CWE database
- The CWE Community for their ongoing contributions
- Rust community for excellent libraries

---

**Note**: This tool is not affiliated with MITRE Corporation. It simply provides a convenient way to work with their publicly available CWE data.
