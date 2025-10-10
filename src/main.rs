mod db;
mod common;
mod cwe;
mod rmf;
mod cci;
mod stig;
mod stigwe;
mod nvd;

use crate::db::{create_database,display_database_summary};
use crate::cci::process_cci;
use crate::common::Args;
use crate::cwe::process_cwe;
use crate::nvd::process_nvd;
use crate::rmf::process_rmf;
use crate::stig::process_stig;
use crate::stigwe::process_stigwe;
use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
	let args = Args::parse();

	println!("RuskTeX Database Builder v0.1.0");

	// DB Structure
	let conn = create_database(&args.output)?;

	// CWE Data
	process_cwe(&conn, &args).await?;

	// RMF Data
	process_rmf(&conn, &args).await?;

	// CCI Data
	process_cci(&conn, &args).await?;

	// STIG Data
	process_stig(&conn, &args).await?;

	// STIG↔CWE Mapping Data
	process_stigwe(&conn, &args).await?;

	// NVD Data
	process_nvd(&conn, &args).await?;

	// Display summary
	display_database_summary(&conn)?;

	println!("\nCWE database build completed successfully: {}", args.output);
	Ok(())
}
