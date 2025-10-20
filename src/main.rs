// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use stitch::cci::process_cci;
use stitch::common::Args;
use stitch::cwe::process_cwe;
use stitch::db::{create_database, display_database_summary};
use stitch::nvd::process_nvd;
use stitch::rmf::process_rmf;
use stitch::stig::process_stig;
use stitch::stigwe::process_stigwe;
use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
	let args = Args::parse();

	println!("STITCH Database Builder v0.1.0");
	println!("Copyright © 2025 Jon Hood");

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
