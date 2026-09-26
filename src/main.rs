// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use anyhow::Result;
use clap::Parser;
use stitch::cci::process_cci;
use stitch::common::Args;
use stitch::cwe::process_cwe;
use stitch::db::{create_database, display_database_summary};
use stitch::nvd::process_nvd;
use stitch::rmf::process_rmf;
use stitch::stig::process_stig;
use stitch::stigwe::process_stigwe;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("STITCH Database Builder v{}", env!("CARGO_PKG_VERSION"));
    println!("Copyright © 2025-2026 Jon Hood");

    // DB Structure
    let database = create_database(&args.output)?;
    let conn = database.connection();

    // CWE Data
    process_cwe(conn, &args).await?;

    // RMF Data
    process_rmf(conn, &args).await?;

    // CCI Data
    process_cci(conn, &args).await?;

    // STIG Data
    process_stig(conn, &args).await?;

    // STIG↔CWE Mapping Data
    process_stigwe(conn, &args).await?;

    // NVD Data
    process_nvd(conn, &args).await?;

    // Display summary
    display_database_summary(conn)?;
    database.publish()?;

    println!(
        "\nSTITCH database build completed successfully: {}",
        args.output
    );
    Ok(())
}
