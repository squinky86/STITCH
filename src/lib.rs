// Copyright (c) 2025 Jon Hood
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Structural design: rusqlite Connection is !Send; all DB work runs on a single
// thread, so async fns that hold &Connection are intentionally not Send.
#![allow(clippy::future_not_send)]
// Internal APIs don't need # Errors / # Panics doc sections.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
// XML and JSON parser functions are inherently long; splitting adds indirection
// without clarity.
#![allow(clippy::too_many_lines)]

// scoring.md uses trailing double-space for line breaks (CommonMark) and LaTeX
// math notation that looks like format args; suppress false-positive lints.
#[allow(clippy::doc_comment_double_space_linebreaks, clippy::doc_markdown)]
#[doc = include_str!("../doc/scoring.md")]
pub mod cci;
pub mod common;
pub mod cwe;
pub mod db;
pub mod nvd;
pub mod rmf;
pub mod stig;
pub mod stigwe;
