//! Braid: does this Soroban contract's storage design allow it to run in
//! parallel?
//!
//! Protocol 23 (CAP-0063) executes Soroban transactions in parallel, grouping
//! them into sequential clusters by their declared footprints. Two transactions
//! that share a ledger entry, where at least one writes it, cannot run at the
//! same time. Because Soroban footprints are *declared* rather than discovered
//! at runtime, whether a contract can parallelise is a static property of how
//! it derives its storage keys — and therefore something a tool can check
//! before the contract is ever deployed.
//!
//! Braid answers that one question. It is not a security scanner and not a
//! resource profiler; those are covered elsewhere in the Soroban ecosystem.

pub mod analyze;
pub mod model;
pub mod parse;

pub use analyze::analyze;
pub use model::{
    Access, ConflictEdge, Durability, Finding, KeyClass, Report, Severity, StorageAccess, Summary,
    SCHEMA_VERSION,
};

use std::path::Path;

/// Scan a path and produce a report. The entry point for library users.
pub fn analyze_path(path: &Path) -> (Report, Vec<(String, String)>) {
    let scan = parse::scan(path);
    let errors = scan.parse_errors.clone();
    let report = analyze(&path.display().to_string(), &scan);
    (report, errors)
}
