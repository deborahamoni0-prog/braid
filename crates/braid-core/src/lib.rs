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
    Access, ConflictEdge, Durability, Finding, KeyClass, Report, Severity, SourceLine,
    StorageAccess, Summary, SCHEMA_VERSION,
};

use std::path::Path;

/// Scan a path and produce a report. The entry point for library users.
pub fn analyze_path(path: &Path) -> (Report, Vec<(String, String)>) {
    let scan = parse::scan(path);
    let errors = scan.parse_errors.clone();
    let report = analyze(&path.display().to_string(), &scan);
    (report, errors)
}

/// Attach source context to every finding, reading each file once.
///
/// Kept out of `analyze` so the core stays filesystem-free and callers decide
/// whether the extra weight is worth it.
pub fn attach_source(report: &mut Report, radius: usize) {
    use std::collections::HashMap;
    let mut cache: HashMap<String, Vec<String>> = HashMap::new();
    for f in &mut report.findings {
        let lines = cache.entry(f.access.file.clone()).or_insert_with(|| {
            std::fs::read_to_string(&f.access.file)
                .map(|s| s.lines().map(str::to_string).collect())
                .unwrap_or_default()
        });
        if lines.is_empty() {
            continue;
        }
        let start = f.access.line.saturating_sub(radius).max(1);
        let end = (f.access.line + radius).min(lines.len());
        f.context = (start..=end)
            .map(|n| model::SourceLine {
                number: n,
                text: lines.get(n - 1).cloned().unwrap_or_default(),
                hit: n == f.access.line,
            })
            .collect();
    }
}
