//! Regression tests over the fixture corpus.
//!
//! Each fixture encodes one claim about CAP-0063 clustering. If a change to the
//! classifier alters any of these, that is either a fix worth explaining in the
//! pull request or a regression — but never something to notice in production.

use braid_core::{analyze_path, KeyClass, Report, Severity};
use std::path::Path;

fn run(name: &str) -> Report {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);
    let (report, errors) = analyze_path(&path);
    assert!(errors.is_empty(), "{name}: parse errors: {errors:?}");
    report
}

fn severities(r: &Report, s: Severity) -> Vec<&str> {
    r.findings
        .iter()
        .filter(|f| f.severity == s)
        .map(|f| f.access.function.as_str())
        .collect()
}

#[test]
fn good_registry_is_completely_clean() {
    let r = run("good_registry");
    assert!(
        r.findings.is_empty(),
        "expected no findings, got: {:?}",
        r.findings.iter().map(|f| &f.summary).collect::<Vec<_>>()
    );
    assert!(r.conflict_edges.is_empty());
    assert_eq!(r.exit_code(Some(Severity::Info)), 0);
}

#[test]
fn clean_token_has_no_actionable_findings() {
    let r = run("clean_token");
    assert_eq!(severities(&r, Severity::Critical).len(), 0);
    assert_eq!(severities(&r, Severity::Warning).len(), 0);
    // Per-address balances in persistent storage must never form an edge:
    // Balance(alice) and Balance(bob) are different ledger entries.
    assert!(
        r.conflict_edges.is_empty(),
        "subject-derived keys must not conflict, got {:?}",
        r.conflict_edges
    );
    assert!(r
        .parallel_safe_entry_points
        .contains(&"transfer".to_string()));
}

#[test]
fn hot_counter_flags_the_shared_counter_write() {
    let r = run("hot_counter");
    let crit = severities(&r, Severity::Critical);
    assert_eq!(
        crit,
        vec!["create_job"],
        "the Seq write is the critical one"
    );

    let seq_write = r
        .findings
        .iter()
        .find(|f| f.severity == Severity::Critical)
        .unwrap();
    assert_eq!(seq_write.access.key_root, "DataKey::Seq");
    assert!(matches!(seq_write.access.class, KeyClass::Static));
}

#[test]
fn hot_counter_attributes_the_sequence_derived_key_to_its_counter() {
    let r = run("hot_counter");
    let job = r
        .findings
        .iter()
        .find(|f| {
            f.access.key_root == "DataKey::Job" && f.access.access == braid_core::Access::Write
        })
        .expect("DataKey::Job write should be reported");

    match &job.access.class {
        KeyClass::SequenceDerived { counter } => {
            assert!(
                counter.contains("DataKey::Seq"),
                "counter should be attributed to Seq, got {counter}"
            );
        }
        other => panic!("expected sequence-derived, got {other:?}"),
    }
    assert_eq!(job.severity, Severity::Warning);
}

#[test]
fn constructor_writes_are_not_reported() {
    // A constructor runs once and cannot race. Reporting it is noise, and noise
    // is how a tool gets muted.
    for fixture in [
        "hot_counter",
        "clean_token",
        "instance_trap",
        "good_registry",
    ] {
        let r = run(fixture);
        assert!(
            !r.findings
                .iter()
                .any(|f| f.access.function == "__constructor"),
            "{fixture}: constructor should produce no findings"
        );
    }
}

#[test]
fn instance_storage_defeats_a_per_subject_key() {
    let r = run("instance_trap");
    let crit = severities(&r, Severity::Critical);
    assert!(crit.contains(&"deposit"));
    assert!(crit.contains(&"withdraw"));

    // The key *is* subject-derived — the finding is about where it lives.
    let dep = r
        .findings
        .iter()
        .find(|f| f.access.function == "deposit")
        .unwrap();
    assert!(matches!(dep.access.class, KeyClass::SubjectDerived { .. }));
    assert_eq!(dep.access.durability, braid_core::Durability::Instance);
    assert!(dep.summary.contains("instance storage"));

    assert_eq!(r.conflict_edges.len(), 1);
    assert_eq!(
        r.conflict_edges[0].key_root,
        braid_core::analyze::INSTANCE_DOMAIN
    );
}

#[test]
fn global_supply_flags_the_aggregate_but_not_the_balances() {
    let r = run("global_supply");
    let crit = severities(&r, Severity::Critical);
    assert!(crit.contains(&"mint"));
    assert!(crit.contains(&"burn"));

    for f in r
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
    {
        assert_eq!(
            f.access.key_root, "DataKey::TotalSupply",
            "only the shared aggregate is critical; per-address balances are not"
        );
    }

    // The admin write to FeeBps is real but rare.
    let fee = r
        .findings
        .iter()
        .find(|f| f.access.function == "set_fee")
        .unwrap();
    assert_eq!(fee.severity, Severity::Warning);

    // quote() only reads, so it must never be critical.
    assert!(!crit.contains(&"quote"));
}

#[test]
fn reads_alone_never_produce_a_conflict_edge() {
    for fixture in [
        "clean_token",
        "good_registry",
        "hot_counter",
        "global_supply",
    ] {
        let r = run(fixture);
        for e in &r.conflict_edges {
            let has_writer = r.findings.iter().any(|f| {
                f.access.key_root == e.key_root && f.access.access == braid_core::Access::Write
            }) || e.key_root == braid_core::analyze::INSTANCE_DOMAIN;
            assert!(
                has_writer,
                "{fixture}: edge on {} has no writer",
                e.key_root
            );
        }
    }
}

#[test]
fn fail_on_thresholds_map_to_exit_codes() {
    let clean = run("good_registry");
    let dirty = run("instance_trap");

    assert_eq!(clean.exit_code(Some(Severity::Critical)), 0);
    assert_eq!(clean.exit_code(None), 0);
    assert_eq!(dirty.exit_code(Some(Severity::Critical)), 1);
    assert_eq!(dirty.exit_code(Some(Severity::Warning)), 1);
    assert_eq!(dirty.exit_code(None), 0, "no threshold means never fail");
}

#[test]
fn every_actionable_finding_carries_a_remediation() {
    for fixture in ["hot_counter", "instance_trap", "global_supply"] {
        let r = run(fixture);
        for f in r.findings.iter().filter(|f| f.severity > Severity::Info) {
            assert!(
                f.remediation.len() > 80,
                "{fixture}: {} has no real remediation",
                f.summary
            );
        }
    }
}

#[test]
fn json_schema_round_trips() {
    let r = run("hot_counter");
    let json = serde_json::to_string(&r).unwrap();
    let back: Report = serde_json::from_str(&json).unwrap();
    assert_eq!(back.schema_version, braid_core::SCHEMA_VERSION);
    assert_eq!(back.findings.len(), r.findings.len());
}
