//! Core data model: what Braid observes, how it classifies it, and what it reports.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Which Soroban storage durability an access targets.
///
/// Temporary entries still participate in footprints and therefore still cause
/// conflicts, so Braid does not exempt them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Durability {
    Instance,
    Persistent,
    Temporary,
}

impl fmt::Display for Durability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Durability::Instance => "instance",
            Durability::Persistent => "persistent",
            Durability::Temporary => "temporary",
        };
        f.write_str(s)
    }
}

/// Whether an access reads or writes the entry.
///
/// The distinction is the single most important input to severity: under
/// CAP-0063 two transactions conflict only when at least one of them *writes*
/// the shared entry. Read-only sharing is free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
}

impl Access {
    /// Map a Soroban storage method name onto an access kind.
    ///
    /// `extend_ttl` is a write to the entry's TTL, but TTL bumps do not place
    /// the entry in the transaction's read-write footprint the way a value
    /// write does, so Braid records it as a read. This is deliberate: treating
    /// every `extend_ttl` as a conflict would flag the unpermissioned rent
    /// extension that good Soroban contracts are supposed to have.
    pub fn from_method(name: &str) -> Option<Self> {
        match name {
            "get" | "try_get" | "has" => Some(Access::Read),
            "extend_ttl" | "bump" => Some(Access::Read),
            "set" | "remove" | "update" => Some(Access::Write),
            _ => None,
        }
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Access::Read => "read",
            Access::Write => "write",
        })
    }
}

/// How a storage key is derived, which is what decides whether two callers
/// touch the same ledger entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyClass {
    /// A fixed key with no parameters — `DataKey::Admin`.
    ///
    /// Every caller touches the same ledger entry. A write here serialises
    /// every transaction that reaches it.
    Static,

    /// Parameterised by a value the caller supplies — `DataKey::Balance(addr)`.
    ///
    /// Different callers touch different entries. Parallel-safe.
    SubjectDerived { param: String },

    /// Parameterised by a value read from a static entry — `DataKey::Job(id)`
    /// where `id` came from `DataKey::Seq`.
    ///
    /// The trap. The key looks parameterised, but minting the parameter
    /// required reading and bumping a shared counter, so every caller still
    /// serialises on that counter.
    SequenceDerived { counter: String },

    /// Braid could not resolve the key expression.
    ///
    /// Reported honestly as unknown rather than assumed safe. A tool that
    /// silently downgrades what it cannot understand gives a false clean bill
    /// of health, which is worse than no tool.
    Unresolvable { reason: String },
}

impl KeyClass {
    pub fn label(&self) -> &'static str {
        match self {
            KeyClass::Static => "static",
            KeyClass::SubjectDerived { .. } => "subject-derived",
            KeyClass::SequenceDerived { .. } => "sequence-derived",
            KeyClass::Unresolvable { .. } => "unresolvable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "warning" | "warn" => Some(Severity::Warning),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A single storage access site found in the source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAccess {
    pub file: String,
    pub line: usize,
    pub column: usize,
    /// The enclosing function's name.
    pub function: String,
    /// Whether that function is a public contract entry point.
    pub entry_point: bool,
    /// Whether that entry point looks like an admin or configuration path,
    /// which changes how often it is expected to run.
    pub admin_path: bool,
    pub durability: Durability,
    pub access: Access,
    /// The key expression as written, e.g. `DataKey::Balance(addr)`.
    pub key_expr: String,
    /// A stable identity for the entry the key names, e.g. `DataKey::Balance`.
    pub key_root: String,
    pub class: KeyClass,
}

/// One line of source context attached to a finding.
///
/// Carried in the report so a viewer — or a reviewer reading the JSON months
/// later — can see the offending code without the working tree it came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLine {
    pub number: usize,
    pub text: String,
    /// True for the line the finding points at.
    pub hit: bool,
}

/// A conflict Braid is reporting, with the remediation that goes with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub access: StorageAccess,
    /// One sentence naming what is wrong.
    pub summary: String,
    /// What to do about it, with a code sketch where one helps.
    pub remediation: String,
    /// Other entry points that touch the same entry, so the reader can see the
    /// blast radius rather than only the site.
    pub also_touched_by: Vec<String>,
    /// Source lines around the finding. Populated only with `--include-source`,
    /// because embedding source makes reports much larger and is not always
    /// wanted in CI artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<SourceLine>,
}

/// Two entry points that cannot run in parallel, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictEdge {
    pub a: String,
    pub b: String,
    pub key_root: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub files_scanned: usize,
    pub functions_scanned: usize,
    pub accesses_found: usize,
    pub entry_points: usize,
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
}

/// Schema version for `--format json`.
///
/// Downstream consumers pin this. Bump it on any breaking shape change.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub target: String,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub conflict_edges: Vec<ConflictEdge>,
    /// Entry points with no conflicting access at all. Worth naming: it is the
    /// evidence that the analyser is discriminating rather than flagging
    /// everything.
    pub parallel_safe_entry_points: Vec<String>,
    /// Entry points that conflict with *themselves*: two concurrent calls to
    /// the same function serialise because it writes a shared entry. There is
    /// no edge to draw for these — the pair is the function and itself — so
    /// they are listed separately rather than being invisible.
    #[serde(default)]
    pub self_conflicting_entry_points: Vec<String>,
}

impl Report {
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Exit code for CI: 1 when any finding is at or above `fail_on`.
    pub fn exit_code(&self, fail_on: Option<Severity>) -> i32 {
        match (fail_on, self.worst_severity()) {
            (Some(threshold), Some(worst)) if worst >= threshold => 1,
            _ => 0,
        }
    }
}
