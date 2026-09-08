//! Classification, conflict-graph construction, and remediation.
//!
//! This is where scanned syntax becomes a claim about parallel execution.
//! Every rule here traces to CAP-0063: two transactions land in the same
//! sequential cluster when their declared footprints share a ledger entry and
//! at least one of them writes it.

use crate::model::*;
use crate::parse::{ArgOrigin, FunctionInfo, ScanResult};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Everything under `instance()` lives in **one** ledger entry — the contract
/// instance — regardless of how many `DataKey` variants you put in it.
///
/// This is the rule that surprises people. A per-address key in instance
/// storage is not parallel-safe, because the address never separated anything:
/// all instance keys share a single entry, so every instance write in the
/// contract conflicts with every other one.
pub const INSTANCE_DOMAIN: &str = "<contract instance>";

/// The ledger entry an access actually touches, which is what conflicts.
fn conflict_domain(durability: Durability, key_root: &str) -> String {
    match durability {
        Durability::Instance => INSTANCE_DOMAIN.to_string(),
        _ => key_root.to_string(),
    }
}

/// Whether two different callers reaching this access land on the *same* ledger
/// entry.
///
/// A subject-derived key outside instance storage does not: `Balance(alice)` and
/// `Balance(bob)` are separate entries, so two callers never collide there. Only
/// domains where the entry is genuinely shared can produce a conflict.
fn is_shared_domain(durability: Durability, class: &KeyClass) -> bool {
    if durability == Durability::Instance {
        return true;
    }
    !matches!(class, KeyClass::SubjectDerived { .. })
}

/// A function that can only ever run once, so it cannot race anything.
///
/// Excluded from the conflict graph: an edge to the constructor is technically
/// true and practically useless, and noise is how a tool gets muted.
fn runs_once(name: &str) -> bool {
    matches!(name, "__constructor" | "initialize" | "init")
}

pub fn analyze(target: &str, scan: &ScanResult) -> Report {
    let counters = find_counter_functions(&scan.functions);

    // Classify every access.
    let mut classified: Vec<StorageAccess> = Vec::new();
    for f in &scan.functions {
        let admin = f.is_admin_path();
        for raw in &f.accesses {
            let class = classify_key(f, raw, &counters);
            classified.push(StorageAccess {
                file: f.file.clone(),
                line: raw.line,
                column: raw.column,
                function: f.name.clone(),
                entry_point: f.entry_point,
                admin_path: admin,
                durability: raw.durability,
                access: raw.access,
                key_expr: raw.key_expr.clone(),
                key_root: raw.key_root.clone(),
                class,
            });
        }
    }

    // Which entry points touch each conflict domain, and does anyone write it?
    let mut domain_touchers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut domain_writers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut domain_class: BTreeMap<String, KeyClass> = BTreeMap::new();
    for a in classified.iter().filter(|a| a.entry_point) {
        if !is_shared_domain(a.durability, &a.class) {
            continue;
        }
        let domain = conflict_domain(a.durability, &a.key_root);
        domain_class
            .entry(domain.clone())
            .or_insert_with(|| a.class.clone());
        if runs_once(&a.function) {
            continue;
        }
        domain_touchers
            .entry(domain.clone())
            .or_default()
            .insert(a.function.clone());
        if a.access == Access::Write {
            domain_writers
                .entry(domain)
                .or_default()
                .insert(a.function.clone());
        }
    }

    let mut findings = Vec::new();
    for a in &classified {
        let Some(severity) = severity_of(a) else {
            continue;
        };
        let domain = conflict_domain(a.durability, &a.key_root);
        let mut also: Vec<String> = domain_touchers
            .get(&domain)
            .map(|s| s.iter().filter(|n| **n != a.function).cloned().collect())
            .unwrap_or_default();
        also.sort();

        findings.push(Finding {
            severity,
            summary: summary_of(a),
            remediation: remediation_for(a),
            also_touched_by: also,
            access: a.clone(),
        });
    }

    // Most severe first, then by file and line so output is stable.
    findings.sort_by(|x, y| {
        y.severity
            .cmp(&x.severity)
            .then(x.access.file.cmp(&y.access.file))
            .then(x.access.line.cmp(&y.access.line))
    });

    let conflict_edges = build_edges(&domain_touchers, &domain_writers, &domain_class);

    let entry_points: BTreeSet<String> = classified
        .iter()
        .filter(|a| a.entry_point)
        .map(|a| a.function.clone())
        .collect();
    let conflicted: BTreeSet<String> = conflict_edges
        .iter()
        .flat_map(|e| [e.a.clone(), e.b.clone()])
        .collect();
    let self_conflicted: BTreeSet<String> = domain_writers
        .values()
        .filter(|w| w.len() == 1)
        .flat_map(|w| w.iter().cloned())
        .collect();

    let parallel_safe: Vec<String> = entry_points
        .iter()
        .filter(|n| !conflicted.contains(*n) && !self_conflicted.contains(*n))
        .cloned()
        .collect();

    let summary = Summary {
        files_scanned: scan.files_scanned,
        functions_scanned: scan.functions.len(),
        accesses_found: classified.len(),
        entry_points: entry_points.len(),
        critical: findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count(),
        warning: findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count(),
        info: findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count(),
    };

    Report {
        schema_version: SCHEMA_VERSION,
        target: target.to_string(),
        summary,
        findings,
        conflict_edges,
        parallel_safe_entry_points: parallel_safe,
    }
}

/// A function that reads and writes the same static key is minting values from
/// a shared counter. Anything derived from its return value inherits that.
fn find_counter_functions(functions: &[FunctionInfo]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for f in functions {
        let mut reads = BTreeSet::new();
        let mut writes = BTreeSet::new();
        for a in &f.accesses {
            if !a.key_args.is_empty() {
                continue; // only a parameterless key can be a global counter
            }
            match a.access {
                Access::Read => {
                    reads.insert(a.key_root.clone());
                }
                Access::Write => {
                    writes.insert(a.key_root.clone());
                }
            }
        }
        if let Some(k) = reads.intersection(&writes).next() {
            out.insert(f.name.clone(), k.clone());
        }
    }
    out
}

fn classify_key(
    f: &FunctionInfo,
    raw: &crate::parse::RawAccess,
    counters: &HashMap<String, String>,
) -> KeyClass {
    if raw.key_args.is_empty() {
        return KeyClass::Static;
    }

    let mut subjects = Vec::new();
    let mut unresolved: Option<String> = None;

    for arg in &raw.key_args {
        match arg {
            ArgOrigin::Ident(name) => {
                if f.params.contains(name) {
                    subjects.push(name.clone());
                    continue;
                }
                // A local. Find the most recent binding declared above this use.
                let binding = f
                    .lets
                    .iter()
                    .filter(|l| &l.name == name && l.line <= raw.line)
                    .max_by_key(|l| l.line);

                match binding {
                    Some(b) => {
                        // Minted straight from a shared entry.
                        if let Some(counter) = &b.from_storage_key {
                            return KeyClass::SequenceDerived {
                                counter: counter.clone(),
                            };
                        }
                        // Minted by a function that bumps a shared entry.
                        if let Some(call) = &b.from_call {
                            if let Some(counter) = counters.get(call) {
                                return KeyClass::SequenceDerived {
                                    counter: format!("{counter} (via {call}())"),
                                };
                            }
                        }
                        // A local we can see but cannot attribute. Common for
                        // hashes of caller input, which are parallel-safe, and
                        // for values pulled from an argument struct, which are
                        // too — but we do not assume it.
                        unresolved.get_or_insert(format!(
                            "`{name}` is a local bound at line {}; Braid cannot tell whether it came from caller input",
                            b.line
                        ));
                    }
                    None => {
                        unresolved.get_or_insert(format!(
                            "`{name}` is not a parameter of `{}` and has no visible binding",
                            f.name
                        ));
                    }
                }
            }
            ArgOrigin::Opaque(text) => {
                unresolved.get_or_insert(format!("`{text}` does not reduce to a named binding"));
            }
        }
    }

    if let Some(reason) = unresolved {
        return KeyClass::Unresolvable { reason };
    }
    KeyClass::SubjectDerived {
        param: subjects.join(", "),
    }
}

fn severity_of(a: &StorageAccess) -> Option<Severity> {
    let hot = a.entry_point && !a.admin_path;

    // A constructor runs exactly once and cannot race anything, so seeding a
    // counter or writing config there is not a conflict. The conflict is
    // whatever bumps that entry afterwards, and it is reported on its own.
    if runs_once(&a.function) && a.access == Access::Write {
        return None;
    }

    // Instance storage is a single ledger entry, so the key class cannot make an
    // instance write parallel-safe. But a fixed key written on an admin path is
    // precisely what instance storage exists for — the admin address, immutable
    // config — and reporting it would be noise.
    if a.durability == Durability::Instance && a.access == Access::Write {
        return match &a.class {
            KeyClass::Static if !hot => None,
            KeyClass::Static => Some(Severity::Warning),
            // A per-subject key in instance storage is the trap: the parameter
            // looks like it separates callers and separates nothing.
            _ => Some(if hot {
                Severity::Critical
            } else {
                Severity::Warning
            }),
        };
    }

    match (&a.class, a.access) {
        (KeyClass::Static, Access::Write) => Some(if hot {
            Severity::Critical
        } else {
            Severity::Warning
        }),
        (KeyClass::SequenceDerived { .. }, Access::Write) => Some(Severity::Warning),
        (KeyClass::SequenceDerived { .. }, Access::Read) => Some(Severity::Info),
        (KeyClass::Unresolvable { .. }, Access::Write) => Some(Severity::Warning),
        (KeyClass::Static, Access::Read) if a.entry_point => Some(Severity::Info),
        // Subject-derived keys outside instance storage are the goal state.
        _ => None,
    }
}

fn summary_of(a: &StorageAccess) -> String {
    if a.durability == Durability::Instance && a.access == Access::Write {
        return match &a.class {
            KeyClass::SubjectDerived { param } => format!(
                "`{}` is keyed by `{param}`, but it lives in instance storage — one ledger entry for every key, so the parameter separates nothing",
                a.key_expr
            ),
            _ => format!(
                "writes `{}` in instance storage, which is a single ledger entry shared by every instance key in this contract",
                a.key_expr
            ),
        };
    }
    match &a.class {
        KeyClass::Static => match a.access {
            Access::Write => format!(
                "writes the fixed key `{}` — every caller reaching `{}` touches this same ledger entry",
                a.key_expr, a.function
            ),
            Access::Read => format!(
                "reads the fixed key `{}` — shared, but reads alone never conflict",
                a.key_expr
            ),
        },
        KeyClass::SequenceDerived { counter } => format!(
            "`{}` looks parameterised, but its identifier was minted from `{counter}` — every caller serialises on that counter",
            a.key_expr
        ),
        KeyClass::Unresolvable { reason } => {
            format!("could not classify `{}`: {reason}", a.key_expr)
        }
        KeyClass::SubjectDerived { param } => {
            format!("`{}` is keyed by `{param}`", a.key_expr)
        }
    }
}

fn remediation_for(a: &StorageAccess) -> String {
    if a.durability == Durability::Instance && a.access == Access::Write {
        if matches!(a.class, KeyClass::Static) {
            return "\
This is a fixed key in instance storage, which is the right place for it — but it
is written on a path users reach, so every such call serialises on the contract
instance entry. Either move the write off the hot path (set it once at
construction, or in an admin function), or move the value to its own persistent
entry if it genuinely changes during normal operation."
                .to_string();
        }
        return "\
Move per-subject data out of instance storage into persistent storage:

    // before — one ledger entry for the whole contract
    env.storage().instance().set(&DataKey::Balance(addr), &amount);

    // after — one ledger entry per address
    env.storage().persistent().set(&DataKey::Balance(addr), &amount);

Keep instance storage for what genuinely is global and rarely written: the
admin address, immutable configuration, the contract's own TTL. Anything
written on a normal user path does not belong there."
            .to_string();
    }

    match &a.class {
        KeyClass::SequenceDerived { .. } => "\
Derive the identifier from data the caller already supplies, so no shared
counter is read or bumped:

    // before — every caller reads and writes DataKey::Seq
    let id: u64 = env.storage().persistent().get(&DataKey::Seq).unwrap_or(0);
    env.storage().persistent().set(&DataKey::Seq, &(id + 1));
    env.storage().persistent().set(&DataKey::Job(id), &job);

    // after — the id is a function of the caller's own input
    let id = env.crypto().sha256(&(owner, target, salt).to_xdr(&env));
    env.storage().persistent().set(&DataKey::Job(id), &job);

You lose dense sequential ids and gain the ability to run in parallel. If
callers need to enumerate their own entries, keep a per-caller index
(`DataKey::OwnerJobs(owner)`) rather than a global one."
            .to_string(),

        KeyClass::Static if a.access == Access::Write => "\
Shard the entry by whoever writes it, so two callers no longer collide:

    // before — one entry, every caller writes it
    let total: i128 = env.storage().persistent().get(&DataKey::Total).unwrap_or(0);
    env.storage().persistent().set(&DataKey::Total, &(total + amount));

    // after — one entry per writer, summed on read
    let key = DataKey::TotalShard(caller.clone());
    let shard: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    env.storage().persistent().set(&key, &(shard + amount));

If the aggregate must be readable in one call, keep the shards authoritative
and recompute lazily, or accept that the reader pays to fold them. Reads do
not conflict, so a read-heavy aggregate is much cheaper to shard than it looks."
            .to_string(),

        KeyClass::Static => "\
No action needed. Reads never place an entry in the read-write footprint, so a
shared read-only entry — configuration, the admin address, an immutable
parameter — does not serialise anything. It is listed only so the report is a
complete account of what this contract touches."
            .to_string(),

        KeyClass::Unresolvable { .. } => "\
Braid could not follow this key expression, so it makes no claim either way.
Check by hand whether the value in the key comes from caller input (safe) or
from shared contract state (not safe). If it is caller input, binding it
directly from the parameter rather than through intermediate locals will let
Braid classify it next time."
            .to_string(),

        KeyClass::SubjectDerived { .. } => "No action needed.".to_string(),
    }
}

fn build_edges(
    touchers: &BTreeMap<String, BTreeSet<String>>,
    writers: &BTreeMap<String, BTreeSet<String>>,
    domain_class: &BTreeMap<String, KeyClass>,
) -> Vec<ConflictEdge> {
    let mut edges = Vec::new();
    for (domain, fns) in touchers {
        let Some(w) = writers.get(domain) else {
            continue;
        };
        if w.is_empty() {
            continue;
        }
        let reason = if domain == INSTANCE_DOMAIN {
            "all instance storage shares one ledger entry".to_string()
        } else {
            let cls = domain_class
                .get(domain)
                .map(|c| c.label())
                .unwrap_or("shared");
            format!("{cls} key `{domain}`, written by at least one of them")
        };

        let list: Vec<&String> = fns.iter().collect();
        for i in 0..list.len() {
            for j in (i + 1)..list.len() {
                // An edge needs at least one writer among the pair.
                if !w.contains(list[i]) && !w.contains(list[j]) {
                    continue;
                }
                edges.push(ConflictEdge {
                    a: list[i].clone(),
                    b: list[j].clone(),
                    key_root: domain.clone(),
                    reason: reason.clone(),
                });
            }
        }
    }
    edges.sort_by(|x, y| {
        x.a.cmp(&y.a)
            .then(x.b.cmp(&y.b))
            .then(x.key_root.cmp(&y.key_root))
    });
    edges
}
