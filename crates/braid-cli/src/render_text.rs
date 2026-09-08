//! Terminal report.
//!
//! Findings are grouped by severity and every one of them names the fix, not
//! just the problem. A finding without a remediation is noise.

use braid_core::{KeyClass, Report, Severity};
use std::fmt::Write;

struct Palette {
    on: bool,
}

impl Palette {
    fn p(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.p("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.p("2", s)
    }
    fn sev(&self, s: Severity) -> String {
        match s {
            Severity::Critical => self.p("1;31", "critical"),
            Severity::Warning => self.p("1;33", "warning "),
            Severity::Info => self.p("36", "info    "),
        }
    }
}

pub fn render(report: &Report, colour: bool) -> String {
    let c = Palette { on: colour };
    let mut o = String::new();
    let s = &report.summary;

    let _ = writeln!(o, "\n{}", c.bold(&format!("braid — {}", report.target)));
    let _ = writeln!(
        o,
        "{}",
        c.dim(&format!(
            "{} file(s), {} function(s), {} entry point(s), {} storage access(es)",
            s.files_scanned, s.functions_scanned, s.entry_points, s.accesses_found
        ))
    );

    if report.findings.is_empty() {
        let _ = writeln!(
            o,
            "\n  {} no conflicts found — every mutable entry is keyed by caller input\n",
            c.p("1;32", "PASS")
        );
        return o;
    }

    let _ = writeln!(
        o,
        "\n  {}  {}  {}\n",
        c.p("1;31", &format!("{} critical", s.critical)),
        c.p("1;33", &format!("{} warning", s.warning)),
        c.p("36", &format!("{} info", s.info)),
    );

    for (i, f) in report.findings.iter().enumerate() {
        let a = &f.access;
        let _ = writeln!(
            o,
            "{} {}  {}",
            c.sev(f.severity),
            c.bold(&format!("{}:{}:{}", a.file, a.line, a.column)),
            c.dim(&format!("in {}()", a.function)),
        );
        let _ = writeln!(o, "         {}", f.summary);
        let _ = writeln!(
            o,
            "         {}",
            c.dim(&format!(
                "{} {} · key class: {}{}",
                a.durability,
                a.access,
                a.class.label(),
                match &a.class {
                    KeyClass::SequenceDerived { counter } => format!(" (counter: {counter})"),
                    _ => String::new(),
                }
            ))
        );

        if !f.also_touched_by.is_empty() {
            let _ = writeln!(
                o,
                "         {}",
                c.dim(&format!(
                    "same ledger entry is also touched by: {}",
                    f.also_touched_by.join(", ")
                ))
            );
        }

        if f.severity > Severity::Info {
            let _ = writeln!(o);
            for line in f.remediation.lines() {
                let _ = writeln!(o, "         {}", c.dim(line));
            }
        }

        if i + 1 < report.findings.len() {
            let _ = writeln!(o);
        }
    }

    if !report.conflict_edges.is_empty() {
        let _ = writeln!(
            o,
            "\n{}",
            c.bold("Entry points that cannot run in parallel")
        );
        for e in &report.conflict_edges {
            let _ = writeln!(
                o,
                "  {} {} {}   {}",
                e.a,
                c.dim("<->"),
                e.b,
                c.dim(&e.reason)
            );
        }
    }

    if !report.parallel_safe_entry_points.is_empty() {
        let _ = writeln!(
            o,
            "\n{} {}",
            c.p("1;32", "Parallel-safe entry points:"),
            report.parallel_safe_entry_points.join(", ")
        );
    }

    let _ = writeln!(o);
    o
}
