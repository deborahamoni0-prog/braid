//! Self-contained interactive HTML report.
//!
//! No network, no build step, no server: one file you can open, attach to a
//! pull request, or publish as a CI artifact. Source context is inlined at
//! render time so the report stays readable after the working tree moves on.

use braid_core::{KeyClass, Report, Severity};
use std::collections::HashMap;
use std::fmt::Write;

pub fn render(report: &Report) -> String {
    let mut sources: HashMap<String, Vec<String>> = HashMap::new();
    for f in &report.findings {
        sources.entry(f.access.file.clone()).or_insert_with(|| {
            std::fs::read_to_string(&f.access.file)
                .map(|s| s.lines().map(str::to_string).collect())
                .unwrap_or_default()
        });
    }

    let s = &report.summary;
    let mut o = String::new();

    let _ = write!(
        o,
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Braid — {target}</title>
<style>
:root {{
  --paper:#eceef1; --surface:#f7f8fa; --surface-2:#e3e6ea;
  --ink:#181b21; --ink-2:#4a515c; --ink-3:#767d8a;
  --rule:#cdd2d9; --rule-soft:#dde1e6;
  --crit:#a8451a; --warn:#8a6a1e; --info:#3d5a7a; --pass:#2f6552;
  --mono:"SF Mono",SFMono-Regular,ui-monospace,Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --paper:#101317; --surface:#171b21; --surface-2:#1f242b;
    --ink:#e8eaee; --ink-2:#a9b1bc; --ink-3:#7d8593;
    --rule:#2c323a; --rule-soft:#242a31;
    --crit:#e08453; --warn:#cfa445; --info:#7ea6d0; --pass:#6fb99b;
  }}
}}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--paper); color:var(--ink); font-family:var(--sans);
        font-size:15px; line-height:1.6; -webkit-font-smoothing:antialiased }}
.wrap {{ max-width:1000px; margin:0 auto; padding:0 24px }}
header {{ background:var(--surface); border-bottom:1px solid var(--rule); padding:28px 0 24px }}
h1 {{ margin:0; font-size:13px; letter-spacing:.16em; text-transform:uppercase; color:var(--ink-3); font-weight:600 }}
.target {{ font-family:var(--mono); font-size:22px; margin:6px 0 0; word-break:break-all }}
.meta {{ color:var(--ink-3); font-size:13px; margin-top:6px }}
.counts {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:18px }}
.chip {{ font-family:var(--mono); font-size:12px; padding:6px 12px; border:1px solid var(--rule);
         border-radius:2px; background:var(--paper); cursor:pointer; color:var(--ink-2) }}
.chip[aria-pressed="true"] {{ border-color:currentColor; font-weight:600 }}
.chip.critical[aria-pressed="true"] {{ color:var(--crit) }}
.chip.warning[aria-pressed="true"]  {{ color:var(--warn) }}
.chip.info[aria-pressed="true"]     {{ color:var(--info) }}
main {{ padding:28px 0 60px }}
.finding {{ border-left:3px solid var(--rule); background:var(--surface); margin-bottom:2px; padding:16px 20px }}
.finding.critical {{ border-left-color:var(--crit) }}
.finding.warning  {{ border-left-color:var(--warn) }}
.finding.info     {{ border-left-color:var(--info) }}
.fhead {{ display:flex; gap:12px; align-items:baseline; flex-wrap:wrap }}
.sev {{ font-family:var(--mono); font-size:10.5px; letter-spacing:.11em; text-transform:uppercase; font-weight:600 }}
.critical .sev {{ color:var(--crit) }} .warning .sev {{ color:var(--warn) }} .info .sev {{ color:var(--info) }}
.loc {{ font-family:var(--mono); font-size:12.5px; color:var(--ink-2) }}
.fn {{ font-family:var(--mono); font-size:12.5px; color:var(--ink-3) }}
.summary {{ margin:8px 0 0 }}
.tags {{ display:flex; gap:6px; flex-wrap:wrap; margin-top:10px }}
.tag {{ font-family:var(--mono); font-size:10.5px; padding:2px 8px; border:1px solid var(--rule);
        border-radius:2px; color:var(--ink-3) }}
pre {{ background:var(--surface-2); border-radius:2px; padding:12px 0; margin:12px 0 0;
       overflow-x:auto; font-family:var(--mono); font-size:12.5px; line-height:1.55 }}
pre .ln {{ display:block; padding:0 16px; white-space:pre }}
pre .ln .no {{ color:var(--ink-3); user-select:none; display:inline-block; width:3.5em; text-align:right; margin-right:1.2em }}
pre .ln.hit {{ background:color-mix(in srgb, var(--crit) 14%, transparent) }}
details {{ margin-top:12px }}
summary {{ cursor:pointer; font-size:13px; color:var(--ink-2); font-family:var(--mono) }}
details pre {{ background:transparent; border:1px solid var(--rule); padding:12px 16px; white-space:pre-wrap }}
h2 {{ font-size:12px; letter-spacing:.14em; text-transform:uppercase; color:var(--ink-3);
      margin:40px 0 12px; font-weight:600 }}
table {{ border-collapse:collapse; width:100%; font-size:13.5px }}
th {{ text-align:left; font-size:10.5px; letter-spacing:.12em; text-transform:uppercase;
      color:var(--ink-3); font-weight:500; padding:0 14px 8px 0; border-bottom:1px solid var(--rule) }}
td {{ padding:9px 14px 9px 0; border-bottom:1px solid var(--rule-soft); vertical-align:top }}
td.m {{ font-family:var(--mono); font-size:12.5px }}
.pass {{ color:var(--pass); font-weight:600 }}
.empty {{ background:var(--surface); border-left:3px solid var(--pass); padding:20px }}
.hidden {{ display:none !important }}
footer {{ color:var(--ink-3); font-size:12.5px; padding:0 0 40px }}
</style>
</head>
<body>
<header><div class="wrap">
  <h1>Braid · parallel-execution conflicts</h1>
  <p class="target">{target}</p>
  <p class="meta">{files} file(s) · {fns} function(s) · {eps} entry point(s) · {acc} storage access(es) · CAP-0063</p>
  <div class="counts">
    <button class="chip critical" aria-pressed="true" data-sev="critical">{crit} critical</button>
    <button class="chip warning"  aria-pressed="true" data-sev="warning">{warn} warning</button>
    <button class="chip info"     aria-pressed="true" data-sev="info">{info} info</button>
  </div>
</div></header>
<main><div class="wrap">
"##,
        target = esc(&report.target),
        files = s.files_scanned,
        fns = s.functions_scanned,
        eps = s.entry_points,
        acc = s.accesses_found,
        crit = s.critical,
        warn = s.warning,
        info = s.info,
    );

    if report.findings.is_empty() {
        let _ = write!(
            o,
            r#"<div class="empty"><p class="pass">No conflicts found.</p>
<p>Every mutable ledger entry this contract touches is keyed by a value the caller
supplies, and none of them live in instance storage. Under CAP-0063 these entry
points cluster independently, so they can execute in parallel.</p></div>"#
        );
    }

    for f in &report.findings {
        let a = &f.access;
        let sev = a_sev(f.severity);
        let _ = write!(
            o,
            r#"<article class="finding {sev}" data-sev="{sev}">
<div class="fhead"><span class="sev">{sev}</span>
<span class="loc">{file}:{line}:{col}</span>
<span class="fn">in {func}()</span></div>
<p class="summary">{summary}</p>
<div class="tags"><span class="tag">{dur} {acc}</span><span class="tag">{cls}</span>{extra}{ep}</div>"#,
            sev = sev,
            file = esc(&a.file),
            line = a.line,
            col = a.column,
            func = esc(&a.function),
            summary = esc(&f.summary),
            dur = a.durability,
            acc = a.access,
            cls = a.class.label(),
            extra = match &a.class {
                KeyClass::SequenceDerived { counter } =>
                    format!(r#"<span class="tag">counter: {}</span>"#, esc(counter)),
                _ => String::new(),
            },
            ep = if a.entry_point {
                r#"<span class="tag">entry point</span>"#
            } else {
                r#"<span class="tag">internal</span>"#
            },
        );

        if let Some(lines) = sources.get(&a.file) {
            if !lines.is_empty() {
                let start = a.line.saturating_sub(3).max(1);
                let end = (a.line + 2).min(lines.len());
                let _ = write!(o, "<pre>");
                for n in start..=end {
                    let hit = if n == a.line { " hit" } else { "" };
                    let _ = write!(
                        o,
                        r#"<span class="ln{hit}"><span class="no">{n}</span>{}</span>"#,
                        esc(lines.get(n - 1).map(String::as_str).unwrap_or(""))
                    );
                }
                let _ = write!(o, "</pre>");
            }
        }

        if !f.also_touched_by.is_empty() {
            let _ = write!(
                o,
                r#"<p class="meta">Same ledger entry is also touched by: <span class="loc">{}</span></p>"#,
                esc(&f.also_touched_by.join(", "))
            );
        }

        if f.severity > Severity::Info {
            let _ = write!(
                o,
                "<details><summary>How to fix this</summary><pre>{}</pre></details>",
                esc(&f.remediation)
            );
        }
        let _ = write!(o, "</article>");
    }

    if !report.conflict_edges.is_empty() {
        let _ = write!(
            o,
            r#"<h2>Entry points that cannot run in parallel</h2>
<table><thead><tr><th>Entry point</th><th>Entry point</th><th>Why</th></tr></thead><tbody>"#
        );
        for e in &report.conflict_edges {
            let _ = write!(
                o,
                r#"<tr><td class="m">{}</td><td class="m">{}</td><td>{}</td></tr>"#,
                esc(&e.a),
                esc(&e.b),
                esc(&e.reason)
            );
        }
        let _ = write!(o, "</tbody></table>");
    }

    if !report.parallel_safe_entry_points.is_empty() {
        let _ = write!(
            o,
            r#"<h2>Parallel-safe entry points</h2><p class="loc pass">{}</p>"#,
            esc(&report.parallel_safe_entry_points.join(", "))
        );
    }

    let _ = write!(
        o,
        r#"</div></main>
<footer><div class="wrap">
Braid analyses storage-key derivation only. It does not audit security or measure
resource cost. Reads never conflict; only a shared entry with at least one writer does.
</div></footer>
<script>
const chips = document.querySelectorAll('.chip');
function apply() {{
  const on = new Set([...chips].filter(c => c.getAttribute('aria-pressed') === 'true')
                                .map(c => c.dataset.sev));
  document.querySelectorAll('.finding').forEach(el => {{
    el.classList.toggle('hidden', !on.has(el.dataset.sev));
  }});
}}
chips.forEach(c => c.addEventListener('click', () => {{
  c.setAttribute('aria-pressed', c.getAttribute('aria-pressed') === 'true' ? 'false' : 'true');
  apply();
}}));
apply();
</script>
</body>
</html>
"#
    );

    o
}

fn a_sev(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
