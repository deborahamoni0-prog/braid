//! `braid` — does this Soroban contract's storage design allow it to run in
//! parallel?

mod render_html;
mod render_text;

use anyhow::{bail, Context, Result};
use braid_core::{analyze_path, Report, Severity};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "braid",
    version,
    about = "Find the hot ledger entry that is capping your Soroban contract's throughput",
    long_about = "Protocol 23 executes Soroban transactions in parallel, clustering them by their\n\
                  declared footprints (CAP-0063). Two transactions that share a ledger entry, where\n\
                  at least one writes it, cannot run at the same time.\n\n\
                  Braid reads your contract source and reports where the storage design forces\n\
                  that serialisation — before you deploy and find out from throughput numbers."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyse a contract crate, workspace, or single file.
    Analyze {
        /// Path to scan. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,

        #[arg(short, long, value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Write the report to a file instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Exit 1 when any finding reaches this severity. Omit to always exit 0.
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<String>,

        /// Hide info-level findings, which never require action.
        #[arg(long)]
        quiet: bool,

        /// Disable colour even when stdout is a terminal.
        #[arg(long)]
        no_color: bool,

        /// Embed source context in the report, so it stays readable away from
        /// the working tree it was produced in. Implied by --format html.
        #[arg(long)]
        include_source: bool,
    },

    /// Print the JSON schema version this build emits.
    SchemaVersion,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable report for a terminal.
    Text,
    /// Stable machine-readable output for CI and other tools.
    Json,
    /// Self-contained interactive HTML report.
    Html,
}

fn main() {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("braid: {e:#}");
            std::process::exit(2);
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::SchemaVersion => {
            println!("{}", braid_core::SCHEMA_VERSION);
            Ok(0)
        }
        Command::Analyze {
            path,
            format,
            out,
            fail_on,
            quiet,
            no_color,
            include_source,
        } => {
            if !path.exists() {
                bail!("{} does not exist", path.display());
            }

            let threshold = match fail_on.as_deref() {
                None | Some("none") => None,
                Some(s) => Some(Severity::parse(s).with_context(|| {
                    format!("unknown severity `{s}` — use critical, warning, info, or none")
                })?),
            };

            let (mut report, parse_errors) = analyze_path(&path);

            for (file, err) in &parse_errors {
                eprintln!("braid: could not parse {file}: {err}");
            }

            if include_source || format == Format::Html {
                braid_core::attach_source(&mut report, 3);
            }

            if quiet {
                report.findings.retain(|f| f.severity > Severity::Info);
                recount(&mut report);
            }

            let colour = !no_color && out.is_none() && std::io::stdout().is_terminal();
            let rendered = match format {
                Format::Text => render_text::render(&report, colour),
                Format::Json => serde_json::to_string_pretty(&report)? + "\n",
                Format::Html => render_html::render(&report),
            };

            match &out {
                Some(p) => {
                    std::fs::write(p, &rendered)
                        .with_context(|| format!("writing {}", p.display()))?;
                    eprintln!("braid: wrote {}", p.display());
                }
                None => {
                    let mut stdout = std::io::stdout().lock();
                    stdout.write_all(rendered.as_bytes())?;
                    stdout.flush()?;
                }
            }

            Ok(report.exit_code(threshold))
        }
    }
}

fn recount(report: &mut Report) {
    report.summary.critical = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    report.summary.warning = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    report.summary.info = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();
}
