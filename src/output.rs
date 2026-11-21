use crate::error::MaskkeelError;
use crate::pipeline::{MaskReport, ScanReport, VerifyReport};
use clap::ValueEnum;
use owo_colors::OwoColorize;
use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Auto,
    Human,
    Agent,
    Json,
}

impl OutputFormat {
    pub fn resolve(self) -> Self {
        match self {
            Self::Auto => {
                if std::io::stdout().is_terminal() {
                    Self::Human
                } else {
                    Self::Agent
                }
            }
            other => other,
        }
    }
}

pub fn print_error(err: &MaskkeelError, fmt: OutputFormat) {
    match fmt.resolve() {
        OutputFormat::Json => {
            let env = err.to_envelope();
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&env).unwrap_or_else(|_| format!("{err}"))
            );
        }
        OutputFormat::Agent => {
            eprintln!("ERROR [{}]: {}", err.code(), err);
            if !err.fix_hint().is_empty() {
                eprintln!("HINT: {}", err.fix_hint());
            }
        }
        OutputFormat::Human | OutputFormat::Auto => {
            eprintln!(
                "{} [{}] {}",
                "error:".red().bold(),
                err.code().yellow(),
                err
            );
            if !err.fix_hint().is_empty() {
                eprintln!("  {} {}", "hint:".cyan().bold(), err.fix_hint());
            }
        }
    }
}

pub fn print_scan(report: &ScanReport, written_config: Option<&str>, fmt: OutputFormat) {
    match fmt.resolve() {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
            );
        }
        OutputFormat::Agent => {
            println!(
                "# maskkeel scan ({}) | tables={} | pii_columns={}",
                report.source_kind, report.tables_scanned, report.pii_columns_found
            );
            if report.findings.is_empty() {
                println!("No PII columns detected.");
            } else {
                println!("| table | column | pii_type | strategy | confidence | reason |");
                println!("|---|---|---|---|---|---|");
                for f in &report.findings {
                    println!(
                        "| {} | {} | {} | {} | {} | {} |",
                        f.table,
                        f.column,
                        f.pii_type,
                        f.recommended_strategy.as_str(),
                        f.confidence,
                        f.reason
                    );
                }
            }
            if let Some(cfg) = written_config {
                println!("\nWrote starter config: `{cfg}`");
            }
        }
        OutputFormat::Human | OutputFormat::Auto => {
            println!(
                "{} {} ({}, {} tables scanned, {} PII columns detected)",
                "maskkeel scan".cyan().bold(),
                report.source.bold(),
                report.source_kind,
                report.tables_scanned,
                report.pii_columns_found
            );
            if report.findings.is_empty() {
                println!("  {} No PII columns detected.", "✓".green().bold());
            } else {
                for f in &report.findings {
                    let badge = if f.confidence == "high" {
                        format!("[{}]", f.confidence).red().bold().to_string()
                    } else {
                        format!("[{}]", f.confidence).yellow().bold().to_string()
                    };
                    println!(
                        "  {} {}.{} -> {} ({}) — {}",
                        badge,
                        f.table.bold(),
                        f.column.cyan(),
                        f.recommended_strategy.as_str().green().bold(),
                        f.pii_type,
                        f.reason.dimmed()
                    );
                }
            }
            if let Some(cfg) = written_config {
                println!(
                    "\n  {} Wrote starter mask config to {}",
                    "✓".green().bold(),
                    cfg.bold()
                );
            }
        }
    }
}

pub fn print_mask(report: &MaskReport, fmt: OutputFormat) {
    match fmt.resolve() {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
            );
        }
        OutputFormat::Agent => {
            println!(
                "# maskkeel mask | ok={} | tables={} | rows={} | masked_cols={}",
                report.ok, report.tables_masked, report.total_rows, report.total_masked_columns
            );
            println!("output: {}", report.output);
            println!("| table | rows | masked_columns |");
            println!("|---|---:|---|");
            for t in &report.tables {
                let cols = if t.masked_columns.is_empty() {
                    "(none)".to_string()
                } else {
                    t.masked_columns.join(", ")
                };
                println!("| {} | {} | {} |", t.table, t.rows_processed, cols);
            }
        }
        OutputFormat::Human | OutputFormat::Auto => {
            println!(
                "{} Masked {} table(s), {} row(s), {} PII column(s) -> {}",
                "✓".green().bold(),
                report.tables_masked,
                report.total_rows,
                report.total_masked_columns,
                report.output.bold()
            );
            for t in &report.tables {
                let cols = if t.masked_columns.is_empty() {
                    "(passthrough)".dimmed().to_string()
                } else {
                    t.masked_columns.join(", ")
                };
                println!(
                    "  • {} ({} rows): {}",
                    t.table.cyan(),
                    t.rows_processed,
                    cols
                );
            }
        }
    }
}

pub fn print_verify(report: &VerifyReport, fmt: OutputFormat) {
    match fmt.resolve() {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
            );
        }
        OutputFormat::Agent => {
            let status = if report.ok { "PASS" } else { "FAIL" };
            println!(
                "# maskkeel verify | status={} | tables={} | row_counts_matched={} | key_cardinality_preserved={} | pii_leaks={}",
                status,
                report.tables_checked,
                report.row_counts_matched,
                report.key_cardinality_preserved,
                report.pii_leaks_found
            );
            for n in &report.notes {
                println!("- note: {n}");
            }
            if !report.leaks.is_empty() {
                println!("| table | column | leaked_distinct_values |");
                println!("|---|---|---:|");
                for l in &report.leaks {
                    println!("| {} | {} | {} |", l.table, l.column, l.leaked_count);
                }
            }
        }
        OutputFormat::Human | OutputFormat::Auto => {
            if report.ok {
                println!(
                    "{} Zero-leak verification {} ({} tables checked, row counts matched, key cardinality preserved: {})",
                    "✓".green().bold(),
                    "PASSED".green().bold(),
                    report.tables_checked,
                    report.key_cardinality_preserved
                );
            } else {
                println!(
                    "{} Verification {} ({} PII value leaks across {} tables)",
                    "✗".red().bold(),
                    "FAILED".red().bold(),
                    report.pii_leaks_found,
                    report.tables_checked
                );
            }
            for n in &report.notes {
                println!("  {} {}", "!".yellow().bold(), n);
            }
            for l in &report.leaks {
                println!(
                    "  {} {}.{} leaked {} original distinct value(s)",
                    "✗".red().bold(),
                    l.table.bold(),
                    l.column.cyan(),
                    l.leaked_count
                );
            }
        }
    }
}
