mod config;
mod engine;
mod error;
mod html;
mod output;
mod parquet_io;
mod pipeline;
mod skill;

use crate::config::{MaskConfig, render_mask_toml};
use crate::error::MaskkeelError;
use crate::html::render_verify_html;
use crate::output::{OutputFormat, print_error, print_mask, print_scan, print_verify};
use crate::pipeline::{MaskOptions, mask_source, scan_source, verify_masking};
use clap::{Parser, Subcommand};
use std::process::ExitCode;

const DEFAULT_DEV_SALT: &str = "maskkeel-default-dev-salt";

#[derive(Debug, Parser)]
#[command(
    name = "maskkeel",
    version,
    about = "Blazing-fast, deterministic, referentially-intact Rust PII/FERPA data scrubber (DX + AX)."
)]
struct Cli {
    /// Output format: auto (human on TTY, agent markdown when piped), human, agent, or json.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Auto)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan a file, SQLite DB, or PostgreSQL DB for PII/FERPA columns (including embedded PII in free-text/JSONB) and optionally write a starter mask.toml.
    Scan {
        /// Input path (.csv, .tsv, .jsonl, .parquet, sqlite:///path.db, postgres://...)
        source: String,

        /// Comma-separated PostgreSQL schema names to scan (defaults to all non-system schemas).
        #[arg(long, value_delimiter = ',')]
        schema: Vec<String>,

        /// Maximum rows to sample per table/file for value pattern detection.
        #[arg(long, default_value_t = 200)]
        sample_rows: usize,

        /// Write a starter mask TOML config file from detected PII columns.
        #[arg(long)]
        init_config: Option<String>,
    },

    /// Deterministically scrub PII from input -> output (refuses in-place overwrites; supports FK-coherent subsetting).
    Mask {
        /// Input path or DB URL (.csv, .tsv, .jsonl, .parquet, sqlite://..., postgres://...)
        input: String,

        /// Output path or target DB URL (must differ from input).
        output: String,

        /// Path to mask.toml defining [columns] and [tables.<name>] strategies.
        #[arg(long, short = 'c')]
        config: Option<String>,

        /// Auto-detect PII columns (enabled automatically when --config is omitted; pass alongside --config to also catch unlisted columns).
        #[arg(long)]
        auto: bool,

        /// Secret HMAC-SHA256 salt (also reads MASKKEEL_SALT env var). Same salt = identical synthetic values across sources.
        #[arg(long, env = "MASKKEEL_SALT")]
        salt: Option<String>,

        /// Fail with E_CONFIG if --salt / MASKKEEL_SALT is not explicitly provided (recommended in CI/scripts).
        #[arg(long)]
        require_salt: bool,

        /// Override synthetic email domain (default: example.edu, or mask.toml email_domain).
        #[arg(long)]
        email_domain: Option<String>,

        /// Override max date shift window in days (default: 30, or mask.toml date_shift_days).
        #[arg(long)]
        date_shift_days: Option<i64>,

        /// Comma-separated PostgreSQL schema names to migrate & mask (defaults to all non-system schemas).
        #[arg(long, value_delimiter = ',')]
        schema: Vec<String>,

        /// Maximum rows to keep per root table/file (child tables with FKs automatically keep only rows referencing sampled parent keys).
        #[arg(long)]
        limit: Option<usize>,

        /// Deterministic percentage of root rows to sample (0 < pct <= 100; FK-coherent for child tables).
        #[arg(long)]
        sample: Option<f64>,
    },

    /// Audit a masked dataset against the original for zero PII leaks, row-count parity, key cardinality, and optional HTML compliance receipt.
    Verify {
        /// Original source (.csv, .parquet, sqlite://..., postgres://...)
        original: String,

        /// Masked output (.csv, .parquet, sqlite://..., postgres://...)
        masked: String,

        /// Optional mask.toml (respects explicit `keep` exemptions and custom masked columns).
        #[arg(long, short = 'c')]
        config: Option<String>,

        /// Comma-separated PostgreSQL schema names to verify.
        #[arg(long, value_delimiter = ',')]
        schema: Vec<String>,

        /// Allow masked output to be a subset of original rows (use when `mask` ran with `--limit` or `--sample`).
        #[arg(long)]
        allow_subset: bool,

        /// Write a self-contained offline HTML compliance verification receipt to this path.
        #[arg(long)]
        html: Option<String>,
    },

    /// Print the bundled AI agent SKILL.md or install it into a directory (e.g. .agents/skills/maskkeel).
    Skill {
        /// Directory where SKILL.md should be written.
        #[arg(long)]
        install: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let fmt = cli.format;

    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            print_error(&err, fmt);
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> crate::error::Result<ExitCode> {
    let fmt = cli.format;
    match cli.command {
        Commands::Scan {
            source,
            schema,
            sample_rows,
            init_config,
        } => {
            let report = scan_source(&source, &schema, sample_rows)?;
            if let Some(ref path) = init_config {
                let toml_body = render_mask_toml(&report.findings);
                std::fs::write(path, toml_body).map_err(|e| MaskkeelError::io(e, path))?;
            }
            print_scan(&report, init_config.as_deref(), fmt);
            Ok(ExitCode::SUCCESS)
        }

        Commands::Mask {
            input,
            output,
            config,
            auto,
            salt,
            require_salt,
            email_domain,
            date_shift_days,
            schema,
            limit,
            sample,
        } => {
            if let Some(pct) = sample
                && (!(0.0..=100.0).contains(&pct) || pct <= 0.0)
            {
                return Err(MaskkeelError::config(
                    format!("Invalid --sample percentage `{pct}`"),
                    "Provide a value strictly greater than 0 and at most 100 (e.g. `--sample 10`).",
                ));
            }
            let effective_salt = match salt.filter(|s| !s.trim().is_empty()) {
                Some(s) => s,
                None if require_salt => {
                    return Err(MaskkeelError::config(
                        "Missing required HMAC salt (`--salt` or `MASKKEEL_SALT`).",
                        "Set `export MASKKEEL_SALT=\"your-secret\"` or pass `--salt <secret>`.",
                    ));
                }
                None => {
                    eprintln!(
                        "note: using built-in dev salt; set MASKKEEL_SALT or --salt for private repeatable fixtures."
                    );
                    DEFAULT_DEV_SALT.to_string()
                }
            };

            let mut cfg = match &config {
                Some(path) => MaskConfig::load(path)?,
                None => MaskConfig::default(),
            };
            if let Some(dom) = email_domain {
                cfg.email_domain = Some(dom);
            }
            if let Some(days) = date_shift_days {
                cfg.date_shift_days = Some(days);
            }

            let opts = MaskOptions {
                auto_detect: auto || config.is_none(),
                schemas: schema,
                limit,
                sample_pct: sample,
            };
            let report = mask_source(&input, &output, &cfg, &opts, &effective_salt)?;
            print_mask(&report, fmt);
            Ok(ExitCode::SUCCESS)
        }

        Commands::Verify {
            original,
            masked,
            config,
            schema,
            allow_subset,
            html,
        } => {
            let cfg = match &config {
                Some(path) => Some(MaskConfig::load(path)?),
                None => None,
            };
            let report = verify_masking(&original, &masked, cfg.as_ref(), &schema, allow_subset)?;
            if let Some(ref html_path) = html {
                let body = render_verify_html(&report);
                std::fs::write(html_path, body).map_err(|e| MaskkeelError::io(e, html_path))?;
            }
            print_verify(&report, html.as_deref(), fmt);
            if report.ok {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }

        Commands::Skill { install } => {
            if let Some(dir) = install {
                let path = skill::install_skill(&dir)?;
                match fmt.resolve() {
                    OutputFormat::Json => {
                        println!("{}", serde_json::json!({ "ok": true, "installed": path }));
                    }
                    _ => println!("Installed maskkeel SKILL.md to {path}"),
                }
            } else {
                print!("{}", skill::SKILL_MD);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
