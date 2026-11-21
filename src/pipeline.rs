use crate::config::{MaskConfig, ScannedColumn, detection_to_scanned};
use crate::engine::{MaskEngine, MaskStrategy, detect_column_pii};
use crate::error::{MaskkeelError, Result};
use indexmap::IndexSet;
use native_tls::TlsConnector;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field as ParquetField;
use postgres::{Client as PgClient, NoTls};
use postgres_native_tls::MakeTlsConnector;
use rusqlite::{
    Connection as SqliteConn, OpenFlags, params_from_iter,
    types::{Value as SqlVal, ValueRef},
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub source: String,
    pub source_kind: String,
    pub tables_scanned: usize,
    pub pii_columns_found: usize,
    pub findings: Vec<ScannedColumn>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TableMaskSummary {
    pub table: String,
    pub rows_processed: usize,
    pub masked_columns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MaskReport {
    pub ok: bool,
    pub input: String,
    pub output: String,
    pub tables_masked: usize,
    pub total_rows: usize,
    pub total_masked_columns: usize,
    pub tables: Vec<TableMaskSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LeakDetail {
    pub table: String,
    pub column: String,
    pub leaked_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub original: String,
    pub masked: String,
    pub tables_checked: usize,
    pub row_counts_matched: bool,
    pub key_cardinality_preserved: bool,
    pub pii_leaks_found: usize,
    pub leaks: Vec<LeakDetail>,
    pub notes: Vec<String>,
}

pub fn qid(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub fn is_pg(spec: &str) -> bool {
    spec.starts_with("postgres://") || spec.starts_with("postgresql://")
}

pub fn is_sqlite(spec: &str) -> bool {
    let low = spec.to_ascii_lowercase();
    low.starts_with("sqlite://")
        || low.ends_with(".db")
        || low.ends_with(".sqlite")
        || low.ends_with(".sqlite3")
}

fn sqlite_path(spec: &str) -> &str {
    spec.strip_prefix("sqlite://").unwrap_or(spec)
}

fn connect_postgres(db_url: &str) -> Result<PgClient> {
    let parsed = Url::parse(db_url).map_err(|e| {
        MaskkeelError::config(
            format!("Invalid PostgreSQL URL: {e}"),
            "Use `postgres://user:pass@host:5432/dbname`.",
        )
    })?;
    let sslmode = parsed
        .query_pairs()
        .find(|(k, _)| k.eq_ignore_ascii_case("sslmode"))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    let host = parsed.host_str().unwrap_or("localhost");
    let is_local = host == "localhost" || host == "127.0.0.1" || host == "::1";
    let use_tls = match sslmode.as_str() {
        "disable" => false,
        "require" | "verify-ca" | "verify-full" => true,
        _ => !is_local,
    };
    if use_tls {
        let mut builder = TlsConnector::builder();
        if sslmode == "require" || sslmode.is_empty() {
            builder.danger_accept_invalid_certs(true);
        }
        let connector = builder
            .build()
            .map_err(|e| MaskkeelError::db(format!("TLS error: {e}"), "", false))?;
        PgClient::connect(db_url, MakeTlsConnector::new(connector))
            .map_err(|e| MaskkeelError::db(format!("Postgres connect error: {e}"), "", true))
    } else {
        PgClient::connect(db_url, NoTls)
            .map_err(|e| MaskkeelError::db(format!("Postgres connect error: {e}"), "", true))
    }
}

// ── SCAN (Auto-detect PII across CSV, JSONL, Parquet, SQLite, Postgres) ───────

pub fn scan_source(source: &str, schemas: &[String], sample_rows: usize) -> Result<ScanReport> {
    let limit = sample_rows.max(10);
    if is_pg(source) {
        scan_postgres(source, schemas, limit)
    } else if is_sqlite(source) {
        scan_sqlite(source, limit)
    } else {
        let lower = source.to_ascii_lowercase();
        let tname = Path::new(source)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("dataset")
            .to_string();
        if lower.ends_with(".csv") || lower.ends_with(".tsv") {
            let delim = if lower.ends_with(".tsv") { b'\t' } else { b',' };
            let findings = scan_delimited(source, delim, &tname, limit)?;
            Ok(ScanReport {
                source: source.to_string(),
                source_kind: if delim == b'\t' { "tsv" } else { "csv" }.to_string(),
                tables_scanned: 1,
                pii_columns_found: findings.len(),
                findings,
            })
        } else if lower.ends_with(".jsonl") || lower.ends_with(".ndjson") {
            let findings = scan_jsonl(source, &tname, limit)?;
            Ok(ScanReport {
                source: source.to_string(),
                source_kind: "jsonl".to_string(),
                tables_scanned: 1,
                pii_columns_found: findings.len(),
                findings,
            })
        } else if lower.ends_with(".parquet") || lower.ends_with(".pq") {
            let findings = scan_parquet(source, &tname, limit)?;
            Ok(ScanReport {
                source: source.to_string(),
                source_kind: "parquet".to_string(),
                tables_scanned: 1,
                pii_columns_found: findings.len(),
                findings,
            })
        } else {
            Err(MaskkeelError::config(
                format!("Unsupported source `{source}`"),
                "Pass .csv, .tsv, .jsonl, .parquet, sqlite:///path.db, or postgres://...",
            ))
        }
    }
}

fn scan_delimited(path: &str, delim: u8, tname: &str, limit: usize) -> Result<Vec<ScannedColumn>> {
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .from_path(path)
        .map_err(|e| MaskkeelError::io(e, path))?;
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| MaskkeelError::parse(format!("CSV header error: {e}"), ""))?
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut samples: Vec<Vec<String>> = vec![Vec::new(); headers.len()];
    for rec in rdr.records().take(limit) {
        let rec = rec.map_err(|e| MaskkeelError::parse(format!("CSV row error: {e}"), ""))?;
        for (i, s) in samples.iter_mut().enumerate() {
            if let Some(v) = rec.get(i)
                && !v.is_empty()
            {
                s.push(v.to_string());
            }
        }
    }
    let mut findings = Vec::new();
    for (col, vals) in headers.iter().zip(samples.iter()) {
        if let Some(d) = detect_column_pii(col, vals, false) {
            findings.push(detection_to_scanned(tname, col, d));
        }
    }
    Ok(findings)
}

fn scan_jsonl(path: &str, tname: &str, limit: usize) -> Result<Vec<ScannedColumn>> {
    let file = File::open(path).map_err(|e| MaskkeelError::io(e, path))?;
    let rdr = BufReader::new(file);
    let mut cols: IndexSet<String> = IndexSet::new();
    let mut samples: HashMap<String, Vec<String>> = HashMap::new();
    let mut int_flags: HashMap<String, bool> = HashMap::new();
    for line in rdr.lines().take(limit) {
        let line = line.map_err(|e| MaskkeelError::io(e, path))?;
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let val: serde_json::Value = serde_json::from_str(t)
            .map_err(|e| MaskkeelError::parse(format!("JSONL parse error: {e}"), ""))?;
        if let Some(obj) = val.as_object() {
            for (k, v) in obj {
                cols.insert(k.clone());
                let entry = int_flags.entry(k.clone()).or_insert(true);
                match v {
                    serde_json::Value::Null => {}
                    serde_json::Value::Number(n) if n.is_i64() => {
                        samples.entry(k.clone()).or_default().push(n.to_string());
                    }
                    serde_json::Value::String(s) => {
                        *entry = false;
                        if !s.is_empty() {
                            samples.entry(k.clone()).or_default().push(s.clone());
                        }
                    }
                    other => {
                        *entry = false;
                        samples
                            .entry(k.clone())
                            .or_default()
                            .push(other.to_string());
                    }
                }
            }
        }
    }
    let mut findings = Vec::new();
    for c in cols {
        let vals = samples.get(&c).cloned().unwrap_or_default();
        let is_int = *int_flags.get(&c).unwrap_or(&false) && !vals.is_empty();
        if let Some(d) = detect_column_pii(&c, &vals, is_int) {
            findings.push(detection_to_scanned(tname, &c, d));
        }
    }
    Ok(findings)
}

fn scan_parquet(path: &str, tname: &str, limit: usize) -> Result<Vec<ScannedColumn>> {
    let file = File::open(path).map_err(|e| MaskkeelError::io(e, path))?;
    let reader = SerializedFileReader::new(file)
        .map_err(|e| MaskkeelError::parse(format!("Parquet error: {e}"), ""))?;
    let fields = reader
        .metadata()
        .file_metadata()
        .schema_descr()
        .root_schema()
        .get_fields();
    let cols: Vec<(String, bool)> = fields
        .iter()
        .map(|f| {
            let is_int = matches!(
                f.get_physical_type(),
                parquet::basic::Type::INT32 | parquet::basic::Type::INT64
            );
            (f.name().to_string(), is_int)
        })
        .collect();
    let mut samples: Vec<Vec<String>> = vec![Vec::new(); cols.len()];
    let iter = reader
        .get_row_iter(None)
        .map_err(|e| MaskkeelError::parse(format!("Parquet row error: {e}"), ""))?;
    for row_res in iter.take(limit) {
        let rec =
            row_res.map_err(|e| MaskkeelError::parse(format!("Parquet row error: {e}"), ""))?;
        for (i, (_, field)) in rec.get_column_iter().enumerate() {
            if let Some(s) = parquet_field_str(field)
                && i < samples.len()
            {
                samples[i].push(s);
            }
        }
    }
    let mut findings = Vec::new();
    for ((col, is_int), vals) in cols.iter().zip(samples.iter()) {
        if let Some(d) = detect_column_pii(col, vals, *is_int) {
            findings.push(detection_to_scanned(tname, col, d));
        }
    }
    Ok(findings)
}

fn scan_sqlite(source: &str, limit: usize) -> Result<ScanReport> {
    let path = sqlite_path(source);
    let conn = SqliteConn::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| MaskkeelError::db(format!("SQLite open failed: {e}"), "", false))?;
    let tables = sqlite_user_tables(&conn)?;
    let mut findings = Vec::new();
    for tbl in &tables {
        let cols = sqlite_table_cols(&conn, tbl)?;
        for (cname, ctype) in cols {
            let is_int = ctype.to_ascii_uppercase().contains("INT");
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT CAST({} AS TEXT) FROM {} WHERE {} IS NOT NULL LIMIT {limit}",
                    qid(&cname),
                    qid(tbl),
                    qid(&cname)
                ))
                .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
            let vals: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?
                .filter_map(|r| r.ok())
                .collect();
            if let Some(d) = detect_column_pii(&cname, &vals, is_int) {
                findings.push(detection_to_scanned(tbl, &cname, d));
            }
        }
    }
    Ok(ScanReport {
        source: path.to_string(),
        source_kind: "sqlite".to_string(),
        tables_scanned: tables.len(),
        pii_columns_found: findings.len(),
        findings,
    })
}

fn scan_postgres(db_url: &str, schemas: &[String], limit: usize) -> Result<ScanReport> {
    let mut client = connect_postgres(db_url)?;
    let mut tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .map_err(|e| MaskkeelError::db(e.to_string(), "", true))?;
    let _ = tx.batch_execute("SET LOCAL statement_timeout = '30s';");

    let tables = pg_list_tables(&mut tx, schemas)?;
    let mut findings = Vec::new();
    for (sch, tbl) in &tables {
        let qname = format!("{sch}.{tbl}");
        let cols = pg_table_cols(&mut tx, sch, tbl)?;
        for (cname, dtype) in cols {
            let is_int = dtype.to_ascii_lowercase().contains("int");
            let q = format!(
                "SELECT CAST({} AS TEXT) FROM {}.{} WHERE {} IS NOT NULL LIMIT {limit}",
                qid(&cname),
                qid(sch),
                qid(tbl),
                qid(&cname)
            );
            let vals: Vec<String> = tx
                .query(&q, &[])
                .unwrap_or_default()
                .into_iter()
                .map(|r| r.get::<_, String>(0))
                .collect();
            if let Some(d) = detect_column_pii(&cname, &vals, is_int) {
                findings.push(detection_to_scanned(&qname, &cname, d));
            }
        }
    }
    let _ = tx.rollback();
    Ok(ScanReport {
        source: "postgres".to_string(),
        source_kind: "postgres".to_string(),
        tables_scanned: tables.len(),
        pii_columns_found: findings.len(),
        findings,
    })
}

// ── MASK (File->File, SQLite->SQLite, Postgres->Postgres) ─────────────────────

pub fn mask_source(
    input: &str,
    output: &str,
    config: &MaskConfig,
    auto_detect: bool,
    salt: &str,
    schemas: &[String],
) -> Result<MaskReport> {
    // Hard safety check: NEVER overwrite input in place!
    if input.trim() == output.trim() {
        return Err(MaskkeelError::UnsafeInPlace {
            message: format!("Input and output are identical (`{input}`)"),
            fix_hint: "Always write masked data to a separate output file, SQLite copy, or target PostgreSQL database.".to_string(),
        });
    }

    let engine = MaskEngine::new(
        salt,
        config.email_domain.as_deref(),
        config.date_shift_days.unwrap_or(30),
    );

    if is_pg(input) && is_pg(output) {
        mask_postgres(input, output, config, auto_detect, &engine, schemas)
    } else if is_sqlite(input) && is_sqlite(output) {
        mask_sqlite(input, output, config, auto_detect, &engine)
    } else {
        let lower_in = input.to_ascii_lowercase();
        if lower_in.ends_with(".csv") || lower_in.ends_with(".tsv") {
            let delim = if lower_in.ends_with(".tsv") {
                b'\t'
            } else {
                b','
            };
            mask_delimited_file(input, output, delim, config, auto_detect, &engine)
        } else if lower_in.ends_with(".jsonl") || lower_in.ends_with(".ndjson") {
            mask_jsonl_file(input, output, config, auto_detect, &engine)
        } else if lower_in.ends_with(".parquet") || lower_in.ends_with(".pq") {
            mask_parquet_to_jsonl(input, output, config, auto_detect, &engine)
        } else {
            Err(MaskkeelError::config(
                format!("Unsupported input/output pair `{input}` -> `{output}`"),
                "Supported: CSV->CSV, TSV->TSV, JSONL->JSONL, Parquet->JSONL, SQLite->SQLite, Postgres->Postgres.",
            ))
        }
    }
}

fn mask_delimited_file(
    input: &str,
    output: &str,
    delim: u8,
    config: &MaskConfig,
    auto_detect: bool,
    engine: &MaskEngine,
) -> Result<MaskReport> {
    let tname = Path::new(input)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("dataset")
        .to_string();

    let mut auto_map: HashMap<String, MaskStrategy> = HashMap::new();
    if auto_detect {
        for f in scan_delimited(input, delim, &tname, 200)? {
            auto_map.insert(f.column.to_ascii_lowercase(), f.recommended_strategy);
        }
    }

    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .from_path(input)
        .map_err(|e| MaskkeelError::io(e, input))?;
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| MaskkeelError::parse(e.to_string(), ""))?
        .iter()
        .map(|s| s.to_string())
        .collect();

    let strategies: Vec<MaskStrategy> = headers
        .iter()
        .map(|h| {
            config
                .resolve_strategy(&tname, h)
                .or_else(|| auto_map.get(&h.to_ascii_lowercase()).copied())
                .unwrap_or(MaskStrategy::Keep)
        })
        .collect();

    let masked_columns: Vec<String> = headers
        .iter()
        .zip(strategies.iter())
        .filter(|(_, s)| **s != MaskStrategy::Keep)
        .map(|(h, s)| format!("{h}:{}", s.as_str()))
        .collect();

    let mut wtr = csv::WriterBuilder::new()
        .delimiter(delim)
        .from_path(output)
        .map_err(|e| MaskkeelError::io(e, output))?;
    wtr.write_record(&headers)
        .map_err(|e| MaskkeelError::io(e, output))?;

    let mut rows_processed = 0usize;
    for rec in rdr.records() {
        let rec = rec.map_err(|e| MaskkeelError::parse(e.to_string(), ""))?;
        let mut out_row = Vec::with_capacity(headers.len());
        for (i, &strat) in strategies.iter().enumerate() {
            let raw = rec.get(i).unwrap_or("");
            if raw.is_empty() {
                out_row.push(String::new());
            } else {
                out_row.push(engine.mask_str(raw, strat).unwrap_or_default());
            }
        }
        wtr.write_record(&out_row)
            .map_err(|e| MaskkeelError::io(e, output))?;
        rows_processed += 1;
    }
    wtr.flush().map_err(|e| MaskkeelError::io(e, output))?;

    Ok(MaskReport {
        ok: true,
        input: input.to_string(),
        output: output.to_string(),
        tables_masked: 1,
        total_rows: rows_processed,
        total_masked_columns: masked_columns.len(),
        tables: vec![TableMaskSummary {
            table: tname,
            rows_processed,
            masked_columns,
        }],
    })
}

fn mask_jsonl_file(
    input: &str,
    output: &str,
    config: &MaskConfig,
    auto_detect: bool,
    engine: &MaskEngine,
) -> Result<MaskReport> {
    let tname = Path::new(input)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("dataset")
        .to_string();

    let mut auto_map: HashMap<String, MaskStrategy> = HashMap::new();
    if auto_detect {
        for f in scan_jsonl(input, &tname, 200)? {
            auto_map.insert(f.column.to_ascii_lowercase(), f.recommended_strategy);
        }
    }

    let in_file = File::open(input).map_err(|e| MaskkeelError::io(e, input))?;
    let out_file = File::create(output).map_err(|e| MaskkeelError::io(e, output))?;
    let rdr = BufReader::new(in_file);
    let mut wtr = BufWriter::new(out_file);

    let mut rows_processed = 0usize;
    let mut masked_cols_seen: IndexSet<String> = IndexSet::new();

    for line in rdr.lines() {
        let line = line.map_err(|e| MaskkeelError::io(e, input))?;
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let mut val: serde_json::Value =
            serde_json::from_str(t).map_err(|e| MaskkeelError::parse(e.to_string(), ""))?;
        if let Some(obj) = val.as_object_mut() {
            for (k, v) in obj.iter_mut() {
                let strat = config
                    .resolve_strategy(&tname, k)
                    .or_else(|| auto_map.get(&k.to_ascii_lowercase()).copied())
                    .unwrap_or(MaskStrategy::Keep);
                if strat == MaskStrategy::Keep {
                    continue;
                }
                masked_cols_seen.insert(format!("{k}:{}", strat.as_str()));
                *v = mask_json_val(v, strat, engine);
            }
        }
        writeln!(wtr, "{}", serde_json::to_string(&val).unwrap_or_default())
            .map_err(|e| MaskkeelError::io(e, output))?;
        rows_processed += 1;
    }
    wtr.flush().map_err(|e| MaskkeelError::io(e, output))?;

    let masked_columns: Vec<String> = masked_cols_seen.into_iter().collect();
    Ok(MaskReport {
        ok: true,
        input: input.to_string(),
        output: output.to_string(),
        tables_masked: 1,
        total_rows: rows_processed,
        total_masked_columns: masked_columns.len(),
        tables: vec![TableMaskSummary {
            table: tname,
            rows_processed,
            masked_columns,
        }],
    })
}

fn mask_parquet_to_jsonl(
    input: &str,
    output: &str,
    config: &MaskConfig,
    auto_detect: bool,
    engine: &MaskEngine,
) -> Result<MaskReport> {
    let tname = Path::new(input)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("dataset")
        .to_string();

    let mut auto_map: HashMap<String, MaskStrategy> = HashMap::new();
    if auto_detect {
        for f in scan_parquet(input, &tname, 200)? {
            auto_map.insert(f.column.to_ascii_lowercase(), f.recommended_strategy);
        }
    }

    let in_file = File::open(input).map_err(|e| MaskkeelError::io(e, input))?;
    let reader =
        SerializedFileReader::new(in_file).map_err(|e| MaskkeelError::parse(e.to_string(), ""))?;
    let out_file = File::create(output).map_err(|e| MaskkeelError::io(e, output))?;
    let mut wtr = BufWriter::new(out_file);

    let iter = reader
        .get_row_iter(None)
        .map_err(|e| MaskkeelError::parse(e.to_string(), ""))?;
    let mut rows_processed = 0usize;
    let mut masked_cols_seen: IndexSet<String> = IndexSet::new();

    for row_res in iter {
        let rec = row_res.map_err(|e| MaskkeelError::parse(e.to_string(), ""))?;
        let mut obj = serde_json::Map::new();
        for (name, field) in rec.get_column_iter() {
            let mut jv = parquet_field_json(field);
            let strat = config
                .resolve_strategy(&tname, name)
                .or_else(|| auto_map.get(&name.to_ascii_lowercase()).copied())
                .unwrap_or(MaskStrategy::Keep);
            if strat != MaskStrategy::Keep {
                masked_cols_seen.insert(format!("{name}:{}", strat.as_str()));
                jv = mask_json_val(&jv, strat, engine);
            }
            obj.insert(name.clone(), jv);
        }
        writeln!(
            wtr,
            "{}",
            serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_default()
        )
        .map_err(|e| MaskkeelError::io(e, output))?;
        rows_processed += 1;
    }
    wtr.flush().map_err(|e| MaskkeelError::io(e, output))?;

    let masked_columns: Vec<String> = masked_cols_seen.into_iter().collect();
    Ok(MaskReport {
        ok: true,
        input: input.to_string(),
        output: output.to_string(),
        tables_masked: 1,
        total_rows: rows_processed,
        total_masked_columns: masked_columns.len(),
        tables: vec![TableMaskSummary {
            table: tname,
            rows_processed,
            masked_columns,
        }],
    })
}

fn mask_sqlite(
    input: &str,
    output: &str,
    config: &MaskConfig,
    auto_detect: bool,
    engine: &MaskEngine,
) -> Result<MaskReport> {
    let in_path = sqlite_path(input);
    let out_path = sqlite_path(output);
    if Path::new(out_path).exists() {
        std::fs::remove_file(out_path).map_err(|e| MaskkeelError::io(e, out_path))?;
    }

    let src = SqliteConn::open_with_flags(in_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| MaskkeelError::db(format!("SQLite open failed: {e}"), "", false))?;
    let mut dst = SqliteConn::open(out_path)
        .map_err(|e| MaskkeelError::db(format!("SQLite create failed: {e}"), "", false))?;
    let _ = dst.execute_batch("PRAGMA foreign_keys = OFF; PRAGMA journal_mode = WAL;");

    let mut auto_map: HashMap<(String, String), MaskStrategy> = HashMap::new();
    if auto_detect {
        let scan = scan_sqlite(input, 200)?;
        for f in scan.findings {
            auto_map.insert(
                (f.table.to_ascii_lowercase(), f.column.to_ascii_lowercase()),
                f.recommended_strategy,
            );
        }
    }

    // 1. Copy table DDL
    let mut ddl_stmt = src
        .prepare("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name")
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
    let table_ddls: Vec<(String, String)> = ddl_stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?
        .filter_map(|r| r.ok())
        .collect();

    for (_, sql) in &table_ddls {
        dst.execute(sql, [])
            .map_err(|e| MaskkeelError::db(format!("Failed creating table: {e}"), "", false))?;
    }

    // 2. Copy & mask every table's rows inside transactions!
    let mut summaries = Vec::new();
    let mut total_rows = 0usize;
    let mut total_masked_cols = 0usize;

    for (tbl, _) in &table_ddls {
        let cols = sqlite_table_cols(&src, tbl)?;
        let strategies: Vec<MaskStrategy> = cols
            .iter()
            .map(|(cname, _)| {
                config
                    .resolve_strategy(tbl, cname)
                    .or_else(|| {
                        auto_map
                            .get(&(tbl.to_ascii_lowercase(), cname.to_ascii_lowercase()))
                            .copied()
                    })
                    .unwrap_or(MaskStrategy::Keep)
            })
            .collect();

        let masked_columns: Vec<String> = cols
            .iter()
            .zip(strategies.iter())
            .filter(|(_, s)| **s != MaskStrategy::Keep)
            .map(|((c, _), s)| format!("{c}:{}", s.as_str()))
            .collect();
        total_masked_cols += masked_columns.len();

        let col_q: Vec<String> = cols.iter().map(|(c, _)| qid(c)).collect();
        let placeholders: Vec<&str> = vec!["?"; cols.len()];
        let ins_sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            qid(tbl),
            col_q.join(", "),
            placeholders.join(", ")
        );
        let sel_sql = format!("SELECT {} FROM {}", col_q.join(", "), qid(tbl));

        let tx = dst
            .transaction()
            .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
        let mut rows_processed = 0usize;
        {
            let mut ins = tx
                .prepare(&ins_sql)
                .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
            let mut sel = src
                .prepare(&sel_sql)
                .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
            let mut qrows = sel
                .query([])
                .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
            while let Some(r) = qrows
                .next()
                .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?
            {
                let mut params: Vec<SqlVal> = Vec::with_capacity(cols.len());
                for (i, &strat) in strategies.iter().enumerate() {
                    let v = match r.get_ref_unwrap(i) {
                        ValueRef::Null => SqlVal::Null,
                        ValueRef::Integer(n) => {
                            if strat == MaskStrategy::Keep {
                                SqlVal::Integer(n)
                            } else if strat == MaskStrategy::Null {
                                SqlVal::Null
                            } else if matches!(strat, MaskStrategy::IntId | MaskStrategy::Id) {
                                engine
                                    .mask_i64(n, strat)
                                    .map(SqlVal::Integer)
                                    .unwrap_or(SqlVal::Null)
                            } else {
                                engine
                                    .mask_str(&n.to_string(), strat)
                                    .map(SqlVal::Text)
                                    .unwrap_or(SqlVal::Null)
                            }
                        }
                        ValueRef::Real(f) => {
                            if strat == MaskStrategy::Keep {
                                SqlVal::Real(f)
                            } else if strat == MaskStrategy::Null {
                                SqlVal::Null
                            } else {
                                engine
                                    .mask_str(&f.to_string(), strat)
                                    .map(SqlVal::Text)
                                    .unwrap_or(SqlVal::Null)
                            }
                        }
                        ValueRef::Text(b) => {
                            let s = String::from_utf8_lossy(b);
                            engine
                                .mask_str(&s, strat)
                                .map(SqlVal::Text)
                                .unwrap_or(SqlVal::Null)
                        }
                        ValueRef::Blob(b) => {
                            if strat == MaskStrategy::Null {
                                SqlVal::Null
                            } else {
                                SqlVal::Blob(b.to_vec())
                            }
                        }
                    };
                    params.push(v);
                }
                ins.execute(params_from_iter(params.iter())).map_err(|e| {
                    MaskkeelError::db(format!("Masked insert into `{tbl}` failed: {e}"), "", false)
                })?;
                rows_processed += 1;
            }
        }
        tx.commit()
            .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
        total_rows += rows_processed;
        summaries.push(TableMaskSummary {
            table: tbl.clone(),
            rows_processed,
            masked_columns,
        });
    }

    // 3. Recreate indexes & views
    if let Ok(mut idx_stmt) = src.prepare(
        "SELECT sql FROM sqlite_master WHERE type IN ('index', 'view') AND sql IS NOT NULL",
    ) && let Ok(rows) = idx_stmt.query_map([], |r| r.get::<_, String>(0))
    {
        for sql in rows.flatten() {
            let _ = dst.execute(&sql, []);
        }
    }
    let _ = dst.execute_batch("PRAGMA foreign_keys = ON;");

    Ok(MaskReport {
        ok: true,
        input: in_path.to_string(),
        output: out_path.to_string(),
        tables_masked: summaries.len(),
        total_rows,
        total_masked_columns: total_masked_cols,
        tables: summaries,
    })
}

fn mask_postgres(
    src_url: &str,
    dst_url: &str,
    config: &MaskConfig,
    auto_detect: bool,
    engine: &MaskEngine,
    schemas: &[String],
) -> Result<MaskReport> {
    let mut auto_map: HashMap<(String, String), MaskStrategy> = HashMap::new();
    if auto_detect {
        let scan = scan_postgres(src_url, schemas, 200)?;
        for f in scan.findings {
            auto_map.insert(
                (f.table.to_ascii_lowercase(), f.column.to_ascii_lowercase()),
                f.recommended_strategy,
            );
        }
    }

    let mut src_client = connect_postgres(src_url)?;
    let mut dst_client = connect_postgres(dst_url)?;

    let mut src_tx = src_client
        .build_transaction()
        .read_only(true)
        .start()
        .map_err(|e| MaskkeelError::db(e.to_string(), "", true))?;

    let tables = pg_list_tables(&mut src_tx, schemas)?;
    let mut summaries = Vec::new();
    let mut total_rows = 0usize;
    let mut total_masked_cols = 0usize;

    for (sch, tbl) in &tables {
        let qname = format!("{sch}.{tbl}");
        let cols = pg_table_cols(&mut src_tx, sch, tbl)?;
        let strategies: Vec<MaskStrategy> = cols
            .iter()
            .map(|(cname, _)| {
                config
                    .resolve_strategy(&qname, cname)
                    .or_else(|| {
                        auto_map
                            .get(&(qname.to_ascii_lowercase(), cname.to_ascii_lowercase()))
                            .copied()
                    })
                    .unwrap_or(MaskStrategy::Keep)
            })
            .collect();

        let masked_columns: Vec<String> = cols
            .iter()
            .zip(strategies.iter())
            .filter(|(_, s)| **s != MaskStrategy::Keep)
            .map(|((c, _), s)| format!("{c}:{}", s.as_str()))
            .collect();
        total_masked_cols += masked_columns.len();

        // Create schema & table cleanly in destination Postgres
        dst_client
            .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {};", qid(sch)))
            .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
        let col_defs: Vec<String> = cols
            .iter()
            .map(|(c, dt)| format!("{} {dt}", qid(c)))
            .collect();
        dst_client
            .batch_execute(&format!(
                "DROP TABLE IF EXISTS {}.{} CASCADE; CREATE TABLE {}.{} ({});",
                qid(sch),
                qid(tbl),
                qid(sch),
                qid(tbl),
                col_defs.join(", ")
            ))
            .map_err(|e| {
                MaskkeelError::db(format!("CREATE TABLE {qname} failed: {e}"), "", false)
            })?;

        // Stream via row_to_json from read-only src -> masked CSV COPY into dst!
        let src_rows = src_tx
            .query(
                &format!(
                    "SELECT row_to_json(t)::text FROM {}.{} t",
                    qid(sch),
                    qid(tbl)
                ),
                &[],
            )
            .map_err(|e| MaskkeelError::db(e.to_string(), "", true))?;

        let col_q: Vec<String> = cols.iter().map(|(c, _)| qid(c)).collect();
        let copy_sql = format!(
            "COPY {}.{} ({}) FROM STDIN WITH (FORMAT csv, NULL '\\N', QUOTE '\"', ESCAPE '\"')",
            qid(sch),
            qid(tbl),
            col_q.join(", ")
        );
        let cw = dst_client.copy_in(&copy_sql).map_err(|e| {
            MaskkeelError::db(format!("COPY start failed on {qname}: {e}"), "", false)
        })?;
        let mut buf = BufWriter::new(cw);
        let mut rows_processed = 0usize;

        for r in src_rows {
            let js: String = r.get(0);
            let obj: serde_json::Value =
                serde_json::from_str(&js).map_err(|e| MaskkeelError::parse(e.to_string(), ""))?;
            let map = obj.as_object();
            for (i, ((cname, _), &strat)) in cols.iter().zip(strategies.iter()).enumerate() {
                if i > 0 {
                    buf.write_all(b",")
                        .map_err(|e| MaskkeelError::io(e, "COPY"))?;
                }
                let raw_val = map.and_then(|m| m.get(cname));
                let masked_opt: Option<String> = match raw_val {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => {
                        let mv = mask_json_val(v, strat, engine);
                        match mv {
                            serde_json::Value::Null => None,
                            serde_json::Value::String(s) => Some(s),
                            other => Some(other.to_string()),
                        }
                    }
                };
                write_pg_csv_val(&mut buf, masked_opt.as_deref())?;
            }
            buf.write_all(b"\n")
                .map_err(|e| MaskkeelError::io(e, "COPY"))?;
            rows_processed += 1;
        }
        let inner = buf
            .into_inner()
            .map_err(|e| MaskkeelError::io(e.error(), "COPY"))?;
        inner.finish().map_err(|e| {
            MaskkeelError::db(format!("COPY finish failed on {qname}: {e}"), "", false)
        })?;

        total_rows += rows_processed;
        summaries.push(TableMaskSummary {
            table: qname,
            rows_processed,
            masked_columns,
        });
    }

    let _ = src_tx.rollback();
    Ok(MaskReport {
        ok: true,
        input: "postgres (source)".to_string(),
        output: "postgres (target)".to_string(),
        tables_masked: summaries.len(),
        total_rows,
        total_masked_columns: total_masked_cols,
        tables: summaries,
    })
}

// ── VERIFY (Zero-Leak PII Audit + Row/Cardinality Parity) ─────────────────────

pub fn verify_masking(
    original: &str,
    masked: &str,
    config: Option<&MaskConfig>,
    schemas: &[String],
) -> Result<VerifyReport> {
    if is_sqlite(original) && is_sqlite(masked) {
        verify_sqlite(original, masked, config)
    } else if is_pg(original) && is_pg(masked) {
        verify_postgres(original, masked, config, schemas)
    } else if original.to_ascii_lowercase().ends_with(".csv")
        && masked.to_ascii_lowercase().ends_with(".csv")
    {
        verify_csv(original, masked, config)
    } else {
        Err(MaskkeelError::config(
            format!("Unsupported verify pair `{original}` vs `{masked}`"),
            "Compare CSV vs CSV, SQLite vs SQLite, or PostgreSQL vs PostgreSQL.",
        ))
    }
}

fn verify_csv(orig: &str, msk: &str, config: Option<&MaskConfig>) -> Result<VerifyReport> {
    let tname = Path::new(orig)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("dataset");
    let detected = scan_delimited(orig, b',', tname, 500)?;
    let pii_cols: HashSet<String> = detected
        .iter()
        .map(|d| d.column.to_ascii_lowercase())
        .chain(
            config
                .map(|c| {
                    c.columns
                        .iter()
                        .filter(|(_, s)| **s != MaskStrategy::Keep)
                        .map(|(k, _)| k.to_ascii_lowercase())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        )
        .collect();

    let (oh, orows) = read_csv_all(orig)?;
    let (mh, mrows) = read_csv_all(msk)?;
    let row_counts_matched = orows.len() == mrows.len();
    let mut key_cardinality_preserved = true;
    let mut leaks = Vec::new();
    let mut notes = Vec::new();
    if !row_counts_matched {
        notes.push(format!(
            "Row count mismatch: original={}, masked={}",
            orows.len(),
            mrows.len()
        ));
    }

    for (idx, col) in oh.iter().enumerate() {
        let Some(midx) = mh.iter().position(|c| c == col) else {
            continue;
        };
        if !pii_cols.contains(&col.to_ascii_lowercase()) {
            continue;
        }
        let orig_vals: HashSet<String> = orows
            .iter()
            .filter_map(|r| r.get(idx))
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() >= 3)
            .collect();
        let mask_vals: HashSet<String> = mrows
            .iter()
            .filter_map(|r| r.get(midx))
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() >= 3)
            .collect();
        let is_key_col = detected.iter().any(|d| {
            d.column.eq_ignore_ascii_case(col)
                && matches!(
                    d.recommended_strategy,
                    MaskStrategy::Id
                        | MaskStrategy::IntId
                        | MaskStrategy::Email
                        | MaskStrategy::Ssn
                )
        });
        if is_key_col && orig_vals.len() != mask_vals.len() && !mask_vals.contains("[REDACTED]") {
            key_cardinality_preserved = false;
        }
        let leaked = orig_vals.intersection(&mask_vals).count();
        if leaked > 0 {
            leaks.push(LeakDetail {
                table: tname.to_string(),
                column: col.clone(),
                leaked_count: leaked,
            });
        }
    }

    let pii_leaks_found: usize = leaks.iter().map(|l| l.leaked_count).sum();
    Ok(VerifyReport {
        ok: row_counts_matched && pii_leaks_found == 0,
        original: orig.to_string(),
        masked: msk.to_string(),
        tables_checked: 1,
        row_counts_matched,
        key_cardinality_preserved,
        pii_leaks_found,
        leaks,
        notes,
    })
}

fn verify_sqlite(orig: &str, msk: &str, config: Option<&MaskConfig>) -> Result<VerifyReport> {
    let oc = SqliteConn::open_with_flags(sqlite_path(orig), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
    let mc = SqliteConn::open_with_flags(sqlite_path(msk), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
    let scan = scan_sqlite(orig, 500)?;
    let tables = sqlite_user_tables(&oc)?;
    let mut row_counts_matched = true;
    let mut key_cardinality_preserved = true;
    let mut leaks = Vec::new();
    let mut notes = Vec::new();

    for tbl in &tables {
        let ocnt: i64 = oc
            .query_row(&format!("SELECT COUNT(*) FROM {}", qid(tbl)), [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        let mcnt: i64 = mc
            .query_row(&format!("SELECT COUNT(*) FROM {}", qid(tbl)), [], |r| {
                r.get(0)
            })
            .unwrap_or(-1);
        if ocnt != mcnt {
            row_counts_matched = false;
            notes.push(format!(
                "`{tbl}` row count mismatch: original={ocnt}, masked={mcnt}"
            ));
        }

        let pii_cols: HashSet<String> = scan
            .findings
            .iter()
            .filter(|f| f.table == *tbl)
            .map(|f| f.column.clone())
            .collect();
        for col in pii_cols {
            if let Some(cfg) = config
                && cfg.resolve_strategy(tbl, &col) == Some(MaskStrategy::Keep)
            {
                continue;
            }
            let ov = sqlite_distinct_strs(&oc, tbl, &col, 2000);
            let mv = sqlite_distinct_strs(&mc, tbl, &col, 2000);
            let is_key_col = scan.findings.iter().any(|f| {
                f.table == *tbl
                    && f.column == col
                    && matches!(
                        f.recommended_strategy,
                        MaskStrategy::Id
                            | MaskStrategy::IntId
                            | MaskStrategy::Email
                            | MaskStrategy::Ssn
                    )
            });
            if is_key_col && ov.len() != mv.len() && !mv.contains("[REDACTED]") {
                key_cardinality_preserved = false;
            }
            let leaked = ov.intersection(&mv).count();
            if leaked > 0 {
                leaks.push(LeakDetail {
                    table: tbl.clone(),
                    column: col,
                    leaked_count: leaked,
                });
            }
        }
    }

    let pii_leaks_found: usize = leaks.iter().map(|l| l.leaked_count).sum();
    Ok(VerifyReport {
        ok: row_counts_matched && pii_leaks_found == 0,
        original: orig.to_string(),
        masked: msk.to_string(),
        tables_checked: tables.len(),
        row_counts_matched,
        key_cardinality_preserved,
        pii_leaks_found,
        leaks,
        notes,
    })
}

fn verify_postgres(
    orig_url: &str,
    msk_url: &str,
    config: Option<&MaskConfig>,
    schemas: &[String],
) -> Result<VerifyReport> {
    let scan = scan_postgres(orig_url, schemas, 500)?;
    let mut oc = connect_postgres(orig_url)?;
    let mut mc = connect_postgres(msk_url)?;
    let mut otx = oc
        .build_transaction()
        .read_only(true)
        .start()
        .map_err(|e| MaskkeelError::db(e.to_string(), "", true))?;
    let mut mtx = mc
        .build_transaction()
        .read_only(true)
        .start()
        .map_err(|e| MaskkeelError::db(e.to_string(), "", true))?;

    let tables = pg_list_tables(&mut otx, schemas)?;
    let mut row_counts_matched = true;
    let mut key_cardinality_preserved = true;
    let mut leaks = Vec::new();
    let mut notes = Vec::new();

    for (sch, tbl) in &tables {
        let qname = format!("{sch}.{tbl}");
        let q = format!("SELECT COUNT(*) FROM {}.{}", qid(sch), qid(tbl));
        let ocnt: i64 = otx.query_one(&q, &[]).map(|r| r.get(0)).unwrap_or(0);
        let mcnt: i64 = mtx.query_one(&q, &[]).map(|r| r.get(0)).unwrap_or(-1);
        if ocnt != mcnt {
            row_counts_matched = false;
            notes.push(format!(
                "`{qname}` row count mismatch: original={ocnt}, masked={mcnt}"
            ));
        }
        let pii_cols: HashSet<String> = scan
            .findings
            .iter()
            .filter(|f| f.table == qname)
            .map(|f| f.column.clone())
            .collect();
        for col in pii_cols {
            if let Some(cfg) = config
                && cfg.resolve_strategy(&qname, &col) == Some(MaskStrategy::Keep)
            {
                continue;
            }
            let ov = pg_distinct_strs(&mut otx, sch, tbl, &col, 2000);
            let mv = pg_distinct_strs(&mut mtx, sch, tbl, &col, 2000);
            let is_key_col = scan.findings.iter().any(|f| {
                f.table == qname
                    && f.column == col
                    && matches!(
                        f.recommended_strategy,
                        MaskStrategy::Id
                            | MaskStrategy::IntId
                            | MaskStrategy::Email
                            | MaskStrategy::Ssn
                    )
            });
            if is_key_col && ov.len() != mv.len() && !mv.contains("[REDACTED]") {
                key_cardinality_preserved = false;
            }
            let leaked = ov.intersection(&mv).count();
            if leaked > 0 {
                leaks.push(LeakDetail {
                    table: qname.clone(),
                    column: col,
                    leaked_count: leaked,
                });
            }
        }
    }
    let _ = otx.rollback();
    let _ = mtx.rollback();

    let pii_leaks_found: usize = leaks.iter().map(|l| l.leaked_count).sum();
    Ok(VerifyReport {
        ok: row_counts_matched && pii_leaks_found == 0,
        original: "postgres (original)".to_string(),
        masked: "postgres (masked)".to_string(),
        tables_checked: tables.len(),
        row_counts_matched,
        key_cardinality_preserved,
        pii_leaks_found,
        leaks,
        notes,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn mask_json_val(
    v: &serde_json::Value,
    strat: MaskStrategy,
    engine: &MaskEngine,
) -> serde_json::Value {
    match v {
        serde_json::Value::Null => serde_json::Value::Null,
        serde_json::Value::Number(n) => {
            if strat == MaskStrategy::Keep {
                return v.clone();
            }
            if strat == MaskStrategy::Null {
                return serde_json::Value::Null;
            }
            if let Some(i) = n.as_i64()
                && matches!(strat, MaskStrategy::IntId | MaskStrategy::Id)
            {
                return engine
                    .mask_i64(i, strat)
                    .map(|m| serde_json::json!(m))
                    .unwrap_or(serde_json::Value::Null);
            }
            engine
                .mask_str(&n.to_string(), strat)
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null)
        }
        serde_json::Value::String(s) => engine
            .mask_str(s, strat)
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
        other => {
            if strat == MaskStrategy::Keep {
                other.clone()
            } else if strat == MaskStrategy::Null {
                serde_json::Value::Null
            } else {
                engine
                    .mask_str(&other.to_string(), strat)
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null)
            }
        }
    }
}

fn write_pg_csv_val<W: Write>(w: &mut W, val: Option<&str>) -> Result<()> {
    let map_err = |e: std::io::Error| MaskkeelError::io(e, "COPY");
    match val {
        None => w.write_all(b"\\N").map_err(map_err),
        Some(s) => {
            let needs_quote = s.contains(',')
                || s.contains('"')
                || s.contains('\n')
                || s.contains('\r')
                || s == "\\N";
            if !needs_quote {
                w.write_all(s.as_bytes()).map_err(map_err)
            } else {
                w.write_all(b"\"").map_err(map_err)?;
                for ch in s.chars() {
                    if ch == '"' {
                        w.write_all(b"\"\"").map_err(map_err)?;
                    } else {
                        let mut b = [0u8; 4];
                        w.write_all(ch.encode_utf8(&mut b).as_bytes())
                            .map_err(map_err)?;
                    }
                }
                w.write_all(b"\"").map_err(map_err)
            }
        }
    }
}

fn sqlite_user_tables(conn: &SqliteConn) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
    let out: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(out)
}

fn sqlite_table_cols(conn: &SqliteConn, tbl: &str) -> Result<Vec<(String, String)>> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({})", qid(tbl)))
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
    let out: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(out)
}

fn sqlite_distinct_strs(conn: &SqliteConn, tbl: &str, col: &str, limit: usize) -> HashSet<String> {
    let q = format!(
        "SELECT DISTINCT CAST({} AS TEXT) FROM {} WHERE {} IS NOT NULL LIMIT {limit}",
        qid(col),
        qid(tbl),
        qid(col)
    );
    conn.prepare(&q)
        .ok()
        .and_then(|mut s| {
            s.query_map([], |r| r.get::<_, String>(0))
                .ok()
                .map(|it| it.flatten().filter(|v| v.trim().len() >= 3).collect())
        })
        .unwrap_or_default()
}

fn pg_list_tables(
    tx: &mut postgres::Transaction,
    schemas: &[String],
) -> Result<Vec<(String, String)>> {
    let rows = tx
        .query(
            "SELECT n.nspname, c.relname
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE c.relkind IN ('r', 'p')
               AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
               AND n.nspname NOT LIKE 'pg_temp_%'
             ORDER BY n.nspname, c.relname",
            &[],
        )
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
    let mut out = Vec::new();
    for r in rows {
        let sch: String = r.get(0);
        let tbl: String = r.get(1);
        if schemas.is_empty() || schemas.iter().any(|s| s.eq_ignore_ascii_case(&sch)) {
            out.push((sch, tbl));
        }
    }
    Ok(out)
}

fn pg_table_cols(
    tx: &mut postgres::Transaction,
    sch: &str,
    tbl: &str,
) -> Result<Vec<(String, String)>> {
    let rows = tx
        .query(
            "SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod)
             FROM pg_catalog.pg_attribute a
             JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = $1 AND c.relname = $2 AND a.attnum > 0 AND NOT a.attisdropped
             ORDER BY a.attnum",
            &[&sch, &tbl],
        )
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?;
    Ok(rows.into_iter().map(|r| (r.get(0), r.get(1))).collect())
}

fn pg_distinct_strs(
    tx: &mut postgres::Transaction,
    sch: &str,
    tbl: &str,
    col: &str,
    limit: usize,
) -> HashSet<String> {
    let q = format!(
        "SELECT DISTINCT CAST({} AS TEXT) FROM {}.{} WHERE {} IS NOT NULL LIMIT {limit}",
        qid(col),
        qid(sch),
        qid(tbl),
        qid(col)
    );
    tx.query(&q, &[])
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.get::<_, String>(0))
        .filter(|v| v.trim().len() >= 3)
        .collect()
}

fn read_csv_all(path: &str) -> Result<(Vec<String>, Vec<Vec<String>>)> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .map_err(|e| MaskkeelError::io(e, path))?;
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| MaskkeelError::parse(e.to_string(), ""))?
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| MaskkeelError::parse(e.to_string(), ""))?;
        rows.push(rec.iter().map(|s| s.to_string()).collect());
    }
    Ok((headers, rows))
}

fn parquet_field_str(field: &ParquetField) -> Option<String> {
    match field {
        ParquetField::Null => None,
        ParquetField::Str(s) => Some(s.clone()),
        ParquetField::Int(v) => Some(v.to_string()),
        ParquetField::Long(v) => Some(v.to_string()),
        other => Some(other.to_string()),
    }
}

fn parquet_field_json(field: &ParquetField) -> serde_json::Value {
    match field {
        ParquetField::Null => serde_json::Value::Null,
        ParquetField::Bool(b) => serde_json::Value::Bool(*b),
        ParquetField::Int(v) => serde_json::json!(*v),
        ParquetField::Long(v) => serde_json::json!(*v),
        ParquetField::Float(v) => serde_json::json!(*v),
        ParquetField::Double(v) => serde_json::json!(*v),
        ParquetField::Str(s) => serde_json::Value::String(s.clone()),
        other => serde_json::Value::String(other.to_string()),
    }
}
