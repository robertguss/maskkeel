use crate::config::{MaskConfig, ScannedColumn, detection_to_scanned};
use crate::engine::{
    MaskEngine, MaskStrategy, detect_table_column_pii, extract_embedded_pii_tokens,
};
use crate::error::{MaskkeelError, Result};
use crate::parquet_io::{mask_parquet_to_parquet, verify_parquet};
use chrono::Utc;
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
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use url::Url;

#[derive(Debug, Clone, Default)]
pub struct MaskOptions {
    pub auto_detect: bool,
    pub schemas: Vec<String>,
    pub limit: Option<usize>,
    pub sample_pct: Option<f64>,
}

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
    pub salt_fingerprint: String,
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
pub struct TableVerifySummary {
    pub table: String,
    pub original_rows: usize,
    pub masked_rows: usize,
    pub pii_columns_checked: usize,
    pub leaked_values: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub verified_at: String,
    pub original: String,
    pub masked: String,
    pub tables_checked: usize,
    pub row_counts_matched: bool,
    pub key_cardinality_preserved: bool,
    pub pii_leaks_found: usize,
    pub table_results: Vec<TableVerifySummary>,
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

fn is_parquet(spec: &str) -> bool {
    let low = spec.to_ascii_lowercase();
    low.ends_with(".parquet") || low.ends_with(".pq")
}

fn sqlite_path(spec: &str) -> &str {
    spec.strip_prefix("sqlite://").unwrap_or(spec)
}

fn should_keep_sample(row_idx: usize, sample_pct: Option<f64>) -> bool {
    let Some(pct) = sample_pct else {
        return true;
    };
    if pct >= 100.0 {
        return true;
    }
    // Deterministic 10_000-bucket hash so repeated runs sample the exact same rows
    let h = (row_idx as u64)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    let bucket = (h >> 16) % 10_000;
    (bucket as f64) < (pct * 100.0)
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
        } else if is_parquet(source) {
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
        if let Some(d) = detect_table_column_pii(tname, col, vals, false) {
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
        if let Some(d) = detect_table_column_pii(tname, &c, &vals, is_int) {
            findings.push(detection_to_scanned(tname, &c, d));
        }
    }
    Ok(findings)
}

pub fn scan_parquet(path: &str, tname: &str, limit: usize) -> Result<Vec<ScannedColumn>> {
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
        if let Some(d) = detect_table_column_pii(tname, col, vals, *is_int) {
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
            if let Some(d) = detect_table_column_pii(tbl, &cname, &vals, is_int) {
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
            if let Some(d) = detect_table_column_pii(&qname, &cname, &vals, is_int) {
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

// ── MASK (File->File, Parquet->Parquet/JSONL, SQLite->SQLite, Postgres->Postgres) ──

pub fn mask_source(
    input: &str,
    output: &str,
    config: &MaskConfig,
    opts: &MaskOptions,
    salt: &str,
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
        mask_postgres(input, output, config, opts, &engine)
    } else if is_sqlite(input) && is_sqlite(output) {
        mask_sqlite(input, output, config, opts, &engine)
    } else {
        let lower_in = input.to_ascii_lowercase();
        if lower_in.ends_with(".csv") || lower_in.ends_with(".tsv") {
            let delim = if lower_in.ends_with(".tsv") {
                b'\t'
            } else {
                b','
            };
            mask_delimited_file(input, output, delim, config, opts, &engine)
        } else if lower_in.ends_with(".jsonl") || lower_in.ends_with(".ndjson") {
            mask_jsonl_file(input, output, config, opts, &engine)
        } else if is_parquet(input) {
            if is_parquet(output) {
                mask_parquet_to_parquet(
                    input,
                    output,
                    config,
                    opts.auto_detect,
                    &engine,
                    opts.limit,
                )
            } else {
                mask_parquet_to_jsonl(input, output, config, opts, &engine)
            }
        } else {
            Err(MaskkeelError::config(
                format!("Unsupported input/output pair `{input}` -> `{output}`"),
                "Supported: CSV->CSV, TSV->TSV, JSONL->JSONL, Parquet->Parquet/JSONL, SQLite->SQLite, Postgres->Postgres.",
            ))
        }
    }
}

fn mask_delimited_file(
    input: &str,
    output: &str,
    delim: u8,
    config: &MaskConfig,
    opts: &MaskOptions,
    engine: &MaskEngine,
) -> Result<MaskReport> {
    let tname = Path::new(input)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("dataset")
        .to_string();

    let mut auto_map: HashMap<String, MaskStrategy> = HashMap::new();
    if opts.auto_detect {
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
    for (row_idx, rec) in rdr.records().enumerate() {
        if let Some(lim) = opts.limit
            && rows_processed >= lim
        {
            break;
        }
        let rec = rec.map_err(|e| MaskkeelError::parse(e.to_string(), ""))?;
        if !should_keep_sample(row_idx, opts.sample_pct) {
            continue;
        }
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
        salt_fingerprint: engine.salt_fingerprint(),
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
    opts: &MaskOptions,
    engine: &MaskEngine,
) -> Result<MaskReport> {
    let tname = Path::new(input)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("dataset")
        .to_string();

    let mut auto_map: HashMap<String, MaskStrategy> = HashMap::new();
    if opts.auto_detect {
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

    for (row_idx, line) in rdr.lines().enumerate() {
        if let Some(lim) = opts.limit
            && rows_processed >= lim
        {
            break;
        }
        let line = line.map_err(|e| MaskkeelError::io(e, input))?;
        let t = line.trim();
        if t.is_empty() || !should_keep_sample(row_idx, opts.sample_pct) {
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
        salt_fingerprint: engine.salt_fingerprint(),
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
    opts: &MaskOptions,
    engine: &MaskEngine,
) -> Result<MaskReport> {
    let tname = Path::new(input)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("dataset")
        .to_string();

    let mut auto_map: HashMap<String, MaskStrategy> = HashMap::new();
    if opts.auto_detect {
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

    for (row_idx, row_res) in iter.enumerate() {
        if let Some(lim) = opts.limit
            && rows_processed >= lim
        {
            break;
        }
        let rec = row_res.map_err(|e| MaskkeelError::parse(e.to_string(), ""))?;
        if !should_keep_sample(row_idx, opts.sample_pct) {
            continue;
        }
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
        salt_fingerprint: engine.salt_fingerprint(),
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

// ── Topological FK ordering helper (parents before children) ──────────────────

#[derive(Debug, Clone)]
struct FkEdge {
    child_table: String,
    child_col: String,
    parent_table: String,
    parent_col: String,
}

fn topo_sort_tables(tables: &[String], fks: &[FkEdge]) -> Vec<String> {
    let table_set: HashSet<String> = tables.iter().cloned().collect();
    let mut in_degree: HashMap<String, usize> = tables.iter().map(|t| (t.clone(), 0)).collect();
    let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

    for fk in fks {
        if fk.child_table == fk.parent_table {
            continue;
        }
        if table_set.contains(&fk.child_table) && table_set.contains(&fk.parent_table) {
            let entry = dependents.entry(fk.parent_table.clone()).or_default();
            if !entry.contains(&fk.child_table) {
                entry.push(fk.child_table.clone());
                *in_degree.entry(fk.child_table.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut queue: VecDeque<String> = tables
        .iter()
        .filter(|t| *in_degree.get(*t).unwrap_or(&0) == 0)
        .cloned()
        .collect();
    let mut ordered = Vec::with_capacity(tables.len());
    let mut seen: HashSet<String> = HashSet::new();

    while let Some(t) = queue.pop_front() {
        if !seen.insert(t.clone()) {
            continue;
        }
        ordered.push(t.clone());
        if let Some(children) = dependents.get(&t) {
            for c in children {
                if let Some(deg) = in_degree.get_mut(c) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push_back(c.clone());
                    }
                }
            }
        }
    }
    // Append any cycle participants deterministically
    for t in tables {
        if seen.insert(t.clone()) {
            ordered.push(t.clone());
        }
    }
    ordered
}

fn mask_sqlite(
    input: &str,
    output: &str,
    config: &MaskConfig,
    opts: &MaskOptions,
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
    if opts.auto_detect {
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
    let ddl_map: HashMap<String, String> = ddl_stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| MaskkeelError::db(e.to_string(), "", false))?
        .filter_map(|r| r.ok())
        .collect();

    let mut table_names: Vec<String> = ddl_map.keys().cloned().collect();
    table_names.sort();

    // Collect SQLite foreign keys for FK-coherent topological ordering & subsetting
    let mut fks = Vec::new();
    for tbl in &table_names {
        if let Ok(mut st) = src.prepare(&format!("PRAGMA foreign_key_list({})", qid(tbl)))
            && let Ok(rows) = st.query_map([], |r| {
                Ok((
                    r.get::<_, String>(2)?, // ref_table
                    r.get::<_, String>(3)?, // from_col
                    r.get::<_, String>(4)?, // to_col
                ))
            })
        {
            for (ref_tbl, from_col, to_col) in rows.flatten() {
                fks.push(FkEdge {
                    child_table: tbl.clone(),
                    child_col: from_col,
                    parent_table: ref_tbl,
                    parent_col: to_col,
                });
            }
        }
    }

    let ordered_tables = topo_sort_tables(&table_names, &fks);
    for tbl in &ordered_tables {
        if let Some(sql) = ddl_map.get(tbl) {
            dst.execute(sql, []).map_err(|e| {
                MaskkeelError::db(format!("Failed creating table `{tbl}`: {e}"), "", false)
            })?;
        }
    }

    let subsetting = opts.limit.is_some() || opts.sample_pct.is_some();
    let referenced_cols: HashSet<(String, String)> = fks
        .iter()
        .map(|f| (f.parent_table.clone(), f.parent_col.to_ascii_lowercase()))
        .collect();
    let mut kept_parent_keys: HashMap<(String, String), HashSet<String>> = HashMap::new();

    // 2. Copy & mask tables in topological parent -> child order!
    let mut summaries = Vec::new();
    let mut total_rows = 0usize;
    let mut total_masked_cols = 0usize;

    for tbl in &ordered_tables {
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

        let incoming_fks: Vec<&FkEdge> = fks
            .iter()
            .filter(|f| f.child_table == *tbl && f.parent_table != *tbl)
            .collect();
        let has_sampled_parent = subsetting
            && incoming_fks.iter().any(|f| {
                kept_parent_keys
                    .contains_key(&(f.parent_table.clone(), f.parent_col.to_ascii_lowercase()))
            });

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
        let mut raw_row_idx = 0usize;
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
                let cur_idx = raw_row_idx;
                raw_row_idx += 1;

                if subsetting {
                    if has_sampled_parent {
                        // Keep row ONLY if every non-null FK references a kept parent key!
                        let mut fk_ok = true;
                        for fk in &incoming_fks {
                            if let Some(pkeys) = kept_parent_keys
                                .get(&(fk.parent_table.clone(), fk.parent_col.to_ascii_lowercase()))
                                && let Some(ci) = cols
                                    .iter()
                                    .position(|(c, _)| c.eq_ignore_ascii_case(&fk.child_col))
                                && let Some(raw_fk) = sqlite_val_key(r.get_ref_unwrap(ci))
                                && !pkeys.contains(&raw_fk)
                            {
                                fk_ok = false;
                                break;
                            }
                        }
                        if !fk_ok {
                            continue;
                        }
                    } else {
                        if let Some(lim) = opts.limit
                            && rows_processed >= lim
                        {
                            break;
                        }
                        if !should_keep_sample(cur_idx, opts.sample_pct) {
                            continue;
                        }
                    }
                }

                // Record kept raw keys if downstream child tables reference this table
                if subsetting {
                    for (ci, (cname, _)) in cols.iter().enumerate() {
                        let key = (tbl.clone(), cname.to_ascii_lowercase());
                        if referenced_cols.contains(&key)
                            && let Some(raw_k) = sqlite_val_key(r.get_ref_unwrap(ci))
                        {
                            kept_parent_keys.entry(key).or_default().insert(raw_k);
                        }
                    }
                }

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
        salt_fingerprint: engine.salt_fingerprint(),
        tables_masked: summaries.len(),
        total_rows,
        total_masked_columns: total_masked_cols,
        tables: summaries,
    })
}

fn sqlite_val_key(vr: ValueRef<'_>) -> Option<String> {
    match vr {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Text(b) => Some(String::from_utf8_lossy(b).into_owned()),
        ValueRef::Blob(_) => None,
    }
}

fn mask_postgres(
    src_url: &str,
    dst_url: &str,
    config: &MaskConfig,
    opts: &MaskOptions,
    engine: &MaskEngine,
) -> Result<MaskReport> {
    let mut auto_map: HashMap<(String, String), MaskStrategy> = HashMap::new();
    if opts.auto_detect {
        let scan = scan_postgres(src_url, &opts.schemas, 200)?;
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

    let raw_tables = pg_list_tables(&mut src_tx, &opts.schemas)?;
    let qnames: Vec<String> = raw_tables.iter().map(|(s, t)| format!("{s}.{t}")).collect();
    let table_split: HashMap<String, (String, String)> = raw_tables
        .iter()
        .map(|(s, t)| (format!("{s}.{t}"), (s.clone(), t.clone())))
        .collect();

    let pg_fks = pg_list_fks(&mut src_tx, &opts.schemas)?;
    let ordered_qnames = topo_sort_tables(&qnames, &pg_fks);

    let subsetting = opts.limit.is_some() || opts.sample_pct.is_some();
    let referenced_cols: HashSet<(String, String)> = pg_fks
        .iter()
        .map(|f| (f.parent_table.clone(), f.parent_col.to_ascii_lowercase()))
        .collect();
    let mut kept_parent_keys: HashMap<(String, String), HashSet<String>> = HashMap::new();

    // Pre-create schemas & tables (drop children first via CASCADE safely)
    let mut table_cols_map: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for qname in &ordered_qnames {
        let (sch, tbl) = &table_split[qname];
        let cols = pg_table_cols(&mut src_tx, sch, tbl)?;
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
        table_cols_map.insert(qname.clone(), cols);
    }

    let mut summaries = Vec::new();
    let mut total_rows = 0usize;
    let mut total_masked_cols = 0usize;

    for qname in &ordered_qnames {
        let (sch, tbl) = &table_split[qname];
        let cols = &table_cols_map[qname];
        let strategies: Vec<MaskStrategy> = cols
            .iter()
            .map(|(cname, _)| {
                config
                    .resolve_strategy(qname, cname)
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

        let incoming_fks: Vec<&FkEdge> = pg_fks
            .iter()
            .filter(|f| f.child_table == *qname && f.parent_table != *qname)
            .collect();
        let has_sampled_parent = subsetting
            && incoming_fks.iter().any(|f| {
                kept_parent_keys
                    .contains_key(&(f.parent_table.clone(), f.parent_col.to_ascii_lowercase()))
            });

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

        for (raw_idx, r) in src_rows.into_iter().enumerate() {
            let js: String = r.get(0);
            let obj: serde_json::Value =
                serde_json::from_str(&js).map_err(|e| MaskkeelError::parse(e.to_string(), ""))?;
            let map = obj.as_object();

            if subsetting {
                if has_sampled_parent {
                    let mut fk_ok = true;
                    for fk in &incoming_fks {
                        if let Some(pkeys) = kept_parent_keys
                            .get(&(fk.parent_table.clone(), fk.parent_col.to_ascii_lowercase()))
                            && let Some(v) = map.and_then(|m| m.get(&fk.child_col))
                            && let Some(raw_fk) = json_val_key(v)
                            && !pkeys.contains(&raw_fk)
                        {
                            fk_ok = false;
                            break;
                        }
                    }
                    if !fk_ok {
                        continue;
                    }
                } else {
                    if let Some(lim) = opts.limit
                        && rows_processed >= lim
                    {
                        break;
                    }
                    if !should_keep_sample(raw_idx, opts.sample_pct) {
                        continue;
                    }
                }

                // Record kept parent raw keys for downstream child tables
                for (cname, _) in cols {
                    let key = (qname.clone(), cname.to_ascii_lowercase());
                    if referenced_cols.contains(&key)
                        && let Some(v) = map.and_then(|m| m.get(cname))
                        && let Some(raw_k) = json_val_key(v)
                    {
                        kept_parent_keys.entry(key).or_default().insert(raw_k);
                    }
                }
            }

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
            table: qname.clone(),
            rows_processed,
            masked_columns,
        });
    }

    // Preserve PKs, UNIQUE constraints, secondary indexes, FKs, and identity/serial sequences!
    pg_apply_constraints_and_indexes(&mut src_tx, &mut dst_client, &ordered_qnames, &table_split)?;

    let _ = src_tx.rollback();
    Ok(MaskReport {
        ok: true,
        input: "postgres (source)".to_string(),
        output: "postgres (target)".to_string(),
        salt_fingerprint: engine.salt_fingerprint(),
        tables_masked: summaries.len(),
        total_rows,
        total_masked_columns: total_masked_cols,
        tables: summaries,
    })
}

fn json_val_key(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn pg_list_fks(tx: &mut postgres::Transaction, schemas: &[String]) -> Result<Vec<FkEdge>> {
    let rows = tx
        .query(
            "SELECT
                cn.nspname AS child_schema,
                cc.relname AS child_table,
                ca.attname AS child_col,
                pn.nspname AS parent_schema,
                pc.relname AS parent_table,
                pa.attname AS parent_col
             FROM pg_catalog.pg_constraint con
             JOIN pg_catalog.pg_class cc ON cc.oid = con.conrelid
             JOIN pg_catalog.pg_namespace cn ON cn.oid = cc.relnamespace
             JOIN pg_catalog.pg_class pc ON pc.oid = con.confrelid
             JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace
             JOIN pg_catalog.pg_attribute ca ON ca.attrelid = cc.oid AND ca.attnum = con.conkey[1]
             JOIN pg_catalog.pg_attribute pa ON pa.attrelid = pc.oid AND pa.attnum = con.confkey[1]
             WHERE con.contype = 'f' AND array_length(con.conkey, 1) = 1",
            &[],
        )
        .unwrap_or_default();

    let mut out = Vec::new();
    for r in rows {
        let cs: String = r.get(0);
        let ct: String = r.get(1);
        let cc: String = r.get(2);
        let ps: String = r.get(3);
        let pt: String = r.get(4);
        let pc: String = r.get(5);
        if schemas.is_empty()
            || (schemas.iter().any(|s| s.eq_ignore_ascii_case(&cs))
                && schemas.iter().any(|s| s.eq_ignore_ascii_case(&ps)))
        {
            out.push(FkEdge {
                child_table: format!("{cs}.{ct}"),
                child_col: cc,
                parent_table: format!("{ps}.{pt}"),
                parent_col: pc,
            });
        }
    }
    Ok(out)
}

fn pg_apply_constraints_and_indexes(
    src_tx: &mut postgres::Transaction,
    dst: &mut PgClient,
    ordered_qnames: &[String],
    table_split: &HashMap<String, (String, String)>,
) -> Result<()> {
    let mut deferred_fks: Vec<String> = Vec::new();

    for qname in ordered_qnames {
        let (sch, tbl) = &table_split[qname];

        // 1. Primary Key & Unique constraints
        let cons = src_tx
            .query(
                "SELECT con.conname, con.contype::text, pg_catalog.pg_get_constraintdef(con.oid)
                 FROM pg_catalog.pg_constraint con
                 JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = $1 AND c.relname = $2 AND con.contype IN ('p', 'u', 'f')
                 ORDER BY CASE con.contype WHEN 'p' THEN 0 WHEN 'u' THEN 1 ELSE 2 END, con.conname",
                &[sch, tbl],
            )
            .unwrap_or_default();

        for r in cons {
            let cname: String = r.get(0);
            let ctype: String = r.get(1);
            let cdef: String = r.get(2);
            let stmt = format!(
                "ALTER TABLE {}.{} ADD CONSTRAINT {} {};",
                qid(sch),
                qid(tbl),
                qid(&cname),
                cdef
            );
            if ctype == "f" {
                deferred_fks.push(stmt);
            } else {
                let _ = dst.batch_execute(&stmt);
            }
        }

        // 2. Non-constraint secondary indexes
        let idxs = src_tx
            .query(
                "SELECT pg_catalog.pg_get_indexdef(i.indexrelid)
                 FROM pg_catalog.pg_index i
                 JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                 LEFT JOIN pg_catalog.pg_constraint con ON con.conindid = i.indexrelid
                 WHERE n.nspname = $1 AND c.relname = $2 AND con.oid IS NULL",
                &[sch, tbl],
            )
            .unwrap_or_default();
        for r in idxs {
            let idef: String = r.get(0);
            let _ = dst.batch_execute(&idef);
        }

        // 3. Preserve serial / identity sequences if present
        let seq_cols = src_tx
            .query(
                "SELECT a.attname, pg_catalog.pg_get_serial_sequence(format('%I.%I', n.nspname, c.relname), a.attname)
                 FROM pg_catalog.pg_attribute a
                 JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = $1 AND c.relname = $2 AND a.attnum > 0 AND NOT a.attisdropped",
                &[sch, tbl],
            )
            .unwrap_or_default();
        for r in seq_cols {
            let col: String = r.get(0);
            let seq: Option<String> = r.get(1);
            if seq.is_some() {
                let seq_name = format!("{tbl}_{col}_seq");
                let _ = dst.batch_execute(&format!(
                    "CREATE SEQUENCE IF NOT EXISTS {}.{};
                     ALTER TABLE {}.{} ALTER COLUMN {} SET DEFAULT nextval('{}.{}');
                     SELECT setval('{}.{}', COALESCE((SELECT MAX({}) FROM {}.{}), 1), true);",
                    qid(sch),
                    qid(&seq_name),
                    qid(sch),
                    qid(tbl),
                    qid(&col),
                    sch,
                    seq_name,
                    sch,
                    seq_name,
                    qid(&col),
                    qid(sch),
                    qid(tbl)
                ));
            }
        }
    }

    // 4. Apply FKs AFTER all tables & PKs are populated!
    for fk_stmt in deferred_fks {
        let _ = dst.batch_execute(&fk_stmt);
    }
    Ok(())
}

// ── VERIFY (Zero-Leak PII Audit + Embedded PII Check + Row/Cardinality Parity) ──

pub fn verify_masking(
    original: &str,
    masked: &str,
    config: Option<&MaskConfig>,
    schemas: &[String],
    allow_subset: bool,
) -> Result<VerifyReport> {
    if is_sqlite(original) && is_sqlite(masked) {
        verify_sqlite(original, masked, config, allow_subset)
    } else if is_pg(original) && is_pg(masked) {
        verify_postgres(original, masked, config, schemas, allow_subset)
    } else if is_parquet(original) && is_parquet(masked) {
        verify_parquet(original, masked, config, allow_subset)
    } else if original.to_ascii_lowercase().ends_with(".csv")
        && masked.to_ascii_lowercase().ends_with(".csv")
    {
        verify_csv(original, masked, config, allow_subset)
    } else {
        Err(MaskkeelError::config(
            format!("Unsupported verify pair `{original}` vs `{masked}`"),
            "Compare CSV vs CSV, Parquet vs Parquet, SQLite vs SQLite, or PostgreSQL vs PostgreSQL.",
        ))
    }
}

fn count_leaks(
    orig_vals: &HashSet<String>,
    mask_vals: &HashSet<String>,
    is_text_redact: bool,
) -> usize {
    if is_text_redact {
        let o_toks: HashSet<String> = orig_vals
            .iter()
            .flat_map(|s| extract_embedded_pii_tokens(s))
            .collect();
        let m_toks: HashSet<String> = mask_vals
            .iter()
            .flat_map(|s| extract_embedded_pii_tokens(s))
            .collect();
        o_toks.intersection(&m_toks).count()
    } else {
        orig_vals.intersection(mask_vals).count()
    }
}

fn verify_csv(
    orig: &str,
    msk: &str,
    config: Option<&MaskConfig>,
    allow_subset: bool,
) -> Result<VerifyReport> {
    let tname = Path::new(orig)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("dataset");
    let detected = scan_delimited(orig, b',', tname, 500)?;
    let mut pii_cols: HashMap<String, MaskStrategy> = detected
        .iter()
        .map(|d| (d.column.to_ascii_lowercase(), d.recommended_strategy))
        .collect();
    if let Some(cfg) = config {
        for (k, &s) in &cfg.columns {
            if s == MaskStrategy::Keep {
                pii_cols.remove(&k.to_ascii_lowercase());
            } else {
                pii_cols.insert(k.to_ascii_lowercase(), s);
            }
        }
    }

    let (oh, orows) = read_csv_all(orig)?;
    let (mh, mrows) = read_csv_all(msk)?;
    let row_counts_matched = if allow_subset {
        mrows.len() <= orows.len() && (orows.is_empty() || !mrows.is_empty())
    } else {
        orows.len() == mrows.len()
    };
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

    let mut checked_cols = 0usize;
    let mut table_leaks = 0usize;

    for (idx, col) in oh.iter().enumerate() {
        let Some(midx) = mh.iter().position(|c| c == col) else {
            continue;
        };
        let Some(&strat) = pii_cols.get(&col.to_ascii_lowercase()) else {
            continue;
        };
        checked_cols += 1;
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
        let is_key_col = matches!(
            strat,
            MaskStrategy::Id | MaskStrategy::IntId | MaskStrategy::Email | MaskStrategy::Ssn
        );
        if !allow_subset
            && is_key_col
            && orig_vals.len() != mask_vals.len()
            && !mask_vals.contains("[REDACTED]")
        {
            key_cardinality_preserved = false;
        }
        let leaked = count_leaks(&orig_vals, &mask_vals, strat == MaskStrategy::TextRedact);
        if leaked > 0 {
            table_leaks += leaked;
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
        verified_at: Utc::now().to_rfc3339(),
        original: orig.to_string(),
        masked: msk.to_string(),
        tables_checked: 1,
        row_counts_matched,
        key_cardinality_preserved,
        pii_leaks_found,
        table_results: vec![TableVerifySummary {
            table: tname.to_string(),
            original_rows: orows.len(),
            masked_rows: mrows.len(),
            pii_columns_checked: checked_cols,
            leaked_values: table_leaks,
        }],
        leaks,
        notes,
    })
}

fn verify_sqlite(
    orig: &str,
    msk: &str,
    config: Option<&MaskConfig>,
    allow_subset: bool,
) -> Result<VerifyReport> {
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
    let mut table_results = Vec::new();

    for tbl in &tables {
        let ocnt: usize = oc
            .query_row(&format!("SELECT COUNT(*) FROM {}", qid(tbl)), [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap_or(0)
            .max(0) as usize;
        let mcnt: usize = mc
            .query_row(&format!("SELECT COUNT(*) FROM {}", qid(tbl)), [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap_or(0)
            .max(0) as usize;

        let ok_cnt = if allow_subset {
            mcnt <= ocnt
        } else {
            ocnt == mcnt
        };
        if !ok_cnt {
            row_counts_matched = false;
            notes.push(format!(
                "`{tbl}` row count mismatch: original={ocnt}, masked={mcnt}"
            ));
        }

        let mut pii_cols: HashMap<String, MaskStrategy> = scan
            .findings
            .iter()
            .filter(|f| f.table == *tbl)
            .map(|f| (f.column.clone(), f.recommended_strategy))
            .collect();
        if let Some(cfg) = config {
            for (cname, _) in sqlite_table_cols(&oc, tbl)? {
                if let Some(s) = cfg.resolve_strategy(tbl, &cname) {
                    if s == MaskStrategy::Keep {
                        pii_cols.remove(&cname);
                    } else {
                        pii_cols.insert(cname, s);
                    }
                }
            }
        }

        let mut table_leaks = 0usize;
        for (col, strat) in &pii_cols {
            let ov = sqlite_distinct_strs(&oc, tbl, col, 2000);
            let mv = sqlite_distinct_strs(&mc, tbl, col, 2000);
            let is_key_col = matches!(
                strat,
                MaskStrategy::Id | MaskStrategy::IntId | MaskStrategy::Email | MaskStrategy::Ssn
            );
            if !allow_subset && is_key_col && ov.len() != mv.len() && !mv.contains("[REDACTED]") {
                key_cardinality_preserved = false;
            }
            let leaked = count_leaks(&ov, &mv, *strat == MaskStrategy::TextRedact);
            if leaked > 0 {
                table_leaks += leaked;
                leaks.push(LeakDetail {
                    table: tbl.clone(),
                    column: col.clone(),
                    leaked_count: leaked,
                });
            }
        }
        table_results.push(TableVerifySummary {
            table: tbl.clone(),
            original_rows: ocnt,
            masked_rows: mcnt,
            pii_columns_checked: pii_cols.len(),
            leaked_values: table_leaks,
        });
    }

    let pii_leaks_found: usize = leaks.iter().map(|l| l.leaked_count).sum();
    Ok(VerifyReport {
        ok: row_counts_matched && pii_leaks_found == 0,
        verified_at: Utc::now().to_rfc3339(),
        original: orig.to_string(),
        masked: msk.to_string(),
        tables_checked: tables.len(),
        row_counts_matched,
        key_cardinality_preserved,
        pii_leaks_found,
        table_results,
        leaks,
        notes,
    })
}

fn verify_postgres(
    orig_url: &str,
    msk_url: &str,
    config: Option<&MaskConfig>,
    schemas: &[String],
    allow_subset: bool,
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
    let mut table_results = Vec::new();

    for (sch, tbl) in &tables {
        let qname = format!("{sch}.{tbl}");
        let q = format!("SELECT COUNT(*) FROM {}.{}", qid(sch), qid(tbl));
        let ocnt: usize = otx
            .query_one(&q, &[])
            .map(|r| r.get::<_, i64>(0))
            .unwrap_or(0)
            .max(0) as usize;
        let mcnt: usize = mtx
            .query_one(&q, &[])
            .map(|r| r.get::<_, i64>(0))
            .unwrap_or(0)
            .max(0) as usize;
        let ok_cnt = if allow_subset {
            mcnt <= ocnt
        } else {
            ocnt == mcnt
        };
        if !ok_cnt {
            row_counts_matched = false;
            notes.push(format!(
                "`{qname}` row count mismatch: original={ocnt}, masked={mcnt}"
            ));
        }

        let mut pii_cols: HashMap<String, MaskStrategy> = scan
            .findings
            .iter()
            .filter(|f| f.table == qname)
            .map(|f| (f.column.clone(), f.recommended_strategy))
            .collect();
        if let Some(cfg) = config {
            for (cname, _) in pg_table_cols(&mut otx, sch, tbl)? {
                if let Some(s) = cfg.resolve_strategy(&qname, &cname) {
                    if s == MaskStrategy::Keep {
                        pii_cols.remove(&cname);
                    } else {
                        pii_cols.insert(cname, s);
                    }
                }
            }
        }

        let mut table_leaks = 0usize;
        for (col, strat) in &pii_cols {
            let ov = pg_distinct_strs(&mut otx, sch, tbl, col, 2000);
            let mv = pg_distinct_strs(&mut mtx, sch, tbl, col, 2000);
            let is_key_col = matches!(
                strat,
                MaskStrategy::Id | MaskStrategy::IntId | MaskStrategy::Email | MaskStrategy::Ssn
            );
            if !allow_subset && is_key_col && ov.len() != mv.len() && !mv.contains("[REDACTED]") {
                key_cardinality_preserved = false;
            }
            let leaked = count_leaks(&ov, &mv, *strat == MaskStrategy::TextRedact);
            if leaked > 0 {
                table_leaks += leaked;
                leaks.push(LeakDetail {
                    table: qname.clone(),
                    column: col.clone(),
                    leaked_count: leaked,
                });
            }
        }
        table_results.push(TableVerifySummary {
            table: qname,
            original_rows: ocnt,
            masked_rows: mcnt,
            pii_columns_checked: pii_cols.len(),
            leaked_values: table_leaks,
        });
    }
    let _ = otx.rollback();
    let _ = mtx.rollback();

    let pii_leaks_found: usize = leaks.iter().map(|l| l.leaked_count).sum();
    Ok(VerifyReport {
        ok: row_counts_matched && pii_leaks_found == 0,
        verified_at: Utc::now().to_rfc3339(),
        original: "postgres (original)".to_string(),
        masked: "postgres (masked)".to_string(),
        tables_checked: tables.len(),
        row_counts_matched,
        key_cardinality_preserved,
        pii_leaks_found,
        table_results,
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
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
            if strat == MaskStrategy::Keep {
                v.clone()
            } else if strat == MaskStrategy::Null {
                serde_json::Value::Null
            } else if strat == MaskStrategy::TextRedact {
                engine.mask_json_recursive(v)
            } else {
                engine
                    .mask_str(&v.to_string(), strat)
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null)
            }
        }
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
