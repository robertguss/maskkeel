# maskkeel

> **Blazing-fast, deterministic, referentially-intact Rust PII/FERPA data scrubber** for CSV, TSV, JSONL, Parquet, SQLite, and PostgreSQL — engineered for both **Developer Experience (DX)** and **Agent Experience (AX)**.

Part of the [Keel Data Stack](https://github.com/robertguss/keel-stack).

## Why `maskkeel`?

When building analytics, debugging tricky cross-system joins, or working with AI coding agents on **FERPA / HIPAA / PII** datasets, you want realistic dev/test fixtures that **preserve every join key, edge case, and distribution** — without ever leaking a single real student name, email, SSN, phone number, or ID.

- **Deterministic Keyed HMAC-SHA256 (`--salt` / `MASKKEEL_SALT`)**: The exact same raw value + salt produces the exact same synthetic value across files, schemas, and databases (with a non-reversible `salt_fingerprint` for audit trails).
- **Cross-Type & Leading-Zero Format Preservation**: `INTEGER 1001` (`int_id`), `TEXT "1001"` (`id`), and zero-padded `TEXT "001001"` (`id`) share the exact same numeric core hash (`8472`, `"8472"`, `"008472"`), keeping real cross-system joins like `LTRIM(c.sis_user_id, '0') = CAST(s.person_id AS TEXT)` **100% intact**.
- **Free-Text & JSONB Embedded PII Redaction (`text_redact`)**: Automatically detects and deterministically scrubs emails, SSNs, phones, and IPv4s hidden inside unstructured notes, Canvas comments, and Postgres `JSON`/`JSONB` columns.
- **FK-Coherent Subsetting (`--limit` / `--sample`) & Postgres Structure Preservation**: Shrink giant production databases into fast, referentially-intact dev mirrors while preserving Postgres PKs, UNIQUEs, secondary indexes, FKs, and identity/serial sequences (`setval`).
- **Native Parquet → Parquet + Offline Compliance Receipts**: Streams ZSTD-compressed Parquet outputs and emits standalone `--html compliance-receipt.html` audit reports via `maskkeel verify`.
- **Read-Only Source Safety**: Refuses in-place overwrites (`E_UNSAFE_INPLACE`) and streams PostgreSQL sources inside `READ ONLY` transactions into target databases via `COPY`.
- **DX + AX Native**: `--format auto|human|agent|json`, strict `stdout`/`stderr` separation, stable error codes + `fix_hint`, and bundled `maskkeel skill`.

## Install

```bash
# Via Cargo
cargo install maskkeel

# Via uv / pip (prebuilt wheel)
uv tool install maskkeel

# Or prebuilt single binary from GitHub Releases
curl -fsSL https://raw.githubusercontent.com/robertguss/keel-stack/main/scripts/install.sh | bash -s -- maskkeel
```

## Quick Start

### 1. Scan & Generate `mask.toml`
```bash
maskkeel scan students.csv --init-config mask.toml
maskkeel scan postgres://readonly@prod/lake --schema populi,canvas --init-config mask.toml
```

### 2. Scrub to a Safe Dev Copy
```bash
export MASKKEEL_SALT="team-dev-fixture-secret"

# CSV / TSV / JSONL / Parquet -> masked file
maskkeel mask students.csv dev_students.csv --config mask.toml --require-salt

# SQLite -> masked SQLite (preserves DDL, indexes, views)
maskkeel mask prod_lake.db dev_lake.db --config mask.toml --require-salt

# PostgreSQL (read-only) -> local dev PostgreSQL (COPY)
maskkeel mask "$PROD_RO_URL" "$DEV_DB_URL" --config mask.toml --require-salt --schema populi,canvas
```

### 3. Verify Zero PII Leaks
```bash
maskkeel verify prod_lake.db dev_lake.db --config mask.toml
maskkeel verify "$PROD_RO_URL" "$DEV_DB_URL" --config mask.toml --schema populi,canvas
```

## Supported Masking Strategies

`name`, `first_name`, `last_name`, `email`, `phone` (FCC `555-01xx`), `ssn` (SSA invalid `900-xx-xxxx`), `id` (format & leading-zero preserving), `int_id` (matches `id` numeric core), `address`, `date_shift`, `ip` (RFC-5737 `198.51.100.x`), `hash`, `redact`, `null`, `keep`.

## Bundled Agent Skill

```bash
maskkeel skill --install .agents/skills/maskkeel
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
