use crate::error::{MaskkeelError, Result};
use std::path::Path;

pub const SKILL_MD: &str = r#"---
name: maskkeel
description: Deterministic, referentially-intact FERPA/PII data scrubber for CSV, TSV, JSONL, Parquet, SQLite, and PostgreSQL using keyed HMAC-SHA256, with embedded free-text/JSONB redaction, FK-coherent subsetting, and offline HTML compliance receipts.
---

# maskkeel — Deterministic PII & FERPA Data Scrubber (v0.2)

`maskkeel` safely anonymizes sensitive production exports and databases into realistic, **referentially-intact** dev/test fixtures so engineers and AI coding agents can debug real schemas, queries, and join edge cases with **zero real PII exposure**.

## Core Safety & Referential Integrity Guarantees

1. **Deterministic Keyed HMAC-SHA256 (`--salt` / `MASKKEEL_SALT`)**:
   - The same real value + same salt ALWAYS produces the exact same synthetic value across files, tables, and databases (`populi.students` ↔ `canvas.pseudonyms` ↔ exported CSVs/Parquets).
   - Emits a non-reversible `salt_fingerprint` so compliance logs prove fixture consistency without ever leaking the secret salt.
2. **Cross-Type & Leading-Zero Format Preservation**:
   - `INTEGER 1001` (`int_id`), `TEXT "1001"` (`id`), and zero-padded `TEXT "001001"` (`id`) share the exact same numeric core hash -> `8472`, `"8472"`, and `"008472"`.
   - Real cross-system joins like `LTRIM(c.sis_user_id, '0') = CAST(s.person_id AS TEXT)` keep **100% identical match rates, fan-out, and orphan ratios**!
3. **Free-Text & JSONB Embedded PII Redaction (`text_redact`)**:
   - Auto-detects emails, SSNs, phones, and IPv4s hidden inside unstructured notes, Canvas comments, and Postgres `JSON`/`JSONB` blobs — replacing them deterministically using the same HMAC engine (so an email inside an advisor note hashes to the exact same synthetic email as `students.email`!).
4. **FK-Coherent Subsetting (`--limit` / `--sample`) & Postgres Structure Preservation**:
   - Topologically sorts parent → child foreign-key tables so `--limit 1000` or `--sample 10` shrinks large DBs into fast dev mirrors with **zero broken FKs**, while preserving Postgres PKs, UNIQUEs, secondary indexes, FKs, and identity sequences (`setval`).
5. **Never Overwrites In-Place (`E_UNSAFE_INPLACE`)**:
   - Refuses identical input/output paths or database URLs. Production reads run in `READ ONLY` transactions.
6. **Zero-Leak Audit & Compliance Receipt (`maskkeel verify --html receipt.html`)**:
   - Audits masked outputs (including embedded PII inside `text_redact` columns) for row-count parity, identifier cardinality preservation, and **0 leaked original PII values** (exits `1` if any leak is found).

## Standard 3-Step Workflow

### 1. Scan & Generate a Masking Plan
```bash
maskkeel scan postgres://readonly@prod/lake --schema populi,canvas --init-config mask.toml
maskkeel scan students.parquet --init-config mask.toml
```

### 2. Scrub to a Safe Target (with Secret Salt & Optional Subsetting)
```bash
export MASKKEEL_SALT="replace-with-team-dev-secret"

# PostgreSQL -> local dev PostgreSQL (read-only src -> COPY dst, preserves PK/FK/indexes/sequences)
maskkeel mask "$PROD_RO_URL" "$DEV_DB_URL" --config mask.toml --require-salt --schema populi,canvas

# Fast FK-coherent subset for giant databases
maskkeel mask "$PROD_RO_URL" "$DEV_DB_URL" --config mask.toml --require-salt --limit 5000 --schema populi,canvas

# Native Parquet -> Parquet (ZSTD compressed)
maskkeel mask raw_students.parquet dev_students.parquet --config mask.toml --require-salt

# SQLite -> masked SQLite copy (preserves DDL, indexes, views; supports --limit / --sample)
maskkeel mask prod_lake.db dev_lake.db --config mask.toml --require-salt
```

### 3. Verify Zero PII Leaks & Emit Offline HTML Compliance Receipt
```bash
maskkeel verify "$PROD_RO_URL" "$DEV_DB_URL" --config mask.toml --schema populi,canvas --html compliance-receipt.html
maskkeel verify raw_students.parquet dev_students.parquet --config mask.toml --html receipt.html
# If masked with --limit or --sample:
maskkeel verify prod_lake.db dev_lake.db --allow-subset --html receipt.html
```

## Available Masking Strategies (`mask.toml`)

| Strategy | Output Example | Notes |
|---|---|---|
| `name` | `Elena Vance` | Deterministic full name |
| `first_name` | `Elena` | Deterministic first name |
| `last_name` | `Vance` | Deterministic last name |
| `email` | `elena.vance.4821@example.edu` | Case-insensitive HMAC, configurable `email_domain` |
| `phone` | `(555) 142-8831` | FCC fictional `555-01xx` block |
| `ssn` | `942-51-7724` | SSA guaranteed-invalid `900-xx-xxxx` range |
| `id` | `008472` / `KLP-7391-582` | Format & leading-zero preserving deterministic ID |
| `int_id` | `8472` | Matches `id` numeric core for cross-type INT/TEXT joins |
| `address` | `4821 Oak Ridge Ln` | Deterministic synthetic street address |
| `date_shift` | `1998-04-19` | Deterministic non-zero day shift within `±date_shift_days` |
| `ip` | `198.51.100.42` | RFC-5737 `TEST-NET-2` |
| `hash` | `h_9f4b2a1c8e7d6a5f` | Deterministic 16-hex HMAC token |
| `text_redact` | `Contact elena.vance...@example.edu` | Deterministically scrubs embedded emails/SSNs/phones/IPs in free-text & JSON/JSONB |
| `redact` | `[REDACTED]` | Constant redaction marker |
| `null` | `NULL` / empty | Nullifies the column |
| `keep` | *(unchanged)* | Explicitly exempts a column from auto-masking |

## Output Modes & Exit Codes
- `--format auto|human|agent|json` (auto-switches to compact Markdown `agent` format when stdout is piped).
- Exit `0`: success / verify passed.
- Exit `1`: verification failed (PII leak or row mismatch).
- Exit `2`: usage, config, I/O, DB, or `E_UNSAFE_INPLACE` error.
"#;

pub fn install_skill(target_dir: &str) -> Result<String> {
    let dir = Path::new(target_dir);
    std::fs::create_dir_all(dir).map_err(|e| MaskkeelError::io(e, target_dir))?;
    let file = dir.join("SKILL.md");
    std::fs::write(&file, SKILL_MD)
        .map_err(|e| MaskkeelError::io(e, &file.display().to_string()))?;
    Ok(file.display().to_string())
}
