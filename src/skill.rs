use crate::error::{MaskkeelError, Result};
use std::path::Path;

pub const SKILL_MD: &str = r#"---
name: maskkeel
description: Deterministic, referentially-intact FERPA/PII data scrubber for CSV, TSV, JSONL, Parquet, SQLite, and PostgreSQL using keyed HMAC-SHA256.
---

# maskkeel — Deterministic PII & FERPA Data Scrubber

`maskkeel` safely anonymizes sensitive production exports and databases into realistic, **referentially-intact** dev/test fixtures so engineers and AI coding agents can debug real schemas, queries, and join edge cases with **zero real PII exposure**.

## Core Safety & Referential Integrity Guarantees

1. **Deterministic Keyed HMAC-SHA256 (`--salt` / `MASKKEEL_SALT`)**:
   - The same real value + same salt ALWAYS produces the exact same synthetic value across files, tables, and databases (`populi.students` ↔ `canvas.pseudonyms` ↔ exported CSVs).
2. **Cross-Type & Leading-Zero Format Preservation**:
   - `INTEGER 1001` (`int_id`), `TEXT "1001"` (`id`), and zero-padded `TEXT "001001"` (`id`) all hash the same numeric core -> `8472`, `"8472"`, and `"008472"`.
   - Real cross-system joins like `LTRIM(c.sis_user_id, '0') = CAST(s.person_id AS TEXT)` keep **100% identical match rates, fan-out, and orphan ratios**!
3. **Never Overwrites In-Place (`E_UNSAFE_INPLACE`)**:
   - Refuses identical input/output paths or database URLs. Production reads use read-only transactions.
4. **Zero-Leak Verification (`maskkeel verify`)**:
   - Audits masked outputs against originals for row-count parity, identifier cardinality preservation, and **0 leaked original PII values** (exits `1` if any leak is found).

## Standard 3-Step Workflow

### 1. Scan & Generate a Masking Plan
```bash
maskkeel scan postgres://readonly@prod/lake --schema populi,canvas --init-config mask.toml
# Or for files / SQLite:
maskkeel scan students.csv --init-config mask.toml
maskkeel scan lake.db --init-config mask.toml
```

### 2. Scrub to a Safe Target (with Secret Salt)
```bash
export MASKKEEL_SALT="replace-with-team-dev-secret"

# PostgreSQL -> local dev PostgreSQL (read-only src -> COPY dst)
maskkeel mask "$PROD_RO_URL" "$DEV_DB_URL" --config mask.toml --require-salt --schema populi,canvas

# SQLite -> masked SQLite copy (preserves DDL, indexes, views)
maskkeel mask prod_lake.db dev_lake.db --config mask.toml --require-salt

# Files (CSV->CSV, TSV->TSV, JSONL->JSONL, Parquet->JSONL)
maskkeel mask raw_students.csv dev_students.csv --config mask.toml --require-salt
```
*(Omit `--config` to use automatic PII detection, or combine `--config mask.toml --auto` to apply explicit overrides plus auto-detection on new columns.)*

### 3. Verify Zero PII Leaks & Join Parity
```bash
maskkeel verify prod_lake.db dev_lake.db --config mask.toml
maskkeel verify "$PROD_RO_URL" "$DEV_DB_URL" --config mask.toml --schema populi,canvas --format agent
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
