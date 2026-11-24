use chrono::{Duration, NaiveDate};
use hmac::{Hmac, Mac};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaskStrategy {
    Name,
    FirstName,
    LastName,
    Email,
    Phone,
    Ssn,
    Id,
    IntId,
    Address,
    DateShift,
    Ip,
    Hash,
    TextRedact,
    Redact,
    Null,
    Keep,
}

impl MaskStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::FirstName => "first_name",
            Self::LastName => "last_name",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::Id => "id",
            Self::IntId => "int_id",
            Self::Address => "address",
            Self::DateShift => "date_shift",
            Self::Ip => "ip",
            Self::Hash => "hash",
            Self::TextRedact => "text_redact",
            Self::Redact => "redact",
            Self::Null => "null",
            Self::Keep => "keep",
        }
    }
}

const FIRST_NAMES: &[&str] = &[
    "Elena", "Marcus", "Hannah", "Caleb", "Lydia", "Nathan", "Miriam", "Samuel", "Clara", "Isaac",
    "Naomi", "Daniel", "Rachel", "Owen", "Esther", "Lucas", "Abigail", "Jonah", "Grace", "Ethan",
    "Ruth", "Micah", "Sarah", "Gideon", "Leah", "Ezra", "Martha", "Silas", "Phoebe", "Noah",
    "Tessa", "Simon", "Nora", "Josiah", "Audrey", "Eli", "Chloe", "Benjamin", "Maya", "Aaron",
    "Sophie", "Thomas", "Anna", "Peter", "Chloe", "Andrew", "Emma", "Paul", "Olivia", "Luke",
    "Evelyn", "Mark", "Hazel", "Philip", "Ruby", "Stephen", "Iris", "James", "Lillian", "John",
    "Alice", "Matthew", "Violet", "David",
];

const LAST_NAMES: &[&str] = &[
    "Vance",
    "Cole",
    "Mercer",
    "Bennett",
    "Holloway",
    "Caldwell",
    "Sutton",
    "Parrish",
    "Whitaker",
    "Keller",
    "Aldridge",
    "Prescott",
    "harlow",
    "Bramwell",
    "Sterling",
    "Keating",
    "Lowe",
    "Thornton",
    "Benson",
    "Chambers",
    "Fletcher",
    "Garrison",
    "Halstead",
    "Langley",
    "Monroe",
    "Nolan",
    "Pendleton",
    "Quincy",
    "Radcliffe",
    "Sinclair",
    "Tanner",
    "Upton",
    "Vaughn",
    "Waverly",
    "Yates",
    "Zimmer",
    "Alcott",
    "Barrett",
    "Carlisle",
    "Dalton",
    "Ellis",
    "Foster",
    "Graham",
    "Hayes",
    "Irving",
    "Jennings",
    "Kendall",
    "Lawson",
    "Marshall",
    "Norris",
    "Osborne",
    "Parker",
    "Quinn",
    "Reynolds",
    "Spencer",
    "Taylor",
    "Underwood",
    "Vickery",
    "Walsh",
    "Young",
    "Abbott",
    "Bishop",
    "Carter",
    "Dawson",
];

const STREETS: &[&str] = &[
    "Oak Ridge Ln",
    "Cedar Creek Rd",
    "Maple Grove Ave",
    "Birchwood Dr",
    "Sycamore Way",
    "Pinehurst Ct",
    "Willowbrook St",
    "Elmhurst Pl",
    "Ashford Ter",
    "Chestnut Hill Rd",
    "Laurel Valley Ln",
    "Meadowlark Dr",
    "Briarwood Ave",
    "Alder Spring Rd",
    "Hawthorne Way",
    "Linden Park Ct",
];

#[derive(Debug, Clone)]
pub struct MaskEngine {
    salt: Vec<u8>,
    email_domain: String,
    date_shift_days: i64,
}

impl MaskEngine {
    pub fn new(salt: &str, email_domain: Option<&str>, date_shift_days: i64) -> Self {
        Self {
            salt: salt.as_bytes().to_vec(),
            email_domain: email_domain.unwrap_or("example.edu").to_string(),
            date_shift_days: date_shift_days.max(1),
        }
    }

    /// Non-reversible 12-hex fingerprint of the active salt (safe to log in compliance receipts).
    pub fn salt_fingerprint(&self) -> String {
        let h = self.hmac_bytes("salt_fingerprint", "maskkeel-v2");
        let mut out = String::with_capacity(12);
        for b in &h[..6] {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// Deterministically scrub embedded emails, SSNs, phone numbers, and IPv4s inside free-text prose or notes.
    pub fn mask_free_text(&self, text: &str) -> String {
        let re = pii_regexes();
        let s1 = re.email_inline.replace_all(text, |caps: &regex::Captures| {
            self.mask_str(&caps[0], MaskStrategy::Email)
                .unwrap_or_else(|| "[EMAIL]".to_string())
        });
        let s2 = re.ssn_inline.replace_all(&s1, |caps: &regex::Captures| {
            self.mask_str(&caps[0], MaskStrategy::Ssn)
                .unwrap_or_else(|| "[SSN]".to_string())
        });
        let s3 = re.phone_inline.replace_all(&s2, |caps: &regex::Captures| {
            self.mask_str(&caps[0], MaskStrategy::Phone)
                .unwrap_or_else(|| "[PHONE]".to_string())
        });
        let s4 = re.ipv4_inline.replace_all(&s3, |caps: &regex::Captures| {
            self.mask_str(&caps[0], MaskStrategy::Ip)
                .unwrap_or_else(|| "[IP]".to_string())
        });
        s4.into_owned()
    }

    /// Recursively scrub nested JSON objects/arrays (e.g. Postgres JSONB columns or nested JSONL).
    pub fn mask_json_recursive(&self, val: &serde_json::Value) -> serde_json::Value {
        match val {
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
                val.clone()
            }
            serde_json::Value::String(s) => serde_json::Value::String(self.mask_free_text(s)),
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(|v| self.mask_json_recursive(v)).collect())
            }
            serde_json::Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, v) in map {
                    let masked_v = match v {
                        serde_json::Value::String(s) => {
                            if let Some(det) = detect_column_pii(k, std::slice::from_ref(s), false)
                                && det.recommended_strategy != MaskStrategy::TextRedact
                            {
                                self.mask_str(s, det.recommended_strategy)
                                    .map(serde_json::Value::String)
                                    .unwrap_or(serde_json::Value::Null)
                            } else {
                                serde_json::Value::String(self.mask_free_text(s))
                            }
                        }
                        serde_json::Value::Number(n) => {
                            if let Some(i) = n.as_i64()
                                && let Some(det) = detect_column_pii(k, &[i.to_string()], true)
                                && matches!(
                                    det.recommended_strategy,
                                    MaskStrategy::IntId | MaskStrategy::Id
                                )
                            {
                                self.mask_i64(i, det.recommended_strategy)
                                    .map(|m| serde_json::json!(m))
                                    .unwrap_or(serde_json::Value::Null)
                            } else {
                                v.clone()
                            }
                        }
                        other => self.mask_json_recursive(other),
                    };
                    out.insert(k.clone(), masked_v);
                }
                serde_json::Value::Object(out)
            }
        }
    }

    /// Deterministic day-offset for `DateShift` (shared by ISO string dates and Arrow `Date32`).
    pub fn date_shift_offset(&self, key: &str) -> i64 {
        let h = self.hmac_bytes("date_shift", key);
        let span = (self.date_shift_days * 2 + 1) as u64;
        let offset = (Self::u64_from(&h, 0) % span) as i64 - self.date_shift_days;
        if offset == 0 { 7 } else { offset }
    }

    fn hmac_bytes(&self, domain_tag: &str, input: &str) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.salt).expect("HMAC accepts any key size");
        mac.update(domain_tag.as_bytes());
        mac.update(b":");
        mac.update(input.as_bytes());
        let res = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    fn u64_from(bytes: &[u8; 32], offset: usize) -> u64 {
        let slice = &bytes[offset..offset + 8];
        u64::from_be_bytes(slice.try_into().unwrap())
    }

    /// Deterministic numeric-core mapper shared by `Id` (text, with or without leading zeros)
    /// and `IntId` (integer). Guarantees cross-type join parity:
    /// - `INTEGER 1001` -> `8472`
    /// - `TEXT "1001"` -> `"8472"`
    /// - `TEXT "001001"` -> `"008472"`
    fn mask_numeric_core(&self, core_key: &str) -> String {
        let h = self.hmac_bytes("id_num", core_key);
        let digits_needed = core_key.len().max(1);
        let mut digits: Vec<u8> = Vec::with_capacity(digits_needed);
        for idx in 0..digits_needed {
            let byte = h[idx % 32].wrapping_add((idx as u8).wrapping_mul(17));
            let d = if idx == 0 {
                if digits_needed == 10 {
                    // Keep 10-digit IDs within signed INT4 max (2_147_483_647)
                    1
                } else {
                    1 + (byte % 9)
                }
            } else {
                byte % 10
            };
            digits.push(d);
        }
        let mut out: String = digits.iter().map(|&d| (b'0' + d) as char).collect();
        // Guarantee deterministic non-identity mapping (never accidentally leaks original ID)
        if out == core_key {
            let last = digits.len() - 1;
            if digits.len() == 1 {
                digits[0] = (digits[0] % 9) + 1;
            } else {
                digits[last] = (digits[last] + 1) % 10;
            }
            out = digits.iter().map(|&d| (b'0' + d) as char).collect();
        }
        out
    }

    /// Deterministically mask a non-null string value.
    /// Returns `None` if strategy is `Null`.
    pub fn mask_str(&self, raw: &str, strategy: MaskStrategy) -> Option<String> {
        if strategy == MaskStrategy::Keep {
            return Some(raw.to_string());
        }
        if strategy == MaskStrategy::Null {
            return None;
        }
        if raw.is_empty() {
            return Some(String::new());
        }
        if strategy == MaskStrategy::Redact {
            return Some("[REDACTED]".to_string());
        }

        let norm_key = raw.trim();
        match strategy {
            MaskStrategy::Name => {
                let h = self.hmac_bytes("name", norm_key);
                let f = FIRST_NAMES[(Self::u64_from(&h, 0) as usize) % FIRST_NAMES.len()];
                let l_raw = LAST_NAMES[(Self::u64_from(&h, 8) as usize) % LAST_NAMES.len()];
                let l = capitalize(l_raw);
                Some(format!("{f} {l}"))
            }
            MaskStrategy::FirstName => {
                let h = self.hmac_bytes("first_name", norm_key);
                let f = FIRST_NAMES[(Self::u64_from(&h, 0) as usize) % FIRST_NAMES.len()];
                Some(f.to_string())
            }
            MaskStrategy::LastName => {
                let h = self.hmac_bytes("last_name", norm_key);
                let l = LAST_NAMES[(Self::u64_from(&h, 0) as usize) % LAST_NAMES.len()];
                Some(capitalize(l))
            }
            MaskStrategy::Email => {
                let h = self.hmac_bytes("email", &norm_key.to_ascii_lowercase());
                let f = FIRST_NAMES[(Self::u64_from(&h, 0) as usize) % FIRST_NAMES.len()]
                    .to_ascii_lowercase();
                let l = LAST_NAMES[(Self::u64_from(&h, 8) as usize) % LAST_NAMES.len()]
                    .to_ascii_lowercase();
                let num = Self::u64_from(&h, 16) % 10000;
                Some(format!("{f}.{l}.{num:04}@{}", self.email_domain))
            }
            MaskStrategy::Phone => {
                let h = self.hmac_bytes("phone", norm_key);
                // FCC fictional 555-01xx block (555-0100 through 555-0199)
                let mid = 100 + (Self::u64_from(&h, 0) % 100);
                let tail = Self::u64_from(&h, 8) % 10000;
                Some(format!("(555) {mid:03}-{tail:04}"))
            }
            MaskStrategy::Ssn => {
                let h = self.hmac_bytes("ssn", norm_key);
                // 900-xx-xxxx is guaranteed invalid/fictional by SSA rules!
                let a = 900 + (Self::u64_from(&h, 0) % 99);
                let b = 10 + (Self::u64_from(&h, 8) % 89);
                let c = 1000 + (Self::u64_from(&h, 16) % 9000);
                Some(format!("{a:03}-{b:02}-{c:04}"))
            }
            MaskStrategy::Id => {
                // Format-preserving deterministic token!
                // Crucial for Populi <-> Canvas:
                // - Preserves leading zeros ("001001" -> "008472" AND "1001" -> "8472" AND INT 1001 -> 8472!)
                let trimmed = norm_key;
                if trimmed.bytes().all(|b| b.is_ascii_digit()) {
                    let leading_zeros = trimmed.bytes().take_while(|&b| b == b'0').count();
                    let core = trimmed.trim_start_matches('0');
                    let core_key = if core.is_empty() { "0" } else { core };
                    let mut out = "0".repeat(leading_zeros);
                    out.push_str(&self.mask_numeric_core(core_key));
                    return Some(out);
                }

                // General format-preserving character-class substitution (e.g. "STU-2026-041" -> "KLP-7391-582")
                let h = self.hmac_bytes("id_str", trimmed);
                let mut out = String::with_capacity(trimmed.len());
                for (i, ch) in trimmed.chars().enumerate() {
                    let b = h[i % 32].wrapping_add((i as u8).wrapping_mul(31));
                    if ch.is_ascii_digit() {
                        out.push((b'0' + (b % 10)) as char);
                    } else if ch.is_ascii_uppercase() {
                        out.push((b'A' + (b % 26)) as char);
                    } else if ch.is_ascii_lowercase() {
                        out.push((b'a' + (b % 26)) as char);
                    } else {
                        out.push(ch);
                    }
                }
                Some(out)
            }
            MaskStrategy::IntId => {
                let core = norm_key.trim_start_matches('0');
                let core_key = if core.is_empty() { "0" } else { core };
                if core_key.bytes().all(|b| b.is_ascii_digit()) {
                    Some(self.mask_numeric_core(core_key))
                } else {
                    let h = self.hmac_bytes("id_num", core_key);
                    let v = 100_000 + (Self::u64_from(&h, 0) % 899_900_000);
                    Some(v.to_string())
                }
            }
            MaskStrategy::Address => {
                let h = self.hmac_bytes("address", norm_key);
                let num = 100 + (Self::u64_from(&h, 0) % 9800);
                let st = STREETS[(Self::u64_from(&h, 8) as usize) % STREETS.len()];
                Some(format!("{num} {st}"))
            }
            MaskStrategy::DateShift => {
                let offset = self.date_shift_offset(norm_key);
                if norm_key.len() >= 10
                    && let Ok(date) = NaiveDate::parse_from_str(&norm_key[..10], "%Y-%m-%d")
                {
                    let shifted = date + Duration::days(offset);
                    let suffix = &norm_key[10..];
                    return Some(format!("{}{suffix}", shifted.format("%Y-%m-%d")));
                }
                // Fallback if non-ISO date format
                let h = self.hmac_bytes("date_shift", norm_key);
                Some(format!("1990-01-{:02}", 1 + (Self::u64_from(&h, 0) % 28)))
            }
            MaskStrategy::Ip => {
                let h = self.hmac_bytes("ip", norm_key);
                // RFC-5737 TEST-NET-2 (198.51.100.0/24)
                let host = 1 + (Self::u64_from(&h, 0) % 253);
                Some(format!("198.51.100.{host}"))
            }
            MaskStrategy::Hash => {
                let h = self.hmac_bytes("hash", norm_key);
                let mut hex = String::from("h_");
                for b in &h[..8] {
                    hex.push_str(&format!("{b:02x}"));
                }
                Some(hex)
            }
            MaskStrategy::TextRedact => Some(self.mask_free_text(raw)),
            MaskStrategy::Keep | MaskStrategy::Null | MaskStrategy::Redact => unreachable!(),
        }
    }

    pub fn mask_i64(&self, val: i64, strategy: MaskStrategy) -> Option<i64> {
        match strategy {
            MaskStrategy::Keep => Some(val),
            MaskStrategy::Null => None,
            MaskStrategy::IntId | MaskStrategy::Id => {
                let abs_str = val.unsigned_abs().to_string();
                let mapped = self.mask_numeric_core(&abs_str);
                let parsed = mapped.parse::<i64>().unwrap_or_else(|_| {
                    let h = self.hmac_bytes("id_num", &abs_str);
                    (100_000 + (Self::u64_from(&h, 0) % 899_900_000)) as i64
                });
                Some(if val < 0 { -parsed } else { parsed })
            }
            _ => None,
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

// ── PII Detection (Column Names + Sample Values) ──────────────────────────────

struct PiiRegexes {
    email: Regex,
    ssn: Regex,
    phone: Regex,
    ipv4: Regex,
    email_inline: Regex,
    ssn_inline: Regex,
    phone_inline: Regex,
    ipv4_inline: Regex,
}

fn pii_regexes() -> &'static PiiRegexes {
    static RE: OnceLock<PiiRegexes> = OnceLock::new();
    RE.get_or_init(|| PiiRegexes {
        email: Regex::new(r"(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$").unwrap(),
        ssn: Regex::new(r"^\d{3}-\d{2}-\d{4}$").unwrap(),
        phone: Regex::new(r"^(\+?1[-.\s]?)?(\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}$").unwrap(),
        ipv4: Regex::new(r"^(?:\d{1,3}\.){3}\d{1,3}$").unwrap(),
        email_inline: Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").unwrap(),
        ssn_inline: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
        phone_inline: Regex::new(r"(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\b\d{3})[-.\s]\d{3}[-.\s]\d{4}\b")
            .unwrap(),
        ipv4_inline: Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        )
        .unwrap(),
    })
}

/// Extract embedded PII tokens (emails, SSNs, phones) inside unstructured strings for zero-leak verification.
pub fn extract_embedded_pii_tokens(text: &str) -> Vec<String> {
    let re = pii_regexes();
    let mut out = Vec::new();
    for m in re.email_inline.find_iter(text) {
        out.push(m.as_str().to_ascii_lowercase());
    }
    for m in re.ssn_inline.find_iter(text) {
        out.push(m.as_str().to_string());
    }
    for m in re.phone_inline.find_iter(text) {
        out.push(m.as_str().to_string());
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct PiiDetection {
    pub pii_type: String,
    pub recommended_strategy: MaskStrategy,
    pub confidence: String, // "high" | "medium"
    pub reason: String,
}

pub fn detect_column_pii(
    col_name: &str,
    samples: &[String],
    is_integer_col: bool,
) -> Option<PiiDetection> {
    let re = pii_regexes();
    let non_empty: Vec<&str> = samples
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let total = non_empty.len();

    // 1. High-confidence value pattern matches first!
    if total > 0 {
        let email_hits = non_empty.iter().filter(|s| re.email.is_match(s)).count();
        if email_hits * 2 >= total {
            return Some(PiiDetection {
                pii_type: "email".to_string(),
                recommended_strategy: MaskStrategy::Email,
                confidence: "high".to_string(),
                reason: format!("{email_hits}/{total} sampled values match email pattern"),
            });
        }
        let ssn_hits = non_empty.iter().filter(|s| re.ssn.is_match(s)).count();
        if ssn_hits > 0 {
            return Some(PiiDetection {
                pii_type: "ssn".to_string(),
                recommended_strategy: MaskStrategy::Ssn,
                confidence: "high".to_string(),
                reason: format!(
                    "{ssn_hits}/{total} sampled values match SSN pattern (XXX-XX-XXXX)"
                ),
            });
        }
        let phone_hits = non_empty.iter().filter(|s| re.phone.is_match(s)).count();
        if phone_hits * 2 >= total {
            return Some(PiiDetection {
                pii_type: "phone".to_string(),
                recommended_strategy: MaskStrategy::Phone,
                confidence: "high".to_string(),
                reason: format!("{phone_hits}/{total} sampled values match phone pattern"),
            });
        }
        let ip_hits = non_empty.iter().filter(|s| re.ipv4.is_match(s)).count();
        if ip_hits * 2 >= total {
            return Some(PiiDetection {
                pii_type: "ip_address".to_string(),
                recommended_strategy: MaskStrategy::Ip,
                confidence: "high".to_string(),
                reason: format!("{ip_hits}/{total} sampled values match IPv4 pattern"),
            });
        }
    }

    // 2. Column-name heuristics (essential for FERPA / SIS / LMS schemas!)
    let n = col_name.to_ascii_lowercase();
    if n.contains("ssn") || n.contains("social_security") || n == "tax_id" {
        return Some(PiiDetection {
            pii_type: "ssn".to_string(),
            recommended_strategy: MaskStrategy::Ssn,
            confidence: "high".to_string(),
            reason: format!("Column name `{col_name}` indicates SSN/tax identifier"),
        });
    }
    if (n.contains("email") || n == "e_mail") && !n.ends_with("_id") {
        return Some(PiiDetection {
            pii_type: "email".to_string(),
            recommended_strategy: MaskStrategy::Email,
            confidence: "high".to_string(),
            reason: format!("Column name `{col_name}` indicates email address"),
        });
    }
    if (n.contains("phone") || n.contains("mobile") || n == "cell" || n.contains("tel_"))
        && !n.ends_with("_id")
    {
        return Some(PiiDetection {
            pii_type: "phone".to_string(),
            recommended_strategy: MaskStrategy::Phone,
            confidence: "high".to_string(),
            reason: format!("Column name `{col_name}` indicates phone number"),
        });
    }
    if n == "first_name" || n == "fname" || n == "given_name" || n.ends_with("_first_name") {
        return Some(PiiDetection {
            pii_type: "first_name".to_string(),
            recommended_strategy: MaskStrategy::FirstName,
            confidence: "high".to_string(),
            reason: format!("Column name `{col_name}` indicates person first name"),
        });
    }
    if n == "last_name"
        || n == "lname"
        || n == "surname"
        || n == "family_name"
        || n.ends_with("_last_name")
    {
        return Some(PiiDetection {
            pii_type: "last_name".to_string(),
            recommended_strategy: MaskStrategy::LastName,
            confidence: "high".to_string(),
            reason: format!("Column name `{col_name}` indicates person last name"),
        });
    }
    if n == "full_name"
        || n == "student_name"
        || n == "sortable_name"
        || n == "short_name"
        || n == "display_name"
        || n == "legal_name"
        || n == "preferred_name"
        || n == "instructor_name"
    {
        return Some(PiiDetection {
            pii_type: "full_name".to_string(),
            recommended_strategy: MaskStrategy::Name,
            confidence: "high".to_string(),
            reason: format!("Column name `{col_name}` indicates person name"),
        });
    }
    if n == "dob"
        || n.contains("birth_date")
        || n.contains("birthdate")
        || n.contains("date_of_birth")
    {
        return Some(PiiDetection {
            pii_type: "date_of_birth".to_string(),
            recommended_strategy: MaskStrategy::DateShift,
            confidence: "high".to_string(),
            reason: format!("Column name `{col_name}` indicates date of birth"),
        });
    }
    if n.contains("street")
        || n == "address"
        || n == "address1"
        || n == "address_line_1"
        || n.contains("home_address")
    {
        return Some(PiiDetection {
            pii_type: "street_address".to_string(),
            recommended_strategy: MaskStrategy::Address,
            confidence: "medium".to_string(),
            reason: format!("Column name `{col_name}` indicates physical address"),
        });
    }
    if n == "sis_user_id"
        || n == "person_id"
        || n == "student_id"
        || n == "populi_id"
        || n == "unique_id"
        || n == "login_id"
    {
        let strat = if is_integer_col {
            MaskStrategy::IntId
        } else {
            MaskStrategy::Id
        };
        return Some(PiiDetection {
            pii_type: "person_identifier".to_string(),
            recommended_strategy: strat,
            confidence: "high".to_string(),
            reason: format!(
                "Column name `{col_name}` is a FERPA student/person identifier (format-preserving deterministic ID keeps cross-source joins intact!)"
            ),
        });
    }
    if n.contains("ip_address") || n == "client_ip" || n == "remote_ip" {
        return Some(PiiDetection {
            pii_type: "ip_address".to_string(),
            recommended_strategy: MaskStrategy::Ip,
            confidence: "medium".to_string(),
            reason: format!("Column name `{col_name}` indicates IP address"),
        });
    }

    // 3. Embedded PII inside unstructured free-text, notes, comments, or JSON/JSONB blobs!
    if total > 0 {
        let embedded_hits = non_empty
            .iter()
            .filter(|s| {
                re.email_inline.is_match(s)
                    || re.ssn_inline.is_match(s)
                    || re.phone_inline.is_match(s)
            })
            .count();
        if embedded_hits > 0 {
            return Some(PiiDetection {
                pii_type: "embedded_pii".to_string(),
                recommended_strategy: MaskStrategy::TextRedact,
                confidence: "high".to_string(),
                reason: format!(
                    "{embedded_hits}/{total} sampled values contain embedded email/SSN/phone inside free-text or JSON"
                ),
            });
        }
    }

    None
}

const NON_PERSON_TABLES: &[&str] = &[
    "academic_terms",
    "academic_years",
    "terms",
    "enrollment_terms",
    "courses",
    "catalog_courses",
    "course_offerings",
    "campuses",
    "programs",
    "degrees",
    "departments",
    "schools",
    "roles",
    "sections",
    "exit_reasons",
    "grade_scales",
    "grade_points",
    "aid_types",
    "statuses",
    "types",
    "categories",
];

/// Table-aware wrapper around [`detect_column_pii`] that avoids flagging generic label columns
/// (such as `display_name` or `short_name`) on non-person lookup/reference tables like `academic_terms`.
pub fn detect_table_column_pii(
    table_name: &str,
    col_name: &str,
    samples: &[String],
    is_integer_col: bool,
) -> Option<PiiDetection> {
    let det = detect_column_pii(col_name, samples, is_integer_col)?;
    let col_low = col_name.to_ascii_lowercase();
    if matches!(col_low.as_str(), "display_name" | "short_name") && det.pii_type == "full_name" {
        let short_tbl = table_name
            .rsplit('.')
            .next()
            .unwrap_or(table_name)
            .trim_matches('"')
            .to_ascii_lowercase();
        if NON_PERSON_TABLES.contains(&short_tbl.as_str()) {
            return None;
        }
    }
    Some(det)
}
