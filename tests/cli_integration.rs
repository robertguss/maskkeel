use assert_cmd::Command;
use predicates::prelude::*;
use rusqlite::Connection;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

fn maskkeel_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("maskkeel"))
}

#[test]
fn test_scan_and_init_config_csv() {
    let dir = tempdir().unwrap();
    let csv_path = dir.path().join("students.csv");
    let cfg_path = dir.path().join("mask.toml");
    fs::write(
        &csv_path,
        "person_id,first_name,last_name,email,ssn,phone,dob,major\n\
         1001,Alice,Johnson,alice.johnson@wts.edu,123-45-6789,(215) 555-1234,1997-05-14,MDiv\n\
         1002,Bob,Smith,bob.smith@wts.edu,987-65-4321,215-555-9876,1995-11-02,MAR\n",
    )
    .unwrap();

    let out = maskkeel_cmd()
        .args([
            "scan",
            csv_path.to_str().unwrap(),
            "--init-config",
            cfg_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let report: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["tables_scanned"], 1);
    assert!(report["pii_columns_found"].as_u64().unwrap() >= 7);

    let cfg_text = fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_text.contains("\"email\" = \"email\""));
    assert!(cfg_text.contains("\"ssn\" = \"ssn\""));
    assert!(cfg_text.contains("\"person_id\" = \"id\""));
    assert!(!cfg_text.contains("\"major\""));
}

#[test]
fn test_csv_deterministic_leading_zero_preservation_and_verify() {
    let dir = tempdir().unwrap();
    let populi_csv = dir.path().join("populi.csv");
    let canvas_csv = dir.path().join("canvas.csv");
    let populi_out = dir.path().join("populi_masked.csv");
    let canvas_out = dir.path().join("canvas_masked.csv");

    fs::write(
        &populi_csv,
        "person_id,full_name,email,gpa\n\
         1001,Alice Johnson,alice@wts.edu,3.92\n\
         1002,Bob Smith,bob@wts.edu,3.45\n",
    )
    .unwrap();
    fs::write(
        &canvas_csv,
        "sis_user_id,login_id,course\n\
         001001,alice@wts.edu,NT101\n\
         001002,bob@wts.edu,OT101\n",
    )
    .unwrap();

    for (inp, outp) in [(&populi_csv, &populi_out), (&canvas_csv, &canvas_out)] {
        maskkeel_cmd()
            .args([
                "mask",
                inp.to_str().unwrap(),
                outp.to_str().unwrap(),
                "--salt",
                "wts-ferpa-test-secret",
                "--format",
                "json",
            ])
            .assert()
            .success();
    }

    let p_masked = fs::read_to_string(&populi_out).unwrap();
    let c_masked = fs::read_to_string(&canvas_out).unwrap();

    // Zero real PII leaked
    assert!(!p_masked.contains("Alice Johnson"));
    assert!(!p_masked.contains("alice@wts.edu"));
    assert!(!p_masked.contains("1001"));
    assert!(!c_masked.contains("001001"));
    assert!(!c_masked.contains("alice@wts.edu"));
    // Non-PII preserved
    assert!(p_masked.contains("3.92"));
    assert!(c_masked.contains("NT101"));

    // Extract masked person_id from populi_masked & masked sis_user_id from canvas_masked
    let p_id = p_masked.lines().nth(1).unwrap().split(',').next().unwrap();
    let c_id = c_masked.lines().nth(1).unwrap().split(',').next().unwrap();
    assert!(
        c_id.starts_with("00"),
        "Leading zeros must be preserved: {c_id}"
    );
    assert_eq!(
        c_id.trim_start_matches('0'),
        p_id,
        "Stripping leading zeros from Canvas sis_user_id ({c_id}) must exactly match Populi person_id ({p_id})!"
    );

    // Verify passes on masked CSV
    let v_out = maskkeel_cmd()
        .args([
            "verify",
            populi_csv.to_str().unwrap(),
            populi_out.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v_json: Value = serde_json::from_slice(&v_out).unwrap();
    assert_eq!(v_json["ok"], true);
    assert_eq!(v_json["pii_leaks_found"], 0);
    assert_eq!(v_json["key_cardinality_preserved"], true);
}

#[test]
fn test_sqlite_cross_table_cross_type_referential_integrity_and_verify() {
    let dir = tempdir().unwrap();
    let src_db = dir.path().join("prod.db");
    let dst_db = dir.path().join("dev.db");

    {
        let conn = Connection::open(&src_db).unwrap();
        conn.execute_batch(
            "CREATE TABLE populi_students (
                person_id INTEGER PRIMARY KEY,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL,
                ssn TEXT NOT NULL,
                program TEXT NOT NULL
            );
            CREATE TABLE canvas_pseudonyms (
                id INTEGER PRIMARY KEY,
                sis_user_id TEXT NOT NULL,
                unique_id TEXT NOT NULL,
                course_code TEXT NOT NULL,
                grade TEXT NOT NULL
            );
            INSERT INTO populi_students VALUES
                (1001, 'Alice', 'Johnson', 'alice.johnson@wts.edu', '123-45-6789', 'MDiv'),
                (1002, 'Bob', 'Smith', 'bob.smith@wts.edu', '234-56-7890', 'MAR'),
                (1003, 'Carol', 'Davis', 'carol.davis@wts.edu', '345-67-8901', 'PhD');
            INSERT INTO canvas_pseudonyms VALUES
                (1, '001001', 'alice.johnson@wts.edu', 'NT101', 'A'),
                (2, '001001', 'alice.johnson@wts.edu', 'ST101', 'A-'),
                (3, '001002', 'bob.smith@wts.edu', 'OT101', 'B+');",
        )
        .unwrap();
    }

    // Mask prod.db -> dev.db
    maskkeel_cmd()
        .args([
            "mask",
            src_db.to_str().unwrap(),
            dst_db.to_str().unwrap(),
            "--salt",
            "ferpa-cross-type-salt",
            "--format",
            "json",
        ])
        .assert()
        .success();

    // Verify zero leaks & parity
    let v_out = maskkeel_cmd()
        .args([
            "verify",
            src_db.to_str().unwrap(),
            dst_db.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v_json: Value = serde_json::from_slice(&v_out).unwrap();
    assert_eq!(v_json["ok"], true);
    assert_eq!(v_json["pii_leaks_found"], 0);
    assert_eq!(v_json["row_counts_matched"], true);
    assert_eq!(v_json["key_cardinality_preserved"], true);

    // Crucial proof: INTEGER populi_students.person_id STILL joins 100% identically
    // with zero-padded TEXT canvas_pseudonyms.sis_user_id in dev.db!
    let dev = Connection::open(&dst_db).unwrap();
    let joined_count: i64 = dev
        .query_row(
            "SELECT COUNT(*) FROM populi_students s
             JOIN canvas_pseudonyms c
               ON LTRIM(c.sis_user_id, '0') = CAST(s.person_id AS TEXT)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        joined_count, 3,
        "All 3 Populi<->Canvas enrollment joins must remain intact!"
    );

    // Check that MDiv student still has 2 enrollments and PhD student still has 0
    let mdiv_courses: i64 = dev
        .query_row(
            "SELECT COUNT(*) FROM populi_students s
             JOIN canvas_pseudonyms c
               ON LTRIM(c.sis_user_id, '0') = CAST(s.person_id AS TEXT)
             WHERE s.program = 'MDiv'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(mdiv_courses, 2);

    // Confirm real PII is 100% absent from dev.db
    let leak_count: i64 = dev
        .query_row(
            "SELECT COUNT(*) FROM populi_students WHERE email LIKE '%wts.edu%' OR ssn = '123-45-6789' OR person_id = 1001",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(leak_count, 0);

    // Verify MUST FAIL (exit 1) when auditing an unmasked copy!
    let unmasked_copy = dir.path().join("unmasked_copy.db");
    fs::copy(&src_db, &unmasked_copy).unwrap();
    let fail_out = maskkeel_cmd()
        .args([
            "verify",
            src_db.to_str().unwrap(),
            unmasked_copy.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let fail_json: Value = serde_json::from_slice(&fail_out).unwrap();
    assert_eq!(fail_json["ok"], false);
    assert!(fail_json["pii_leaks_found"].as_u64().unwrap() > 0);
}

#[test]
fn test_unsafe_inplace_and_require_salt_guardrails() {
    let dir = tempdir().unwrap();
    let f = dir.path().join("data.csv");
    fs::write(&f, "email,score\nalice@wts.edu,95\n").unwrap();

    // In-place overwrite refused with E_UNSAFE_INPLACE
    maskkeel_cmd()
        .args([
            "mask",
            f.to_str().unwrap(),
            f.to_str().unwrap(),
            "--salt",
            "abc",
            "--format",
            "json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("E_UNSAFE_INPLACE"));

    // --require-salt fails cleanly when MASKKEEL_SALT is absent
    let out = dir.path().join("masked.csv");
    maskkeel_cmd()
        .env_remove("MASKKEEL_SALT")
        .args([
            "mask",
            f.to_str().unwrap(),
            out.to_str().unwrap(),
            "--require-salt",
            "--format",
            "json",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("E_CONFIG"));
}

#[test]
fn test_jsonl_masking_and_skill_install() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("events.jsonl");
    let dst = dir.path().join("events_masked.jsonl");
    fs::write(
        &src,
        "{\"person_id\":1001,\"email\":\"alice@wts.edu\",\"action\":\"login\"}\n\
         {\"person_id\":1002,\"email\":\"bob@wts.edu\",\"action\":\"submit\"}\n",
    )
    .unwrap();

    maskkeel_cmd()
        .env("MASKKEEL_SALT", "env-salt-123")
        .args([
            "mask",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--require-salt",
            "--format",
            "agent",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("maskkeel mask"));

    let text = fs::read_to_string(&dst).unwrap();
    assert!(!text.contains("alice@wts.edu"));
    assert!(!text.contains("1001"));
    assert!(text.contains("\"action\":\"login\""));

    // Skill stdout & --install
    maskkeel_cmd()
        .args(["skill"])
        .assert()
        .success()
        .stdout(predicate::str::contains("name: maskkeel"));

    let skill_dir = dir.path().join(".agents/skills/maskkeel");
    maskkeel_cmd()
        .args(["skill", "--install", skill_dir.to_str().unwrap()])
        .assert()
        .success();
    assert!(skill_dir.join("SKILL.md").exists());
}
