use crate::pipeline::VerifyReport;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn render_verify_html(report: &VerifyReport) -> String {
    let status_cls = if report.ok { "pass" } else { "fail" };
    let status_lbl = if report.ok {
        "PASS — ZERO PII LEAKS"
    } else {
        "FAIL — ATTENTION REQUIRED"
    };

    let mut table_rows = String::new();
    for t in &report.table_results {
        let row_badge = if t.original_rows == t.masked_rows {
            format!(
                "<span class=\"pill ok\">{} / {}</span>",
                t.masked_rows, t.original_rows
            )
        } else {
            format!(
                "<span class=\"pill warn\">{} / {} (subset/diff)</span>",
                t.masked_rows, t.original_rows
            )
        };
        let leak_badge = if t.leaked_values == 0 {
            "<span class=\"pill ok\">0</span>".to_string()
        } else {
            format!("<span class=\"pill bad\">{}</span>", t.leaked_values)
        };
        table_rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            esc(&t.table),
            row_badge,
            t.pii_columns_checked,
            leak_badge
        ));
    }

    let mut leaks_section = String::new();
    if !report.leaks.is_empty() {
        leaks_section.push_str("<section class=\"card\"><h2>Detected Leaks</h2><table><thead><tr><th>Table</th><th>Column</th><th>Leaked Distinct Values</th></tr></thead><tbody>");
        for l in &report.leaks {
            leaks_section.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td><span class=\"pill bad\">{}</span></td></tr>",
                esc(&l.table),
                esc(&l.column),
                l.leaked_count
            ));
        }
        leaks_section.push_str("</tbody></table></section>");
    }

    let mut notes_section = String::new();
    if !report.notes.is_empty() {
        notes_section.push_str("<section class=\"card\"><h2>Audit Notes</h2><ul>");
        for n in &report.notes {
            notes_section.push_str(&format!("<li>{}</li>", esc(n)));
        }
        notes_section.push_str("</ul></section>");
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>maskkeel Compliance Verification Receipt</title>
<style>
  :root {{
    --bg: #0b1020; --card: #12192e; --border: #23304d;
    --fg: #e6edf7; --muted: #93a4c3;
    --ok: #22c55e; --bad: #ef4444; --warn: #f59e0b; --accent: #38bdf8;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{
      --bg: #f6f8fc; --card: #ffffff; --border: #dbe3f0;
      --fg: #0f172a; --muted: #475569;
      --ok: #15803d; --bad: #b91c1c; --warn: #b45309; --accent: #0284c7;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--fg); margin: 0; padding: 32px 20px; line-height: 1.5; }}
  .wrap {{ max-width: 920px; margin: 0 auto; display: flex; flex-direction: column; gap: 20px; }}
  .header {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; padding: 20px 24px; background: var(--card); border: 1px solid var(--border); border-radius: 12px; }}
  .header h1 {{ margin: 0; font-size: 1.25rem; }}
  .meta {{ color: var(--muted); font-size: 0.875rem; }}
  .badge {{ padding: 6px 14px; border-radius: 999px; font-weight: 700; font-size: 0.85rem; letter-spacing: 0.03em; }}
  .badge.pass {{ background: color-mix(in srgb, var(--ok) 16%, transparent); color: var(--ok); border: 1px solid color-mix(in srgb, var(--ok) 45%, transparent); }}
  .badge.fail {{ background: color-mix(in srgb, var(--bad) 16%, transparent); color: var(--bad); border: 1px solid color-mix(in srgb, var(--bad) 45%, transparent); }}
  .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }}
  .kpi {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }}
  .kpi .lbl {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .kpi .val {{ font-size: 1.4rem; font-weight: 700; margin-top: 4px; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px 22px; }}
  .card h2 {{ margin: 0 0 12px; font-size: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.86em; color: var(--accent); }}
  .pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.78rem; font-weight: 600; }}
  .pill.ok {{ background: color-mix(in srgb, var(--ok) 15%, transparent); color: var(--ok); }}
  .pill.bad {{ background: color-mix(in srgb, var(--bad) 15%, transparent); color: var(--bad); }}
  .pill.warn {{ background: color-mix(in srgb, var(--warn) 15%, transparent); color: var(--warn); }}
  footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="header">
    <div>
      <h1>maskkeel PII Scrubbing Compliance Receipt</h1>
      <div class="meta">Verified at <code>{}</code> &middot; Original: <code>{}</code> &rarr; Masked: <code>{}</code></div>
    </div>
    <span class="badge {}">{}</span>
  </header>

  <div class="kpis">
    <div class="kpi"><div class="lbl">Tables Checked</div><div class="val">{}</div></div>
    <div class="kpi"><div class="lbl">Row Counts Matched</div><div class="val">{}</div></div>
    <div class="kpi"><div class="lbl">Key Cardinality Preserved</div><div class="val">{}</div></div>
    <div class="kpi"><div class="lbl">PII Leaks Found</div><div class="val">{}</div></div>
  </div>

  <section class="card">
    <h2>Table Audit Breakdown</h2>
    <table>
      <thead><tr><th>Table / File</th><th>Rows (Masked / Original)</th><th>PII Columns Checked</th><th>Leaks</th></tr></thead>
      <tbody>{}</tbody>
    </table>
  </section>

  {}
  {}

  <footer>Generated offline by <strong>maskkeel v{}</strong> (Keel Data Stack) &mdash; zero external assets, safe for FERPA/HIPAA audit archives.</footer>
</div>
</body>
</html>
"#,
        esc(&report.verified_at),
        esc(&report.original),
        esc(&report.masked),
        status_cls,
        status_lbl,
        report.tables_checked,
        if report.row_counts_matched {
            "Yes"
        } else {
            "No"
        },
        if report.key_cardinality_preserved {
            "Yes"
        } else {
            "No"
        },
        report.pii_leaks_found,
        table_rows,
        leaks_section,
        notes_section,
        env!("CARGO_PKG_VERSION")
    )
}
