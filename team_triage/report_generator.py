#!/usr/bin/env python3
"""Vector (SG) — Track B Automated Triage Report Generator (Markdown + JSON + PDF).

Usage (Offline Frozen Snapshot):
  python3 -m team_triage.report_generator \
    --snapshot path/to/snapshot.json \
    --out-dir path/to/output

Usage (Live Public GitHub API):
  python3 -m team_triage.report_generator \
    --target-name "Example Protocol" \
    --repo owner/repo1 --repo owner/repo2 \
    --address bsc:0x1234...:deployer \
    --out-dir path/to/output
"""
from __future__ import annotations

import argparse
import hashlib
import html as html_lib
import json
import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List

from .github_fetcher import fetch_public_github_snapshot
from .signals import evaluate_triage_snapshot, scrub_email

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
DEFAULT_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "vector_labels_v1.sqlite",
)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_triage_markdown(result: Dict[str, Any], snapshot_sha: str) -> str:
    lines: List[str] = []
    target = result["target_name"]
    lines.append(f"# Vector (SG) — Track B Public-Signal Team & Entity Risk Triage (`{target}`)")
    lines.append("")
    lines.append(f"> **Provider**: Vector (SG) (`VECTOR (SG) PTE. LTD.`, Singapore) · **Engine**: `{result['engine_version']}`  ")
    lines.append(f"> **Snapshot (UTC)**: `{result['snapshot_utc']}` · **Snapshot SHA-256**: `{snapshot_sha[:24]}...` · **Evidence Hash**: `{result['evidence_hash'][:24]}...`  ")
    lines.append("> **Mandatory Operating Boundaries**: Public-data decision-support signals only. **Not** a DPRK identity detector. **Not** legal advice. **Zero** nationality, language, geolocation, or ethnic-name features. **Zero** raw email PII emitted. Execution & hiring/listing decisions remain strictly with the client (`execution_authority: CLIENT_ONLY`).")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. Executive Triage Summary")
    lines.append("")
    lines.append("| Field | Verified Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| Subject Target | `{target}` |")
    lines.append(f"| Overall Triage Band | **`{result['triage_band']}`** *(Score: `{result['triage_score']}/100`)* |")
    lines.append(f"| Confidence & Qualification | {result['band_confidence']} |")
    lines.append(f"| Signals Triggered | `{result['triggered_signal_count']} / {result['total_signals_evaluated']}` public API & on-chain signals |")
    lines.append(f"| False-Positive Baseline | {result['calibration_disclosure']['false_positive_baseline']} |")
    lines.append(f"| Positive Recall Disclosure | {result['calibration_disclosure']['positive_recall_status']} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 2. Section A — Verified Public Facts (`OBSERVED FACTS`)")
    lines.append("")
    for f in result["observed_facts"]:
        lines.append(f"- **{f['fact']}**: {f['detail']}")
    lines.append("")

    if result["onchain_assessments"]:
        lines.append("### Declared Address On-Chain Screening (`Grade-Isolated Label Store v1.0`)")
        lines.append("")
        lines.append("| Role | Chain | Address | Risk Level | Score | Evidence Hash |")
        lines.append("| :--- | :---: | :--- | :---: | :---: | :--- |")
        for oc in result["onchain_assessments"]:
            addr = oc["address"]
            short = f"{addr[:10]}...{addr[-6:]}" if len(addr) > 18 else addr
            lines.append(
                f"| `{oc['role']}` | `{oc['chain']}` | `{short}` | `{oc['risk_level']}` | `{oc['risk_score']}` | `{oc['evidence_hash'][:14]}...` |"
            )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 3. Section B — Triggered Behavioral & On-Chain Signals (`ANALYTICAL SIGNALS`)")
    lines.append("")
    if result["triggered_signals"]:
        for s in result["triggered_signals"]:
            lines.append(f"### `{s['signal_id']}` · {s['name']} *(Family: {s['family']} · Severity: `{s['severity']}` · Confidence: `{s['confidence']}`)*")
            lines.append(f"- **Observed Evidence**: {s['evidence']}")
            if s["evidence_urls"]:
                lines.append("- **Public Reference URLs**: " + ", ".join(f"`{u}`" for u in s["evidence_urls"][:4]))
            lines.append(f"- **Benign Counter-Hypothesis**: *{s['benign_counter_hypothesis']}*")
            lines.append("")
    else:
        lines.append("No elevated behavioral or on-chain signals triggered across the 18 evaluated public signals. Absence of public red flags is not a guarantee of counterparty safety.")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 4. Complete 18-Signal Audit Matrix (`TRANSPARENCY LOG`)")
    lines.append("")
    lines.append("| Signal ID | Family | Signal Name | Status | Severity | Summary |")
    lines.append("| :---: | :--- | :--- | :---: | :---: | :--- |")
    for s in result["signals"]:
        st = "TRIGGERED" if s["triggered"] else "CLEAR"
        lines.append(f"| `{s['signal_id']}` | {s['family']} | {s['name']} | `{st}` | `{s['severity']}` | {s['evidence'][:110]} |")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 5. Section C — Explicit Gaps & Client Verification Checklist (`UNCONFIRMED / ACTION ITEMS`)")
    lines.append("")
    lines.append("- **What Public Signals Cannot Determine**: True legal identity, jurisdiction, nationality, employment contracts, private repositories, or subjective intent of contributors.")
    lines.append("- **Recommended Non-Invasive Verification Actions**:")
    for idx, step in enumerate(result["verification_checklist"], 1):
        lines.append(f"  {idx}. {step}")
    lines.append("")
    return "\n".join(lines)


def render_triage_pdf(md_text: str, pdf_path: str, target_name: str) -> None:
    def inline_md(s: str) -> str:
        s = html_lib.escape(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", s)
        return s

    lines = md_text.splitlines()
    out, table_rows, bq_buf = [], [], []
    in_ul = in_ol = in_table = False

    def flush_lists():
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>"); in_ul = False
        if in_ol:
            out.append("</ol>"); in_ol = False

    def flush_table():
        nonlocal in_table, table_rows
        if not in_table:
            return
        out.append("<table>")
        for idx, row in enumerate(table_rows):
            cells = [c.strip() for c in row.strip("|").split("|")]
            if idx == 1 and all(re.match(r"^:?-{3,}:?$", c) for c in cells):
                continue
            tag = "th" if idx == 0 else "td"
            if idx == 0:
                out.append("<thead><tr>" + "".join(f"<{tag}>{inline_md(c)}</{tag}>" for c in cells) + "</tr></thead><tbody>")
            else:
                out.append("<tr>" + "".join(f"<{tag}>{inline_md(c)}</{tag}>" for c in cells) + "</tr>")
        out.append("</tbody></table>")
        in_table = False
        table_rows = []

    def flush_bq():
        nonlocal bq_buf
        if bq_buf:
            out.append("<blockquote>" + "<br>".join(inline_md(x) for x in bq_buf) + "</blockquote>")
            bq_buf = []

    for line in lines:
        st = line.strip()
        if not st:
            flush_lists(); flush_table(); flush_bq()
            continue
        if st == "---":
            flush_lists(); flush_table(); flush_bq()
            out.append("<hr>")
            continue
        if st.startswith(">"):
            flush_lists(); flush_table()
            bq_buf.append(st.lstrip(">").strip())
            continue
        else:
            flush_bq()
        if st.startswith("|") and st.endswith("|"):
            flush_lists()
            in_table = True
            table_rows.append(st)
            continue
        else:
            flush_table()
        m = re.match(r"^(#{1,3})\s+(.*)$", st)
        if m:
            flush_lists()
            out.append(f"<h{len(m.group(1))}>{inline_md(m.group(2))}</h{len(m.group(1))}>")
            continue
        if st.startswith("- "):
            if in_ol:
                out.append("</ol>"); in_ol = False
            if not in_ul:
                out.append("<ul>"); in_ul = True
            out.append(f"<li>{inline_md(st[2:])}</li>")
            continue
        mo = re.match(r"^\d+\.\s+(.*)$", st)
        if mo:
            if in_ul:
                out.append("</ul>"); in_ul = False
            if not in_ol:
                out.append("<ol>"); in_ol = True
            out.append(f"<li>{inline_md(mo.group(1))}</li>")
            continue
        flush_lists()
        out.append(f"<p>{inline_md(st)}</p>")

    flush_lists(); flush_table(); flush_bq()

    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><style>
@page {{ size: A4; margin: 14mm 13mm 15mm 13mm; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111827; font-size: 8.6pt; line-height: 1.45; }}
.banner {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2.5px solid #0f2440; padding-bottom: 6px; margin-bottom: 10px; }}
.brand {{ font-weight: 800; font-size: 11.5pt; color: #0f2440; }}
.brand span {{ color: #b8862d; }}
.tag {{ font-size: 7.4pt; font-weight: 700; color: #0f2440; background: #f8f1e3; border: 1px solid #c9973b; padding: 2px 8px; border-radius: 4px; }}
h1 {{ font-size: 13pt; color: #0f2440; margin: 4px 0 6px; }}
h2 {{ font-size: 10.4pt; color: #0f2440; border-bottom: 1px solid #cbd5e1; padding-bottom: 2px; margin: 11px 0 5px; page-break-after: avoid; }}
h3 {{ font-size: 9pt; color: #1b365d; margin: 7px 0 3px; page-break-after: avoid; }}
blockquote {{ background: #f8fafc; border-left: 3px solid #b8862d; padding: 6px 9px; margin: 6px 0; font-size: 8pt; color: #334155; }}
table {{ width: 100%; border-collapse: collapse; margin: 6px 0 8px; font-size: 7.3pt; page-break-inside: auto; }}
tr {{ page-break-inside: avoid; }}
th {{ background: #0f2440; color: #fff; text-align: left; padding: 4px 5px; font-weight: 600; }}
td {{ border: 1px solid #cbd5e1; padding: 4px 5px; vertical-align: top; word-break: normal; overflow-wrap: break-word; }}
tbody tr:nth-child(even) {{ background: #f8fafc; }}
ul, ol {{ margin: 3px 0 5px 18px; padding: 0; }}
li {{ margin: 2px 0; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 7.2pt; background: #f1f5f9; padding: 1px 3px; border-radius: 3px; color: #0f2440; }}
hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 8px 0; }}
</style></head><body>
<div class="banner">
  <div class="brand">VECTOR <span>(SG)</span> — Track B Public-Signal Team Risk Triage</div>
  <div class="tag">{html_lib.escape(target_name)} · PUBLIC METADATA ONLY</div>
</div>
{"".join(out)}
</body></html>"""

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as f:
        f.write(doc)
        tmp = f.name
    try:
        subprocess.run(
            [CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf_path}", f"file://{tmp}"],
            check=True,
            capture_output=True,
        )
    finally:
        os.unlink(tmp)


def _scrub_snapshot_emails(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deep-copied snapshot with all raw email fields replaced by domain + sha256."""
    clean = json.loads(json.dumps(snapshot))
    for c in clean.get("commits", []):
        if "author_email" in c:
            ae = scrub_email(c.pop("author_email"))
            c.setdefault("author_email_hash", ae["email_hash"])
            c.setdefault("author_email_domain", ae["email_domain"])
        if "committer_email" in c:
            ce = scrub_email(c.pop("committer_email"))
            c.setdefault("committer_email_hash", ce["email_hash"])
            c.setdefault("committer_email_domain", ce["email_domain"])
    return clean


def generate_triage_bundle(
    snapshot: Dict[str, Any],
    out_dir: str,
    label_db_path: str = DEFAULT_DB,
    slug: str = "",
) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    safe_slug = slug or re.sub(r"[^a-zA-Z0-9_-]+", "_", snapshot.get("target_name", "target")).strip("_").lower()
    scrubbed_snapshot = _scrub_snapshot_emails(snapshot)
    snap_path = os.path.join(out_dir, f"{safe_slug}_frozen_snapshot.json")
    with open(snap_path, "w", encoding="utf-8") as f:
        json.dump(scrubbed_snapshot, f, indent=2, sort_keys=True)
    snap_sha = sha256_file(snap_path)

    result = evaluate_triage_snapshot(scrubbed_snapshot, label_db_path=label_db_path)
    result["frozen_snapshot_sha256"] = snap_sha

    md_text = build_triage_markdown(result, snap_sha)
    md_path = os.path.join(out_dir, f"{safe_slug}_triage_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_text)

    json_path = os.path.join(out_dir, f"{safe_slug}_triage_bundle.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)

    pdf_path = os.path.join(out_dir, f"{safe_slug}_triage_report.pdf")
    render_triage_pdf(md_text, pdf_path, result["target_name"])

    return {
        "snapshot": snap_path,
        "markdown": md_path,
        "json": json_path,
        "pdf": pdf_path,
        "triage_band": result["triage_band"],
        "triage_score": str(result["triage_score"]),
        "evidence_hash": result["evidence_hash"],
    }


def parse_address_arg(val: str) -> Dict[str, str]:
    parts = val.split(":")
    if len(parts) == 2:
        return {"chain": parts[0].strip(), "address": parts[1].strip(), "role": "declared_address"}
    if len(parts) >= 3:
        return {"chain": parts[0].strip(), "address": parts[1].strip(), "role": parts[2].strip()}
    return {"chain": "bsc", "address": val.strip(), "role": "declared_address"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Vector (SG) Track B Team & Entity Risk-Signal Triage CLI")
    parser.add_argument("--snapshot", help="Path to frozen JSON snapshot (offline deterministic mode)")
    parser.add_argument("--target-name", help="Target project/entity name (for live GitHub mode)")
    parser.add_argument("--repo", action="append", default=[], help="Public GitHub repo `owner/repo` (repeatable)")
    parser.add_argument("--address", action="append", default=[], help="Declared address `chain:address[:role]` (repeatable)")
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to vector_labels_v1.sqlite")
    parser.add_argument("--out-dir", required=True, help="Output directory for MD + JSON + PDF bundle")
    args = parser.parse_args()

    if args.snapshot:
        with open(args.snapshot, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
    else:
        if not args.target_name or not args.repo:
            raise SystemExit("Provide either --snapshot OR (--target-name and at least one --repo).")
        addrs = [parse_address_arg(a) for a in args.address]
        snapshot = fetch_public_github_snapshot(
            target_name=args.target_name,
            repos=args.repo,
            declared_addresses=addrs,
        )

    out = generate_triage_bundle(snapshot, out_dir=args.out_dir, label_db_path=args.db)
    print(f"=== TRACK B TRIAGE BUNDLE GENERATED ===")
    print(f"  Band          : {out['triage_band']} (score={out['triage_score']}/100)")
    print(f"  Evidence Hash : {out['evidence_hash']}")
    print(f"  Markdown      : {out['markdown']}")
    print(f"  JSON          : {out['json']}")
    print(f"  PDF           : {out['pdf']} ({os.path.getsize(out['pdf']):,} bytes)")


if __name__ == "__main__":
    main()
