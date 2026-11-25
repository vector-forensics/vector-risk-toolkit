#!/usr/bin/env python3
"""Vector (SG) — Shadow Mode Drop-In Python Client & 30-Day Pilot Simulator (Stdlib Only).

Provides:
  1. `VectorShadowClient`: fail-open, non-blocking Shadow Mode HTTP client for wallets,
     on/off-ramps, and exchanges. Never blocks production traffic on timeout/network errors.
  2. Built-in end-to-end pilot simulation (`python3 -m shadow_pilot_kit.shadow_client --simulate`)
     that boots an isolated local Risk API server, replays 10 realistic pre-sign/deposit events,
     renders a client-ready Day-30 Lift Report (`sample_day30_lift_report.md`), and renders
     `shadow_mode_integration_brief_v0.1.pdf`.
"""
from __future__ import annotations

import argparse
import datetime
import html as html_lib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional

from risk_api.server import DEFAULT_DB, start_server

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
KIT_DIR = os.path.dirname(os.path.abspath(__file__))


class VectorShadowClient:
    """Fail-open Shadow Mode client. Never raises on timeout; always preserves client latency SLA."""

    def __init__(self, base_url: str, client_id: str, timeout_sec: float = 0.25):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.timeout_sec = timeout_sec

    def _post(self, path: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "VectorShadowClient/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None  # Strict fail-open in Shadow Mode

    def _get(self, path: str) -> Optional[Dict[str, Any]]:
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            method="GET",
            headers={"User-Agent": "VectorShadowClient/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=max(2.0, self.timeout_sec)) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None

    def mirror_address(self, chain: str, address: str, baseline_verdict: str = "ALLOW") -> Optional[Dict[str, Any]]:
        return self._post("/v1/risk/address", {
            "chain": chain,
            "address": address,
            "shadow_mode": True,
            "client_id": self.client_id,
            "baseline_verdict": baseline_verdict,
        })

    def mirror_transfer(
        self,
        chain: str,
        from_addr: str,
        to_addr: str,
        token_addr: str,
        symbol: Optional[str],
        amount_raw: int,
        decimals: int = 18,
        baseline_verdict: str = "ALLOW",
        tx_hash: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        return self._post("/v1/risk/transfer", {
            "chain": chain,
            "from": from_addr,
            "to": to_addr,
            "token_addr": token_addr,
            "symbol": symbol,
            "amount_raw": amount_raw,
            "decimals": decimals,
            "tx_hash": tx_hash,
            "shadow_mode": True,
            "client_id": self.client_id,
            "baseline_verdict": baseline_verdict,
        })

    def shadow_summary(self) -> Optional[Dict[str, Any]]:
        return self._get(f"/v1/shadow/summary?client_id={self.client_id}")


def render_brief_pdf(md_path: str, pdf_path: str) -> None:
    md_text = open(md_path, "r", encoding="utf-8").read()

    def inline_md(s: str) -> str:
        s = html_lib.escape(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", s)
        return s

    lines = md_text.splitlines()
    out, table_rows, bq_buf, code_buf = [], [], [], []
    in_ul = in_ol = in_table = in_code = False

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
        if st.startswith("```"):
            flush_lists(); flush_table(); flush_bq()
            if not in_code:
                in_code = True; code_buf = []
            else:
                out.append("<pre><code>" + html_lib.escape("\n".join(code_buf)) + "</code></pre>")
                in_code = False; code_buf = []
            continue
        if in_code:
            code_buf.append(line)
            continue
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
@page {{ size: A4; margin: 13mm 13mm 14mm 13mm; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111827; font-size: 8.6pt; line-height: 1.45; }}
.banner {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2.5px solid #0f2440; padding-bottom: 6px; margin-bottom: 10px; }}
.brand {{ font-weight: 800; font-size: 11.5pt; color: #0f2440; }}
.brand span {{ color: #b8862d; }}
.tag {{ font-size: 7.4pt; font-weight: 700; color: #0f2440; background: #f8f1e3; border: 1px solid #c9973b; padding: 2px 8px; border-radius: 4px; }}
h1 {{ font-size: 13pt; color: #0f2440; margin: 4px 0 6px; }}
h2 {{ font-size: 10.4pt; color: #0f2440; border-bottom: 1px solid #cbd5e1; padding-bottom: 2px; margin: 10px 0 5px; page-break-after: avoid; }}
h3 {{ font-size: 9pt; color: #1b365d; margin: 7px 0 3px; page-break-after: avoid; }}
blockquote {{ background: #f8fafc; border-left: 3px solid #b8862d; padding: 6px 9px; margin: 6px 0; font-size: 8pt; color: #334155; }}
table {{ width: 100%; border-collapse: collapse; margin: 6px 0 8px; font-size: 7.5pt; }}
tr {{ page-break-inside: avoid; }}
th {{ background: #0f2440; color: #fff; text-align: left; padding: 4px 5px; }}
td {{ border: 1px solid #cbd5e1; padding: 4px 5px; vertical-align: top; }}
tbody tr:nth-child(even) {{ background: #f8fafc; }}
pre {{ background: #0f172a; color: #e2e8f0; padding: 7px 9px; border-radius: 5px; font-size: 7.3pt; overflow-x: auto; page-break-inside: avoid; }}
pre code {{ background: transparent; color: #e2e8f0; padding: 0; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 7.4pt; background: #f1f5f9; padding: 1px 3px; border-radius: 3px; color: #0f2440; }}
ul, ol {{ margin: 3px 0 5px 18px; padding: 0; }}
li {{ margin: 2px 0; }}
hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 8px 0; }}
</style></head><body>
<div class="banner">
  <div class="brand">VECTOR <span>(SG)</span> — 30-Day Shadow Mode Pilot Kit</div>
  <div class="tag">ZERO AUTO-BLOCKING · CLIENT_ONLY AUTHORITY</div>
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


def run_pilot_simulation() -> None:
    tmp_dir = tempfile.mkdtemp(prefix="vector_shadow_sim_")
    tmp_db = os.path.join(tmp_dir, "labels_copy.sqlite")
    shutil.copy2(DEFAULT_DB, tmp_db)

    conn = sqlite3.connect(tmp_db)
    ofac_eth = conn.execute(
        "SELECT address FROM labels_grade_a_official_sanctions WHERE chain='ethereum' LIMIT 1"
    ).fetchone()[0]
    bsc_hub = conn.execute(
        "SELECT address FROM labels_grade_c_reference_hubs WHERE chain='bsc' AND category='dex_router' LIMIT 1"
    ).fetchone()[0]
    conn.close()

    srv = start_server("127.0.0.1", 0, tmp_db)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()

    try:
        client = VectorShadowClient(f"http://127.0.0.1:{port}", client_id="bnb-wallet-pilot-sim", timeout_sec=1.0)
        events: List[Dict[str, Any]] = []
        lat_ms: List[float] = []

        def record(label: str, fn):
            t0 = time.perf_counter()
            res = fn()
            dt = (time.perf_counter() - t0) * 1000.0
            lat_ms.append(dt)
            assert res is not None, f"Shadow request failed for {label}"
            events.append({"scenario": label, "latency_ms": round(dt, 3), **res})

        # 10 realistic Shadow Mode pre-sign / deposit events
        record("ofac_grade_a_deposit_caught_by_both", lambda: client.mirror_address("ethereum", ofac_eth, "BLOCK"))
        record("bsc_tornado_proxy_missed_by_baseline", lambda: client.mirror_address("bsc", "0x0d5550d52428e7e3175bfc9550207e4ad3859b17", "ALLOW"))
        record("bsc_tornado_100bnb_missed_by_baseline", lambda: client.mirror_address("bsc", "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd", "ALLOW"))
        record("spoofed_zero_width_usdt_missed_by_baseline", lambda: client.mirror_transfer(
            "bsc", "0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222",
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "US\u200bDT", 50 * 10**18, 18, "ALLOW",
        ))
        record("zero_value_poisoning_missed_by_baseline", lambda: client.mirror_transfer(
            "bsc", "0x3333333333333333333333333333333333333333", "0x4444444444444444444444444444444444444444",
            "0x55d398326f99059ff775485246999027b3197955", "USDT", 0, 18, "ALLOW",
        ))
        record("benign_bsc_dex_router_1", lambda: client.mirror_address("bsc", bsc_hub, "ALLOW"))
        record("benign_canonical_usdt_transfer", lambda: client.mirror_transfer(
            "bsc", bsc_hub, "0x5555555555555555555555555555555555555555",
            "0x55d398326f99059ff775485246999027b3197955", "USDT", 250 * 10**18, 18, "ALLOW",
        ))
        record("unknown_fresh_eoa_1_abstain", lambda: client.mirror_address("bsc", "0x7777777777777777777777777777777777777777", "ALLOW"))
        record("unknown_fresh_eoa_2_abstain", lambda: client.mirror_address("bsc", "0x8888888888888888888888888888888888888888", "ALLOW"))
        record("phishing_url_symbol_missed_by_baseline", lambda: client.mirror_transfer(
            "bsc", "0x6666666666666666666666666666666666666666", "0x9999999999999999999999999999999999999999",
            "0xbadbadbadbadbadbadbadbadbadbadbadbadbadb", "ClaimUSDT.io", 1000 * 10**18, 18, "ALLOW",
        ))

        summary = client.shadow_summary()
        assert summary is not None and summary["total_shadow_events"] == 10

        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        md_lines = [
            "# Vector (SG) — Sample Day-30 Shadow Mode Lift Report *(Simulated Pilot Output)*",
            "",
            f"> **Client ID**: `bnb-wallet-pilot-sim` · **Generated**: `{now_utc}`  ",
            "> **Notice**: Illustrative simulation output generated by `shadow_pilot_kit/shadow_client.py` against local isolated SQLite WAL store. **Not** a live customer deployment or production SLA.",
            "",
            "## 1. Aggregate Shadow Mode Summary",
            "",
            f"- **Total Mirrored Events**: `{summary['total_shadow_events']}`",
            f"- **Lift Breakdown**: `{json.dumps(summary['by_lift_category'], sort_keys=True)}`",
            f"- **Vector Risk Distribution**: `{json.dumps(summary['by_vector_risk_level'], sort_keys=True)}`",
            f"- **Local Round-Trip Avg Latency**: `{sum(lat_ms)/len(lat_ms):.3f} ms` *(local prototype only)*",
            "",
            "## 2. Event-Level Audit Ledger",
            "",
            "| Scenario | Baseline | Vector Risk | Lift Category | Evidence Hash |",
            "| :--- | :---: | :---: | :--- | :--- |",
        ]
        for ev in events:
            sh = ev["shadow_mode"]
            md_lines.append(
                f"| `{ev['scenario']}` | `{sh['baseline_verdict']}` | `{ev['risk_level']} ({ev['risk_score']})` | "
                f"`{sh['lift_category']}` | `{ev['evidence_hash'][:14]}...` |"
            )

        sample_md = os.path.join(KIT_DIR, "sample_day30_lift_report.md")
        with open(sample_md, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines) + "\n")

        brief_md = os.path.join(KIT_DIR, "shadow_mode_integration_brief_v0.1.md")
        brief_pdf = os.path.join(KIT_DIR, "shadow_mode_integration_brief_v0.1.pdf")
        render_brief_pdf(brief_md, brief_pdf)

        print("=== SHADOW MODE PILOT KIT VERIFIED ===")
        print(json.dumps(summary, indent=2))
        print(f"Sample Lift Report : {sample_md}")
        print(f"Integration Brief  : {brief_pdf} ({os.path.getsize(brief_pdf):,} bytes)")
    finally:
        srv.shutdown()
        srv.engine.close()  # type: ignore[attr-defined]
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Vector (SG) Shadow Mode Pilot Client & Simulator")
    parser.add_argument("--simulate", action="store_true", help="Run local 10-event Shadow Mode pilot simulation and build PDF brief")
    args = parser.parse_args()
    if args.simulate:
        run_pilot_simulation()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
