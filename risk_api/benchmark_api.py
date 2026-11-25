#!/usr/bin/env python3
"""Vector (SG) — Risk API v1.0 Phase 1 Exit-Gate Verification Suite.

Runs 4 automated checks against a live local ThreadingHTTPServer instance
(using an isolated copy of `data/vector_labels_v1.sqlite` so production DB is untouched):
  1. 100-Iteration Reproducibility Check (hard target: 100.0% identical `evidence_hash`)
  2. Latency Distribution (p50 / p95 / p99 in ms) across real OFAC, BSC Hub, Spoofed Token,
     Mixer Breakpoint, and Unknown Abstention scenarios
  3. End-to-End Simulated Appeal & Correction Drill (submit -> disputed -> revoke -> verify)
  4. Shadow Mode Lift Report Drill (simulated 6-event pilot comparing baseline vs. Vector)

Saves structured evaluation report to `evidence/risk_api_v1_eval_2026-11-25.json`.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
import urllib.request

from .server import DEFAULT_DB, start_server


def http_json(url: str, body: dict | None = None) -> dict:
    if body is None:
        req = urllib.request.Request(url, method="GET")
    else:
        raw = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=raw, method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int(round((p / 100.0) * (len(sorted_vals) - 1))))
    return round(sorted_vals[idx], 3)


def main():
    tmp_dir = tempfile.mkdtemp(prefix="vector_api_eval_")
    tmp_db = os.path.join(tmp_dir, "test_labels.sqlite")
    shutil.copy2(DEFAULT_DB, tmp_db)

    srv = start_server("127.0.0.1", 0, tmp_db)
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()

    try:
        health = http_json(f"{base}/v1/health")

        # Pull 1 real Grade-A OFAC ETH address & 1 real Grade-C BSC exploit/scam tag from the migrated DB
        ofac_row = srv.engine.store.conn.execute(
            "SELECT chain, address FROM labels_grade_a_official_sanctions WHERE chain='ethereum' LIMIT 1"
        ).fetchone()
        bsc_hub_row = srv.engine.store.conn.execute(
            "SELECT chain, address, label FROM labels_grade_c_reference_hubs WHERE chain='bsc' AND category='dex_router' LIMIT 1"
        ).fetchone()
        bsc_adv_row = srv.engine.store.conn.execute(
            "SELECT chain, address, label FROM labels_grade_c_reference_hubs WHERE chain='bsc' AND category IN ('exploit','scam') LIMIT 1"
        ).fetchone()

        # 1. Reproducibility Check (100 repeated identical calls)
        spoof_req = {
            "chain": "bsc",
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "token_addr": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "symbol": "US\u200bDT",
            "amount_raw": 10**18,
            "decimals": 18,
            "tx_hash": "0x" + "ab" * 32,
        }
        hashes = set()
        repro_lat = []
        for _ in range(100):
            t0 = time.perf_counter()
            r = http_json(f"{base}/v1/risk/transfer", spoof_req)
            repro_lat.append((time.perf_counter() - t0) * 1000.0)
            hashes.add(r["evidence_hash"])
        repro_pass = (len(hashes) == 1)

        # 2. Mixed Workload Latency & Accuracy Sanity
        test_cases = [
            ("ofac_grade_a", "/v1/risk/address", {"chain": ofac_row["chain"], "address": ofac_row["address"]}),
            ("bsc_grade_c_hub", "/v1/risk/address", {"chain": bsc_hub_row["chain"], "address": bsc_hub_row["address"]}),
            ("bsc_tornado_mixer", "/v1/risk/address", {"chain": "bsc", "address": "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd"}),
            ("unknown_abstain", "/v1/risk/address", {"chain": "bsc", "address": "0x9999999999999999999999999999999999999999"}),
            ("spoof_zero_width_token", "/v1/risk/transfer", spoof_req),
            ("zero_value_poisoning", "/v1/risk/transfer", {
                "chain": "bsc", "from": "0x3333333333333333333333333333333333333333",
                "to": "0x4444444444444444444444444444444444444444",
                "token_addr": "0x55d398326f99059ff775485246999027b3197955",
                "symbol": "USDT", "amount_raw": 0, "decimals": 18,
            }),
        ]
        scenario_outputs = {}
        all_lat = list(repro_lat)
        for name, ep, payload in test_cases:
            t0 = time.perf_counter()
            out = http_json(f"{base}{ep}", payload)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            all_lat.append(dt_ms)
            scenario_outputs[name] = {
                "risk_level": out["risk_level"],
                "risk_score": out["risk_score"],
                "recommended_action": out["recommended_action"],
                "evidence_hash": out["evidence_hash"][:16],
                "latency_ms": round(dt_ms, 3),
            }

        # 3. End-to-End Appeal & Correction Drill
        appeal_drill = {}
        if bsc_adv_row:
            pre = http_json(f"{base}/v1/risk/address", {"chain": "bsc", "address": bsc_adv_row["address"]})
            sub = http_json(f"{base}/v1/appeals", {
                "appeal_id": "APL-DRILL-001",
                "evidence_grade": "Grade-C",
                "chain": "bsc",
                "address": bsc_adv_row["address"],
                "label": bsc_adv_row["label"],
                "submitted_by": "simulated-counterparty",
                "appeal_reason": "Simulated false-positive appeal drill for Phase 1 exit gate.",
            })
            mid = http_json(f"{base}/v1/risk/address", {"chain": "bsc", "address": bsc_adv_row["address"]})
            res = http_json(f"{base}/v1/appeals/resolve", {
                "appeal_id": "APL-DRILL-001",
                "resolution_action": "revoke",
                "reviewer": "Lucy Li",
                "resolution_note": "Verified benign contract in simulated drill; revoked Grade-C tag.",
            })
            post = http_json(f"{base}/v1/risk/address", {"chain": "bsc", "address": bsc_adv_row["address"]})
            appeal_drill = {
                "target_address": bsc_adv_row["address"],
                "target_label": bsc_adv_row["label"],
                "pre_appeal_level_score": [pre["risk_level"], pre["risk_score"]],
                "submit_response": sub,
                "during_dispute_level_score": [mid["risk_level"], mid["risk_score"]],
                "resolve_response": res,
                "post_revoke_level_score": [post["risk_level"], post["risk_score"]],
                "passed": (pre["risk_score"] > mid["risk_score"] and post["risk_level"] != pre["risk_level"]),
            }

        # 4. Shadow Mode Lift Drill
        shadow_inputs = [
            ("/v1/risk/transfer", {**spoof_req, "shadow_mode": True, "client_id": "wallet-pilot-sim", "baseline_verdict": "ALLOW"}),
            ("/v1/risk/address", {"chain": ofac_row["chain"], "address": ofac_row["address"], "shadow_mode": True, "client_id": "wallet-pilot-sim", "baseline_verdict": "BLOCK"}),
            ("/v1/risk/address", {"chain": "bsc", "address": "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd", "shadow_mode": True, "client_id": "wallet-pilot-sim", "baseline_verdict": "ALLOW"}),
            ("/v1/risk/address", {"chain": bsc_hub_row["chain"], "address": bsc_hub_row["address"], "shadow_mode": True, "client_id": "wallet-pilot-sim", "baseline_verdict": "ALLOW"}),
            ("/v1/risk/address", {"chain": "bsc", "address": "0x9999999999999999999999999999999999999999", "shadow_mode": True, "client_id": "wallet-pilot-sim", "baseline_verdict": "ALLOW"}),
        ]
        for ep, payload in shadow_inputs:
            http_json(f"{base}{ep}", payload)
        shadow_summary = http_json(f"{base}/v1/shadow/summary?client_id=wallet-pilot-sim")

        all_lat.sort()
        report = {
            "eval_note": "Internal experimental benchmark on local SQLite WAL store (not production SLA claim).",
            "health": health,
            "reproducibility_100_runs": {
                "iterations": 100,
                "unique_evidence_hashes": len(hashes),
                "reproducibility_rate_pct": 100.0 if repro_pass else 0.0,
                "passed": repro_pass,
            },
            "latency_ms": {
                "sample_count": len(all_lat),
                "p50": percentile(all_lat, 50),
                "p95": percentile(all_lat, 95),
                "p99": percentile(all_lat, 99),
                "max": round(max(all_lat), 3),
            },
            "scenarios": scenario_outputs,
            "appeal_correction_drill": appeal_drill,
            "shadow_mode_drill": shadow_summary,
        }

        out_path = "/Users/orange/Documents/Projects/ChainWorld/evidence/risk_api_v1_eval_2026-11-25.json"
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print("=== VECTOR (SG) RISK API v1.0 PHASE 1 EXIT-GATE VERIFICATION ===")
        print(f"Reproducibility (100 runs) : {report['reproducibility_100_runs']['reproducibility_rate_pct']}% (PASS={repro_pass})")
        print(f"Latency (local SQLite WAL) : p50={report['latency_ms']['p50']} ms | p95={report['latency_ms']['p95']} ms | p99={report['latency_ms']['p99']} ms")
        print(f"Scenarios                  : {json.dumps(scenario_outputs, indent=2)}")
        print(f"Appeal/Correction Drill    : PASS={appeal_drill.get('passed')} | {appeal_drill.get('pre_appeal_level_score')} -> {appeal_drill.get('during_dispute_level_score')} -> {appeal_drill.get('post_revoke_level_score')}")
        print(f"Shadow Mode Drill          : {json.dumps(shadow_summary)}")
        print(f"Saved report               : {out_path}")
    finally:
        srv.shutdown()
        srv.engine.close()  # type: ignore[attr-defined]
        srv.server_close()
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
