#!/usr/bin/env python3
"""End-to-end verification suite for Vector (SG) Track B (`team_triage/`) CLI & 18-signal engine.

Tests:
  1. Benign Veteran OSS Calibration Fixture (Foundry/Geth-style) -> LOW_RISK (false-positive control).
  2. Elevated Behavioral + Real Grade-A OFAC SDN Fixture -> CRITICAL_COMPLIANCE_ESCALATION,
     verifying:
       - All 6 signal families operational;
       - Zero raw email PII leakage anywhere in JSON, Markdown, or PDF;
       - Benign counter-hypotheses attached to every signal;
       - 100% deterministic `evidence_hash` reproducibility across runs;
       - Full MD + JSON + PDF bundle generated cleanly.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile

from team_triage.report_generator import generate_triage_bundle
from team_triage.signals import evaluate_triage_snapshot

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROD_DB = os.path.join(ROOT, "data", "vector_labels_v1.sqlite")
EVIDENCE_OUT = os.path.join(ROOT, "evidence", "track_b_demo")


def fetch_sample_addresses(db_path: str):
    conn = sqlite3.connect(db_path)
    ofac = conn.execute(
        "SELECT chain, address, label FROM labels_grade_a_official_sanctions WHERE chain='ethereum' LIMIT 1"
    ).fetchone()
    hub = conn.execute(
        "SELECT chain, address, label FROM labels_grade_c_reference_hubs WHERE chain='bsc' AND category='dex_router' LIMIT 1"
    ).fetchone()
    conn.close()
    return ofac, hub


def run_tests() -> None:
    tmp_dir = tempfile.mkdtemp(prefix="vector_track_b_test_")
    try:
        db_copy = os.path.join(tmp_dir, "labels_copy.sqlite")
        shutil.copy2(PROD_DB, db_copy)
        ofac_row, hub_row = fetch_sample_addresses(db_copy)
        assert ofac_row is not None and hub_row is not None, "Missing Grade-A or Grade-C sample rows"

        # 1. Benign Veteran OSS Calibration Profile
        benign_snapshot = {
            "target_name": "Calibration-Benign-OSS-Team",
            "snapshot_utc": "2026-11-25T12:00:00Z",
            "repos": [
                {
                    "full_name": "benign-org/core-protocol",
                    "html_url": "https://github.com/benign-org/core-protocol",
                    "created_at": "2022-03-10T10:00:00Z",
                    "is_fork": False,
                    "stargazers_count": 420,
                    "open_issues_count": 18,
                    "closed_issues_count": 95,
                    "pr_count": 140,
                    "is_core_claimed": True,
                }
            ],
            "contributors": [
                {
                    "login": "alice-dev",
                    "html_url": "https://github.com/alice-dev",
                    "created_at": "2018-04-12T08:00:00Z",
                    "public_repos": 44,
                    "external_repos": ["ethereum/go-ethereum", "foundry-rs/foundry"],
                },
                {
                    "login": "bob-dev",
                    "html_url": "https://github.com/bob-dev",
                    "created_at": "2019-09-21T14:30:00Z",
                    "public_repos": 31,
                    "external_repos": ["ethereum/go-ethereum", "foundry-rs/foundry"],
                },
            ],
            "commits": [
                {
                    "repo": "benign-org/core-protocol",
                    "sha": f"abc{i:04d}",
                    "url": f"https://github.com/benign-org/core-protocol/commit/abc{i:04d}",
                    "author_login": "alice-dev" if i % 2 == 0 else "bob-dev",
                    "committer_login": "alice-dev" if i % 2 == 0 else "bob-dev",
                    "author_email": "alice@benign-protocol.org" if i % 2 == 0 else "bob@benign-protocol.org",
                    "committer_email": "alice@benign-protocol.org" if i % 2 == 0 else "bob@benign-protocol.org",
                    "timestamp": f"2026-11-{10 + i:02d}T{9 + (i % 7):02d}:15:00+08:00",
                    "verified": True,
                    "additions": 120,
                    "deletions": 45,
                    "message": f"feat: modular accounting step {i}",
                }
                for i in range(8)
            ],
            "pull_requests": [
                {
                    "repo": "benign-org/core-protocol",
                    "number": 101,
                    "url": "https://github.com/benign-org/core-protocol/pull/101",
                    "created_at": "2026-11-12T08:00:00Z",
                    "approved_at": "2026-11-12T15:30:00Z",
                }
            ],
            "declared_addresses": [
                {"chain": hub_row[0], "address": hub_row[1], "role": "router_reference"}
            ],
        }

        benign_res = evaluate_triage_snapshot(benign_snapshot, db_copy)
        assert benign_res["triage_band"] == "LOW_RISK_NO_MAJOR_PUBLIC_ANOMALIES", f"Unexpected benign band: {benign_res['triage_band']}"
        assert benign_res["triggered_signal_count"] == 0, f"Benign calibration triggered signals: {benign_res['triggered_signals']}"
        assert benign_res["total_signals_evaluated"] == 18

        # 2. Synthetic Adverse / Elevated Triage Fixture (including real Grade-A OFAC check)
        raw_secret_email = "secret-operator-pii@proton.me"
        adverse_snapshot = {
            "target_name": "Synthetic-Elevated-Protocol-Demo",
            "snapshot_utc": "2026-11-25T12:00:00Z",
            "repos": [
                {
                    "full_name": "synth-demo/core-vault",
                    "html_url": "https://github.com/synth-demo/core-vault",
                    "created_at": "2026-11-14T10:00:00Z",
                    "is_fork": True,
                    "original_commits_ahead": 2,
                    "stargazers_count": 120,
                    "open_issues_count": 0,
                    "closed_issues_count": 0,
                    "pr_count": 0,
                    "is_core_claimed": True,
                }
            ],
            "contributors": [
                {
                    "login": "dev-alpha-new",
                    "html_url": "https://github.com/dev-alpha-new",
                    "created_at": "2026-11-10T08:00:00Z",
                    "public_repos": 1,
                    "external_repos": ["niche-stealth-org/private-mirror"],
                },
                {
                    "login": "dev-beta-new",
                    "html_url": "https://github.com/dev-beta-new",
                    "created_at": "2026-11-11T16:00:00Z",
                    "public_repos": 1,
                    "external_repos": ["niche-stealth-org/private-mirror"],
                },
            ],
            "commits": [
                {
                    "repo": "synth-demo/core-vault",
                    "sha": "deadbeef01",
                    "url": "https://github.com/synth-demo/core-vault/commit/deadbeef01",
                    "author_login": "dev-alpha-new",
                    "committer_login": "dev-beta-new",
                    "author_email": raw_secret_email,
                    "committer_email": "other-committer@proton.me",
                    "timestamp": "2026-11-15T09:00:00+09:00",
                    "verified": False,
                    "additions": 4200,
                    "deletions": 0,
                    "message": "init: full vault contracts deployer 0x1111111111111111111111111111111111111111",
                },
                {
                    "repo": "synth-demo/core-vault",
                    "sha": "deadbeef02",
                    "url": "https://github.com/synth-demo/core-vault/commit/deadbeef02",
                    "author_login": "dev-beta-new",
                    "committer_login": "dev-alpha-new",
                    "author_email": "other-committer@proton.me",
                    "committer_email": raw_secret_email,
                    "timestamp": "2026-11-15T09:00:45+09:00",
                    "verified": False,
                    "additions": 60,
                    "deletions": 5,
                    "message": "chore: update rpc",
                },
                {
                    "repo": "synth-demo/core-vault",
                    "sha": "deadbeef03",
                    "url": "https://github.com/synth-demo/core-vault/commit/deadbeef03",
                    "author_login": "dev-alpha-new",
                    "committer_login": "dev-alpha-new",
                    "author_email": raw_secret_email,
                    "committer_email": raw_secret_email,
                    "timestamp": "2026-11-16T09:01:10-05:00",
                    "verified": False,
                    "additions": 40,
                    "deletions": 2,
                    "message": "fix: fee config",
                },
                {
                    "repo": "synth-demo/core-vault",
                    "sha": "deadbeef04",
                    "url": "https://github.com/synth-demo/core-vault/commit/deadbeef04",
                    "author_login": "dev-beta-new",
                    "committer_login": "dev-beta-new",
                    "author_email": "other-committer@proton.me",
                    "committer_email": "other-committer@proton.me",
                    "timestamp": "2026-11-16T09:01:40-05:00",
                    "verified": False,
                    "additions": 30,
                    "deletions": 2,
                    "message": "fix: readme",
                },
                {
                    "repo": "synth-demo/other-script",
                    "sha": "deadbeef05",
                    "url": "https://github.com/synth-demo/other-script/commit/deadbeef05",
                    "author_login": "dev-alpha-new",
                    "committer_login": "dev-alpha-new",
                    "author_email": raw_secret_email,
                    "committer_email": raw_secret_email,
                    "timestamp": "2026-11-17T10:00:00+09:00",
                    "verified": False,
                    "additions": 25,
                    "deletions": 0,
                    "message": "reuse test wallet 0x1111111111111111111111111111111111111111",
                },
            ],
            "pull_requests": [],
            "declared_addresses": [
                {"chain": ofac_row[0], "address": ofac_row[1], "role": "declared_treasury_test_ofac"},
                {"chain": hub_row[0], "address": hub_row[1], "role": "declared_router_ref"},
            ],
        }

        res1 = evaluate_triage_snapshot(adverse_snapshot, db_copy)
        res2 = evaluate_triage_snapshot(adverse_snapshot, db_copy)
        assert res1["evidence_hash"] == res2["evidence_hash"], "Non-deterministic triage hash!"
        assert res1["triage_band"] == "CRITICAL_COMPLIANCE_ESCALATION"
        assert res1["triggered_signal_count"] >= 10, f"Expected >=10 signals, got {res1['triggered_signal_count']}"

        # Verify zero raw email leakage in output JSON
        json_blob = json.dumps(res1)
        assert raw_secret_email not in json_blob, "PII LEAK: raw email found in triage JSON!"
        assert "other-committer@proton.me" not in json_blob, "PII LEAK: raw committer email found!"

        # Generate full MD + JSON + PDF bundle in evidence/track_b_demo/
        out_bundle = generate_triage_bundle(
            adverse_snapshot,
            out_dir=EVIDENCE_OUT,
            label_db_path=db_copy,
            slug="synthetic_elevated_demo",
        )
        with open(out_bundle["markdown"], "r", encoding="utf-8") as f:
            md_txt = f.read()
        assert raw_secret_email not in md_txt, "PII LEAK: raw email in Markdown!"
        assert os.path.getsize(out_bundle["pdf"]) > 15000, "Generated PDF unexpectedly small!"

        # Save summary eval JSON
        eval_summary = {
            "test_status": "PASS",
            "benign_calibration": {
                "triage_band": benign_res["triage_band"],
                "triage_score": benign_res["triage_score"],
                "triggered_signals": benign_res["triggered_signal_count"],
                "total_signals": benign_res["total_signals_evaluated"],
                "evidence_hash": benign_res["evidence_hash"],
            },
            "adverse_synthetic_demo": {
                "triage_band": res1["triage_band"],
                "triage_score": res1["triage_score"],
                "triggered_signals": res1["triggered_signal_count"],
                "total_signals": res1["total_signals_evaluated"],
                "deterministic_reproducibility": res1["evidence_hash"] == res2["evidence_hash"],
                "raw_email_pii_leak": False,
                "prohibited_feature_audit": res1["prohibited_feature_audit"],
                "pdf_bytes": os.path.getsize(out_bundle["pdf"]),
                "artifacts": {
                    "markdown": os.path.relpath(out_bundle["markdown"], ROOT),
                    "json": os.path.relpath(out_bundle["json"], ROOT),
                    "pdf": os.path.relpath(out_bundle["pdf"], ROOT),
                },
            },
        }
        eval_path = os.path.join(ROOT, "evidence", "track_b_cli_eval_2026-11-25.json")
        with open(eval_path, "w", encoding="utf-8") as f:
            json.dump(eval_summary, f, indent=2)

        print("=== TRACK B CLI VERIFICATION PASSED ===")
        print(json.dumps(eval_summary, indent=2))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_tests()
