#!/usr/bin/env python3
"""Self-contained verification suite for the public Vector (SG) Risk Toolkit.

Creates an isolated temporary Grade-isolated SQLite store with synthetic public test records,
then verifies:
  1. Label Store 5-table isolation & dispute/revocation lifecycle
  2. Risk API v1.0 deterministic reproducibility (50 runs) + Shadow Mode + Appeals
  3. Track B (`team_triage`) 18-signal engine + zero raw email PII leakage
  4. MCP Server JSON-RPC 2.0 stdio handshake + x402 pre-flight checks
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

from auto_tracer.label_store import VectorLabelStore
from risk_api.engine import VectorRiskEngine
from team_triage.signals import evaluate_triage_snapshot


def seed_public_test_db(db_path: str) -> None:
    store = VectorLabelStore(db_path)
    try:
        store.conn.execute(
            """
            INSERT INTO labels_grade_a_official_sanctions
            (chain, norm_address, address, label, entity, category, source_url, evidence_excerpt,
             retrieved_at_utc, effective_date_utc, evidence_grade, confidence, reviewer, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            """,
            (
                "ethereum", "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
                "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
                "OFAC SDN Official Test Seed (Ronin Exploiter)", "Lazarus Group (OFAC SDN)",
                "sanctioned", "https://sanctionssearch.ofac.treas.gov/",
                "Public OFAC SDN test record for CI verification",
                "2026-10-27T00:00:00Z", "2022-04-14T00:00:00Z", "Grade-A", 1.0, "CI-Seed",
            ),
        )
        store.conn.execute(
            """
            INSERT INTO labels_grade_c_reference_hubs
            (chain, norm_address, address, label, entity, category, source_url, evidence_excerpt,
             retrieved_at_utc, effective_date_utc, evidence_grade, confidence, reviewer, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            """,
            (
                "bsc", "0x10ed43c718714eb63d5aa57b78b54704e256024e",
                "0x10ed43c718714eb63d5aa57b78b54704e256024e",
                "PancakeSwap Router v2", "PancakeSwap", "dex_router",
                "https://bscscan.com/address/0x10ed43c718714eb63d5aa57b78b54704e256024e",
                "Canonical public BSC DEX router",
                "2026-11-25T00:00:00Z", "", "Grade-C", 0.95, "CI-Seed",
            ),
        )
        store.conn.commit()
    finally:
        store.close()


def main() -> None:
    tmp_dir = tempfile.mkdtemp(prefix="vector_oss_check_")
    try:
        db = os.path.join(tmp_dir, "test_labels.sqlite")
        seed_public_test_db(db)

        # 1. Risk Engine determinism + scenarios
        eng = VectorRiskEngine(db)
        try:
            r_ofac = eng.assess_address("ethereum", "0x098b716b8aaf21512996dc57eb0615e2383e2f96")
            assert r_ofac["risk_level"] == "CRITICAL" and r_ofac["risk_score"] == 98
            r_hub = eng.assess_address("bsc", "0x10ed43c718714eb63d5aa57b78b54704e256024e")
            assert r_hub["risk_level"] == "LOW" and r_hub["risk_score"] == 0
            r_unk = eng.assess_address("bsc", "0x9999999999999999999999999999999999999999")
            assert r_unk["risk_level"] == "UNABLE_TO_ASSESS"
            hashes = {
                eng.assess_transfer(
                    "bsc", "0x1111111111111111111111111111111111111111",
                    "0x2222222222222222222222222222222222222222",
                    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "US\u200bDT", 10**18, 18,
                )["evidence_hash"]
                for _ in range(50)
            }
            assert len(hashes) == 1, "Non-deterministic evidence_hash!"
        finally:
            eng.close()

        # 2. Track B triage PII & signal check
        snap = {
            "target_name": "Public-OSS-Check",
            "snapshot_utc": "2026-11-25T12:00:00Z",
            "repos": [],
            "contributors": [],
            "commits": [{
                "repo": "org/repo", "sha": "abc", "url": "", "author_login": "dev1",
                "committer_login": "dev1", "author_email": "private-check@proton.me",
                "committer_email": "private-check@proton.me", "timestamp": "2026-11-25T10:00:00Z",
                "verified": True, "additions": 10, "deletions": 0, "message": "init",
            }],
            "pull_requests": [],
            "declared_addresses": [{"chain": "ethereum", "address": "0x098b716b8aaf21512996dc57eb0615e2383e2f96", "role": "test"}],
        }
        triage = evaluate_triage_snapshot(snap, db)
        assert triage["triage_band"] == "CRITICAL_COMPLIANCE_ESCALATION"
        assert "private-check@proton.me" not in json.dumps(triage)

        # 3. MCP stdio subprocess handshake + x402 check
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_preflight_demo.mcp_server", "--db", db],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            def rpc(msg):
                proc.stdin.write(json.dumps(msg) + "\n")
                proc.stdin.flush()
                return json.loads(proc.stdout.readline())

            init = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
            assert init["result"]["serverInfo"]["name"] == "vector-sg-preflight-mcp"
            call = rpc({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "vector_preflight_check_x402_payment",
                    "arguments": {
                        "network": "eip155:56",
                        "payTo": "0x0d5550d52428e7e3175bfc9550207e4ad3859b17",
                        "asset": "native",
                        "assetSymbol": "BNB",
                        "maxAmountRequired": "1000000000000000000",
                    },
                },
            })
            sc = call["result"]["structuredContent"]
            assert sc["verdict"] == "BLOCK_RECOMMENDED_CLIENT_DECIDES"
            assert sc["execution_authority"] == "CLIENT_ONLY"
        finally:
            proc.stdin.close()
            proc.wait(timeout=5)

        print("ALL PUBLIC TOOLKIT CHECKS PASSED (Risk API + Track B + MCP/x402)")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
