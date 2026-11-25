#!/usr/bin/env python3
"""End-to-end stdio JSON-RPC 2.0 verification for Vector (SG) MCP & x402 Pre-Flight Demo.

Spawns `python3 -m mcp_preflight_demo.mcp_server` as a real subprocess over stdin/stdout,
executes full MCP handshake + 7 tool calls (5 x402 scenarios + address + transfer),
checks determinism, and writes a reproducible evaluation report to:
  evidence/mcp_x402_demo_eval_2026-11-25.json
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROD_DB = os.path.join(ROOT, "data", "vector_labels_v1.sqlite")


def rpc(proc: subprocess.Popen, payload: Dict[str, Any]) -> Dict[str, Any]:
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        stderr_out = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"MCP server exited prematurely. stderr={stderr_out}")
    return json.loads(line)


def notify(proc: subprocess.Popen, payload: Dict[str, Any]) -> None:
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
    proc.stdin.flush()


def run_suite() -> None:
    tmp_dir = tempfile.mkdtemp(prefix="vector_mcp_test_")
    try:
        db_copy = os.path.join(tmp_dir, "labels_copy.sqlite")
        shutil.copy2(PROD_DB, db_copy)

        conn = sqlite3.connect(db_copy)
        ofac_eth = conn.execute(
            "SELECT address FROM labels_grade_a_official_sanctions WHERE chain='ethereum' LIMIT 1"
        ).fetchone()[0]
        bsc_hub = conn.execute(
            "SELECT address FROM labels_grade_c_reference_hubs WHERE chain='bsc' AND category IN ('dex_router','benign_contract') LIMIT 1"
        ).fetchone()[0]
        conn.close()

        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_preflight_demo.mcp_server", "--db", db_copy],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # 1. MCP initialize
            init_resp = rpc(proc, {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "vector-test-harness", "version": "1.0"},
                },
            })
            assert init_resp["result"]["serverInfo"]["name"] == "vector-sg-preflight-mcp"

            # 2. notifications/initialized + ping
            notify(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
            ping_resp = rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "ping"})
            assert ping_resp["result"] == {}

            # 3. tools/list
            tools_resp = rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
            tool_names = [t["name"] for t in tools_resp["result"]["tools"]]
            assert set(tool_names) == {
                "vector_preflight_check_address",
                "vector_preflight_check_transfer",
                "vector_preflight_check_x402_payment",
            }

            # 4. Run 5 x402 pre-flight scenarios
            scenarios = [
                (
                    "x402_benign_bsc_hub_canonical_usdt",
                    {
                        "scheme": "exact",
                        "network": "eip155:56",
                        "payTo": bsc_hub,
                        "asset": "0x55d398326f99059ff775485246999027b3197955",
                        "assetSymbol": "USDT",
                        "maxAmountRequired": "25000000000000000000",
                        "decimals": 18,
                        "resource": "https://api.example.io/v1/feed",
                    },
                    "ALLOW_PROCEED",
                    "LOW",
                ),
                (
                    "x402_ofac_grade_a_payto",
                    {
                        "scheme": "exact",
                        "network": "eip155:1",
                        "payTo": ofac_eth,
                        "asset": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                        "assetSymbol": "USDC",
                        "maxAmountRequired": "10000000",
                        "decimals": 6,
                        "resource": "https://malicious.example.io/pay",
                    },
                    "BLOCK_RECOMMENDED_CLIENT_DECIDES",
                    "CRITICAL",
                ),
                (
                    "x402_bsc_tornado_mixer_payto",
                    {
                        "scheme": "exact",
                        "network": "bsc",
                        "payTo": "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd",
                        "asset": "native",
                        "assetSymbol": "BNB",
                        "maxAmountRequired": "1000000000000000000",
                        "decimals": 18,
                    },
                    "BLOCK_RECOMMENDED_CLIENT_DECIDES",
                    "HIGH",
                ),
                (
                    "x402_spoofed_zero_width_usdt",
                    {
                        "scheme": "exact",
                        "network": "eip155:56",
                        "payTo": "0x9999999999999999999999999999999999999999",
                        "asset": "0x1234567890abcdef1234567890abcdef12345678",
                        "assetSymbol": "U\u200bSDT",
                        "maxAmountRequired": "50000000000000000000",
                        "decimals": 18,
                    },
                    "BLOCK_RECOMMENDED_CLIENT_DECIDES",
                    "HIGH",
                ),
                (
                    "x402_unknown_counterparty_abstain",
                    {
                        "scheme": "exact",
                        "network": "eip155:8453",
                        "payTo": "0x7777777777777777777777777777777777777777",
                        "asset": "0x8888888888888888888888888888888888888888",
                        "assetSymbol": "NOVEL",
                        "maxAmountRequired": "1000000000000000000",
                        "decimals": 18,
                    },
                    "UNABLE_TO_ASSESS",
                    "UNABLE_TO_ASSESS",
                ),
            ]

            scenario_results = {}
            req_id = 10
            latencies_ms = []
            for name, args, exp_verdict, exp_risk in scenarios:
                t0 = time.perf_counter()
                resp = rpc(proc, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/call",
                    "params": {"name": "vector_preflight_check_x402_payment", "arguments": args},
                })
                dt_ms = (time.perf_counter() - t0) * 1000.0
                latencies_ms.append(dt_ms)
                req_id += 1
                data = resp["result"]["structuredContent"]
                assert data["verdict"] == exp_verdict, f"{name}: expected {exp_verdict}, got {data['verdict']}"
                assert data["risk_level"] == exp_risk, f"{name}: expected {exp_risk}, got {data['risk_level']}"
                assert data["execution_authority"] == "CLIENT_ONLY", f"{name}: execution_authority violated!"
                scenario_results[name] = {
                    "verdict": data["verdict"],
                    "risk_level": data["risk_level"],
                    "risk_score": data["risk_score"],
                    "execution_authority": data["execution_authority"],
                    "evidence_hash": data["evidence_hash"],
                    "latency_ms": round(dt_ms, 3),
                }

            # 5. Determinism check (repeat OFAC scenario via stdio)
            repeat_resp = rpc(proc, {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "vector_preflight_check_x402_payment", "arguments": scenarios[1][1]},
            })
            repeat_hash = repeat_resp["result"]["structuredContent"]["evidence_hash"]
            assert repeat_hash == scenario_results["x402_ofac_grade_a_payto"]["evidence_hash"], "Non-deterministic hash!"

            # 6. Also smoke-test address & transfer MCP tools
            addr_resp = rpc(proc, {
                "jsonrpc": "2.0",
                "id": 100,
                "method": "tools/call",
                "params": {"name": "vector_preflight_check_address", "arguments": {"chain": "ethereum", "address": ofac_eth}},
            })
            assert addr_resp["result"]["structuredContent"]["risk_level"] == "CRITICAL"

            tx_resp = rpc(proc, {
                "jsonrpc": "2.0",
                "id": 101,
                "method": "tools/call",
                "params": {
                    "name": "vector_preflight_check_transfer",
                    "arguments": {
                        "chain": "bsc",
                        "from_addr": "0x1111111111111111111111111111111111111111",
                        "to_addr": "0x2222222222222222222222222222222222222222",
                        "token_addr": "0x55d398326f99059ff775485246999027b3197955",
                        "symbol": "USDT",
                        "amount_raw": "0",
                        "decimals": 18,
                    },
                },
            })
            assert tx_resp["result"]["structuredContent"]["risk_level"] == "ELEVATED"

            summary = {
                "test_status": "PASS",
                "mcp_protocol_version": init_resp["result"]["protocolVersion"],
                "server_info": init_resp["result"]["serverInfo"],
                "tools_registered": tool_names,
                "x402_scenarios": scenario_results,
                "deterministic_reproducibility": True,
                "address_tool_smoke_pass": True,
                "transfer_zero_value_poisoning_smoke_pass": True,
                "avg_stdio_roundtrip_ms": round(sum(latencies_ms) / len(latencies_ms), 3),
                "benchmark_disclaimer": "Local stdio subprocess benchmark on frozen SQLite WAL store; not a production SLA.",
            }
            out_path = os.path.join(ROOT, "evidence", "mcp_x402_demo_eval_2026-11-25.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)

            print("=== MCP + x402 PRE-FLIGHT VERIFICATION PASSED ===")
            print(json.dumps(summary, indent=2))
        finally:
            if proc.stdin:
                proc.stdin.close()
            proc.wait(timeout=5)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_suite()
