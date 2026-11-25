#!/usr/bin/env python3
"""Vector (SG) — Lightweight Open-Source MCP Server (JSON-RPC 2.0 over stdio, Stdlib Only).

Exposes 3 deterministic, read-only, non-custodial pre-flight risk tools wrapping
`risk_api.engine.VectorRiskEngine`:
  1. `vector_preflight_check_address`
  2. `vector_preflight_check_transfer`
  3. `vector_preflight_check_x402_payment`

Run manually:
  python3 -m mcp_preflight_demo.mcp_server --db data/vector_labels_v1.sqlite
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from risk_api.engine import VectorRiskEngine
from . import MCP_DEMO_VERSION, MCP_PROTOCOL_VERSION
from .x402 import evaluate_x402_payment

DEFAULT_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "vector_labels_v1.sqlite",
)

TOOLS_SCHEMA: List[Dict[str, Any]] = [
    {
        "name": "vector_preflight_check_address",
        "description": (
            "Deterministic, grade-isolated pre-flight risk check for a single blockchain address "
            "(Grade-A OFAC SDN, Grade-C reference hubs, known mixers/bridges, canonical tokens). "
            "Advisory only (execution_authority=CLIENT_ONLY); returns UNABLE_TO_ASSESS when no evidence exists."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string", "description": "Chain name (e.g. bsc, ethereum, tron, bitcoin)", "default": "bsc"},
                "address": {"type": "string", "description": "Target blockchain address"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "vector_preflight_check_transfer",
        "description": (
            "Deterministic pre-sign / deposit risk check for a token or native transfer. "
            "Detects Grade-A sanctions, known mixers/bridges, zero-value address poisoning, and "
            "zero-width / spoofed token symbols. Advisory only (execution_authority=CLIENT_ONLY)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain": {"type": "string", "default": "bsc"},
                "from_addr": {"type": "string"},
                "to_addr": {"type": "string"},
                "token_addr": {"type": "string", "default": "native"},
                "symbol": {"type": "string"},
                "amount_raw": {"type": "string", "default": "0"},
                "decimals": {"type": "integer", "default": 18},
                "tx_hash": {"type": "string"},
            },
            "required": ["from_addr", "to_addr"],
        },
    },
    {
        "name": "vector_preflight_check_x402_payment",
        "description": (
            "Pre-flight risk check for an HTTP 402 / x402 autonomous agent payment requirement. "
            "Evaluates payTo counterparty, network coverage, canonical token vs spoofed symbol, "
            "and Grade-A/C sanctions/mixer signals. Never signs or holds funds (execution_authority=CLIENT_ONLY)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scheme": {"type": "string", "default": "exact"},
                "network": {"type": "string", "description": "Chain or CAIP-2 ID (e.g. bsc, eip155:56, ethereum, eip155:1)"},
                "payTo": {"type": "string", "description": "Recipient address requested by HTTP 402 server"},
                "asset": {"type": "string", "description": "Token contract address or 'native'"},
                "assetSymbol": {"type": "string", "description": "Optional token symbol declared in payment header"},
                "maxAmountRequired": {"type": "string", "description": "Raw integer base-unit amount"},
                "decimals": {"type": "integer", "default": 18},
                "fromAddress": {"type": "string", "description": "Optional agent payer wallet address"},
                "resource": {"type": "string", "description": "Optional HTTP resource URL being paid for"},
            },
            "required": ["network", "payTo", "asset", "maxAmountRequired"],
        },
    },
]


class VectorPreflightMCPServer:
    def __init__(self, db_path: str):
        self.engine = VectorRiskEngine(db_path)

    def close(self) -> None:
        self.engine.close()

    def handle_request(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params") or {}

        # Notifications have no id and expect no response
        if req_id is None and method and method.startswith("notifications/"):
            return None

        try:
            if method == "initialize":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {
                            "name": "vector-sg-preflight-mcp",
                            "version": MCP_DEMO_VERSION,
                        },
                        "instructions": (
                            "Vector (SG) non-custodial pre-flight risk engine. "
                            "All outputs are advisory only (execution_authority=CLIENT_ONLY)."
                        ),
                    },
                }

            if method == "ping":
                return {"jsonrpc": "2.0", "id": req_id, "result": {}}

            if method == "tools/list":
                return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS_SCHEMA}}

            if method == "tools/call":
                tool_name = params.get("name")
                args = params.get("arguments") or {}
                payload = self._call_tool(tool_name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(payload, indent=2, ensure_ascii=False),
                            }
                        ],
                        "structuredContent": payload,
                        "isError": False,
                    },
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        except ValueError as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": str(exc)},
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": f"Internal error: {exc}"},
            }

    def _call_tool(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name == "vector_preflight_check_address":
            if not args.get("address"):
                raise ValueError("Missing required argument: 'address'")
            return self.engine.assess_address(
                chain=str(args.get("chain") or "bsc"),
                address=str(args["address"]),
            )
        if tool_name == "vector_preflight_check_transfer":
            if not args.get("from_addr") or not args.get("to_addr"):
                raise ValueError("Missing required arguments: 'from_addr' and 'to_addr'")
            return self.engine.assess_transfer(
                chain=str(args.get("chain") or "bsc"),
                from_addr=str(args["from_addr"]),
                to_addr=str(args["to_addr"]),
                token_addr=str(args.get("token_addr") or "native"),
                symbol=args.get("symbol"),
                amount_raw=int(str(args.get("amount_raw") or "0")),
                decimals=int(args.get("decimals") if args.get("decimals") is not None else 18),
                tx_hash=args.get("tx_hash"),
            )
        if tool_name == "vector_preflight_check_x402_payment":
            return evaluate_x402_payment(self.engine, args)
        raise ValueError(f"Unknown tool: {tool_name}")

    def serve_stdio(self) -> None:
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError as exc:
                err = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()
                continue
            resp = self.handle_request(msg)
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="Vector (SG) Pre-Flight MCP Server (stdio)")
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to vector_labels_v1.sqlite")
    args = parser.parse_args()
    srv = VectorPreflightMCPServer(args.db)
    try:
        srv.serve_stdio()
    finally:
        srv.close()


if __name__ == "__main__":
    main()
