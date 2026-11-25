#!/usr/bin/env python3
"""Vector (SG) — Risk-Scoring API v1.0 HTTP Server (Stdlib ThreadingHTTPServer).

Endpoints:
  GET  /v1/health            — Engine version, isolated label counts & coverage declaration
  POST /v1/risk/address      — Address risk screening (supports shadow_mode=true)
  POST /v1/risk/transfer     — Transfer / pre-sign / spoofed-token screening (Wedge A)
  POST /v1/appeals           — Submit false-positive dispute (immediately marks Grade-C/D disputed)
  POST /v1/appeals/resolve   — Human reviewer resolution (revoke or reinstate with audit log)
  GET  /v1/appeals           — List appeal & correction log
  GET  /v1/shadow/summary    — 30-day Shadow Mode lift vs. client baseline summary

Usage:
  python3 -m risk_api.server --host 127.0.0.1 --port 8787
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import parse_qs, urlparse

from . import ENGINE_RULE_VERSION
from .engine import VectorRiskEngine

DEFAULT_DB = "/Users/orange/Documents/Projects/ChainWorld/data/vector_labels_v1.sqlite"


def make_handler(engine: VectorRiskEngine):
    class RiskAPIHandler(BaseHTTPRequestHandler):
        def _send_json(self, code: int, payload: dict) -> None:
            raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else b"{}"
            return json.loads(body.decode("utf-8"))

        def log_message(self, format, *args):  # noqa: A002
            return  # quiet by default for clean benchmark runs

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/v1/health":
                self._send_json(200, {
                    "status": "ok",
                    "engine_version": ENGINE_RULE_VERSION,
                    "label_store_counts": engine.store.counts(),
                    "coverage": engine.coverage_declaration("bsc"),
                })
            elif parsed.path == "/v1/appeals":
                self._send_json(200, {"appeals": engine.store.list_appeals()})
            elif parsed.path == "/v1/shadow/summary":
                qs = parse_qs(parsed.query)
                cid = qs.get("client_id", [None])[0]
                self._send_json(200, engine.store.shadow_summary(client_id=cid))
            else:
                self._send_json(404, {"error": f"Unknown endpoint: {parsed.path}"})

        def do_POST(self):
            parsed = urlparse(self.path)
            try:
                body = self._read_json()
                if parsed.path == "/v1/risk/address":
                    res = engine.assess_address(
                        chain=body.get("chain", "bsc"),
                        address=body["address"],
                        shadow_mode=bool(body.get("shadow_mode", False)),
                        client_id=body.get("client_id", "pilot-default"),
                        baseline_verdict=body.get("baseline_verdict"),
                    )
                    self._send_json(200, res)
                elif parsed.path == "/v1/risk/transfer":
                    res = engine.assess_transfer(
                        chain=body.get("chain", "bsc"),
                        from_addr=body["from"],
                        to_addr=body["to"],
                        token_addr=body.get("token_addr", "bnb"),
                        symbol=body.get("symbol"),
                        amount_raw=int(body.get("amount_raw", 0)),
                        decimals=int(body.get("decimals", 18)),
                        tx_hash=body.get("tx_hash"),
                        shadow_mode=bool(body.get("shadow_mode", False)),
                        client_id=body.get("client_id", "pilot-default"),
                        baseline_verdict=body.get("baseline_verdict"),
                    )
                    self._send_json(200, res)
                elif parsed.path == "/v1/appeals":
                    res = engine.store.submit_appeal(
                        appeal_id=body["appeal_id"],
                        evidence_grade=body["evidence_grade"],
                        chain=body["chain"],
                        address=body["address"],
                        label=body["label"],
                        submitted_by=body.get("submitted_by", "external-user"),
                        appeal_reason=body["appeal_reason"],
                        supporting_url=body.get("supporting_url", ""),
                    )
                    self._send_json(200, res)
                elif parsed.path == "/v1/appeals/resolve":
                    res = engine.store.resolve_appeal(
                        appeal_id=body["appeal_id"],
                        resolution_action=body["resolution_action"],
                        reviewer=body.get("reviewer", "Lucy Li"),
                        resolution_note=body.get("resolution_note", ""),
                        revocation_source_url=body.get("revocation_source_url", ""),
                    )
                    self._send_json(200, res)
                else:
                    self._send_json(404, {"error": f"Unknown endpoint: {parsed.path}"})
            except KeyError as exc:
                self._send_json(400, {"error": f"Missing required field or key: {exc}"})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})

    return RiskAPIHandler


def start_server(host: str, port: int, db_path: str) -> ThreadingHTTPServer:
    engine = VectorRiskEngine(db_path)
    srv = ThreadingHTTPServer((host, port), make_handler(engine))
    srv.engine = engine  # type: ignore[attr-defined]
    return srv


def main():
    parser = argparse.ArgumentParser(description="Run Vector (SG) Risk API v1.0 HTTP Server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--db", default=DEFAULT_DB)
    args = parser.parse_args()

    srv = start_server(args.host, args.port, args.db)
    print(f"Vector (SG) Risk API v1.0 listening on http://{args.host}:{args.port} (db={args.db})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.engine.close()  # type: ignore[attr-defined]
        srv.server_close()


if __name__ == "__main__":
    main()
