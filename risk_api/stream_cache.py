#!/usr/bin/env python3
"""Vector (SG) — Tier-2 BSC Hotspot Incremental Stream Indexer & Subgraph Cache (Stdlib Only).

Bridges the Phase 1 latency/freshness gap between static frozen label snapshots and
live BSC network activity WITHOUT polluting the grade-isolated label tables:
  - Dedicated SQLite WAL cache (`data/bsc_hotspot_cache.sqlite`)
  - Multi-mirror BSC JSON-RPC failover (`bsc-dataseed1..4` + `bsc-rpc.publicnode.com`)
  - Tracks recent inbound/outbound counts, native volume, and mixer/bridge/spoof touches
  - Supports BOTH live block polling (`--live-latest N`) and deterministic snapshot replay
    (`--replay-snapshot <frozen_snapshot_dir>`) for reproducible benchmarks.

Usage:
  python3 -m risk_api.stream_cache --cache-db data/bsc_hotspot_cache.sqlite --live-latest 5
  python3 -m risk_api.stream_cache --cache-db data/bsc_hotspot_cache.sqlite --replay-snapshot benchmarks/cases/BLIND-003/frozen_snapshot
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import json
import os
import sqlite3
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from auto_tracer.forensics import (
    breakpoint_reason,
    canonical_token_info,
    is_spoof_or_scam_symbol,
)

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

BSC_RPC_MIRRORS = [
    "https://bsc-dataseed1.binance.org/",
    "https://bsc-dataseed2.binance.org/",
    "https://bsc-dataseed3.binance.org/",
    "https://bsc-dataseed4.binance.org/",
    "https://bsc-rpc.publicnode.com",
]

_CACHE_DDL = """
CREATE TABLE IF NOT EXISTS cache_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hotspot_address_stats (
    chain TEXT NOT NULL,
    norm_address TEXT NOT NULL,
    tx_in_count INTEGER NOT NULL DEFAULT 0,
    tx_out_count INTEGER NOT NULL DEFAULT 0,
    total_native_in_wei TEXT NOT NULL DEFAULT '0',
    total_native_out_wei TEXT NOT NULL DEFAULT '0',
    mixer_touch_count INTEGER NOT NULL DEFAULT 0,
    bridge_touch_count INTEGER NOT NULL DEFAULT 0,
    last_seen_block INTEGER NOT NULL DEFAULT 0,
    last_tx_hash TEXT NOT NULL DEFAULT '',
    updated_at_utc TEXT NOT NULL,
    PRIMARY KEY (chain, norm_address)
);

CREATE INDEX IF NOT EXISTS idx_hotspot_mixer ON hotspot_address_stats(chain, mixer_touch_count);
CREATE INDEX IF NOT EXISTS idx_hotspot_block ON hotspot_address_stats(chain, last_seen_block);

CREATE TABLE IF NOT EXISTS hotspot_recent_edges (
    chain TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    block_number INTEGER NOT NULL,
    log_index INTEGER NOT NULL,
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    asset TEXT NOT NULL,
    symbol TEXT NOT NULL DEFAULT '',
    amount_raw TEXT NOT NULL,
    breakpoint_tag TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (chain, tx_hash, log_index)
);

CREATE INDEX IF NOT EXISTS idx_recent_from ON hotspot_recent_edges(chain, from_addr, block_number DESC);
CREATE INDEX IF NOT EXISTS idx_recent_to ON hotspot_recent_edges(chain, to_addr, block_number DESC);
"""


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rpc_call(method: str, params: list, mirrors: Optional[List[str]] = None, retries: int = 5) -> Any:
    urls = mirrors or BSC_RPC_MIRRORS
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode("utf-8")
    last_err = None
    for attempt in range(retries):
        target = urls[attempt % len(urls)]
        try:
            req = urllib.request.Request(
                target,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "VectorSG-HotspotIndexer/0.1"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            if body.get("error"):
                raise RuntimeError(f"RPC error {method}: {body['error']}")
            return body.get("result")
        except Exception as exc:
            last_err = exc
            time.sleep(0.3 * (attempt + 1))
    raise RuntimeError(f"RPC {method} failed after {retries} attempts: {last_err}")


class HotspotCacheStore:
    """Fast local SQLite WAL Tier-2 hotspot index (strictly separate from label provenance tables)."""

    def __init__(self, cache_db_path: str):
        self.cache_db_path = cache_db_path
        os.makedirs(os.path.dirname(cache_db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(cache_db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.executescript(_CACHE_DDL)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO cache_metadata (key, value) VALUES (?, ?)",
            (key, str(value)),
        )

    def get_meta(self) -> Dict[str, str]:
        rows = self.conn.execute("SELECT key, value FROM cache_metadata").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def stats(self) -> Dict[str, Any]:
        addrs = self.conn.execute("SELECT COUNT(*) FROM hotspot_address_stats").fetchone()[0]
        edges = self.conn.execute("SELECT COUNT(*) FROM hotspot_recent_edges").fetchone()[0]
        mixers = self.conn.execute("SELECT COUNT(*) FROM hotspot_address_stats WHERE mixer_touch_count > 0").fetchone()[0]
        bridges = self.conn.execute("SELECT COUNT(*) FROM hotspot_address_stats WHERE bridge_touch_count > 0").fetchone()[0]
        return {
            "cached_addresses": addrs,
            "cached_edges": edges,
            "addresses_with_mixer_touch": mixers,
            "addresses_with_bridge_touch": bridges,
            "metadata": self.get_meta(),
        }

    def lookup_address(self, chain: str, address: str) -> Optional[Dict[str, Any]]:
        c = (chain or "bsc").strip().lower()
        na = (address or "").strip().lower()
        row = self.conn.execute(
            "SELECT * FROM hotspot_address_stats WHERE chain=? AND norm_address=?",
            (c, na),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        recent = self.conn.execute(
            """
            SELECT tx_hash, block_number, log_index, from_addr, to_addr, asset, symbol, amount_raw, breakpoint_tag
            FROM hotspot_recent_edges
            WHERE chain=? AND (from_addr=? OR to_addr=?)
            ORDER BY block_number DESC, log_index DESC
            LIMIT 5
            """,
            (c, na, na),
        ).fetchall()
        d["recent_edges"] = [dict(r) for r in recent]
        return d

    def ingest_edges(
        self,
        chain: str,
        edges: List[Dict[str, Any]],
        max_block: int,
        source_label: str,
    ) -> Dict[str, int]:
        """Idempotently ingests decoded edges and updates per-address hotspot summaries."""
        c = chain.lower()
        now = utc_now_iso()
        inserted_edges = 0
        addr_deltas: Dict[str, Dict[str, Any]] = {}

        def _ensure(a: str) -> Dict[str, Any]:
            if a not in addr_deltas:
                addr_deltas[a] = {
                    "tx_in": 0, "tx_out": 0,
                    "native_in": 0, "native_out": 0,
                    "mixer": 0, "bridge": 0,
                    "last_block": 0, "last_tx": "",
                }
            return addr_deltas[a]

        for e in edges:
            txh = e["tx_hash"].lower()
            bn = int(e["block_number"])
            li = int(e["log_index"])
            fr = (e["from_addr"] or "").lower()
            to = (e["to_addr"] or "").lower()
            asset = (e["asset"] or "").lower()
            sym = e.get("symbol") or ""
            amt_int = int(e["amount_raw"])

            bp = breakpoint_reason(to) or breakpoint_reason(fr) or ""
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO hotspot_recent_edges
                (chain, tx_hash, block_number, log_index, from_addr, to_addr, asset, symbol, amount_raw, breakpoint_tag)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (c, txh, bn, li, fr, to, asset, sym, str(amt_int), bp),
            )
            if cur.rowcount == 0:
                continue  # Already indexed idempotently
            inserted_edges += 1

            is_native = asset in ("bnb", "eth", "native")
            is_mixer = bp.startswith("known_mixer:")
            is_bridge = bp.startswith("known_bridge:")

            if fr and fr != "0x0000000000000000000000000000000000000000":
                s = _ensure(fr)
                s["tx_out"] += 1
                if is_native:
                    s["native_out"] += amt_int
                if is_mixer and not breakpoint_reason(fr):
                    s["mixer"] += 1
                if is_bridge and not breakpoint_reason(fr):
                    s["bridge"] += 1
                if bn >= s["last_block"]:
                    s["last_block"] = bn
                    s["last_tx"] = txh

            if to and to != "0x0000000000000000000000000000000000000000":
                s = _ensure(to)
                s["tx_in"] += 1
                if is_native:
                    s["native_in"] += amt_int
                if is_mixer and not breakpoint_reason(to):
                    s["mixer"] += 1
                if is_bridge and not breakpoint_reason(to):
                    s["bridge"] += 1
                if bn >= s["last_block"]:
                    s["last_block"] = bn
                    s["last_tx"] = txh

        for addr, d in addr_deltas.items():
            prev = self.conn.execute(
                "SELECT * FROM hotspot_address_stats WHERE chain=? AND norm_address=?",
                (c, addr),
            ).fetchone()
            if prev:
                tx_in = prev["tx_in_count"] + d["tx_in"]
                tx_out = prev["tx_out_count"] + d["tx_out"]
                nat_in = str(int(prev["total_native_in_wei"]) + d["native_in"])
                nat_out = str(int(prev["total_native_out_wei"]) + d["native_out"])
                mx = prev["mixer_touch_count"] + d["mixer"]
                br = prev["bridge_touch_count"] + d["bridge"]
                lb = max(prev["last_seen_block"], d["last_block"])
                ltx = d["last_tx"] if d["last_block"] >= prev["last_seen_block"] else prev["last_tx_hash"]
            else:
                tx_in, tx_out = d["tx_in"], d["tx_out"]
                nat_in, nat_out = str(d["native_in"]), str(d["native_out"])
                mx, br = d["mixer"], d["bridge"]
                lb, ltx = d["last_block"], d["last_tx"]

            self.conn.execute(
                """
                INSERT OR REPLACE INTO hotspot_address_stats
                (chain, norm_address, tx_in_count, tx_out_count, total_native_in_wei,
                 total_native_out_wei, mixer_touch_count, bridge_touch_count,
                 last_seen_block, last_tx_hash, updated_at_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (c, addr, tx_in, tx_out, nat_in, nat_out, mx, br, lb, ltx, now),
            )

        self.set_meta("chain", c)
        self.set_meta("last_indexed_block", str(max_block))
        self.set_meta("source", source_label)
        self.set_meta("updated_at_utc", now)
        self.conn.commit()
        return {"inserted_edges": inserted_edges, "updated_addresses": len(addr_deltas)}

    def index_live_bsc_blocks(self, num_blocks: int = 5, workers: int = 4) -> Dict[str, Any]:
        """Polls the latest N live BSC blocks via public mirrors and indexes native transfers + hotspot touches."""
        t0 = time.perf_counter()
        tip_hex = rpc_call("eth_blockNumber", [])
        tip = int(tip_hex, 16)
        start_bn = max(1, tip - num_blocks + 1)
        block_nums = list(range(start_bn, tip + 1))

        def fetch_blk(idx_bn: Tuple[int, int]) -> Tuple[int, List[Dict[str, Any]]]:
            idx, bn = idx_bn
            rotated = BSC_RPC_MIRRORS[idx % len(BSC_RPC_MIRRORS):] + BSC_RPC_MIRRORS[:idx % len(BSC_RPC_MIRRORS)]
            blk = rpc_call("eth_getBlockByNumber", [hex(bn), True], mirrors=rotated)
            out: List[Dict[str, Any]] = []
            if not blk:
                return bn, out
            for tx in blk.get("transactions", []):
                fr = (tx.get("from") or "").lower()
                to = (tx.get("to") or "").lower()
                if not to:
                    continue
                val = int(tx.get("value", "0x0"), 16)
                # Index all non-zero native BNB transfers AND any call touching a known mixer/bridge
                if val > 0 or breakpoint_reason(to):
                    out.append({
                        "tx_hash": tx["hash"].lower(),
                        "block_number": bn,
                        "log_index": -1,
                        "from_addr": fr,
                        "to_addr": to,
                        "asset": "bnb",
                        "symbol": "BNB",
                        "amount_raw": str(val),
                    })
            return bn, out

        all_edges: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(fetch_blk, (i, bn)) for i, bn in enumerate(block_nums)]
            for fut in as_completed(futs):
                _bn, bl_edges = fut.result()
                all_edges.extend(bl_edges)

        res = self.ingest_edges("bsc", all_edges, max_block=tip, source_label="live_bsc_rpc_mirrors")
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return {
            "mode": "live_bsc_poll",
            "block_range": [start_bn, tip],
            "blocks_indexed": len(block_nums),
            "elapsed_ms": elapsed_ms,
            **res,
            **self.stats(),
        }

    def replay_frozen_snapshot(self, snap_dir: str) -> Dict[str, Any]:
        """Deterministically ingests a frozen benchmark snapshot into the hotspot cache."""
        with open(os.path.join(snap_dir, "FREEZE_LOCK.json"), "r", encoding="utf-8") as f:
            lock = json.load(f)
        chain = lock.get("chain", "bsc").lower()
        edges: List[Dict[str, Any]] = []
        max_block = 0

        with open(os.path.join(snap_dir, "window_transactions.jsonl"), "r", encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                tx = rec["transaction"]
                bn = int(rec["block_number"])
                max_block = max(max_block, bn)
                val = int(tx.get("value", "0x0"), 16)
                to = (tx.get("to") or "").lower()
                if val > 0 and to:
                    edges.append({
                        "tx_hash": rec["tx_hash"].lower(),
                        "block_number": bn,
                        "log_index": -1,
                        "from_addr": (tx.get("from") or "").lower(),
                        "to_addr": to,
                        "asset": "bnb" if chain == "bsc" else "eth",
                        "symbol": "BNB" if chain == "bsc" else "ETH",
                        "amount_raw": str(val),
                    })

        tr_path = os.path.join(snap_dir, "erc20_transfers_from_receipts.jsonl")
        if os.path.exists(tr_path):
            with open(tr_path, "r", encoding="utf-8") as f:
                for line in f:
                    tr = json.loads(line)
                    bn = int(tr["block_number"])
                    max_block = max(max_block, bn)
                    tok = tr["token_contract"].lower()
                    canon = canonical_token_info(tok, chain=chain)
                    edges.append({
                        "tx_hash": tr["tx_hash"].lower(),
                        "block_number": bn,
                        "log_index": int(tr["log_index"]),
                        "from_addr": tr["from"].lower(),
                        "to_addr": tr["to"].lower(),
                        "asset": tok,
                        "symbol": canon[0] if canon else "",
                        "amount_raw": str(tr["amount_raw"]),
                    })

        res = self.ingest_edges(chain, edges, max_block=max_block, source_label=f"replay:{lock['case_id']}")
        return {"mode": "snapshot_replay", "case_id": lock["case_id"], **res, **self.stats()}


def main() -> None:
    parser = argparse.ArgumentParser(description="Vector (SG) Tier-2 BSC Hotspot Incremental Stream Indexer")
    parser.add_argument("--cache-db", default="data/bsc_hotspot_cache.sqlite", help="SQLite WAL cache path")
    parser.add_argument("--live-latest", type=int, default=0, help="Poll latest N live BSC blocks")
    parser.add_argument("--replay-snapshot", action="append", default=[], help="Frozen snapshot dir(s) to replay")
    args = parser.parse_args()

    cache = HotspotCacheStore(args.cache_db)
    try:
        out: Dict[str, Any] = {}
        if args.replay_snapshot:
            out["replays"] = [cache.replay_frozen_snapshot(p) for p in args.replay_snapshot]
        if args.live_latest > 0:
            out["live_poll"] = cache.index_live_bsc_blocks(num_blocks=args.live_latest)
        if not out:
            out["stats"] = cache.stats()
        print(json.dumps(out, indent=2))
    finally:
        cache.close()


if __name__ == "__main__":
    main()
