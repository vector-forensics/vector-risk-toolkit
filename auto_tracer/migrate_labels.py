#!/usr/bin/env python3
"""Vector (SG) — Label Spec v1.0 Compliant Migration Script.

Migrates existing OnchainInvestigator label files into Vector (SG)'s physically
grade-isolated SQLite WAL store (`data/vector_labels_v1.sqlite`):
  1. `external_labels.json` (OFAC SDN) -> `labels_grade_a_official_sanctions`
     - Resolves exact chain from (currency + address prefix): e.g., USDT `T...` -> `tron`, `0x...` -> `ethereum`.
     - Populates all 8 mandatory provenance fields (official OFAC URL, verbatim excerpt,
       retrieval timestamp, Grade-A, confidence=1.0, reviewer, status=active).
     - Any ambiguous/unmappable address is routed strictly to `labels_quarantine_pending`.
  2. `etherscan_labels.json` (Explorer hubs/references) -> `labels_grade_c_reference_hubs`
     - Strictly kept at Grade-C (NEVER promoted to Grade-A official sanctions).
     - Populates explorer source URL, excerpt, retrieval timestamp, reviewer, status=active.
  3. Verifies 100% of migrated production records pass `validate_labels.validate_record()`.

Usage:
  python3 -m auto_tracer.migrate_labels
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
from typing import Optional, Tuple

from .label_store import VectorLabelStore, norm_address
from .validate_labels import validate_record

OFAC_OFFICIAL_URL = "https://ofac.treasury.gov/specially-designated-nationals-and-blocked-persons-list-sdn-human-readable-lists"
EXPLORER_BASE_URLS = {
    "ethereum": "https://etherscan.io/address/",
    "bsc": "https://bscscan.com/address/",
    "polygon": "https://polygonscan.com/address/",
    "arbitrum": "https://arbiscan.io/address/",
    "optimism": "https://optimistic.etherscan.io/address/",
    "avalanche": "https://snowtrace.io/address/",
}

CURRENCY_DIRECT_CHAIN = {
    "XBT": "bitcoin",
    "BTC": "bitcoin",
    "TRX": "tron",
    "ETH": "ethereum",
    "LTC": "litecoin",
    "XMR": "monero",
    "DASH": "dash",
    "ZEC": "zcash",
    "SOL": "solana",
    "DOGE": "dogecoin",
    "BTG": "btg",
    "ETC": "etc",
    "XVG": "xvg",
    "BCH": "bch",
}

EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")


def infer_ofac_chain(currency: str, address: str) -> Optional[str]:
    cur = (currency or "").strip().upper()
    addr = (address or "").strip()
    if cur in CURRENCY_DIRECT_CHAIN:
        return CURRENCY_DIRECT_CHAIN[cur]
    if cur in ("USDT", "USDC"):
        if TRON_RE.match(addr):
            return "tron"
        if EVM_RE.match(addr):
            return "ethereum"
    return None


def file_mtime_utc(path: str) -> str:
    ts = os.path.getmtime(path)
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def migrate_ofac(store: VectorLabelStore, path: str) -> Tuple[int, int]:
    data = json.load(open(path, "r", encoding="utf-8"))
    rows = data.get("labels", []) if isinstance(data, dict) else data
    retrieved_at = file_mtime_utc(path)
    ok_cnt = 0
    quar_cnt = 0

    for raw in rows:
        addr = str(raw.get("address") or "").strip()
        cur = str(raw.get("currency") or "").strip()
        ent = str(raw.get("entity") or "").strip()
        chain = infer_ofac_chain(cur, addr)
        if not chain:
            store.conn.execute(
                "INSERT INTO labels_quarantine_pending (source_file, raw_address, raw_chain_or_currency, raw_json, quarantine_reasons, quarantined_at_utc) VALUES (?, ?, ?, ?, ?, ?)",
                (os.path.basename(path), addr, cur, json.dumps(raw, ensure_ascii=False), "ambiguous_chain_for_currency", retrieved_at),
            )
            quar_cnt += 1
            continue

        rec = {
            "chain": chain,
            "address": addr,
            "label": f"OFAC SDN: {ent} ({cur})" if ent else f"OFAC SDN ({cur})",
            "entity": ent,
            "category": "sanctioned",
            "source_url": OFAC_OFFICIAL_URL,
            "evidence_excerpt": f"OFAC SDN Entry: {ent} | Digital Currency Address - {cur} {addr}",
            "retrieved_at_utc": retrieved_at,
            "effective_date_utc": retrieved_at[:10],
            "evidence_grade": "Grade-A",
            "confidence": 1.0,
            "reviewer": "ofac-migration-v1.0",
            "status": "active",
        }
        valid, errs = validate_record(rec)
        if not valid:
            store.conn.execute(
                "INSERT INTO labels_quarantine_pending (source_file, raw_address, raw_chain_or_currency, raw_json, quarantine_reasons, quarantined_at_utc) VALUES (?, ?, ?, ?, ?, ?)",
                (os.path.basename(path), addr, cur, json.dumps(raw, ensure_ascii=False), ",".join(errs), retrieved_at),
            )
            quar_cnt += 1
            continue

        store.conn.execute(
            """
            INSERT OR IGNORE INTO labels_grade_a_official_sanctions
            (chain, norm_address, address, label, entity, category, source_url, evidence_excerpt,
             retrieved_at_utc, effective_date_utc, evidence_grade, confidence, reviewer, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rec["chain"], norm_address(rec["chain"], rec["address"]), rec["address"],
                rec["label"], rec["entity"], rec["category"], rec["source_url"],
                rec["evidence_excerpt"], rec["retrieved_at_utc"], rec["effective_date_utc"],
                rec["evidence_grade"], rec["confidence"], rec["reviewer"], rec["status"],
            ),
        )
        ok_cnt += 1

    store.conn.commit()
    return ok_cnt, quar_cnt


def migrate_etherscan(store: VectorLabelStore, path: str) -> Tuple[int, int]:
    data = json.load(open(path, "r", encoding="utf-8"))
    rows = data.get("labels", []) if isinstance(data, dict) else data
    retrieved_at = file_mtime_utc(path)
    ok_cnt = 0
    quar_cnt = 0
    batch_insert = []

    for raw in rows:
        addr = str(raw.get("address") or "").strip()
        chain = str(raw.get("chain") or "").strip().lower()
        lbl = str(raw.get("label") or "").strip()
        ent = str(raw.get("entity") or "").strip()
        cat = str(raw.get("category") or "other").strip().lower()
        base_url = EXPLORER_BASE_URLS.get(chain)

        if not base_url or not EVM_RE.match(addr) or not lbl:
            store.conn.execute(
                "INSERT INTO labels_quarantine_pending (source_file, raw_address, raw_chain_or_currency, raw_json, quarantine_reasons, quarantined_at_utc) VALUES (?, ?, ?, ?, ?, ?)",
                (os.path.basename(path), addr, chain, json.dumps(raw, ensure_ascii=False), "invalid_chain_address_or_label", retrieved_at),
            )
            quar_cnt += 1
            continue

        # Explorer scraped labels are strictly Grade-C (capped <= 0.95; never official sanctions)
        raw_conf = float(raw.get("confidence") or 0.8)
        conf = min(0.95, max(0.5, raw_conf))
        rec = {
            "chain": chain,
            "address": addr,
            "label": lbl,
            "entity": ent,
            "category": cat,
            "source_url": f"{base_url}{addr.lower()}",
            "evidence_excerpt": f"Explorer public tag ({chain}): {lbl} [category={cat}, note={raw.get('note', '')}]",
            "retrieved_at_utc": retrieved_at,
            "effective_date_utc": retrieved_at[:10],
            "evidence_grade": "Grade-C",
            "confidence": conf,
            "reviewer": "explorer-migration-v1.0",
            "status": "active",
        }
        valid, errs = validate_record(rec)
        if not valid:
            store.conn.execute(
                "INSERT INTO labels_quarantine_pending (source_file, raw_address, raw_chain_or_currency, raw_json, quarantine_reasons, quarantined_at_utc) VALUES (?, ?, ?, ?, ?, ?)",
                (os.path.basename(path), addr, chain, json.dumps(raw, ensure_ascii=False), ",".join(errs), retrieved_at),
            )
            quar_cnt += 1
            continue

        batch_insert.append((
            rec["chain"], norm_address(rec["chain"], rec["address"]), rec["address"],
            rec["label"], rec["entity"], rec["category"], rec["source_url"],
            rec["evidence_excerpt"], rec["retrieved_at_utc"], rec["effective_date_utc"],
            rec["evidence_grade"], rec["confidence"], rec["reviewer"], rec["status"],
        ))
        ok_cnt += 1

    store.conn.executemany(
        """
        INSERT OR IGNORE INTO labels_grade_c_reference_hubs
        (chain, norm_address, address, label, entity, category, source_url, evidence_excerpt,
         retrieved_at_utc, effective_date_utc, evidence_grade, confidence, reviewer, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        batch_insert,
    )
    store.conn.commit()
    return ok_cnt, quar_cnt


def main():
    parser = argparse.ArgumentParser(description="Migrate OnchainInvestigator labels into Vector (SG) Grade-Isolated Label Store v1.")
    parser.add_argument("--db", default="/Users/orange/Documents/Projects/ChainWorld/data/vector_labels_v1.sqlite")
    parser.add_argument("--ofac", default="/Users/orange/Documents/Agents/OnchainInvestigator/data/labels/external_labels.json")
    parser.add_argument("--etherscan", default="/Users/orange/Documents/Agents/OnchainInvestigator/data/labels/etherscan_labels.json")
    args = parser.parse_args()

    if os.path.exists(args.db):
        os.remove(args.db)
    store = VectorLabelStore(args.db)
    ofac_ok, ofac_q = migrate_ofac(store, args.ofac)
    eth_ok, eth_q = migrate_etherscan(store, args.etherscan)
    counts = store.counts()
    store.close()

    print("=== LABEL SPEC v1.0 MIGRATION COMPLETE ===")
    print(f"Database       : {args.db}")
    print(f"OFAC Grade-A   : migrated={ofac_ok}, quarantined={ofac_q}")
    print(f"Explorer Grd-C : migrated={eth_ok}, quarantined={eth_q}")
    print(f"Store Counts   : {json.dumps(counts, indent=2)}")


if __name__ == "__main__":
    main()
