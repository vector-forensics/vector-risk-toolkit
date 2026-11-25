#!/usr/bin/env python3
"""Vector (SG) — Official Grade-A OFAC Sync & Grade-B Law Enforcement Advisory Loader (Stdlib Only).

Implements strict provenance isolation per label_spec_v1.md:
  1. Grade-A OFAC SDN Incremental Sync (`sync_ofac_xml`):
     - Parses official U.S. Treasury OFAC SDN XML (`sdn.xml`, live or local file)
     - Extracts `Digital Currency Address - <SYMBOL> <ADDRESS>` entries
     - Hard-blocks re-ingestion of OFAC-delisted Tornado Cash entries (delisted 2025-03-21)
     - Diffs against `labels_grade_a_official_sanctions`; dry-run by default (`--apply` to insert)
     - NEVER auto-deletes existing Grade-A records without human revocation review.
  2. Grade-B Official Law Enforcement Advisory Ingestion (`ingest_grade_b_advisory`):
     - Enforces strict official government/LE domain allowlist (`fbi.gov`, `ic3.gov`,
       `justice.gov`, `treasury.gov`, `mas.gov.sg`, `police.gov.sg`)
     - Non-official or incomplete records are hard-rejected into `labels_quarantine_pending`
     - Validated records are written strictly to `labels_grade_b_official_le` (physically
       isolated from Grade-A OFAC SDN).

Usage:
  python3 -m auto_tracer.label_sync --db data/vector_labels_v1.sqlite --self-test
  python3 -m auto_tracer.label_sync --db data/vector_labels_v1.sqlite --ofac-xml live --dry-run
  python3 -m auto_tracer.label_sync --db data/vector_labels_v1.sqlite --grade-b-json path/to/advisory.json --apply
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import tempfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from .label_store import VectorLabelStore, norm_address, utc_now_iso

OFAC_SDN_XML_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"

OFFICIAL_LE_DOMAINS = {
    "fbi.gov",
    "www.fbi.gov",
    "ic3.gov",
    "www.ic3.gov",
    "justice.gov",
    "www.justice.gov",
    "treasury.gov",
    "home.treasury.gov",
    "ofac.treasury.gov",
    "mas.gov.sg",
    "www.mas.gov.sg",
    "police.gov.sg",
    "www.police.gov.sg",
}

# Delisted by OFAC on 2025-03-21 — MUST NEVER be re-ingested as active Grade-A sanctions
DELISTED_NAME_PATTERNS = ("tornado cash",)

CURRENCY_TO_CHAIN = {
    "ETH": "ethereum",
    "BSC": "bsc",
    "BNB": "bsc",
    "XBT": "bitcoin",
    "BTC": "bitcoin",
    "TRX": "tron",
    "USDT": "ethereum",
    "USDC": "ethereum",
    "LTC": "litecoin",
    "BCH": "bch",
    "DASH": "dash",
    "ZEC": "zcash",
    "XMR": "monero",
    "SOL": "solana",
    "ARB": "arbitrum",
    "MATIC": "polygon",
}

_DCA_RE = re.compile(r"Digital Currency Address\s*-\s*([A-Z0-9]+)\s+([A-Za-z0-9:_-]{20,128})")


def is_official_le_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse((url or "").strip())
        return parsed.scheme == "https" and parsed.netloc.lower() in OFFICIAL_LE_DOMAINS
    except Exception:
        return False


def parse_ofac_sdn_xml(xml_bytes: bytes) -> Tuple[str, List[Dict[str, str]]]:
    """Extracts all Digital Currency Address records from official OFAC sdn.xml."""
    root = ET.fromstring(xml_bytes)

    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    pub_date = ""
    records: List[Dict[str, str]] = []

    for elem in root:
        tag = strip_ns(elem.tag)
        if tag == "publshInformation":
            for child in elem:
                if strip_ns(child.tag) == "Publish_Date" and child.text:
                    pub_date = child.text.strip()
        elif tag == "sdnEntry":
            uid = ""
            last_name = ""
            first_name = ""
            programs: List[str] = []
            remarks = ""
            for child in elem:
                ct = strip_ns(child.tag)
                if ct == "uid" and child.text:
                    uid = child.text.strip()
                elif ct == "lastName" and child.text:
                    last_name = child.text.strip()
                elif ct == "firstName" and child.text:
                    first_name = child.text.strip()
                elif ct == "remarks" and child.text:
                    remarks = child.text.strip()
                elif ct == "programList":
                    for p in child:
                        if strip_ns(p.tag) == "program" and p.text:
                            programs.append(p.text.strip())

            entity_name = f"{first_name} {last_name}".strip() if first_name else last_name
            if any(pat in entity_name.lower() for pat in DELISTED_NAME_PATTERNS):
                continue

            for m in _DCA_RE.finditer(remarks):
                sym = m.group(1).upper()
                addr = m.group(2).rstrip(".;,")
                chain = CURRENCY_TO_CHAIN.get(sym, sym.lower())
                records.append({
                    "uid": uid,
                    "entity": entity_name,
                    "programs": ",".join(programs),
                    "currency": sym,
                    "chain": chain,
                    "address": addr,
                    "norm_address": norm_address(chain, addr),
                    "publish_date": pub_date,
                })
    return pub_date, records


def sync_ofac_xml(
    db_path: str,
    xml_source: str,
    apply: bool = False,
    reviewer: str = "OFAC-AutoSync-v1",
) -> Dict[str, Any]:
    """Diffs (and optionally applies) official OFAC SDN XML digital currency entries to Grade-A table."""
    if xml_source == "live":
        req = urllib.request.Request(
            OFAC_SDN_XML_URL,
            headers={"User-Agent": "VectorSG-LabelSync/1.0"},
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            xml_bytes = resp.read()
        source_url = OFAC_SDN_XML_URL
    else:
        with open(xml_source, "rb") as f:
            xml_bytes = f.read()
        source_url = OFAC_SDN_XML_URL

    pub_date, parsed = parse_ofac_sdn_xml(xml_bytes)
    store = VectorLabelStore(db_path)
    try:
        existing_rows = store.conn.execute(
            "SELECT chain, norm_address, status FROM labels_grade_a_official_sanctions"
        ).fetchall()
        existing_keys = {(r["chain"], r["norm_address"]) for r in existing_rows}
        active_keys = {(r["chain"], r["norm_address"]) for r in existing_rows if r["status"] == "active"}

        parsed_keys = {(r["chain"], r["norm_address"]) for r in parsed}
        new_recs = [r for r in parsed if (r["chain"], r["norm_address"]) not in existing_keys]
        potentially_delisted = sorted(active_keys - parsed_keys)

        inserted = 0
        now = utc_now_iso()
        if apply and new_recs:
            for r in new_recs:
                lbl = f"OFAC SDN [{r['programs'] or 'SDN'}] {r['entity']}"
                excerpt = f"OFAC sdn.xml uid={r['uid']} Digital Currency Address - {r['currency']} {r['address']} (pub={pub_date})"
                cur = store.conn.execute(
                    """
                    INSERT OR IGNORE INTO labels_grade_a_official_sanctions
                    (chain, norm_address, address, label, entity, category, source_url,
                     evidence_excerpt, retrieved_at_utc, effective_date_utc,
                     evidence_grade, confidence, reviewer, status)
                    VALUES (?, ?, ?, ?, ?, 'sanctioned', ?, ?, ?, ?, 'Grade-A', 1.0, ?, 'active')
                    """,
                    (
                        r["chain"], r["norm_address"], r["address"], lbl, r["entity"],
                        source_url, excerpt, now, pub_date, reviewer,
                    ),
                )
                inserted += cur.rowcount
            store.conn.commit()

        return {
            "source": xml_source,
            "ofac_publish_date": pub_date,
            "parsed_digital_currency_records": len(parsed),
            "existing_grade_a_active": len(active_keys),
            "new_records_detected": len(new_recs),
            "applied_inserts": inserted,
            "potentially_delisted_for_human_review": len(potentially_delisted),
            "dry_run": not apply,
        }
    finally:
        store.close()


def ingest_grade_b_advisory(
    db_path: str,
    records: List[Dict[str, Any]],
    source_file: str = "grade_b_advisory.json",
    apply: bool = False,
) -> Dict[str, Any]:
    """Validates and ingests official FBI/DOJ/LE advisories strictly into `labels_grade_b_official_le`.

    Any record missing official `.gov`/`.gov.sg` URL, evidence excerpt, effective date, or reviewer
    is rejected and quarantined into `labels_quarantine_pending` (never touches Grade-A or Grade-B).
    """
    store = VectorLabelStore(db_path)
    accepted: List[Dict[str, Any]] = []
    quarantined: List[Dict[str, Any]] = []
    now = utc_now_iso()

    try:
        for rec in records:
            reasons: List[str] = []
            chain = str(rec.get("chain") or "").strip().lower()
            addr = str(rec.get("address") or "").strip()
            label = str(rec.get("label") or "").strip()
            entity = str(rec.get("entity") or "").strip()
            src_url = str(rec.get("source_url") or "").strip()
            excerpt = str(rec.get("evidence_excerpt") or "").strip()
            eff_date = str(rec.get("effective_date_utc") or "").strip()
            reviewer = str(rec.get("reviewer") or "").strip()
            conf = float(rec.get("confidence", 0.90))

            if not chain:
                reasons.append("missing_chain")
            if not addr:
                reasons.append("missing_address")
            if not label:
                reasons.append("missing_label")
            if not is_official_le_url(src_url):
                reasons.append(f"non_official_le_domain:{src_url}")
            if len(excerpt) < 16:
                reasons.append("missing_or_short_evidence_excerpt")
            if not eff_date:
                reasons.append("missing_effective_date_utc")
            if not reviewer:
                reasons.append("missing_reviewer")

            if reasons:
                quarantined.append({"address": addr, "reasons": reasons})
                if apply:
                    store.conn.execute(
                        """
                        INSERT INTO labels_quarantine_pending
                        (source_file, raw_address, raw_chain_or_currency, raw_json, quarantine_reasons, quarantined_at_utc)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (source_file, addr, chain, json.dumps(rec, sort_keys=True), ";".join(reasons), now),
                    )
            else:
                na = norm_address(chain, addr)
                accepted.append({"chain": chain, "address": addr, "label": label})
                if apply:
                    store.conn.execute(
                        """
                        INSERT OR IGNORE INTO labels_grade_b_official_le
                        (chain, norm_address, address, label, entity, category, source_url,
                         evidence_excerpt, retrieved_at_utc, effective_date_utc,
                         evidence_grade, confidence, reviewer, status)
                        VALUES (?, ?, ?, ?, ?, 'exploit', ?, ?, ?, ?, 'Grade-B', ?, ?, 'active')
                        """,
                        (
                            chain, na, addr, label, entity, src_url, excerpt,
                            now, eff_date, min(0.95, max(0.5, conf)), reviewer,
                        ),
                    )
        if apply:
            store.conn.commit()
        return {
            "source_file": source_file,
            "total_input": len(records),
            "accepted_grade_b": len(accepted),
            "quarantined_invalid": len(quarantined),
            "quarantine_details": quarantined,
            "dry_run": not apply,
        }
    finally:
        store.close()


def run_self_test() -> Dict[str, Any]:
    """Self-contained isolated test verifying OFAC XML parsing, Tornado Cash block, & Grade-B isolation."""
    tmp = tempfile.mkdtemp(prefix="vector_label_sync_test_")
    try:
        db = os.path.join(tmp, "test.sqlite")
        xml_path = os.path.join(tmp, "sample_sdn.xml")
        sample_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <sdnList>
          <publshInformation><Publish_Date>11/25/2026</Publish_Date></publshInformation>
          <sdnEntry>
            <uid>99001</uid>
            <lastName>LAZARUS GROUP</lastName>
            <programList><program>DPRK3</program></programList>
            <remarks>Digital Currency Address - ETH 0x098B716B8Aaf21512996dC57EB0615e2383E2f96; Digital Currency Address - BSC 0x1111111111111111111111111111111111111111.</remarks>
          </sdnEntry>
          <sdnEntry>
            <uid>99002</uid>
            <lastName>TORNADO CASH</lastName>
            <programList><program>CYBER2</program></programList>
            <remarks>Digital Currency Address - ETH 0x8589427373D6D84E98730D7795D8f6f8731FDA16.</remarks>
          </sdnEntry>
        </sdnList>
        """
        with open(xml_path, "wb") as f:
            f.write(sample_xml)

        ofac_res = sync_ofac_xml(db, xml_path, apply=True)
        assert ofac_res["parsed_digital_currency_records"] == 2, f"Expected 2 (Tornado blocked), got {ofac_res}"
        assert ofac_res["applied_inserts"] == 2

        gb_records = [
            {
                "chain": "ethereum",
                "address": "0x2222222222222222222222222222222222222222",
                "label": "FBI PSA Test Advisory Address",
                "entity": "FBI Advisory Test Subject",
                "source_url": "https://www.fbi.gov/news/press-releases/test-advisory",
                "evidence_excerpt": "Official FBI public service announcement listing verified exploit address.",
                "effective_date_utc": "2026-02-26T00:00:00Z",
                "reviewer": "Lucy Li",
                "confidence": 0.92,
            },
            {
                "chain": "bsc",
                "address": "0x3333333333333333333333333333333333333333",
                "label": "Unverified Blog Rumor",
                "entity": "Unknown",
                "source_url": "https://random-crypto-blog.example/rumor",
                "evidence_excerpt": "Unverified rumor from third-party blog post.",
                "effective_date_utc": "2026-11-25T00:00:00Z",
                "reviewer": "Auto",
            },
        ]
        gb_res = ingest_grade_b_advisory(db, gb_records, source_file="self_test", apply=True)
        assert gb_res["accepted_grade_b"] == 1
        assert gb_res["quarantined_invalid"] == 1

        store = VectorLabelStore(db)
        try:
            counts = store.counts()
            assert counts["Grade-A_active"] == 2
            assert counts["Grade-B_active"] == 1
            assert counts["quarantine"] == 1
            # Confirm Grade-B did NOT leak into Grade-A and quarantined address is NOT returned on lookup
            hits_q = store.lookup("0x3333333333333333333333333333333333333333", chain="bsc")
            assert all(len(v) == 0 for v in hits_q.values())
        finally:
            store.close()
        return {"self_test": "PASS", "ofac_sync": ofac_res, "grade_b_ingest": gb_res, "db_counts": counts}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Vector (SG) Official Grade-A OFAC Sync & Grade-B LE Loader")
    parser.add_argument("--db", default="data/vector_labels_v1.sqlite", help="Vector label SQLite DB path")
    parser.add_argument("--ofac-xml", help="Path to local sdn.xml OR 'live' to fetch treasury.gov/ofac/downloads/sdn.xml")
    parser.add_argument("--grade-b-json", help="Path to JSON list of official FBI/DOJ Grade-B records")
    parser.add_argument("--apply", action="store_true", help="Persist validated writes (default: dry-run)")
    parser.add_argument("--self-test", action="store_true", help="Run isolated self-test suite")
    args = parser.parse_args()

    if args.self_test:
        print(json.dumps(run_self_test(), indent=2))
        return

    out: Dict[str, Any] = {}
    if args.ofac_xml:
        out["ofac_sync"] = sync_ofac_xml(args.db, args.ofac_xml, apply=args.apply)
    if args.grade_b_json:
        with open(args.grade_b_json, "r", encoding="utf-8") as f:
            recs = json.load(f)
        out["grade_b_ingest"] = ingest_grade_b_advisory(
            args.db, recs, source_file=os.path.basename(args.grade_b_json), apply=args.apply
        )
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
