#!/usr/bin/env python3
"""Vector (SG) — Label Specification v1.0 Compliance Validator & Quarantine Splitter.

Enforces label_spec_v1.md (8 mandatory provenance fields + 4-tier evidence grade isolation):
  1. source_url
  2. evidence_excerpt (>= 10 chars, no vague placeholders)
  3. chain (explicit supported chain enum; forbids 'any' or blank)
  4. retrieved_at_utc (ISO-8601 UTC timestamp)
  5. evidence_grade (Grade-A | Grade-B | Grade-C | Grade-D)
  6. confidence (float in [0, 1]; Grade-D capped <= 0.85)
  7. reviewer (non-empty reviewer or verified sync pipeline ID)
  8. status (active | disputed | revoked | expired)

Records failing ANY rule are routed to QUARANTINE with explicit missing/violation reasons.

Usage:
  python3 auto_tracer/validate_labels.py \
    --input /Users/orange/Documents/Agents/OnchainInvestigator/data/labels/external_labels.json \
    --input /Users/orange/Documents/Agents/OnchainInvestigator/data/labels/etherscan_labels.json
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple

VALID_CHAINS = {
    "bsc", "ethereum", "eth", "opbnb", "polygon", "arbitrum", "optimism",
    "base", "avalanche", "tron", "solana", "bitcoin", "btc", "trx",
    "litecoin", "ltc", "monero", "xmr", "dash", "zcash", "zec",
    "dogecoin", "doge", "bch", "etc", "btg", "xvg",
}
VALID_GRADES = {"Grade-A", "Grade-B", "Grade-C", "Grade-D"}
VALID_STATUS = {"active", "disputed", "revoked", "expired"}
ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
URL_RE = re.compile(r"^(https?://|internal://).+")
VAGUE_EXCERPTS = {"公开情报", "public", "unknown", "n/a", "none", "tbd"}


def validate_record(rec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors: List[str] = []

    addr = str(rec.get("address") or "").strip()
    if not addr:
        errors.append("missing:address")

    src_url = str(rec.get("source_url") or "").strip()
    if not src_url or not URL_RE.match(src_url):
        errors.append("missing_or_invalid:source_url")

    excerpt = str(rec.get("evidence_excerpt") or "").strip()
    if len(excerpt) < 10 or excerpt.lower() in VAGUE_EXCERPTS:
        errors.append("missing_or_weak:evidence_excerpt")

    chain = str(rec.get("chain") or "").strip().lower()
    if not chain or chain == "any" or chain not in VALID_CHAINS:
        errors.append("missing_or_invalid:chain")

    ret = str(rec.get("retrieved_at_utc") or "").strip()
    if not ret or not ISO_UTC_RE.match(ret):
        errors.append("missing_or_invalid:retrieved_at_utc")

    grade = str(rec.get("evidence_grade") or "").strip()
    if grade not in VALID_GRADES:
        errors.append("missing_or_invalid:evidence_grade")

    conf = rec.get("confidence")
    if conf is None or not isinstance(conf, (int, float)) or not (0.0 <= float(conf) <= 1.0):
        errors.append("missing_or_invalid:confidence")
    elif grade == "Grade-D" and float(conf) > 0.85:
        errors.append("grade_d_confidence_exceeds_0.85")

    reviewer = str(rec.get("reviewer") or "").strip()
    if not reviewer:
        errors.append("missing:reviewer")

    status = str(rec.get("status") or "").strip().lower()
    if status not in VALID_STATUS:
        errors.append("missing_or_invalid:status")

    return (len(errors) == 0), errors


def load_records(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        if path.endswith(".jsonl"):
            return [json.loads(line) for line in f if line.strip()]
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("labels"), list):
        return data["labels"]
    raise ValueError(f"Unsupported label file format in {path}")


def audit_file(path: str) -> Dict[str, Any]:
    records = load_records(path)
    passed = 0
    quarantined = 0
    reason_counts: Counter = Counter()
    grade_counts: Counter = Counter()
    sample_failures: List[Dict[str, Any]] = []

    for rec in records:
        ok, errs = validate_record(rec)
        if ok:
            passed += 1
            grade_counts[rec["evidence_grade"]] += 1
        else:
            quarantined += 1
            for e in errs:
                reason_counts[e] += 1
            if len(sample_failures) < 3:
                sample_failures.append({
                    "address": rec.get("address"),
                    "source": rec.get("source"),
                    "errors": errs,
                })

    return {
        "file": path,
        "total": len(records),
        "passed_production": passed,
        "quarantined": quarantined,
        "grades_passed": dict(grade_counts),
        "top_missing_or_violations": reason_counts.most_common(10),
        "sample_quarantined": sample_failures,
    }


def main():
    parser = argparse.ArgumentParser(description="Validate label datasets against Vector (SG) Label Spec v1.0.")
    parser.add_argument("--input", action="append", required=True, help="Path to label JSON or JSONL file")
    parser.add_argument("--report-out", help="Optional path to save JSON audit report")
    args = parser.parse_args()

    results = []
    for p in args.input:
        if not os.path.exists(p):
            print(f"ERROR: File not found: {p}", file=sys.stderr)
            sys.exit(1)
        res = audit_file(p)
        results.append(res)
        print(f"\n=== LABEL SPEC v1.0 AUDIT: {os.path.basename(p)} ===")
        print(f"Total records      : {res['total']}")
        print(f"Passed (Prod-ready): {res['passed_production']}")
        print(f"Routed QUARANTINE  : {res['quarantined']}")
        print("Violation breakdown:")
        for reason, cnt in res["top_missing_or_violations"]:
            print(f"  - {reason}: {cnt}")

    if args.report_out:
        os.makedirs(os.path.dirname(args.report_out) or ".", exist_ok=True)
        with open(args.report_out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\nSaved JSON audit report to: {args.report_out}")


if __name__ == "__main__":
    main()
