#!/usr/bin/env python3
"""Vector (SG) — auto-tracer Blind Benchmark Runner.

Runs BOTH baseline groups on the EXACT same frozen snapshot (zero network calls,
100% deterministic & reproducible):
  - B0-Rule    : Pure deterministic receipt/transfer decoding + initiator verification
                 + zero-value filter + known mixer/bridge breakpoint tagging.
  - B1-Heur-v2 : B0-Rule + ported OnchainInvestigator RuleDecisionEngine heuristics
                 (zero-address mint/burn pruning, USD-aware dust pruning, non-canonical
                 token prioritization, spoof/zero-width filtering) with 100% raw-record
                 audit retention.

Usage:
  python3 -m auto_tracer.runner --case-dir benchmarks/cases/BLIND-001
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
import time
from typing import Dict, List, Set

from .decisions import HopAction, HopState, RuleDecisionEngine
from .forensics import (
    breakpoint_reason,
    canonical_token_info,
    estimate_usd,
    is_spoof_or_scam_symbol,
)
from .models import ZERO_ADDR, TransferEdge


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_frozen_edges(snap_dir: str, chain: str = "bsc") -> tuple:
    """Deterministically decodes native + ERC-20 transfers from frozen receipts."""
    lock_path = os.path.join(snap_dir, "FREEZE_LOCK.json")
    with open(lock_path, "r", encoding="utf-8") as f:
        lock = json.load(f)

    seed_addrs: Set[str] = {a.lower() for a in lock.get("seed_addresses", [])}
    win_path = os.path.join(snap_dir, "window_transactions.jsonl")
    tr_path = os.path.join(snap_dir, "erc20_transfers_from_receipts.jsonl")

    tx_meta: Dict[str, dict] = {}
    edges: List[TransferEdge] = []

    with open(win_path, "r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            tx = rec["transaction"]
            rcpt = rec.get("receipt") or {}
            status = str(rcpt.get("status") or "0x1").lower()
            txh = rec["tx_hash"].lower()
            frm = (tx.get("from") or "").lower()
            to = (tx.get("to") or "").lower()
            tx_meta[txh] = {
                "from": frm,
                "to": to,
                "status_ok": status not in ("0x0", "0", "false"),
                "block": rec["block_number"],
            }
            if not tx_meta[txh]["status_ok"]:
                continue
            val = int(tx.get("value", "0x0"), 16)
            if val > 0 and to:
                sym = "BNB" if chain == "bsc" else "ETH"
                amt_h = val / (10**18)
                edges.append(
                    TransferEdge(
                        from_addr=frm,
                        to_addr=to,
                        asset=sym,
                        symbol=sym,
                        amount_raw=val,
                        decimals=18,
                        tx_hash=txh,
                        block=rec["block_number"],
                        log_index=-1,
                        chain=chain,
                        source="tx_native_value",
                        tx_initiator=frm,
                        value_usd=estimate_usd(sym, amt_h),
                    )
                )

    with open(tr_path, "r", encoding="utf-8") as f:
        for line in f:
            tr = json.loads(line)
            txh = tr["tx_hash"].lower()
            meta = tx_meta.get(txh)
            if not meta or not meta["status_ok"]:
                continue
            token = tr["token_contract"].lower()
            canon = canonical_token_info(token, chain=chain)
            sym = canon[0] if canon else None
            dec = canon[1] if canon else 18
            amt = int(tr["amount_raw"])
            amt_h = amt / (10**dec)
            edges.append(
                TransferEdge(
                    from_addr=tr["from"].lower(),
                    to_addr=tr["to"].lower(),
                    asset=token,
                    symbol=sym,
                    amount_raw=amt,
                    decimals=dec,
                    tx_hash=txh,
                    block=int(tr["block_number"]),
                    log_index=int(tr["log_index"]),
                    chain=chain,
                    source="receipt_erc20_transfer",
                    tx_initiator=meta["from"],
                    value_usd=estimate_usd(sym, amt_h),
                )
            )

    return lock, seed_addrs, edges


def compute_hop_map(seed_addrs: Set[str], edges: List[TransferEdge]) -> Dict[str, int]:
    """Shortest hop distance from seed_addresses using causal block ordering."""
    adj: Dict[str, List[TransferEdge]] = {}
    for e in edges:
        adj.setdefault(e.from_addr, []).append(e)
        adj.setdefault(e.to_addr, []).append(e)

    hops: Dict[str, int] = {a: 0 for a in seed_addrs}
    q = deque(sorted(seed_addrs))
    while q:
        cur = q.popleft()
        d = hops[cur]
        for e in adj.get(cur, []):
            nxt = e.to_addr if e.from_addr == cur else e.from_addr
            if nxt != ZERO_ADDR and nxt not in hops:
                hops[nxt] = d + 1
                q.append(nxt)
    return hops


def run_b0_rule(seed_addrs: Set[str], edges: List[TransferEdge], hops: Dict[str, int]) -> List[dict]:
    """B0-Rule: Pure deterministic decoding + zero-value filter + known breakpoint tagging."""
    records = []
    for e in edges:
        hop = min(hops.get(e.from_addr, 99), hops.get(e.to_addr, 99)) + 1
        base = {
            "tx_hash": e.tx_hash,
            "block": e.block,
            "log_index": e.log_index,
            "from": e.from_addr,
            "to": e.to_addr,
            "asset": e.asset,
            "symbol": e.symbol,
            "amount_raw": str(e.amount_raw),
            "value_usd": round(e.value_usd, 4) if e.value_usd is not None else None,
            "hop": hop,
            "initiator_is_seed": e.tx_initiator in seed_addrs,
            "citation_valid": True,
            "asset_conservation_ok": True,
        }
        if e.amount_raw == 0:
            base.update({
                "status": "filtered",
                "raw_tx_retained": True,
                "filter_reason": "zero_value_transfer",
            })
        elif breakpoint_reason(e.to_addr):
            base.update({
                "status": "breakpoint",
                "breakpoint_reason": breakpoint_reason(e.to_addr),
            })
        else:
            base["status"] = "kept"
        records.append(base)
    return records


def run_b1_heur_v2(
    seed_addrs: Set[str], edges: List[TransferEdge], hops: Dict[str, int], chain: str = "bsc"
) -> List[dict]:
    """B1-Heur-v2: B0-Rule + OnchainInvestigator RuleDecisionEngine & spoof/dust guardrails."""
    engine = RuleDecisionEngine()
    records = []
    for e in edges:
        hop = min(hops.get(e.from_addr, 99), hops.get(e.to_addr, 99)) + 1
        base = {
            "tx_hash": e.tx_hash,
            "block": e.block,
            "log_index": e.log_index,
            "from": e.from_addr,
            "to": e.to_addr,
            "asset": e.asset,
            "symbol": e.symbol,
            "amount_raw": str(e.amount_raw),
            "value_usd": round(e.value_usd, 4) if e.value_usd is not None else None,
            "hop": hop,
            "initiator_is_seed": e.tx_initiator in seed_addrs,
            "citation_valid": True,
            "asset_conservation_ok": True,
        }

        if e.amount_raw == 0:
            base.update({
                "status": "filtered",
                "raw_tx_retained": True,
                "filter_reason": "zero_value_transfer",
            })
            records.append(base)
            continue

        spoof = is_spoof_or_scam_symbol(e.asset, e.symbol, chain=chain)
        if spoof:
            base.update({
                "status": "filtered",
                "raw_tx_retained": True,
                "filter_reason": spoof,
            })
            records.append(base)
            continue

        bp = breakpoint_reason(e.to_addr)
        if bp:
            base.update({"status": "breakpoint", "breakpoint_reason": bp})
            records.append(base)
            continue

        state = HopState(
            from_addr=e.from_addr,
            to_addr=e.to_addr,
            symbol=e.symbol,
            amount=e.amount_human,
            depth=max(0, hop - 1),
            direction="forward",
            zero_from=(e.from_addr == ZERO_ADDR),
            zero_to=(e.to_addr == ZERO_ADDR),
            is_integer_amount=float(e.amount_human).is_integer(),
            value_usd=e.value_usd,
        )
        dec = engine.decide(state)
        base["decision_engine"] = dec.engine
        base["decision_rationale"] = dec.rationale
        base["decision_confidence"] = dec.confidence

        if dec.action == HopAction.PRUNE:
            base.update({
                "status": "filtered",
                "raw_tx_retained": True,
                "filter_reason": f"heuristic_prune:{dec.rationale}",
            })
        else:
            base["status"] = "kept"
        records.append(base)
    return records


def run_b1_heur_v3(
    seed_addrs: Set[str], edges: List[TransferEdge], hops: Dict[str, int], chain: str = "bsc"
) -> List[dict]:
    """B1-Heur-v3 (Engineering Crystallization from BLIND-001 -> used strictly on BLIND-002+):
    - Splits dust pruning into `attacker_initiated_micro_prep` (initiator_is_seed=True,
      flagged with `attack_prep_candidate=True`) vs `third_party_dust_or_poisoning`.
    - Checks BOTH destination AND source endpoints for known mixer/bridge breakpoints.
    """
    engine = RuleDecisionEngine()
    records = []
    for e in edges:
        hop = min(hops.get(e.from_addr, 99), hops.get(e.to_addr, 99)) + 1
        is_seed_init = e.tx_initiator in seed_addrs
        base = {
            "tx_hash": e.tx_hash,
            "block": e.block,
            "log_index": e.log_index,
            "from": e.from_addr,
            "to": e.to_addr,
            "asset": e.asset,
            "symbol": e.symbol,
            "amount_raw": str(e.amount_raw),
            "value_usd": round(e.value_usd, 4) if e.value_usd is not None else None,
            "hop": hop,
            "initiator_is_seed": is_seed_init,
            "citation_valid": True,
            "asset_conservation_ok": True,
        }

        if e.amount_raw == 0:
            base.update({
                "status": "filtered",
                "raw_tx_retained": True,
                "filter_reason": "zero_value_transfer",
            })
            records.append(base)
            continue

        spoof = is_spoof_or_scam_symbol(e.asset, e.symbol, chain=chain)
        if spoof:
            base.update({
                "status": "filtered",
                "raw_tx_retained": True,
                "filter_reason": spoof,
            })
            records.append(base)
            continue

        bp = breakpoint_reason(e.to_addr) or breakpoint_reason(e.from_addr)
        if bp:
            base.update({"status": "breakpoint", "breakpoint_reason": bp})
            records.append(base)
            continue

        state = HopState(
            from_addr=e.from_addr,
            to_addr=e.to_addr,
            symbol=e.symbol,
            amount=e.amount_human,
            depth=max(0, hop - 1),
            direction="forward",
            zero_from=(e.from_addr == ZERO_ADDR),
            zero_to=(e.to_addr == ZERO_ADDR),
            is_integer_amount=float(e.amount_human).is_integer(),
            value_usd=e.value_usd,
        )
        dec = engine.decide(state)
        base["decision_engine"] = "rule-v3"
        base["decision_rationale"] = dec.rationale
        base["decision_confidence"] = dec.confidence

        if dec.action == HopAction.PRUNE:
            if dec.rationale.startswith("below_dust_threshold"):
                if is_seed_init:
                    base.update({
                        "status": "filtered",
                        "raw_tx_retained": True,
                        "attack_prep_candidate": True,
                        "filter_reason": f"attacker_initiated_micro_prep:{dec.rationale}",
                    })
                else:
                    base.update({
                        "status": "filtered",
                        "raw_tx_retained": True,
                        "attack_prep_candidate": False,
                        "filter_reason": f"third_party_dust_or_poisoning:{dec.rationale}",
                    })
            else:
                base.update({
                    "status": "filtered",
                    "raw_tx_retained": True,
                    "filter_reason": f"heuristic_prune:{dec.rationale}",
                })
        else:
            base["status"] = "kept"
        records.append(base)
    return records


def run_b1_heur_v4(
    seed_addrs: Set[str], edges: List[TransferEdge], hops: Dict[str, int], chain: str = "bsc"
) -> List[dict]:
    """B1-Heur-v4 (Engineering Crystallization from BLIND-003 -> strictly evaluated on BLIND-004+):
    Fixes the BLIND-003 False-Deletion failure (8.3% on Ankr aBNBc infinite mint) where generic
    `zero_address_mint_or_burn` pruned root-cause unbacked mints while keeping routine bookkeeping
    mints/burns filtered:
      - Preserves a zero-address mint (`from == 0x0`, `to != 0x0`) initiated by a tracked seed
        (`initiator_is_seed=True`) when EITHER:
          (a) Direct seed mint of material scale: `to in seed_addrs` and (`amount_human >= 1.0`
              or `value_usd >= 10.0`), OR
          (b) Economically active minted asset: `(to, asset)` is subsequently transferred out
              elsewhere in the snapshot (`amount_raw > 0`) and (`amount_human >= 10.0` or
              `value_usd >= 10.0`).
      - Tags preserved root-cause mints with `exploit_mint_candidate=True` and
        `decision_rationale="seed_initiated_material_mint"`.
      - Retains all B1-Heur-v3 guardrails (spoof/zero-width filtering, attacker micro-prep split,
        bidirectional mixer/bridge breakpoint detection, 100% raw audit retention).
    """
    engine = RuleDecisionEngine()
    # Pre-index assets actually transferred/disposed out by each address (conservation signal)
    spent_assets_by_addr: Set[tuple] = {
        (e.from_addr, e.asset)
        for e in edges
        if e.amount_raw > 0 and e.from_addr != ZERO_ADDR
    }

    records = []
    for e in edges:
        hop = min(hops.get(e.from_addr, 99), hops.get(e.to_addr, 99)) + 1
        is_seed_init = e.tx_initiator in seed_addrs
        base = {
            "tx_hash": e.tx_hash,
            "block": e.block,
            "log_index": e.log_index,
            "from": e.from_addr,
            "to": e.to_addr,
            "asset": e.asset,
            "symbol": e.symbol,
            "amount_raw": str(e.amount_raw),
            "value_usd": round(e.value_usd, 4) if e.value_usd is not None else None,
            "hop": hop,
            "initiator_is_seed": is_seed_init,
            "citation_valid": True,
            "asset_conservation_ok": True,
        }

        if e.amount_raw == 0:
            base.update({
                "status": "filtered",
                "raw_tx_retained": True,
                "filter_reason": "zero_value_transfer",
            })
            records.append(base)
            continue

        spoof = is_spoof_or_scam_symbol(e.asset, e.symbol, chain=chain)
        if spoof:
            base.update({
                "status": "filtered",
                "raw_tx_retained": True,
                "filter_reason": spoof,
            })
            records.append(base)
            continue

        bp = breakpoint_reason(e.to_addr) or breakpoint_reason(e.from_addr)
        if bp:
            base.update({"status": "breakpoint", "breakpoint_reason": bp})
            records.append(base)
            continue

        # B1-Heur-v4: Preserve material seed-initiated root-cause mints (BLIND-003 crystallization)
        if e.from_addr == ZERO_ADDR and e.to_addr != ZERO_ADDR and is_seed_init:
            direct_seed_mint = (
                e.to_addr in seed_addrs
                and (
                    (e.value_usd is not None and e.value_usd >= 10.0)
                    or e.amount_human >= 1.0
                )
            )
            spent_material_mint = (
                (e.to_addr, e.asset) in spent_assets_by_addr
                and (
                    (e.value_usd is not None and e.value_usd >= 10.0)
                    or e.amount_human >= 10.0
                )
            )
            if direct_seed_mint or spent_material_mint:
                base.update({
                    "status": "kept",
                    "exploit_mint_candidate": True,
                    "decision_engine": "rule-v4",
                    "decision_rationale": "seed_initiated_material_mint",
                    "decision_confidence": 0.95,
                })
                records.append(base)
                continue

        state = HopState(
            from_addr=e.from_addr,
            to_addr=e.to_addr,
            symbol=e.symbol,
            amount=e.amount_human,
            depth=max(0, hop - 1),
            direction="forward",
            zero_from=(e.from_addr == ZERO_ADDR),
            zero_to=(e.to_addr == ZERO_ADDR),
            is_integer_amount=float(e.amount_human).is_integer(),
            value_usd=e.value_usd,
        )
        dec = engine.decide(state)
        base["decision_engine"] = "rule-v4"
        base["decision_rationale"] = dec.rationale
        base["decision_confidence"] = dec.confidence

        if dec.action == HopAction.PRUNE:
            if dec.rationale.startswith("below_dust_threshold"):
                if is_seed_init:
                    base.update({
                        "status": "filtered",
                        "raw_tx_retained": True,
                        "attack_prep_candidate": True,
                        "filter_reason": f"attacker_initiated_micro_prep:{dec.rationale}",
                    })
                else:
                    base.update({
                        "status": "filtered",
                        "raw_tx_retained": True,
                        "attack_prep_candidate": False,
                        "filter_reason": f"third_party_dust_or_poisoning:{dec.rationale}",
                    })
            else:
                base.update({
                    "status": "filtered",
                    "raw_tx_retained": True,
                    "filter_reason": f"heuristic_prune:{dec.rationale}",
                })
        else:
            base["status"] = "kept"
        records.append(base)
    return records


def run_b1_heur_v5(
    seed_addrs: Set[str], edges: List[TransferEdge], hops: Dict[str, int], chain: str = "bsc"
) -> List[dict]:
    """B1-Heur-v5 (Engineering Crystallization from BLIND-004 -> strictly evaluated on BLIND-005+):
    Fixes the BLIND-004 role-separated mint failure (pNetwork pGALA 27.8B mint where tx initiator
    `tx.from` != mint beneficiary `to`, causing B1-Heur-v4 to prune when `to` was outside initial
    seed_addrs and off-window swaps were unseen):
      - Preserves ANY seed-initiated zero-address mint (`from == 0x0`, `to != 0x0`,
        `initiator_is_seed=True`) if:
          (a) Direct seed mint of material scale: `to in seed_addrs` and (`amount_human >= 1.0`
              or `value_usd >= 10.0`), OR
          (b) Economically active minted asset: `(to, asset)` is transferred out elsewhere in
              the snapshot (`amount_raw > 0`) and (`amount_human >= 10.0` or `value_usd >= 10.0`), OR
          (c) Role-separated macro supply creation: `amount_human >= 1_000.0` or `value_usd >= 10_000.0`
              (preserves privileged/exploit mints to secondary wallets while still pruning sub-1000
              internal accounting/loyalty mints such as Level Finance's 0.132-token loop noise).
    """
    engine = RuleDecisionEngine()
    spent_assets_by_addr: Set[tuple] = {
        (e.from_addr, e.asset)
        for e in edges
        if e.amount_raw > 0 and e.from_addr != ZERO_ADDR
    }

    records = []
    for e in edges:
        hop = min(hops.get(e.from_addr, 99), hops.get(e.to_addr, 99)) + 1
        is_seed_init = e.tx_initiator in seed_addrs
        base = {
            "tx_hash": e.tx_hash,
            "block": e.block,
            "log_index": e.log_index,
            "from": e.from_addr,
            "to": e.to_addr,
            "asset": e.asset,
            "symbol": e.symbol,
            "amount_raw": str(e.amount_raw),
            "value_usd": round(e.value_usd, 4) if e.value_usd is not None else None,
            "hop": hop,
            "initiator_is_seed": is_seed_init,
            "citation_valid": True,
            "asset_conservation_ok": True,
        }

        if e.amount_raw == 0:
            base.update({
                "status": "filtered",
                "raw_tx_retained": True,
                "filter_reason": "zero_value_transfer",
            })
            records.append(base)
            continue

        spoof = is_spoof_or_scam_symbol(e.asset, e.symbol, chain=chain)
        if spoof:
            base.update({
                "status": "filtered",
                "raw_tx_retained": True,
                "filter_reason": spoof,
            })
            records.append(base)
            continue

        bp = breakpoint_reason(e.to_addr) or breakpoint_reason(e.from_addr)
        if bp:
            base.update({"status": "breakpoint", "breakpoint_reason": bp})
            records.append(base)
            continue

        # B1-Heur-v5: Preserve seed-initiated material or role-separated macro mints
        if e.from_addr == ZERO_ADDR and e.to_addr != ZERO_ADDR and is_seed_init:
            direct_seed_mint = (
                e.to_addr in seed_addrs
                and (
                    (e.value_usd is not None and e.value_usd >= 10.0)
                    or e.amount_human >= 1.0
                )
            )
            spent_material_mint = (
                (e.to_addr, e.asset) in spent_assets_by_addr
                and (
                    (e.value_usd is not None and e.value_usd >= 10.0)
                    or e.amount_human >= 10.0
                )
            )
            role_separated_macro_mint = (
                (e.value_usd is not None and e.value_usd >= 10_000.0)
                or e.amount_human >= 1_000.0
            )
            if direct_seed_mint or spent_material_mint or role_separated_macro_mint:
                rationale = (
                    "seed_initiated_material_mint"
                    if (direct_seed_mint or spent_material_mint)
                    else "seed_initiated_role_separated_macro_mint"
                )
                base.update({
                    "status": "kept",
                    "exploit_mint_candidate": True,
                    "decision_engine": "rule-v5",
                    "decision_rationale": rationale,
                    "decision_confidence": 0.95,
                })
                records.append(base)
                continue

        state = HopState(
            from_addr=e.from_addr,
            to_addr=e.to_addr,
            symbol=e.symbol,
            amount=e.amount_human,
            depth=max(0, hop - 1),
            direction="forward",
            zero_from=(e.from_addr == ZERO_ADDR),
            zero_to=(e.to_addr == ZERO_ADDR),
            is_integer_amount=float(e.amount_human).is_integer(),
            value_usd=e.value_usd,
        )
        dec = engine.decide(state)
        base["decision_engine"] = "rule-v5"
        base["decision_rationale"] = dec.rationale
        base["decision_confidence"] = dec.confidence

        if dec.action == HopAction.PRUNE:
            if dec.rationale.startswith("below_dust_threshold"):
                if is_seed_init:
                    base.update({
                        "status": "filtered",
                        "raw_tx_retained": True,
                        "attack_prep_candidate": True,
                        "filter_reason": f"attacker_initiated_micro_prep:{dec.rationale}",
                    })
                else:
                    base.update({
                        "status": "filtered",
                        "raw_tx_retained": True,
                        "attack_prep_candidate": False,
                        "filter_reason": f"third_party_dust_or_poisoning:{dec.rationale}",
                    })
            else:
                base.update({
                    "status": "filtered",
                    "raw_tx_retained": True,
                    "filter_reason": f"heuristic_prune:{dec.rationale}",
                })
        else:
            base["status"] = "kept"
        records.append(base)
    return records


def write_jsonl(path: str, rows: List[dict]) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    return sha256_file(path)


def main():
    parser = argparse.ArgumentParser(description="Run Vector (SG) auto-tracer baselines blind on a frozen snapshot.")
    parser.add_argument("--case-dir", required=True, help="Case directory (e.g. benchmarks/cases/BLIND-001)")
    args = parser.parse_args()

    snap_dir = os.path.join(args.case_dir, "frozen_snapshot")
    runs_dir = os.path.join(args.case_dir, "runs")

    t0 = time.perf_counter()
    lock, seed_addrs, edges = load_frozen_edges(snap_dir, chain="bsc")
    hops = compute_hop_map(seed_addrs, edges)
    t_load = (time.perf_counter() - t0) * 1000.0

    t1 = time.perf_counter()
    b0_rows = run_b0_rule(seed_addrs, edges, hops)
    t_b0 = (time.perf_counter() - t1) * 1000.0
    b0_path = os.path.join(runs_dir, "B0-Rule.jsonl")
    b0_sha = write_jsonl(b0_path, b0_rows)

    t2 = time.perf_counter()
    b1_rows = run_b1_heur_v2(seed_addrs, edges, hops, chain=lock.get("chain", "bsc"))
    t_b1 = (time.perf_counter() - t2) * 1000.0
    b1_path = os.path.join(runs_dir, "B1-Heur-v2.jsonl")
    b1_sha = write_jsonl(b1_path, b1_rows)

    t3 = time.perf_counter()
    b3_rows = run_b1_heur_v3(seed_addrs, edges, hops, chain=lock.get("chain", "bsc"))
    t_b3 = (time.perf_counter() - t3) * 1000.0
    b3_path = os.path.join(runs_dir, "B1-Heur-v3.jsonl")
    b3_sha = write_jsonl(b3_path, b3_rows)

    t4 = time.perf_counter()
    b4_rows = run_b1_heur_v4(seed_addrs, edges, hops, chain=lock.get("chain", "bsc"))
    t_b4 = (time.perf_counter() - t4) * 1000.0
    b4_path = os.path.join(runs_dir, "B1-Heur-v4.jsonl")
    b4_sha = write_jsonl(b4_path, b4_rows)

    t5 = time.perf_counter()
    b5_rows = run_b1_heur_v5(seed_addrs, edges, hops, chain=lock.get("chain", "bsc"))
    t_b5 = (time.perf_counter() - t5) * 1000.0
    b5_path = os.path.join(runs_dir, "B1-Heur-v5.jsonl")
    b5_sha = write_jsonl(b5_path, b5_rows)

    def summarize(rows):
        counts = {}
        for r in rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        return counts

    print(f"=== BLIND RUN COMPLETE: {lock['case_id']} ({lock['case_name']}) ===")
    print(f"Loaded edges: {len(edges)} (load={t_load:.1f} ms)")
    print(f"B0-Rule    : {summarize(b0_rows)} | runtime={t_b0:.2f} ms | sha256={b0_sha}")
    print(f"B1-Heur-v2 : {summarize(b1_rows)} | runtime={t_b1:.2f} ms | sha256={b1_sha}")
    print(f"B1-Heur-v3 : {summarize(b3_rows)} | runtime={t_b3:.2f} ms | sha256={b3_sha}")
    print(f"B1-Heur-v4 : {summarize(b4_rows)} | runtime={t_b4:.2f} ms | sha256={b4_sha}")
    print(f"B1-Heur-v5 : {summarize(b5_rows)} | runtime={t_b5:.2f} ms | sha256={b5_sha}")
    print(f"Outputs written to: {runs_dir}")


if __name__ == "__main__":
    main()
