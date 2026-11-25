"""Intra-transaction flash-loan & wash-swap net-flow collapser for Vector (SG) auto-tracer.

Engineering crystallization from BLIND-002 (Level Finance BSC 2023-05-01):
In DeFi exploits, a single transaction can contain 100+ intra-tx ping-pong swaps
(e.g., WBNB <-> USDT repeated 40x via a 300 WBNB flash loan), inflating gross
edge volume to $28M+ while net stolen value is dramatically smaller.

This module NEVER deletes raw edges (100% audit retention). Instead, for each tx:
  1. Computes per-(address, asset) net balance delta across all non-filtered transfers;
  2. Identifies paired flash-loan borrow/repay legs (same counterparty pair, equal/near-equal
     outflow & return within the same tx);
  3. Identifies high-frequency bidirectional wash-swap pairs (A <-> B >= 4 transfers in one tx)
     and computes exact net economic delta alongside gross volume so analysts & counsel
     never confuse wash-swap turnover with stolen loss.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Tuple


def analyze_tx_net_flows(rows: List[dict]) -> Dict[str, Any]:
    """Analyzes kept edges grouped by tx_hash to detect wash-loops & compute net asset deltas."""
    by_tx: Dict[str, List[dict]] = defaultdict(list)
    for r in rows:
        if r.get("status") in ("kept", "breakpoint"):
            by_tx[r["tx_hash"]].append(r)

    tx_summaries: Dict[str, Any] = {}
    total_wash_edges = 0
    wash_edge_keys = set()

    for txh, tx_rows in by_tx.items():
        # 1. Detect bidirectional pair loops within the same tx
        pair_counts: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
        net_deltas: Dict[Tuple[str, str], int] = defaultdict(int)
        asset_symbol: Dict[str, str] = {}
        gross_by_asset: Dict[str, int] = defaultdict(int)

        for r in tx_rows:
            frm = r["from"]
            to = r["to"]
            asset = r["asset"]
            amt = int(r["amount_raw"])
            if r.get("symbol"):
                asset_symbol[asset] = r["symbol"]
            pair_key = tuple(sorted((frm, to)))
            pair_counts[pair_key].append(r)
            net_deltas[(frm, asset)] -= amt
            net_deltas[(to, asset)] += amt
            gross_by_asset[asset] += amt

        wash_pairs = []
        flash_loan_pairs = []
        for (a, b), p_rows in pair_counts.items():
            # Check directionality
            a_to_b = [x for x in p_rows if x["from"] == a and x["to"] == b]
            b_to_a = [x for x in p_rows if x["from"] == b and x["to"] == a]
            if a_to_b and b_to_a and len(p_rows) >= 6:
                # High-frequency intra-tx ping-pong / wash-swap loop
                wash_pairs.append({
                    "pair": [a, b],
                    "edge_count": len(p_rows),
                    "a_to_b_count": len(a_to_b),
                    "b_to_a_count": len(b_to_a),
                    "assets": sorted({asset_symbol.get(x["asset"], x["asset"]) for x in p_rows}),
                })
                for x in p_rows:
                    wash_edge_keys.add((x["tx_hash"], x.get("log_index")))
                total_wash_edges += len(p_rows)
            elif len(a_to_b) == 1 and len(b_to_a) == 1 and a_to_b[0]["asset"] == b_to_a[0]["asset"]:
                # Classic same-asset flash-loan borrow & repay pair
                v1 = int(a_to_b[0]["amount_raw"])
                v2 = int(b_to_a[0]["amount_raw"])
                hi = max(v1, v2)
                if hi > 0 and abs(v1 - v2) / hi <= 0.01:
                    asset = a_to_b[0]["asset"]
                    flash_loan_pairs.append({
                        "pair": [a, b],
                        "asset": asset_symbol.get(asset, asset),
                        "borrowed_raw": str(min(v1, v2)),
                        "repaid_raw": str(max(v1, v2)),
                        "fee_raw": str(abs(v1 - v2)),
                    })

        # Build clean non-zero net inflows/outflows per (address, asset)
        net_positions = []
        for (addr, asset), delta in sorted(net_deltas.items(), key=lambda kv: abs(kv[1]), reverse=True):
            if delta == 0:
                continue
            net_positions.append({
                "address": addr,
                "asset": asset,
                "symbol": asset_symbol.get(asset),
                "net_delta_raw": str(delta),
                "net_delta_human_18": round(delta / 1e18, 6),
                "direction": "NET_INFLOW" if delta > 0 else "NET_OUTFLOW",
            })

        tx_summaries[txh] = {
            "tx_hash": txh,
            "kept_edge_count": len(tx_rows),
            "wash_loop_pairs": wash_pairs,
            "flash_loan_pairs": flash_loan_pairs,
            "net_positions": net_positions[:20],
            "gross_by_asset": {
                asset_symbol.get(k, k): round(v / 1e18, 4) for k, v in gross_by_asset.items()
            },
        }

    return {
        "tx_count_analyzed": len(tx_summaries),
        "total_wash_loop_edges_flagged": total_wash_edges,
        "wash_edge_keys": sorted(list(wash_edge_keys)),
        "by_tx": tx_summaries,
    }
