"""Vector (SG) — Conservative Entity-Level Clustering Baseline with Anti-False-Merge Hub Firewall.

Implements Dimension 3 of benchmark.md ("Entity-Level Clustering", Phase 1–2):
  - Core objective: MINIMIZE FALSE MERGES (hard red line: 0.0% merges across shared hubs
    such as CEX hot wallets, DEX routers, cross-chain bridges, mixers, or token contracts).
  - Deterministic, auditable high-precision linking rules (all emitted strictly as
    Grade-D analytical hypotheses with confidence <= 0.85, NEVER promoted to Grade-A):
      1. `CONTRACT_DEPLOYER_LINK`       (conf=0.85): EOA deploys custom contract in tx
      2. `SAME_TX_EXPLOIT_CONTROLLER`   (conf=0.80): tx initiator invokes non-hub custom
         contract that sweeps funds directly back to tx initiator in the same tx
      3. `EXCLUSIVE_CONSOLIDATION_LINK` (conf=0.75): non-hub EOA A exclusively funds gas
         for fresh non-hub EOA B AND B sweeps assets directly to A (1-to-1 closed loop)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from .forensics import (
    BSC_CANONICAL_TOKENS,
    ETH_CANONICAL_TOKENS,
    KNOWN_BRIDGES,
    KNOWN_DEX_ROUTERS_BSC,
    KNOWN_MIXERS,
    PASSTHROUGH_CONTRACTS,
)
from .models import ZERO_ADDR

FIREWALL_CATEGORIES = {"cex_hot", "cex_deposit", "dex_router", "bridge", "mixer", "benign_contract"}


class UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        if x not in self.parent:
            self.parent[x] = x
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if ra < rb:
            self.parent[rb] = ra
        else:
            self.parent[ra] = rb


def is_hub_protected(
    addr: str,
    known_hubs: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Returns hub firewall reason if `addr` MUST NEVER be merged into a user/attacker cluster."""
    a = (addr or "").strip().lower()
    if not a or a == ZERO_ADDR:
        return "zero_address"
    if a in KNOWN_MIXERS:
        return f"mixer:{KNOWN_MIXERS[a]}"
    if a in KNOWN_BRIDGES:
        return f"bridge:{KNOWN_BRIDGES[a][0]}"
    if a in KNOWN_DEX_ROUTERS_BSC:
        return f"dex_router:{KNOWN_DEX_ROUTERS_BSC[a]}"
    if a in PASSTHROUGH_CONTRACTS:
        return f"passthrough:{PASSTHROUGH_CONTRACTS[a]}"
    if a in BSC_CANONICAL_TOKENS:
        return f"canonical_token:{BSC_CANONICAL_TOKENS[a][0]}"
    if a in ETH_CANONICAL_TOKENS:
        return f"canonical_token:{ETH_CANONICAL_TOKENS[a][0]}"
    if known_hubs and a in known_hubs:
        return f"store_hub:{known_hubs[a]}"
    return None


def cluster_entities_conservative(
    events: List[Dict[str, Any]],
    known_hubs: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Clusters addresses from structured tx/transfer events using conservative, auditable rules.

    Each event dict may contain:
      - `type`: "contract_deploy" | "tx_call_and_sweep" | "gas_fund_and_sweep" | "transfer"
      - `tx_hash`, `from`, `to`, `tx_initiator`, `contract_address`, `amount_raw`, `asset`
    """
    uf = UnionFind()
    links: List[Dict[str, Any]] = []
    firewall_blocks: List[Dict[str, Any]] = []
    all_addrs: Set[str] = set()

    # Track 1-to-1 gas funding and sweep pairs for EXCLUSIVE_CONSOLIDATION_LINK
    gas_funders: Dict[str, Set[str]] = {}
    sweep_targets: Dict[str, Set[str]] = {}

    for ev in events:
        etype = (ev.get("type") or "transfer").lower()
        fr = (ev.get("from") or "").lower()
        to = (ev.get("to") or "").lower()
        init = (ev.get("tx_initiator") or fr).lower()
        caddr = (ev.get("contract_address") or "").lower()

        for a in (fr, to, init, caddr):
            if a and a != ZERO_ADDR:
                all_addrs.add(a)
                uf.find(a)

        def try_link(a: str, b: str, rule: str, conf: float, tx_hash: str) -> None:
            if not a or not b or a == b:
                return
            hub_a = is_hub_protected(a, known_hubs)
            hub_b = is_hub_protected(b, known_hubs)
            if hub_a or hub_b:
                firewall_blocks.append({
                    "rule": rule,
                    "addr_a": a,
                    "addr_b": b,
                    "blocked_reason": hub_a or hub_b,
                    "tx_hash": tx_hash,
                })
                return
            uf.union(a, b)
            links.append({
                "rule": rule,
                "addr_a": a,
                "addr_b": b,
                "evidence_grade": "Grade-D",
                "confidence": min(0.85, conf),
                "tx_hash": tx_hash,
            })

        txh = str(ev.get("tx_hash") or "")
        if etype == "contract_deploy" and fr and caddr:
            try_link(fr, caddr, "CONTRACT_DEPLOYER_LINK", 0.85, txh)
        elif etype == "tx_call_and_sweep" and init and fr and to:
            # Custom contract `fr` invoked by `init` sweeps proceeds back to `init` (`to == init`)
            if to == init and fr != init:
                try_link(init, fr, "SAME_TX_EXPLOIT_CONTROLLER", 0.80, txh)
        elif etype == "gas_fund" and fr and to:
            gas_funders.setdefault(to, set()).add(fr)
        elif etype == "sweep" and fr and to:
            sweep_targets.setdefault(fr, set()).add(to)

    # Rule 3: Exclusive 1-to-1 gas-funder + direct consolidation loop (strictly anti-CEX)
    for child, funders in gas_funders.items():
        if len(funders) != 1:
            continue
        funder = next(iter(funders))
        targets = sweep_targets.get(child, set())
        if targets == {funder}:
            hub_f = is_hub_protected(funder, known_hubs)
            hub_c = is_hub_protected(child, known_hubs)
            if hub_f or hub_c:
                firewall_blocks.append({
                    "rule": "EXCLUSIVE_CONSOLIDATION_LINK",
                    "addr_a": funder,
                    "addr_b": child,
                    "blocked_reason": hub_f or hub_c,
                    "tx_hash": "multi-tx",
                })
            else:
                uf.union(funder, child)
                links.append({
                    "rule": "EXCLUSIVE_CONSOLIDATION_LINK",
                    "addr_a": funder,
                    "addr_b": child,
                    "evidence_grade": "Grade-D",
                    "confidence": 0.75,
                    "tx_hash": "multi-tx",
                })

    clusters: Dict[str, List[str]] = {}
    for a in sorted(all_addrs):
        root = uf.find(a)
        clusters.setdefault(root, []).append(a)

    return {
        "cluster_count": len(clusters),
        "clusters": clusters,
        "links": links,
        "firewall_blocks": firewall_blocks,
    }


def same_cluster(result: Dict[str, Any], a: str, b: str) -> bool:
    al, bl = a.lower(), b.lower()
    for members in result["clusters"].values():
        if al in members and bl in members:
            return True
    return False
