"""Vector (SG) — Deterministic, Explainable Risk-Scoring Engine v1.0 (Stdlib Only).

Implements Phase 1 Narrow Wedge A (Emerging Exploit, Poisoning, Spoofed-Token &
Sanctions Screening) + Shadow Mode telemetry + Appeal-aware Grade-isolated lookups.

Core Guarantees:
  1. 100% deterministic & reproducible given fixed label DB & rule version
     (cryptographic `evidence_hash` = SHA-256 over canonical inputs + findings).
  2. Strict separation: `observed_facts`, `analytical_signals`, `breakpoints`,
     and `coverage_declaration`.
  3. Explicit abstention (`UNABLE_TO_ASSESS`) when no verified evidence exists.
  4. Non-custodial & advisory only: `execution_authority` is ALWAYS `"CLIENT_ONLY"`.
  5. Disputed Grade-C/D labels are explicitly flagged as `UNDER_APPEAL` and
     down-weighted until resolved; revoked labels are excluded from active scoring.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

from auto_tracer.forensics import (
    KNOWN_DEX_ROUTERS_BSC,
    breakpoint_reason,
    canonical_token_info,
    estimate_usd,
    is_spoof_or_scam_symbol,
)
from auto_tracer.label_store import VectorLabelStore
from auto_tracer.models import ZERO_ADDR
from . import ENGINE_RULE_VERSION
from .stream_cache import HotspotCacheStore

SUPPORTED_CHAINS = ("bsc", "ethereum", "polygon", "arbitrum", "optimism", "avalanche", "tron", "bitcoin")
HUB_NEUTRAL_CATEGORIES = {"dex_router", "bridge", "cex_hot", "cex_deposit", "benign_contract"}


def compute_evidence_hash(payload: Dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def classify_shadow_lift(baseline_verdict: str, vector_risk_level: str) -> str:
    base = (baseline_verdict or "unknown").strip().upper()
    vec = vector_risk_level.upper()
    base_risky = base in ("BLOCK", "HIGH", "CRITICAL", "FLAG", "ALERT", "WARN")
    vec_risky = vec in ("CRITICAL", "HIGH", "ELEVATED")
    if vec == "UNABLE_TO_ASSESS":
        return "ABSTAIN_NO_EVIDENCE"
    if not base_risky and vec_risky:
        return "NEW_DETECTION_LIFT"
    if base_risky and vec_risky:
        return "AGREE_HIGH_RISK"
    if not base_risky and not vec_risky:
        return "AGREE_LOW_OR_NEUTRAL"
    return "BASELINE_ONLY_ALERT"


class VectorRiskEngine:
    def __init__(self, db_path: str, cache_db_path: Optional[str] = None):
        self.store = VectorLabelStore(db_path)
        self.db_path = db_path
        self.hotspot_cache = HotspotCacheStore(cache_db_path) if cache_db_path else None

    def close(self) -> None:
        self.store.close()
        if self.hotspot_cache:
            self.hotspot_cache.close()

    def coverage_declaration(self, chain: str) -> Dict[str, Any]:
        c = (chain or "").strip().lower()
        cache_meta = self.hotspot_cache.get_meta() if self.hotspot_cache else None
        return {
            "engine_version": ENGINE_RULE_VERSION,
            "requested_chain": c,
            "chain_supported": c in SUPPORTED_CHAINS,
            "supported_chains": list(SUPPORTED_CHAINS),
            "label_isolation_spec": "label_spec_v1.0",
            "data_mode": (
                "tier2_hotspot_cache_plus_isolated_label_store"
                if self.hotspot_cache
                else "local_frozen_label_store_plus_deterministic_rules"
            ),
            "hotspot_cache_tip_block": int(cache_meta["last_indexed_block"]) if (cache_meta and "last_indexed_block" in cache_meta) else None,
            "fallback_policy": "Returns UNABLE_TO_ASSESS on missing evidence; never fabricates risk or auto-blocks.",
            "execution_authority": "CLIENT_ONLY",
        }

    def assess_address(
        self,
        chain: str,
        address: str,
        shadow_mode: bool = False,
        client_id: str = "pilot-default",
        baseline_verdict: Optional[str] = None,
    ) -> Dict[str, Any]:
        c = (chain or "bsc").strip().lower()
        addr = (address or "").strip()
        observed_facts: List[Dict[str, Any]] = []
        analytical_signals: List[Dict[str, Any]] = []
        breakpoints: List[Dict[str, Any]] = []
        score = 0
        has_any_evidence = False

        # 1. Built-in deterministic breakpoint (mixer / bridge) check
        bp = breakpoint_reason(addr)
        if bp:
            has_any_evidence = True
            breakpoints.append({
                "rule": "known_mixer_or_bridge_registry",
                "detail": bp,
                "address": addr.lower(),
            })
            if bp.startswith("known_mixer:"):
                score = max(score, 85)
                observed_facts.append({
                    "grade": "Grade-C",
                    "type": "MIXER_CONTRACT",
                    "label": bp,
                    "confidence": 0.95,
                    "note": "Public mixer contract; interaction warrants compliance review (not a legal determination).",
                })
            else:
                observed_facts.append({
                    "grade": "Grade-C",
                    "type": "CROSS_CHAIN_BRIDGE",
                    "label": bp,
                    "confidence": 0.90,
                    "note": "Cross-chain bridge breakpoint; downstream legs require destination-chain verification.",
                })

        # 2. Canonical token & built-in DEX router check
        canon = canonical_token_info(addr, chain=c)
        if canon:
            has_any_evidence = True
            observed_facts.append({
                "grade": "Grade-C",
                "type": "CANONICAL_TOKEN_CONTRACT",
                "symbol": canon[0],
                "decimals": canon[1],
                "confidence": 0.99,
            })
        elif c == "bsc" and addr.lower() in KNOWN_DEX_ROUTERS_BSC:
            has_any_evidence = True
            observed_facts.append({
                "grade": "Grade-C",
                "type": "KNOWN_DEX_ROUTER",
                "label": KNOWN_DEX_ROUTERS_BSC[addr.lower()],
                "confidence": 0.95,
            })

        # 3. Physically grade-isolated label store lookup (NEVER reads QUARANTINE)
        hits = self.store.lookup(addr, chain=c, include_disputed=True)

        for r in hits["Grade-A"]:
            has_any_evidence = True
            score = max(score, 98)
            observed_facts.append({
                "grade": "Grade-A",
                "type": "OFFICIAL_SANCTIONS_EXACT_MATCH",
                "label": r["label"],
                "entity": r["entity"],
                "source_url": r["source_url"],
                "evidence_excerpt": r["evidence_excerpt"],
                "retrieved_at_utc": r["retrieved_at_utc"],
                "confidence": r["confidence"],
                "status": r["status"],
                "note": "Exact address match on official published list; legal applicability must be verified by counsel.",
            })

        for r in hits["Grade-B"]:
            has_any_evidence = True
            score = max(score, 90)
            observed_facts.append({
                "grade": "Grade-B",
                "type": "OFFICIAL_LE_ADVISORY_MATCH",
                "label": r["label"],
                "source_url": r["source_url"],
                "retrieved_at_utc": r["retrieved_at_utc"],
                "confidence": r["confidence"],
                "status": r["status"],
            })

        for r in hits["Grade-C"]:
            has_any_evidence = True
            cat = (r["category"] or "other").lower()
            is_disputed = (r["status"] == "disputed")
            if cat in ("exploit", "scam", "fraud", "sanctioned", "mixer"):
                # Grade-C explorer tags NEVER override Grade-A; disputed tags are down-weighted
                sig_score = 35 if is_disputed else (75 if cat in ("exploit", "sanctioned", "mixer") else 65)
                score = max(score, sig_score)
                analytical_signals.append({
                    "grade": "Grade-C",
                    "type": f"EXPLORER_REFERENCE_{cat.upper()}",
                    "label": r["label"],
                    "source_url": r["source_url"],
                    "confidence": round(r["confidence"] * (0.5 if is_disputed else 1.0), 3),
                    "status": r["status"],
                    "under_appeal": is_disputed,
                    "note": (
                        "Label currently UNDER APPEAL (disputed); down-weighted pending human resolution."
                        if is_disputed
                        else "Public explorer tag (Grade-C reference only; not an official sanctions or legal finding)."
                    ),
                })
            else:
                observed_facts.append({
                    "grade": "Grade-C",
                    "type": f"INFRA_OR_HUB_{cat.upper()}",
                    "label": r["label"],
                    "entity": r["entity"],
                    "source_url": r["source_url"],
                    "confidence": r["confidence"],
                    "status": r["status"],
                })

        for r in hits["Grade-D"]:
            has_any_evidence = True
            is_disputed = (r["status"] == "disputed")
            score = max(score, 30 if is_disputed else 55)
            analytical_signals.append({
                "grade": "Grade-D",
                "type": "ANALYTICAL_HYPOTHESIS",
                "label": r["label"],
                "source_url": r["source_url"],
                "confidence": min(0.85, r["confidence"]) * (0.5 if is_disputed else 1.0),
                "status": r["status"],
                "under_appeal": is_disputed,
            })

        # 4. Optional Tier-2 Hotspot Stream Cache lookup (recent mixer/bridge touch enrichment)
        if self.hotspot_cache and addr:
            hc = self.hotspot_cache.lookup_address(c, addr)
            if hc:
                if hc["mixer_touch_count"] > 0:
                    has_any_evidence = True
                    score = max(score, 65)
                    analytical_signals.append({
                        "grade": "Grade-D",
                        "type": "HOTSPOT_CACHE_RECENT_MIXER_TOUCH",
                        "mixer_touch_count": hc["mixer_touch_count"],
                        "last_seen_block": hc["last_seen_block"],
                        "last_tx_hash": hc["last_tx_hash"],
                        "confidence": 0.80,
                        "note": "Tier-2 hotspot cache observed direct interaction with a known mixer contract; verify tx context.",
                    })
                elif hc["bridge_touch_count"] > 0:
                    has_any_evidence = True
                    observed_facts.append({
                        "grade": "Grade-C",
                        "type": "HOTSPOT_CACHE_RECENT_BRIDGE_TOUCH",
                        "bridge_touch_count": hc["bridge_touch_count"],
                        "last_seen_block": hc["last_seen_block"],
                        "confidence": 0.85,
                    })

        # Determine transparent risk level & action
        if not has_any_evidence:
            risk_level = "UNABLE_TO_ASSESS"
            recommended_action = "ALLOW_WITH_STANDARD_CONTROLS_NO_ADVERSE_SIGNAL"
            summary = "No verified official list match, hub record, or adverse signal found in current snapshot."
        elif score >= 90:
            risk_level = "CRITICAL"
            recommended_action = "ESCALATE_COMPLIANCE_REVIEW"
            summary = "Exact match on official high-severity source (Grade-A/B). Escalate to compliance/counsel."
        elif score >= 70:
            risk_level = "HIGH"
            recommended_action = "WARN_USER_PRE_SIGN_OR_HOLD_FOR_REVIEW"
            summary = "High-severity public reference or mixer interaction detected. Human compliance review recommended."
        elif score >= 40:
            risk_level = "ELEVATED"
            recommended_action = "MONITOR_AND_VERIFY"
            summary = "Elevated reference/analytical signal detected (or label under appeal). Verify independently."
        else:
            risk_level = "LOW"
            recommended_action = "ALLOW_WITH_STANDARD_CONTROLS"
            summary = "Matched known benign infrastructure/hub contract with no active adverse flags."

        hash_basis = {
            "engine_version": ENGINE_RULE_VERSION,
            "chain": c,
            "address": addr.lower() if c not in ("tron", "solana", "bitcoin") else addr,
            "risk_level": risk_level,
            "risk_score": score,
            "observed_facts": observed_facts,
            "analytical_signals": analytical_signals,
            "breakpoints": breakpoints,
        }
        ev_hash = compute_evidence_hash(hash_basis)

        result = {
            "subject_type": "address",
            "chain": c,
            "address": addr,
            "risk_level": risk_level,
            "risk_score": score,
            "recommended_action": recommended_action,
            "summary": summary,
            "observed_facts": observed_facts,
            "analytical_signals": analytical_signals,
            "breakpoints": breakpoints,
            "evidence_hash": ev_hash,
            "coverage_declaration": self.coverage_declaration(c),
        }

        if shadow_mode:
            lift = classify_shadow_lift(baseline_verdict or "ALLOW", risk_level)
            self.store.log_shadow_event(
                event_id=f"shd-{uuid.uuid4().hex[:12]}",
                client_id=client_id,
                chain=c,
                subject=addr,
                baseline_verdict=baseline_verdict or "ALLOW",
                vector_risk_level=risk_level,
                vector_score=score,
                lift_category=lift,
                evidence_hash=ev_hash,
            )
            result["shadow_mode"] = {
                "logged": True,
                "client_id": client_id,
                "baseline_verdict": baseline_verdict or "ALLOW",
                "lift_category": lift,
            }

        return result

    def assess_transfer(
        self,
        chain: str,
        from_addr: str,
        to_addr: str,
        token_addr: str,
        symbol: Optional[str] = None,
        amount_raw: int = 0,
        decimals: int = 18,
        tx_hash: Optional[str] = None,
        shadow_mode: bool = False,
        client_id: str = "pilot-default",
        baseline_verdict: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Real-time Wedge A transfer / pre-sign / deposit risk check."""
        c = (chain or "bsc").strip().lower()
        amt_int = int(amount_raw)
        amt_h = amt_int / (10 ** int(decimals))

        from_eval = (
            self.assess_address(c, from_addr)
            if from_addr
            else {"observed_facts": [], "analytical_signals": [], "breakpoints": [], "risk_score": 0}
        )
        to_eval = self.assess_address(c, to_addr)

        observed_facts = list(from_eval["observed_facts"]) + list(to_eval["observed_facts"])
        analytical_signals = list(from_eval["analytical_signals"]) + list(to_eval["analytical_signals"])
        breakpoints = list(from_eval["breakpoints"]) + list(to_eval["breakpoints"])
        score = max(from_eval["risk_score"], to_eval["risk_score"])

        # Deterministic Wedge A checks: zero-value poisoning & spoofed/zero-width token symbol
        if amt_int == 0:
            score = max(score, 60)
            observed_facts.append({
                "grade": "Deterministic",
                "type": "ZERO_VALUE_POISONING_SIGNAL",
                "detail": "Zero-value transfer detected (common address-poisoning pattern; raw record retained).",
                "confidence": 0.95,
            })

        spoof_reason = is_spoof_or_scam_symbol(token_addr, symbol, chain=c)
        if spoof_reason:
            score = max(score, 85)
            observed_facts.append({
                "grade": "Deterministic",
                "type": "SPOOFED_OR_SCAM_TOKEN",
                "token_addr": token_addr.lower(),
                "symbol": symbol,
                "reason": spoof_reason,
                "confidence": 0.98,
                "note": "Non-canonical contract using protected/zero-width/phishing symbol.",
            })

        if from_addr.lower() == ZERO_ADDR or to_addr.lower() == ZERO_ADDR:
            observed_facts.append({
                "grade": "Deterministic",
                "type": "ZERO_ADDRESS_MINT_OR_BURN",
                "detail": "Mint/burn bookkeeping event (not a peer-to-peer transfer).",
                "confidence": 0.99,
            })

        canon = canonical_token_info(token_addr, chain=c)
        usd_est = estimate_usd(canon[0] if canon else symbol, amt_h)

        if not observed_facts and not analytical_signals and not breakpoints:
            risk_level = "UNABLE_TO_ASSESS"
            recommended_action = "ALLOW_WITH_STANDARD_CONTROLS_NO_ADVERSE_SIGNAL"
        elif score >= 90:
            risk_level = "CRITICAL"
            recommended_action = "ESCALATE_COMPLIANCE_REVIEW"
        elif score >= 70:
            risk_level = "HIGH"
            recommended_action = "WARN_USER_PRE_SIGN_OR_HOLD_FOR_REVIEW"
        elif score >= 40:
            risk_level = "ELEVATED"
            recommended_action = "MONITOR_AND_VERIFY"
        else:
            risk_level = "LOW"
            recommended_action = "ALLOW_WITH_STANDARD_CONTROLS"

        hash_basis = {
            "engine_version": ENGINE_RULE_VERSION,
            "chain": c,
            "tx_hash": (tx_hash or "").lower(),
            "from": from_addr.lower(),
            "to": to_addr.lower(),
            "token_addr": (token_addr or "").lower(),
            "symbol": symbol,
            "amount_raw": str(amt_int),
            "risk_level": risk_level,
            "risk_score": score,
            "observed_facts": observed_facts,
            "analytical_signals": analytical_signals,
            "breakpoints": breakpoints,
        }
        ev_hash = compute_evidence_hash(hash_basis)

        result = {
            "subject_type": "transfer",
            "chain": c,
            "tx_hash": tx_hash,
            "from": from_addr,
            "to": to_addr,
            "token_addr": token_addr,
            "symbol": canon[0] if canon else symbol,
            "is_canonical_token": canon is not None or token_addr.lower() in ("bnb", "eth", "native", "0x0"),
            "amount_human": round(amt_h, 8),
            "est_usd": round(usd_est, 2) if usd_est is not None else None,
            "risk_level": risk_level,
            "risk_score": score,
            "recommended_action": recommended_action,
            "observed_facts": observed_facts,
            "analytical_signals": analytical_signals,
            "breakpoints": breakpoints,
            "evidence_hash": ev_hash,
            "coverage_declaration": self.coverage_declaration(c),
        }

        if shadow_mode:
            lift = classify_shadow_lift(baseline_verdict or "ALLOW", risk_level)
            self.store.log_shadow_event(
                event_id=f"shd-{uuid.uuid4().hex[:12]}",
                client_id=client_id,
                chain=c,
                subject=tx_hash or f"{from_addr[:10]}->{to_addr[:10]}",
                baseline_verdict=baseline_verdict or "ALLOW",
                vector_risk_level=risk_level,
                vector_score=score,
                lift_category=lift,
                evidence_hash=ev_hash,
            )
            result["shadow_mode"] = {
                "logged": True,
                "client_id": client_id,
                "baseline_verdict": baseline_verdict or "ALLOW",
                "lift_category": lift,
            }

        return result
