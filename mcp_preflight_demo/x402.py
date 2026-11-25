"""Vector (SG) — HTTP 402 / x402 Payment Requirement Pre-Flight Risk Checker.

Parses standard HTTP 402 (`x402`) payment requirement payloads (`payTo`, `network`,
`asset`, `maxAmountRequired`, optional `assetSymbol`, `decimals`, `fromAddress`, `resource`)
and runs deterministic Grade-isolated sanctions, mixer/bridge, canonical-token, and
spoofed-symbol checks via `VectorRiskEngine`.

Hard Invariants:
  1. Never holds private keys, never signs transactions, never auto-blocks funds.
  2. `execution_authority` is ALWAYS `"CLIENT_ONLY"`.
  3. Returns explicit `UNABLE_TO_ASSESS` when no verified evidence exists.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from risk_api.engine import VectorRiskEngine, compute_evidence_hash
from . import MCP_DEMO_VERSION

NETWORK_ALIASES: Dict[str, str] = {
    "bsc": "bsc",
    "bnb": "bsc",
    "eip155:56": "bsc",
    "ethereum": "ethereum",
    "eth": "ethereum",
    "mainnet": "ethereum",
    "eip155:1": "ethereum",
    "polygon": "polygon",
    "matic": "polygon",
    "eip155:137": "polygon",
    "arbitrum": "arbitrum",
    "eip155:42161": "arbitrum",
    "optimism": "optimism",
    "eip155:10": "optimism",
    "avalanche": "avalanche",
    "eip155:43114": "avalanche",
    "base": "base",
    "eip155:8453": "base",
    "tron": "tron",
    "bitcoin": "bitcoin",
}


def normalize_x402_network(network: str) -> str:
    n = (network or "bsc").strip().lower()
    return NETWORK_ALIASES.get(n, n)


def evaluate_x402_payment(
    engine: VectorRiskEngine,
    payment_req: Dict[str, Any],
) -> Dict[str, Any]:
    """Run deterministic pre-flight risk screening on an x402 PaymentRequirement payload."""
    raw_net = str(payment_req.get("network") or "bsc")
    chain = normalize_x402_network(raw_net)
    pay_to = str(payment_req.get("payTo") or "").strip()
    from_addr = str(payment_req.get("fromAddress") or "").strip()
    asset = str(payment_req.get("asset") or "native").strip()
    symbol = payment_req.get("assetSymbol") or payment_req.get("symbol")
    decimals = int(payment_req.get("decimals") if payment_req.get("decimals") is not None else 18)
    max_amount_raw = int(str(payment_req.get("maxAmountRequired") or "0"))
    resource = str(payment_req.get("resource") or "")
    scheme = str(payment_req.get("scheme") or "exact")

    if not pay_to:
        raise ValueError("x402 payment requirement missing required field: 'payTo'")

    transfer_eval = engine.assess_transfer(
        chain=chain,
        from_addr=from_addr,
        to_addr=pay_to,
        token_addr=asset,
        symbol=symbol,
        amount_raw=max_amount_raw,
        decimals=decimals,
    )

    risk_level = transfer_eval["risk_level"]
    risk_score = transfer_eval["risk_score"]
    supported = transfer_eval["coverage_declaration"]["chain_supported"]

    if not supported and risk_level == "UNABLE_TO_ASSESS":
        verdict = "UNABLE_TO_ASSESS"
        guidance = (
            f"Chain '{chain}' (from network '{raw_net}') is outside current frozen label store coverage. "
            "No adverse signal fabricated; client policy governs execution."
        )
    elif risk_level == "CRITICAL":
        verdict = "BLOCK_RECOMMENDED_CLIENT_DECIDES"
        guidance = "Exact match on Grade-A/B official high-severity source. Do not auto-pay; escalate to compliance/counsel."
    elif risk_level == "HIGH":
        verdict = "BLOCK_RECOMMENDED_CLIENT_DECIDES"
        guidance = "High-severity signal (spoofed token, mixer contract, or Grade-C exploit tag). Hold for human approval."
    elif risk_level == "ELEVATED":
        verdict = "WARN_HUMAN_APPROVAL"
        guidance = "Elevated signal (e.g., zero-value poisoning or disputed/reference tag). Require human review before signing."
    elif risk_level == "LOW":
        verdict = "ALLOW_PROCEED"
        guidance = "Matched known benign hub/canonical token with zero active adverse flags."
    else:
        verdict = "UNABLE_TO_ASSESS"
        guidance = "No verified official match or adverse signal found in current snapshot. Client spending policy governs execution."

    preflight_basis = {
        "demo_version": MCP_DEMO_VERSION,
        "scheme": scheme,
        "raw_network": raw_net,
        "chain": chain,
        "payTo": pay_to.lower() if chain not in ("tron", "bitcoin") else pay_to,
        "asset": asset.lower(),
        "maxAmountRequired": str(max_amount_raw),
        "verdict": verdict,
        "transfer_evidence_hash": transfer_eval["evidence_hash"],
    }
    preflight_hash = compute_evidence_hash(preflight_basis)

    return {
        "protocol": "x402-preflight-advisory-v0.1",
        "verdict": verdict,
        "execution_authority": "CLIENT_ONLY",
        "risk_level": risk_level,
        "risk_score": risk_score,
        "guidance": guidance,
        "payment_summary": {
            "scheme": scheme,
            "network_requested": raw_net,
            "chain_resolved": chain,
            "payTo": pay_to,
            "asset": asset,
            "symbol": transfer_eval["symbol"],
            "is_canonical_token": transfer_eval["is_canonical_token"],
            "max_amount_human": transfer_eval["amount_human"],
            "est_usd": transfer_eval["est_usd"],
            "resource": resource,
        },
        "observed_facts": transfer_eval["observed_facts"],
        "analytical_signals": transfer_eval["analytical_signals"],
        "breakpoints": transfer_eval["breakpoints"],
        "evidence_hash": preflight_hash,
        "underlying_transfer_evidence_hash": transfer_eval["evidence_hash"],
        "coverage_declaration": transfer_eval["coverage_declaration"],
    }
