"""Deterministic on-chain forensic primitives for Vector (SG) auto-tracer.

Adapted from OnchainInvestigator/src/onchain_investigation/forensics.py,
chains/bsc.py, crosschain.py, and patterns.py.

Design boundary (Deterministic Rules vs. Model):
  1. Canonical token allowlists (ETH & BSC) and spoof/zero-width symbol detection;
  2. Known mixer / bridge / passthrough contract registries (public intelligence);
  3. Deterministic wei conservation verification;
  4. Zero-hallucination citation validation against frozen receipts.
"""
from __future__ import annotations

from decimal import Decimal
import re
from typing import Any, Dict, Optional, Tuple

from .models import ZERO_ADDR

# Zero-width & invisible Unicode characters commonly abused in spoofed token symbols
_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_SCAM_URL_RE = re.compile(r"(?:https?://|\.com\b|\.io\b|\.xyz\b|claim|airdrop|reward|visit|voucher)", re.I)

# Canonical BSC BEP-20 tokens (from OnchainInvestigator/chains/bsc.py + canonical BUSD/CAKE)
BSC_CANONICAL_TOKENS: Dict[str, Tuple[str, int]] = {
    "0x55d398326f99059ff775485246999027b3197955": ("USDT", 18),
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": ("USDC", 18),  # Fixed post-BLIND-003 canonical Binance-Peg USDC
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": ("WBNB", 18),
    "0x2170ed0880ac9a755fd29b2688956bd959f933f8": ("ETH", 18),
    "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c": ("BTCB", 18),
    "0xe9e7cea3dedca5984780bafc599bd69add087d56": ("BUSD", 18),
    "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82": ("CAKE", 18),
}

# Approximate reference prices for USD-aware heuristic prioritization (offline, deterministic)
REF_PRICES_USD: Dict[str, float] = {
    "BNB": 600.0,
    "WBNB": 600.0,
    "USDT": 1.0,
    "USDC": 1.0,
    "BUSD": 1.0,
    "ETH": 2500.0,
    "BTCB": 85000.0,
    "CAKE": 2.0,
}

# Canonical ETH ERC-20 tokens (from OnchainInvestigator/forensics.py)
ETH_CANONICAL_TOKENS: Dict[str, Tuple[str, int]] = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", 6),
    "0xdac17f958d2ee523a2206206994597c13d831ec7": ("USDT", 6),
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ("WETH", 18),
    "0x6b175474e89094c44da98b954eedeac495271d0f": ("DAI", 18),
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": ("WBTC", 8),
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": ("stETH", 18),
    "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": ("wstETH", 18),
}

PROTECTED_SYMBOLS = {"BNB", "WBNB", "ETH", "WETH", "USDC", "USDT", "BUSD", "DAI", "WBTC", "BTCB"}

# Known passthrough / multicall contracts (from OnchainInvestigator/forensics.py)
PASSTHROUGH_CONTRACTS: Dict[str, str] = {
    "0xca11bde05977b3631167028862be2a173976ca11": "Multicall3",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash Router",
}

# Publicly known mixer / bridge breakpoint contracts (ETH & BSC)
KNOWN_MIXERS: Dict[str, str] = {
    # ETH Tornado pools (from OnchainInvestigator/patterns.py)
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": "Tornado Cash 0.1 ETH",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 1 ETH",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 10 ETH",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 100 ETH",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash Router",
    # BSC Tornado BNB pools & official BSC Tornado Proxy (public Tornado deployments on BSC)
    "0x0d5550d52428e7e3175bfc9550207e4ad3859b17": "Tornado Cash BSC Proxy",
    "0x84443cfd09a48af6ef360c6976c5392ac5023a1f": "Tornado Cash 0.1 BNB",
    "0xd47438c816c9e7f2e2888e060936a499af9582b3": "Tornado Cash 1 BNB",
    "0x330bdfade01ee9bf63c209ee33102dd334618e0a": "Tornado Cash 10 BNB",
    "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd": "Tornado Cash 100 BNB",
}

KNOWN_BRIDGES: Dict[str, Tuple[str, str]] = {
    # ETH bridges (from OnchainInvestigator/crosschain.py)
    "0xd37bbe5744d730a1d98d8dc97c42f0ca46ad7146": ("THORChain Router", "multi-chain"),
    "0xdf0770df86a8034b3efef0a1bb3c889b8332ff56": ("Stargate ETH Pool", "LayerZero"),
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": ("Wormhole Bridge", "multi-chain"),
    "0x8315177ab297ba92a06054ce80db444d7ed3c27a": ("Arbitrum Bridge", "Arbitrum"),
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": ("Optimism Bridge", "Optimism"),
    # BSC public bridges
    "0x4a364f8c717caad9a442737eb7b8a55cc6cf18d8": ("Stargate BSC Router", "LayerZero"),
    "0xb6f6d86a8f9879a9c87f643768d9efc38c1da6e7": ("Wormhole BSC TokenBridge", "multi-chain"),
    "0x841ce48f9446c8e281d3f1444cb859b4a6d0738c": ("cBridge BSC", "multi-chain"),
}

KNOWN_DEX_ROUTERS_BSC: Dict[str, str] = {
    "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap Router v2",
    "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": "PancakeSwap SmartRouter v3",
    "0x1b81d678ffb9c0263b24a97847620c99d213eb14": "PancakeSwap V3 SwapRouter",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch AggregationRouterV5",
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch AggregationRouterV6",
}


def canonical_token_info(token_addr: str, chain: str = "bsc") -> Optional[Tuple[str, int]]:
    addr_l = (token_addr or "").lower()
    if chain.lower() == "bsc":
        return BSC_CANONICAL_TOKENS.get(addr_l)
    if chain.lower() in ("eth", "ethereum"):
        return ETH_CANONICAL_TOKENS.get(addr_l)
    return None


def estimate_usd(symbol: Optional[str], amount_human: float) -> Optional[float]:
    if not symbol:
        return None
    price = REF_PRICES_USD.get(symbol.upper())
    if price is None:
        return None
    return amount_human * price


def is_spoof_or_scam_symbol(token_addr: str, symbol: Optional[str], chain: str = "bsc") -> Optional[str]:
    """Returns a non-empty filter reason if a token exhibits spoofed/zero-width/scam symbol patterns."""
    addr_l = (token_addr or "").lower()
    if addr_l in ("bnb", "eth", "0x0", ZERO_ADDR, "native", ""):
        return None
    if symbol:
        if _ZERO_WIDTH_RE.search(symbol):
            return "zero_width_spoofed_symbol"
        if _SCAM_URL_RE.search(symbol):
            return "scam_url_or_phishing_symbol"
        sym_u = symbol.strip().upper()
        if sym_u in PROTECTED_SYMBOLS:
            official = canonical_token_info(addr_l, chain=chain)
            if official is None or official[0].upper() != sym_u:
                return f"non_canonical_protected_symbol:{sym_u}"
    return None


def breakpoint_reason(address: str) -> Optional[str]:
    a = (address or "").lower()
    if a in KNOWN_MIXERS:
        return f"known_mixer:{KNOWN_MIXERS[a]}"
    if a in KNOWN_BRIDGES:
        name, hint = KNOWN_BRIDGES[a]
        return f"known_bridge:{name}({hint})"
    return None


def verify_wei_conservation(
    inflows_wei: int,
    outflows_wei: int,
    gas_wei: int,
    ending_balance_wei: int,
    starting_balance_wei: int = 0,
) -> Dict[str, Any]:
    """Exact integer wei conservation assertion (from OnchainInvestigator/forensics.py)."""
    expected = int(starting_balance_wei) + int(inflows_wei) - int(outflows_wei) - int(gas_wei)
    actual = int(ending_balance_wei)
    delta = actual - expected
    return {
        "conserved": delta == 0,
        "delta_wei": str(delta),
        "delta_eth": str(Decimal(delta) / Decimal(10**18)),
    }
