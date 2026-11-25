"""Core evidence-first data models for Vector (SG) auto-tracer.

Adapted from OnchainInvestigator/src/onchain_investigation/graph/models.py.
Every edge is cryptographically bound to a transaction hash, block number, and log index.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

ZERO_ADDR = "0x0000000000000000000000000000000000000000"


@dataclass
class TransferEdge:
    from_addr: str
    to_addr: str
    asset: str  # "BNB" / "ETH" for native, or lowercase token contract address
    symbol: Optional[str]
    amount_raw: int
    decimals: int
    tx_hash: str
    block: int
    log_index: int = -1  # -1 for native value transfer
    chain: str = "bsc"
    source: str = "receipt_logs"
    tx_initiator: str = ""
    value_usd: Optional[float] = None

    @property
    def amount_human(self) -> float:
        return self.amount_raw / (10 ** self.decimals)

    @property
    def sort_key(self) -> tuple:
        if self.value_usd is not None:
            return (1, self.value_usd)
        return (0, self.amount_human)
