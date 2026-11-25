"""Deterministic rule decision engine for Vector (SG) auto-tracer.

Adapted directly from OnchainInvestigator/src/onchain_investigation/decisions.py.
Keeps structured HopState inputs and auditable HopAction outputs.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional, Tuple


class HopAction(str, Enum):
    CONTINUE = "continue"
    PRUNE = "prune"
    FLAG = "flag"


@dataclass
class HopState:
    from_addr: str
    to_addr: str
    symbol: Optional[str]
    amount: float
    depth: int
    direction: str
    zero_from: bool
    zero_to: bool
    is_integer_amount: bool
    value_usd: Optional[float] = None


@dataclass
class Decision:
    action: HopAction
    confidence: float
    rationale: str
    engine: str


Rule = Tuple[str, Callable[[HopState], bool], HopAction, float, str]


class RuleDecisionEngine:
    """Deterministic heuristic engine (ported from OnchainInvestigator RuleDecisionEngine v1)."""

    def __init__(
        self,
        dust_threshold: float = 0.01,
        round_flag_threshold: float = 100.0,
        big_amount_threshold: float = 10_000.0,
        dust_usd_threshold: float = 10.0,
        big_usd_threshold: float = 50_000.0,
    ):
        self.rules: List[Rule] = [
            (
                "burn_or_mint_zero_addr",
                lambda s: s.zero_to or s.zero_from,
                HopAction.PRUNE,
                0.99,
                "zero_address_mint_or_burn",
            ),
            (
                "dust",
                lambda s: (
                    s.value_usd < dust_usd_threshold
                    if s.value_usd is not None
                    else s.amount < dust_threshold
                ),
                HopAction.PRUNE,
                0.90,
                f"below_dust_threshold({dust_threshold}/usd<{dust_usd_threshold:g})",
            ),
            (
                "round_amount",
                lambda s: s.is_integer_amount and s.amount >= round_flag_threshold,
                HopAction.FLAG,
                0.70,
                f"integer_peel_or_denomination_signal(>={round_flag_threshold})",
            ),
            (
                "big_amount",
                lambda s: (
                    s.value_usd >= big_usd_threshold
                    if s.value_usd is not None
                    else s.amount >= big_amount_threshold
                ),
                HopAction.CONTINUE,
                0.90,
                f"high_value_flow(>={big_amount_threshold}/usd>={big_usd_threshold:,.0f})",
            ),
        ]

    def decide(self, state: HopState) -> Decision:
        for _name, pred, action, conf, why in self.rules:
            if pred(state):
                return Decision(action=action, confidence=conf, rationale=why, engine="rule-v1")
        return Decision(action=HopAction.CONTINUE, confidence=0.5, rationale="default_continue", engine="rule-v1")
