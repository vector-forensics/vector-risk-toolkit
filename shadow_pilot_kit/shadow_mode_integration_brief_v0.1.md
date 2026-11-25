# Vector (SG) — 30-Day Shadow Mode Risk API Integration Brief (v0.1)

> **Provider**: Vector (SG) (`VECTOR (SG) PTE. LTD.`, Singapore) · **Website**: `https://vector-forensics.pages.dev/`  
> **Contact**: X `@Crypt0Pineapple`  
> **Target Integrators**: BNB Chain Wallets (Pre-Sign Protection), Stablecoin On/Off-Ramps, and Mid-Tier Exchanges (Deposit Screening)  
> **Commercial Terms**: **30-Day Free Shadow Mode Pilot** · Zero auto-blocking · Zero user friction · Client retains 100% execution authority (`execution_authority: "CLIENT_ONLY"`).

---

## 1. Why Shadow Mode First?

Integrating a new risk API directly into a wallet's signing flow or an exchange's deposit queue carries unacceptable false-positive risk. **Vector (SG) Shadow Mode** removes that risk completely:

- **Non-Blocking Mirror**: Your backend fires asynchronous, non-blocking HTTP requests to Vector alongside your existing KYT/allowlist decision (`baseline_verdict`), with a strict client-side timeout (e.g., `250 ms` fail-open).
- **Zero Disruption**: Vector never blocks transactions, never custodies keys/funds, and never surfaces unverified alerts to end users during the 30-day pilot.
- **Measured Proof Before Paid Conversion**: At Day 30, you receive a reproducible **Shadow Mode Lift & False-Positive Report** quantifying:
  1. **Net Detection Lift (`NEW_DETECTION_LIFT`)**: Emerging exploits, zero-value address poisoning, zero-width/spoofed tokens, mixer contracts, and Grade-A OFAC matches caught by Vector that your baseline allowed;
  2. **Agreement & Abstention Calibration**: `AGREE_HIGH_RISK`, `AGREE_LOW_OR_NEUTRAL`, and explicit `ABSTAIN_NO_EVIDENCE` (`UNABLE_TO_ASSESS`) rates;
  3. **False-Positive Cost & Appeal Resolution**: Every disputed tag logged and tested against Vector's formal Appeal & Correction loop.

---

## 2. Narrow Wedge Coverage & Honest System Disclosures

| Dimension | Current v1.0 Specification | Explicit Boundary / Honesty Disclosure |
| :--- | :--- | :--- |
| **Primary Focus (Wedge A)** | Emerging BSC/EVM exploits, zero-value address poisoning, spoofed/zero-width token symbols, mixer/bridge breakpoints, and Grade-A OFAC SDN exact matches | Narrow-wedge risk signals; **not** a drop-in replacement for full enterprise KYC/AML case management |
| **Label Isolation (`label_spec_v1.0`)** | 5-table physical isolation (`487` Grade-A OFAC SDN + `44,103` Grade-C reference hubs incl. `6,723` BSC; `QUARANTINE` never queried) | Grade-C explorer tags never masquerade as official sanctions; disputed tags are immediately down-weighted |
| **Reproducibility** | **`100.0%`** verified across 100 identical requests (deterministic SHA-256 `evidence_hash`) | Requires fixed label DB snapshot & rule engine version |
| **Latency Baseline** | Local SQLite WAL prototype: `p50 = 2.80 ms`, `p95 = 3.91 ms`, `p99 = 4.70 ms` | **Internal local prototype benchmark — NOT a production SLA.** Production SLA & dedicated hot-index cache are scoped per pilot deployment |
| **Abstention Policy** | Returns explicit `UNABLE_TO_ASSESS` when no verified evidence exists | Never fabricates risk scores or blames unknown addresses |
| **Execution Authority** | Hard-coded `"CLIENT_ONLY"` in every API response | Vector (SG) provides technical evidence signals only; **not** legal advice |

---

## 3. API Integration Contract (`risk_api` v1.0)

### 3.1 Endpoints

| Method & Path | Purpose |
| :--- | :--- |
| `GET /v1/health` | Returns engine version, isolated label table counts, and chain coverage declaration |
| `POST /v1/risk/address` | Single-address risk check (supports `shadow_mode: true`, `client_id`, `baseline_verdict`) |
| `POST /v1/risk/transfer` | Pre-sign / deposit transfer check (adds deterministic zero-value poisoning & spoofed-symbol detection) |
| `GET /v1/shadow/summary?client_id=<id>` | Returns aggregated Shadow Mode lift breakdown (`NEW_DETECTION_LIFT`, `AGREE_HIGH_RISK`, `ABSTAIN_NO_EVIDENCE`, etc.) |
| `POST /v1/appeals` & `POST /v1/appeals/resolve` | Submits and resolves false-positive disputes with immutable audit trail (`dispute_correction_log`) |

### 3.2 Sample Shadow-Mode Pre-Sign Request (`POST /v1/risk/transfer`)

```json
{
  "chain": "bsc",
  "from": "0xUserWallet...",
  "to": "0xCounterparty...",
  "token_addr": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "symbol": "US\u200bDT",
  "amount_raw": 1000000000000000000,
  "decimals": 18,
  "shadow_mode": true,
  "client_id": "pilot-wallet-01",
  "baseline_verdict": "ALLOW"
}
```

### 3.3 Sample Response Excerpt

```json
{
  "risk_level": "HIGH",
  "risk_score": 85,
  "recommended_action": "WARN_USER_PRE_SIGN_OR_HOLD_FOR_REVIEW",
  "observed_facts": [
    {
      "grade": "Deterministic",
      "type": "SPOOFED_OR_SCAM_TOKEN",
      "reason": "zero_width_or_bidi_chars_in_symbol",
      "confidence": 0.98
    }
  ],
  "evidence_hash": "ebb484100cb346f3...",
  "coverage_declaration": {
    "engine_version": "vector-risk-api-v1.0",
    "execution_authority": "CLIENT_ONLY"
  },
  "shadow_mode": {
    "logged": true,
    "client_id": "pilot-wallet-01",
    "baseline_verdict": "ALLOW",
    "lift_category": "NEW_DETECTION_LIFT"
  }
}
```

---

## 4. 30-Day Pilot Schedule & Privacy Guardrails

1. **Day 1–3 (Onboarding & Self-Hosted / Dedicated Endpoint)**: Agree on pilot scope (`client_id`, target chains, timeout budget) and deploy either a dedicated Vector SG pilot endpoint or self-hosted container inside your VPC (zero customer PII ever leaves your infrastructure).
2. **Day 4–28 (Silent Shadow Telemetry + Appeal Drills)**: Mirror live pre-sign/deposit metadata (addresses, token contract, raw amount, baseline verdict — **zero user names, KYC docs, IP addresses, or private keys**). Test at least 1 simulated false-positive dispute through `/v1/appeals`.
3. **Day 29–30 (Joint Lift Review & Go/No-Go)**: Vector delivers the reproducible **Day-30 Lift & False-Positive Report** with full `evidence_hash` audit logs. Proceed to paid API / custom streaming cache only if net detection lift outweighs review cost.
