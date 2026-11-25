# Vector (SG) — Verifiable On-Chain Risk & Pre-Flight Toolkit

> **Deterministic evidence first. Guardrailed models second. Zero fabricated on-chain facts.**  
> **Maintainer**: Vector (SG) (`VECTOR (SG) PTE. LTD.`, Singapore) · **Website**: `https://vector-forensics.pages.dev/` · **GitHub**: `https://github.com/vector-forensics/vector-risk-toolkit` · **X**: `@Crypt0Pineapple`

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](#)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-green.svg)](#)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## What Is Included

This open-source repository bundles Vector (SG)'s pure-stdlib Python 3.9+ deterministic risk, forensics, team-triage, and agent pre-flight middleware stack:

| Module | Purpose |
| :--- | :--- |
| `auto_tracer/` | Deterministic EVM/BSC transfer decoder, spoofed/zero-width token filter, intra-tx flash-loan & wash-swap net-flow collapser (`wash_loop.py`), grade-isolated SQLite label store (`label_store.py`), and 1-command forensic report bundler (`report_generator.py`). |
| `risk_api/` | Explainable Narrow-Wedge Risk API v1.0 (`ThreadingHTTPServer`): address & transfer screening, Shadow Mode telemetry (`/v1/shadow/summary`), and formal false-positive Appeal/Revocation loop (`/v1/appeals`). |
| `team_triage/` | Public-signal Team & Entity Risk-Signal Triage CLI (`github-team-signals` v1.0): 18 configurable public GitHub API signals + exact-match Grade-A OFAC screening, paired with benign counter-hypotheses and zero raw email PII output. |
| `mcp_preflight_demo/` | Lightweight **MCP Server (JSON-RPC 2.0 over `stdio`)** & **`x402` Pre-Flight Risk Check Demo** wrapping `VectorRiskEngine` for autonomous agent wallets (`execution_authority: "CLIENT_ONLY"`). |
| `shadow_pilot_kit/` | Non-blocking, fail-open Python client (`shadow_client.py`) and `curl` quickstart for 30-day zero-disruption Shadow Mode pilots. |
| `label_spec_v1.md` | Formal 4-tier provenance isolation specification (`Grade-A/B/C/D` + `QUARANTINE`). |

---

## Core Safety & Honesty Invariants

- **Non-Custodial & Advisory Only (`execution_authority: "CLIENT_ONLY"`)**: Never holds keys, never signs transactions, never auto-blocks funds.
- **Explicit Abstention (`UNABLE_TO_ASSESS`)**: Returns explicit abstention when verified evidence is absent instead of fabricating risk scores.
- **Zero-PII / Anti-Bias Guardrails**: `team_triage/` prohibits nationality, spoken language, geolocation, or ethnic-name features, and emits commit emails strictly as `domain + sha256`.
- **Strategic Scope Note**: `mcp_preflight_demo/` is an open-source interface wedge demonstrating pre-flight risk checks for autonomous wallets. It involves zero hardware/robotics R&D and cites `x402` strictly as an early open reference standard.

---

## Quick Verification (Zero External Packages Required)

Run the self-contained verification suite (builds an isolated temporary synthetic SQLite test store so no private database is required):

```bash
python3 run_all_checks.py
```

---

## MCP Client Configuration Example

```json
{
  "mcpServers": {
    "vector-preflight": {
      "command": "python3",
      "args": [
        "-m",
        "mcp_preflight_demo.mcp_server",
        "--db",
        "/path/to/vector_labels_v1.sqlite"
      ]
    }
  }
}
```

See [SECURITY.md](SECURITY.md) for operating boundaries and appeal procedures.
