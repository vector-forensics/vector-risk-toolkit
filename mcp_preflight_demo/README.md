# Vector (SG) — Open-Source MCP Server & `x402` Pre-Flight Risk Check Demo

> **Status**: Phase 1 Low-Cost Open-Source Interface Demo (`v0.1.0`)  
> **Dependencies**: Pure Python 3.9+ standard library (`risk_api.engine.VectorRiskEngine` + `data/vector_labels_v1.sqlite`)  
> **Strategic Scope Disclosure**: This repository module is a lightweight open-source interface wedge demonstrating how AI agent wallets can call Vector's deterministic risk engine before executing irreversible on-chain payments. It involves **zero hardware/robotics R&D**, is **not a Phase 0–2 revenue line**, and cites HTTP `402` / `x402` strictly as an early open reference standard rather than a sole protocol dependency.

---

## Core Design & Safety Invariants

1. **Non-Custodial & Advisory Only (`execution_authority: "CLIENT_ONLY"`)**  
   This MCP server never holds private keys, never constructs or broadcasts transactions, and never auto-blocks funds. It returns structured risk evidence so the integrating agent framework or human controller can enforce its own spending policy.
2. **Zero-Hallucination Deterministic Guardrail**  
   Every verdict is backed by an immutable SHA-256 `evidence_hash` over grade-isolated `observed_facts` (`Grade-A` OFAC SDN, `Grade-C` reference hubs, canonical token contracts, known mixers/bridges) and `analytical_signals`.
3. **Explicit Abstention (`UNABLE_TO_ASSESS`)**  
   When an address or chain lacks verified evidence in the current frozen snapshot, the server explicitly returns `UNABLE_TO_ASSESS` instead of fabricating a risk score.

---

## Exposed MCP Tools (JSON-RPC 2.0 over `stdio`)

| Tool Name | Purpose |
| :--- | :--- |
| `vector_preflight_check_address` | Single-address screening across Grade-A sanctions, Grade-C reference hubs, mixers/bridges, and canonical tokens. |
| `vector_preflight_check_transfer` | Pre-sign transfer screening adding deterministic zero-value address-poisoning and zero-width/spoofed token symbol checks. |
| `vector_preflight_check_x402_payment` | Parses an HTTP `402 Payment Required` (`x402`) payment requirement (`network`, `payTo`, `asset`, `maxAmountRequired`, `assetSymbol`) and returns `ALLOW_PROCEED`, `WARN_HUMAN_APPROVAL`, `BLOCK_RECOMMENDED_CLIENT_DECIDES`, or `UNABLE_TO_ASSESS`. |

---

## Quick Start (MCP Client Configuration)

Add the following entry to any stdio-compatible MCP client (e.g., Claude Desktop, Cursor, or custom agent runner):

```json
{
  "mcpServers": {
    "vector-preflight": {
      "command": "python3",
      "args": [
        "-m",
        "mcp_preflight_demo.mcp_server",
        "--db",
        "data/vector_labels_v1.sqlite"
      ]
    }
  }
}
```

### Example `vector_preflight_check_x402_payment` Input

```json
{
  "scheme": "exact",
  "network": "eip155:56",
  "payTo": "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd",
  "asset": "0x55d398326f99059ff775485246999027b3197955",
  "assetSymbol": "USDT",
  "maxAmountRequired": "50000000000000000000",
  "decimals": 18,
  "resource": "https://api.example-data.io/v1/premium-feed"
}
```

---

## Automated Verification

```bash
python3 -m mcp_preflight_demo.test_mcp_and_x402
```

Spawns the real MCP server subprocess over `stdio`, runs the full JSON-RPC 2.0 handshake (`initialize` → `notifications/initialized` → `tools/list` → `tools/call`), and verifies all 5 `x402` scenarios plus address/transfer checks and 100% deterministic `evidence_hash` reproducibility.
