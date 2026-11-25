# Security, Compliance & Dispute Policy — Vector (SG)

## Operating Boundaries
1. **Strictly Non-Custodial**: Vector (SG) software never requests private keys, never signs transactions, and never takes custody of client or user assets.
2. **Client Execution Authority (`CLIENT_ONLY`)**: Risk scores, MCP pre-flight verdicts, and team triage signals are advisory technical evidence only. Integrating wallets, exchanges, and agent frameworks retain 100% execution authority.
3. **Not Legal Advice / No Recovery Guarantees**: Outputs do not constitute legal opinions, sanctions determinations, identity attribution verdicts, or asset recovery promises.
4. **Privacy & Non-Doxxing**: Public GitHub triage tools (`team_triage/`) emit zero raw email PII (domain + SHA-256 hash only) and prohibit nationality, language, geolocation, or ethnic-name heuristics.

## Reporting Security Vulnerabilities or False-Positive Label Disputes
- **Public Contact**: X `@Crypt0Pineapple` · Website `https://vector-forensics.pages.dev/`
- **Label Disputes & Appeals**: Submit structured appeals via `POST /v1/appeals` (disputed Grade-C/D labels are immediately down-weighted pending human review; confirmed errors are logged and revoked with immutable provenance).
