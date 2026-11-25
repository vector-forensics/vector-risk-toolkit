#!/usr/bin/env bash
# Vector (SG) — Risk API v1.0 Shadow Mode Quickstart (`curl` examples)
# Start server first:
#   python3 -m risk_api.server --host 127.0.0.1 --port 8787

set -euo pipefail
BASE_URL="${VECTOR_API_URL:-http://127.0.0.1:8787}"
CLIENT_ID="${VECTOR_CLIENT_ID:-pilot-wallet-01}"

echo "1) Health & Coverage Declaration"
curl -sS "${BASE_URL}/v1/health" | python3 -m json.tool

echo ""
echo "2) Shadow Mode Address Screening (Tornado Cash BSC Proxy)"
curl -sS -X POST "${BASE_URL}/v1/risk/address" \
  -H "Content-Type: application/json" \
  -d "{
    \"chain\": \"bsc\",
    \"address\": \"0x0d5550d52428e7e3175bfc9550207e4ad3859b17\",
    \"shadow_mode\": true,
    \"client_id\": \"${CLIENT_ID}\",
    \"baseline_verdict\": \"ALLOW\"
  }" | python3 -m json.tool

echo ""
echo "3) Shadow Mode Transfer Screening (Spoofed Zero-Width Token)"
curl -sS -X POST "${BASE_URL}/v1/risk/transfer" \
  -H "Content-Type: application/json" \
  -d "{
    \"chain\": \"bsc\",
    \"from\": \"0x1111111111111111111111111111111111111111\",
    \"to\": \"0x2222222222222222222222222222222222222222\",
    \"token_addr\": \"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\",
    \"symbol\": \"US\u200bDT\",
    \"amount_raw\": 1000000000000000000,
    \"decimals\": 18,
    \"shadow_mode\": true,
    \"client_id\": \"${CLIENT_ID}\",
    \"baseline_verdict\": \"ALLOW\"
  }" | python3 -m json.tool

echo ""
echo "4) Fetch Shadow Mode Lift Summary"
curl -sS "${BASE_URL}/v1/shadow/summary?client_id=${CLIENT_ID}" | python3 -m json.tool
