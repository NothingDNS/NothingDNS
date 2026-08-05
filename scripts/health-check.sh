#!/bin/bash
# NothingDNS Health Check Script
# Usage: ./scripts/health-check.sh [host:port]

set -euo pipefail

HOST="${1:-localhost:8080}"
METRICS_URL="${NOTHINGDNS_METRICS_URL:-http://localhost:9153/metrics}"
FAILED=0

echo "Running NothingDNS health checks on $HOST..."

# 1. Liveness
echo -n "Liveness: "
if curl -sf "http://$HOST/health" > /dev/null 2>&1; then
    echo "OK"
else
    echo "FAIL"
    FAILED=1
fi

# 2. Readiness
echo -n "Readiness: "
if curl -sf "http://$HOST/readyz" > /dev/null 2>&1; then
    echo "OK"
else
    echo "FAIL"
    FAILED=1
fi

# 3. DNS query test
echo -n "DNS Query: "
if command -v dig &> /dev/null; then
    if dig @localhost +short example.com A > /dev/null 2>&1; then
        echo "OK"
    else
        echo "FAIL"
        FAILED=1
    fi
else
    echo "SKIP (dig not installed)"
fi

# 4. API auth (optional — requires real credentials, never a hardcoded default)
echo -n "API Auth: "
NOTHINGDNS_USER="${NOTHINGDNS_USER:-}"
NOTHINGDNS_PASS="${NOTHINGDNS_PASS:-}"
TOKEN=""
if [ -n "$NOTHINGDNS_USER" ] && [ -n "$NOTHINGDNS_PASS" ]; then
    login_body=$(jq -nc --arg u "$NOTHINGDNS_USER" --arg p "$NOTHINGDNS_PASS" \
        '{username:$u,password:$p}')
    TOKEN=$(curl -sf -X POST "http://$HOST/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "$login_body" 2>/dev/null | \
        jq -r '.token // empty' 2>/dev/null || echo "")
    if [ -n "$TOKEN" ]; then
        echo "OK"
    else
        echo "FAIL"
        FAILED=1
    fi
else
    echo "SKIP (set NOTHINGDNS_USER and NOTHINGDNS_PASS to test authenticated endpoints)"
fi

# 5. Cache stats (requires a token from step 4)
echo -n "Cache: "
if [ -z "$TOKEN" ]; then
    echo "SKIP (no auth token)"
else
    CACHE_SIZE=$(curl -sf -H "Authorization: Bearer $TOKEN" \
        "http://$HOST/api/v1/cache/stats" 2>/dev/null | \
        jq -r '.size // empty' 2>/dev/null || echo "0")
    if [ "$CACHE_SIZE" -ge 0 ] 2>/dev/null; then
        echo "OK (size=$CACHE_SIZE)"
    else
        echo "FAIL"
        FAILED=1
    fi
fi

# 6. Cluster (if enabled; requires a token from step 4)
echo -n "Cluster: "
if [ -z "$TOKEN" ]; then
    echo "SKIP (no auth token)"
else
    CLUSTER_STATUS=$(curl -sf -H "Authorization: Bearer $TOKEN" \
        "http://$HOST/api/v1/cluster/status" 2>/dev/null | \
        jq -r '.enabled // false' 2>/dev/null || echo "false")
    if [ "$CLUSTER_STATUS" = "false" ]; then
        echo "DISABLED"
    else
        NODES=$(curl -sf -H "Authorization: Bearer $TOKEN" \
            "http://$HOST/api/v1/cluster/nodes" 2>/dev/null | \
            jq -r '.nodes | length' 2>/dev/null || echo "0")
        echo "OK ($NODES nodes)"
    fi
fi

# 7. Metrics (dedicated listener, optionally Bearer-protected)
echo -n "Metrics: "
metrics_auth_args=()
if [ -n "${NOTHINGDNS_METRICS_AUTH_TOKEN:-}" ]; then
    metrics_auth_args=(-H "Authorization: Bearer ${NOTHINGDNS_METRICS_AUTH_TOKEN}")
fi
if curl -sf "${metrics_auth_args[@]}" "$METRICS_URL" > /dev/null 2>&1; then
    echo "OK"
else
    echo "FAIL"
    FAILED=1
fi

echo ""
if [ $FAILED -eq 0 ]; then
    echo "All checks passed!"
    exit 0
else
    echo "Some checks failed!"
    exit 1
fi