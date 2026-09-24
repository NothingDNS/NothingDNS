#!/usr/bin/env bash
# Local Docker regression: wildcard bind + secondary /32 alias.
# Verifies UDP and TCP answers on both primary and secondary, and that
# UDP replies are sourced from the queried address (IP_PKTINFO sticky).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${WORKDIR:-/tmp/ndns-multiip-harness}"
NET_NAME="${NET_NAME:-ndns-mip-harness}"
SRV_NAME="${SRV_NAME:-ndns-mip-harness-srv}"
CLI_NAME="${CLI_NAME:-ndns-mip-harness-cli}"
PRIMARY_IP=172.31.50.10
SECONDARY_IP=172.31.50.20
SUBNET=172.31.50.0/24
ARCH="$(uname -m)"
case "$ARCH" in
  arm64|aarch64) GOARCH=arm64 ;;
  x86_64|amd64) GOARCH=amd64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

cleanup() {
  docker rm -f "$SRV_NAME" "$CLI_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"/{zones,data}

cat >"$WORKDIR/nothingdns.yaml" <<EOF
server:
  port: 53
  bind: [0.0.0.0]
  http:
    enabled: true
    bind: "127.0.0.1:8080"
    auth_secret: "local-multiip-harness-secret-do-not-use"
upstream:
  servers: [1.1.1.1:53]
cache: {enabled: true, size: 1000}
dnssec: {enabled: false}
logging: {level: warn, format: text}
metrics: {enabled: false}
storage: {data_dir: /data}
cluster: {enabled: false, data_dir: /data/cluster}
cookie: {enabled: false}
rrl: {enabled: false}
acl: []
allow_recursion: [127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 172.31.0.0/16]
zones: [/etc/nothingdns/zones/example.zone]
EOF

cat >"$WORKDIR/zones/example.zone" <<'EOF'
$ORIGIN example.test.
$TTL 300
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 900 604800 300 )
@ IN NS ns1.example.test.
@ IN A 203.0.113.50
ns1 IN A 203.0.113.50
EOF

echo "== building linux/$GOARCH binary =="
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -trimpath -ldflags='-s -w' \
  -o "$WORKDIR/nothingdns" "$ROOT/cmd/nothingdns"

docker network create --subnet="$SUBNET" "$NET_NAME" >/dev/null
docker run -d --name "$SRV_NAME" --network "$NET_NAME" --ip "$PRIMARY_IP" --cap-add=NET_ADMIN \
  -v "$WORKDIR/nothingdns:/usr/local/bin/nothingdns:ro" \
  -v "$WORKDIR/nothingdns.yaml:/etc/nothingdns/nothingdns.yaml:ro" \
  -v "$WORKDIR/zones:/etc/nothingdns/zones:ro" \
  -v "$WORKDIR/data:/data" \
  alpine:3.20 sleep 7200 >/dev/null
docker run -d --name "$CLI_NAME" --network "$NET_NAME" alpine:3.20 sleep 7200 >/dev/null

docker exec "$SRV_NAME" sh -c '
apk add --no-cache bind-tools iproute2 python3 >/dev/null
ip addr add '"$SECONDARY_IP"'/32 dev eth0
/usr/local/bin/nothingdns -config /etc/nothingdns/nothingdns.yaml >/tmp/ndns.log 2>&1 &
sleep 1.5
if ! pgrep nothingdns >/dev/null; then
  echo "nothingdns failed to start:" >&2
  cat /tmp/ndns.log >&2
  exit 1
fi
# Must be a single wildcard UDP listener (no per-IP fan-out from 0.0.0.0).
udp_lines=$(ss -ulnp | grep -c ":53" || true)
echo "udp_listen_lines=$udp_lines"
ss -ulnp | grep 53 || true
ss -tlnp | grep 53 || true
grep -E "UDP server listening|TCP server listening|error|Error|failed" /tmp/ndns.log || true
'

docker exec "$CLI_NAME" sh -c 'apk add --no-cache bind-tools python3 >/dev/null'

fail=0
check_dig() {
  local ip="$1" proto="$2" label="$3"
  local args=(@"$ip" example.test A +short +time=2 +tries=1)
  if [[ "$proto" == tcp ]]; then
    args+=(+tcp)
  fi
  local out
  out=$(docker exec "$CLI_NAME" dig "${args[@]}" 2>&1) || true
  if echo "$out" | grep -q '203.0.113.50'; then
    echo "PASS dig $label $ip"
  else
    echo "FAIL dig $label $ip: $out" >&2
    fail=1
  fi
}

check_dig "$PRIMARY_IP" udp "udp"
check_dig "$SECONDARY_IP" udp "udp"
check_dig "$PRIMARY_IP" tcp "tcp"
check_dig "$SECONDARY_IP" tcp "tcp"

# Sticky UDP source: reply to secondary query must come from secondary IP.
sticky_rc=0
sticky=$(docker exec -i "$CLI_NAME" python3 - <<PY
import socket, struct, sys
def qname(name):
    out = b""
    for lab in name.split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"
hdr = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
body = hdr + qname("example.test") + struct.pack("!HH", 1, 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
sock.sendto(body, ("$SECONDARY_IP", 53))
data, src = sock.recvfrom(4096)
sys.stdout.write(src[0])
if src[0] != "$SECONDARY_IP":
    sys.exit(2)
if len(data) < 12:
    sys.exit(3)
PY
) || sticky_rc=$?
if [[ "$sticky_rc" -eq 0 && "$sticky" == "$SECONDARY_IP" ]]; then
  echo "PASS sticky UDP source=$sticky"
else
  echo "FAIL sticky UDP source (got '${sticky:-}' rc=$sticky_rc, want $SECONDARY_IP)" >&2
  fail=1
fi

# tcpdump cross-check: UDP replies to secondary queries must show secondary as src
docker exec "$SRV_NAME" sh -c 'apk add --no-cache tcpdump >/dev/null'
docker exec "$SRV_NAME" sh -c "timeout 3 tcpdump -ni eth0 -c 4 'udp and port 53 and host $SECONDARY_IP' 2>/tmp/td.err | tee /tmp/td.out" &
td_pid=$!
sleep 0.4
docker exec "$CLI_NAME" dig @"$SECONDARY_IP" example.test A +short +time=1 +tries=1 >/dev/null || true
wait "$td_pid" || true
td_out=$(docker exec "$SRV_NAME" cat /tmp/td.out 2>/dev/null || true)
echo "tcpdump: $td_out"
if echo "$td_out" | grep -q "${SECONDARY_IP}[.]53 >"; then
  echo "PASS tcpdump shows secondary as UDP reply source"
else
  echo "FAIL tcpdump did not show ${SECONDARY_IP}.53 as reply source" >&2
  docker exec "$SRV_NAME" cat /tmp/td.err >&2 || true
  fail=1
fi
if [[ "$fail" -ne 0 ]]; then
  echo "== server log ==" >&2
  docker exec "$SRV_NAME" cat /tmp/ndns.log >&2 || true
  exit 1
fi

echo "ALL MULTI-IP CHECKS PASSED"
