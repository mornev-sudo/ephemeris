#!/usr/bin/env bash
# End-to-end self-test on a single Linux machine (e.g. the router VM).
#
# Builds two fake hosts out of network namespaces and veth pairs, points
# ephemerisd at the router side of each pair, and checks that traffic flows:
#
#   [netns eph-ha]                                       [netns eph-hb]
#   eth0 10.10.1.10 ── veth ── eph-a ═ ephemerisd ═ eph-b ── veth ── eth0 10.10.2.10
#
# Usage:  sudo lab/netns/selftest.sh [path/to/ephemerisd]
set -euo pipefail

BIN=${1:-target/release/ephemerisd}
EPHCTL=${EPHCTL:-$(dirname "$BIN")/ephctl}
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
[[ -x $BIN ]] || { echo "no binary at $BIN; run: cargo build --release"; exit 1; }
command -v ethtool >/dev/null || { echo "please install ethtool"; exit 1; }

WORK=$(mktemp -d)
PID=
cleanup() {
    [[ -n $PID ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
    ip netns del eph-ha 2>/dev/null || true   # deleting the netns deletes its veth pair
    ip netns del eph-hb 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
# Clear leftovers from an interrupted earlier run.
ip netns del eph-ha 2>/dev/null || true
ip netns del eph-hb 2>/dev/null || true

host() { # name router-veth host-ip gateway
    ip netns add "$1"
    ip link add "$2" type veth peer name eth0 netns "$1"
    ip link set "$2" up
    ip -n "$1" link set lo up
    ip -n "$1" addr add "$3" dev eth0
    ip -n "$1" link set eth0 up
    ip -n "$1" route add default via "$4"
    # The hosts' kernels would otherwise hand us packets with the TCP/UDP
    # checksum left blank ("offloaded") and 64 KB super-packets (TSO/GSO).
    # Real NICs fix both up in hardware; between veths nobody does.
    ip netns exec "$1" ethtool -K eth0 tx off tso off gso off >/dev/null 2>&1 || true
}
host eph-ha eph-a 10.10.1.10/24 10.10.1.1
host eph-hb eph-b 10.10.2.10/24 10.10.2.1

cat > "$WORK/ephemeris.toml" <<CFG
[dataplane]
workers = 1
stats_interval_secs = 2

[management]
listen = "127.0.0.1:18080"
token_file = "$WORK/api-token"

[[interface]]
name = "lan-a"
device = "eph-a"
address = "10.10.1.1/24"

[[interface]]
name = "lan-b"
device = "eph-b"
address = "10.10.2.1/24"
allow_new_sessions = false   # stateful: B may only reply
CFG

"$BIN" --config "$WORK/ephemeris.toml" >"$WORK/log" 2>&1 &
PID=$!
sleep 2
kill -0 "$PID" 2>/dev/null || { echo "ephemerisd exited:"; cat "$WORK/log"; exit 1; }

pass=0 fail=0
check() { # description, command...
    local d=$1; shift
    if "$@" >"$WORK/out" 2>&1; then echo "  PASS  $d"; pass=$((pass+1));
    else echo "  FAIL  $d"; sed 's/^/        /' "$WORK/out"; fail=$((fail+1)); fi
}
echo "Running checks:"
# The first ping may be lost while ARP resolves (Phase 0 drops on a miss).
ip netns exec eph-ha ping -c1 -W1 10.10.2.10 >/dev/null 2>&1 || true
check "ping router's near interface"      ip netns exec eph-ha ping -c3 -i0.2 -W1 10.10.1.1
check "ping router's far interface"       ip netns exec eph-ha ping -c3 -i0.2 -W1 10.10.2.1
check "ping host B through the router"    ip netns exec eph-ha ping -c5 -i0.2 -W1 10.10.2.10
check "B cannot start a session to A"   sh -c "! ip netns exec eph-hb ping -c2 -i0.2 -W1 10.10.1.10"
check "TTL is decremented (expect 63)"    sh -c "ip netns exec eph-ha ping -c1 -W1 10.10.2.10 | grep -q 'ttl=63'"
check "TTL=1 gets Time Exceeded"          sh -c "ip netns exec eph-ha ping -c1 -W1 -t1 10.10.2.10 | grep -qi 'exceeded'"
check "no route gets Net Unreachable"     sh -c "ip netns exec eph-ha ping -c1 -W1 8.8.8.8 | grep -qi 'unreachable'"
check "1400-byte packets"                 ip netns exec eph-ha ping -c3 -i0.2 -W1 -s1400 10.10.2.10
if command -v iperf3 >/dev/null; then
    ip netns exec eph-hb iperf3 -s -1 -D
    sleep 0.5
    check "TCP A->B (iperf3, 5s)"         ip netns exec eph-ha iperf3 -c 10.10.2.10 -t5
    grep -E "sender|receiver" "$WORK/out" | sed 's/^/        /' || true
    ip netns exec eph-hb iperf3 -s -1 -D
    sleep 0.5
    check "TCP B->A on A's session (-R)"  ip netns exec eph-ha iperf3 -c 10.10.2.10 -t5 -R
    grep -E "sender|receiver" "$WORK/out" | sed 's/^/        /' || true
    ip netns exec eph-hb iperf3 -s -1 -D
    sleep 0.5
    check "UDP A->B (iperf3 -u, 3s)"      ip netns exec eph-ha iperf3 -c 10.10.2.10 -u -b 100M -t3
else
    echo "  SKIP  TCP throughput (install iperf3)"
fi

# Management plane: the API answers, and a route added through it reaches
# the running data plane without a restart.
if [[ -x $EPHCTL ]]; then
    export EPHCTL_URL=http://127.0.0.1:18080 EPHCTL_TOKEN=$(cat "$WORK/api-token")
    check "API status via ephctl"          sh -c "$EPHCTL status | grep -q 'lan-b'"
    check "API rejects a wrong token"     sh -c "! EPHCTL_TOKEN=nope $EPHCTL status"
    check "API rejects an invalid route"  sh -c "! $EPHCTL route add 0.0.0.0/0 172.16.0.1"
    check "add default route live"        "$EPHCTL" route add 0.0.0.0/0 10.10.2.10
    check "8.8.8.8 now routed (no Unreachable)" sh -c "! ip netns exec eph-ha ping -c1 -W1 8.8.8.8 | grep -qi unreachable"
    check "route is in the config file"   grep -q 'prefix = "0.0.0.0/0"' "$WORK/ephemeris.toml"
    check "remove default route live"     "$EPHCTL" route del 0.0.0.0/0
    check "8.8.8.8 unreachable again"     sh -c "ip netns exec eph-ha ping -c1 -W1 8.8.8.8 | grep -qi unreachable"
    check "rollback restores the route"   sh -c "$EPHCTL config rollback 1 && $EPHCTL routes | grep -q 0.0.0.0/0"
else
    echo "  SKIP  management API (no ephctl at $EPHCTL)"
fi

sleep 2.5
echo; echo "ephemerisd log (tail):"; tail -n 20 "$WORK/log" | sed 's/^/  /'
echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
