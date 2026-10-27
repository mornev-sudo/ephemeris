#!/usr/bin/env bash
# SD-WAN end-to-end test on one Linux machine: two sites, two routers, two
# WAN paths with emulated latency, and a link failure in the middle.
#
#   [sd-ha] 10.1.0.10                                           [sd-hb] 10.2.0.10
#      │                                                              │
#   r1-lan ─ R1 (site 1) ─ r1-w1 ═[sd-wan1: 5 ms "fibre"]═ r2-w1 ─ R2 (site 2) ─ r2-lan
#                        └ r1-w2 ═[sd-wan2: 40 ms "lte" ]═ r2-w2 ┘
#
# Each WAN is a bridge inside its own namespace, with netem adding delay on
# both of its ports (AF_XDP transmit bypasses the routers' own qdiscs, so the
# delay has to live in the middle).
#
# Usage:  sudo lab/netns/sdwan-test.sh [path/to/ephemerisd]
#         (LOGS=dir: keep both routers' logs there)
set -euo pipefail

BIN=${1:-target/release/ephemerisd}
EPHCTL=${EPHCTL:-$(dirname "$BIN")/ephctl}
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
[[ -x $BIN && -x $EPHCTL ]] || { echo "need $BIN and $EPHCTL; run: cargo build --release"; exit 1; }

WORK=$(mktemp -d)
PIDS=()
NS=(sd-ha sd-hb sd-wan1 sd-wan2)
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    [[ -n ${LOGS:-} ]] && { cp "$WORK"/r*.log "$LOGS"/ 2>/dev/null || true; }
    for n in "${NS[@]}"; do ip netns del "$n" 2>/dev/null || true; done
    for l in r1-lan r2-lan r1-w1 r1-w2 r2-w1 r2-w2; do ip link del "$l" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cleanup_leftovers() { for n in "${NS[@]}"; do ip netns del "$n" 2>/dev/null || true; done; }
cleanup_leftovers
for n in "${NS[@]}"; do ip netns add "$n"; ip -n "$n" link set lo up; done

host() { # ns router-veth addr gw
    ip link add "$2" type veth peer name eth0 netns "$1"
    ip link set "$2" up
    ip -n "$1" addr add "$3" dev eth0
    ip -n "$1" link set eth0 up
    ip -n "$1" route add default via "$4"
    ip netns exec "$1" ethtool -K eth0 tx off tso off gso off >/dev/null 2>&1 || true
}
host sd-ha r1-lan 10.1.0.10/24 10.1.0.1
host sd-hb r2-lan 10.2.0.10/24 10.2.0.1

wan() { # ns r1-veth r2-veth delay
    ip -n "$1" link add br0 type bridge
    ip -n "$1" link set br0 up
    # (Port names matter: `ip link set a ...` would parse "a" as "address".)
    ip link add "$2" type veth peer name port1 netns "$1"
    ip link add "$3" type veth peer name port2 netns "$1"
    for p in port1 port2; do
        ip -n "$1" link set dev "$p" master br0 up
        ip netns exec "$1" tc qdisc add dev "$p" root netem delay "$4"
    done
    ip link set dev "$2" up
    ip link set dev "$3" up
}
wan sd-wan1 r1-w1 r2-w1 5ms
wan sd-wan2 r1-w2 r2-w2 40ms

# Each router has its own SD-WAN key pair and the other's public key: the
# two agree session keys in a handshake. They also share a random key, mixed
# into that handshake. Each router keeps its state (config history, key
# pair) apart.
mkdir -p "$WORK/r1" "$WORK/r2"
KEY=$(openssl rand -hex 32)
PUB1=$("$BIN" --config "$WORK/r1/ephemeris.toml" --sdwan-identity)
PUB2=$("$BIN" --config "$WORK/r2/ephemeris.toml" --sdwan-identity)
pub_of() { if [[ $1 == 1 ]]; then echo "$PUB1"; else echo "$PUB2"; fi; }

config() { # site other-site port
    local s=$1 o=$2
    cat <<CFG
[dataplane]
workers = 1
stats_interval_secs = 5

[management]
listen = "127.0.0.1:$3"
token_file = "$WORK/r$s/token"

[overlay]
site_id = $s

[[interface]]
name = "lan"
device = "r$s-lan"
address = "10.$s.0.1/24"

[[interface]]
name = "wan1"
device = "r$s-w1"
address = "192.0.2.$s/30"
allow_new_sessions = false

[[interface]]
name = "wan2"
device = "r$s-w2"
address = "198.51.100.$s/30"
allow_new_sessions = false

[[tether]]
name = "fibre"
interface = "wan1"
remote = "192.0.2.$o"
site = $o
key = "$KEY"
public_key = "$(pub_of "$o")"

[[tether]]
name = "lte"
interface = "wan2"
remote = "198.51.100.$o"
site = $o
key = "$KEY"
public_key = "$(pub_of "$o")"

[[overlay_route]]
prefix = "10.$o.0.0/24"
site = $o

# Bulk transfers (iperf3's port) go over LTE, keeping fibre free.
[[class]]
name = "bulk"
protocol = "tcp"
ports = "5201"
prefer = ["lte", "fibre"]
CFG
}
config 1 2 18081 > "$WORK/r1/ephemeris.toml"
config 2 1 18082 > "$WORK/r2/ephemeris.toml"
"$BIN" --config "$WORK/r1/ephemeris.toml" > "$WORK/r1.log" 2>&1 & PIDS+=($!)
"$BIN" --config "$WORK/r2/ephemeris.toml" > "$WORK/r2.log" 2>&1 & PIDS+=($!)

eph1() { EPHCTL_URL=http://127.0.0.1:18081 EPHCTL_TOKEN=$(cat "$WORK/r1/token") "$EPHCTL" "$@"; }
# Read ephctl's tables: tether rows are
#   NAME VIA REMOTE SITE STATE RTT ms JITTER ms LOSS TX RX   ($5 state, $6 rtt, $11 tx)
# and path rows are  SITE CLASS USING.
tun_field() { eph1 overlay | awk -v n="$1" -v f="$2" '$1 == n {print $f}'; }
path_of() { eph1 overlay | awk -v c="$1" '$1 ~ /^[0-9]+$/ && $2 == c {print $3}'; }
tethers_up() { [ "$(tun_field fibre 5)" = up ] && [ "$(tun_field lte 5)" = up ]; }
uses() { [ "$(path_of "$1")" = "$2" ]; }
fibre_down() { [ "$(tun_field fibre 5)" = DOWN ]; }
fibre_rtt_ok() { local r; r=$(tun_field fibre 6 | cut -d. -f1); [ "$r" -ge 8 ] && [ "$r" -le 30 ]; }
lte_carried() { [ $(( $(tun_field lte 11) - $1 )) -gt 500 ]; }
wait_for() { # seconds description command...
    local t=$1 d=$2; shift 2
    for _ in $(seq 1 $((t * 5))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done
    echo "timed out waiting for: $d"; return 1
}

pass=0 fail=0
check() {
    local d=$1; shift
    if "$@" >"$WORK/out" 2>&1; then echo "  PASS  $d"; pass=$((pass+1));
    else echo "  FAIL  $d"; sed 's/^/        /' "$WORK/out"; fail=$((fail+1)); fi
}
echo "SD-WAN checks:"
check "both tethers come up"              wait_for 15 "tethers up" tethers_up
check "keys agreed in a handshake"        grep -q "new session keys" "$WORK/r1.log" "$WORK/r2.log"
check "default traffic uses fibre"        wait_for 5 "fibre chosen" uses default fibre
ip netns exec sd-ha ping -c1 -W1 10.2.0.10 >/dev/null 2>&1 || true   # first packet: ARP
check "ping site A -> site B over overlay" ip netns exec sd-ha ping -c5 -i0.2 -W1 10.2.0.10
check "ping site B -> site A over overlay" ip netns exec sd-hb ping -c5 -i0.2 -W1 10.1.0.10
check "RTT reflects fibre (< 30 ms)"      sh -c "ip netns exec sd-ha ping -c3 -i0.2 10.2.0.10 | awk -F/ '/rtt/ {exit !(\$5 < 30)}'"
check "fibre probes measure ~10 ms RTT"   fibre_rtt_ok
check "Frag Needed with overlay MTU"      sh -c "ip netns exec sd-ha ping -c1 -W1 -M do -s 1472 10.2.0.10 2>&1 | grep -qi 'mtu'"
if command -v iperf3 >/dev/null; then
    ip netns exec sd-hb iperf3 -s -1 -D; sleep 0.5
    before=$(tun_field lte 11)
    check "TCP through overlay (bulk class)" ip netns exec sd-ha iperf3 -c 10.2.0.10 -t3
    grep -E "sender|receiver" "$WORK/out" | sed 's/^/        /' || true
    check "bulk class went over lte"      lte_carried "$before"
fi

echo "Cutting the fibre link..."
ip netns exec sd-ha ping -c80 -i0.1 -W1 10.2.0.10 > "$WORK/ping-failover" 2>&1 &
ping_pid=$!
sleep 0.5
ip -n sd-wan1 link set dev br0 down
check "fibre detected down"               wait_for 5 "fibre down" fibre_down
check "default traffic moved to lte"      wait_for 5 "lte chosen" uses default lte
wait $ping_pid || true
check "ping survives failover (< 40% loss)" sh -c "grep -o '[0-9.]*% packet loss' $WORK/ping-failover | awk '{exit !(\$1+0 < 40)}'"
grep 'packet loss' "$WORK/ping-failover" | sed 's/^/        /'
check "still reachable over lte"          ip netns exec sd-ha ping -c3 -i0.2 -W1 10.2.0.10
ip -n sd-wan1 link set dev br0 up
check "fibre recovers, traffic moves back" wait_for 10 "fibre chosen again" uses default fibre

echo; eph1 overlay | sed 's/^/  /'
echo; echo "R1 log (path changes):"; grep -i "path change" "$WORK/r1.log" | sed 's/^/  /' || true
echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
