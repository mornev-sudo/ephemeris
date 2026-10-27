#!/usr/bin/env bash
# End-to-end test of the *production* image, driven entirely from outside.
#
# Nothing test-related is inside the image. The router boots exactly as on
# Proxmox (UEFI + Secure Boot in setup mode, virtio NICs, credentials via
# SMBIOS like deploy-image.sh), and this script plays the part of the
# network and the operator:
#
#   [netns ci-ha] 10.10.1.10 ─ veth ─ bridge ─ tap ─ enp0s19 ┐
#                                                             ├─ router VM ─ enp0s18 (QEMU user net: SSH 2222, HTTPS 8443)
#   [netns ci-hb] 10.10.2.10 ─ veth ─ bridge ─ tap ─ enp0s20 ┘
#
# lan-a serves DHCP; lan-b gets its own address by DHCP from a dnsmasq in
# ci-hb (always 10.10.2.1, reserved for its MAC; no gateway, one DNS server,
# and one classless static route (option 121): 10.10.98.0/24 via host B).
#
# usage: sudo ci/e2e.sh <image.qcow2> <expected-version> [<update-dir> <update-version>]
set -euo pipefail

IMAGE=$1
VERSION=$2
UPDATE_DIR=${3:-}
UPDATE_VERSION=${4:-}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
LOGS=${LOGS:-$PWD/e2e-logs}
mkdir -p "$LOGS"
QEMU_PID= HTTP_PID= DNSMASQ_PID=

cleanup() {
    [[ -n $QEMU_PID ]] && kill "$QEMU_PID" 2>/dev/null || true
    [[ -n $HTTP_PID ]] && kill "$HTTP_PID" 2>/dev/null || true
    [[ -n $DNSMASQ_PID ]] && { kill "$DNSMASQ_PID" 2>/dev/null; wait "$DNSMASQ_PID" 2>/dev/null; } || true
    pkill -f "pppoe-server -I eth0" 2>/dev/null || true
    pkill -x pppd 2>/dev/null || true
    # This runs as root; the workflow uploads the logs as a normal user.
    chmod -R a+rX "$LOGS" 2>/dev/null || true
    ip netns del ci-ha 2>/dev/null || true
    ip netns del ci-hb 2>/dev/null || true
    for l in ephtap-a ephtap-b ephbr-a ephbr-b; do ip link del "$l" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------- deploy
# Like deploy-image.sh: generated admin password (only its hash goes to the
# VM), an SSH key, a hostname and the router config, as credentials.
PASSWORD=$(head -c 600 /dev/urandom | LC_ALL=C tr -dc 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789' | cut -c1-20)
HASH=$(printf '%s' "$PASSWORD" | openssl passwd -6 -stdin)
ssh-keygen -q -t ed25519 -N "" -f "$WORK/key"
cat > "$WORK/ephemeris.toml" <<'CFG'
[dataplane]
workers = 1
stats_interval_secs = 5

[[interface]]
name = "lan-a"
device = "enp0s19"
address = "10.10.1.1/24"

# No DNS servers here: hand out the ones lan-b's lease brings.
[interface.dhcp]
range = "10.10.1.100-10.10.1.110"

# lan-b plays the internet: outside role, so it only lets replies in and
# traffic towards it is source-NATed to its address, which comes from DHCP.
[[interface]]
name = "lan-b"
device = "enp0s20"
address = "dhcp"
role = "outside"
CFG
# QEMU puts the NICs on the root PCI bus, so they're named enp0s18..20
# rather than Proxmox's ens18..20: point management DHCP at enp0s18.
printf '[Match]\nName=enp0s18\n\n[Network]\nDHCP=yes\n' > "$WORK/mgmt.network"

b64() { base64 -w0 < "$1"; }
printf '%s' "$HASH" > "$WORK/hash"
qemu-img create -q -f qcow2 -F qcow2 -b "$(realpath "$IMAGE")" "$WORK/disk.qcow2" 8G
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$WORK/vars.fd"
for t in ephtap-a ephtap-b; do ip tuntap add dev "$t" mode tap; done
accel=tcg; [[ -w /dev/kvm ]] && accel=kvm

qemu-system-x86_64 \
    -machine q35,smm=on,accel=$accel -cpu max -smp 2 -m 2048 \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
    -drive if=pflash,format=raw,file="$WORK/vars.fd" \
    -device virtio-scsi-pci,id=scsi \
    -drive id=disk,if=none,format=qcow2,file="$WORK/disk.qcow2" -device scsi-hd,drive=disk \
    -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8443-:8443 \
    -device virtio-net-pci,netdev=mgmt,addr=0x12 \
    -netdev tap,id=lana,ifname=ephtap-a,script=no,downscript=no -device virtio-net-pci,netdev=lana,addr=0x13 \
    -netdev tap,id=lanb,ifname=ephtap-b,script=no,downscript=no -device virtio-net-pci,netdev=lanb,addr=0x14,mac=52:54:00:12:34:58 \
    -smbios type=11,value=io.systemd.credential:system.hostname=ci-router \
    -smbios type=11,value=io.systemd.credential.binary:ephemeris.admin_password_hash=$(b64 "$WORK/hash") \
    -smbios type=11,value=io.systemd.credential.binary:ssh.authorized_keys.root=$(b64 "$WORK/key.pub") \
    -smbios type=11,value=io.systemd.credential.binary:ephemeris.config=$(b64 "$WORK/ephemeris.toml") \
    -smbios type=11,value=io.systemd.credential.binary:network.network.10-mgmt=$(b64 "$WORK/mgmt.network") \
    -smbios type=11,value=io.systemd.credential:ephemeris.update_url=http://10.0.2.2:8000/ \
    -display none -serial file:"$LOGS/serial.log" &
QEMU_PID=$!

# The LAN hosts. Each tap stays in the main namespace (QEMU holds it open)
# and is bridged to a veth pair whose other end lives in the host's netns.
host() { # ns tap bridge address gateway
    ip netns add "$1"
    ip link add "$3" type bridge
    ip link set dev "$2" master "$3" up
    ip link add "$3-v" type veth peer name eth0 netns "$1"
    ip link set dev "$3-v" master "$3" up
    ip link set dev "$3" up
    ip -n "$1" link set lo up
    ip -n "$1" addr add "$4" dev eth0
    ip -n "$1" link set dev eth0 up
    ip -n "$1" route add default via "$5"
    # Full-size, fully checksummed frames: there's no NIC on this path to
    # finish the job for the host's TCP/IP stack.
    ip netns exec "$1" ethtool -K eth0 tx off tso off gso off >/dev/null 2>&1 || true
}
host ci-ha ephtap-a ephbr-a 10.10.1.10/24 10.10.1.1
host ci-hb ephtap-b ephbr-b 10.10.2.10/24 10.10.2.1

# The "ISP" DHCP server for lan-b: the router always gets 10.10.2.1, no
# default gateway (the forwarding tests expect none), DNS 10.10.2.53.
ip netns exec ci-hb dnsmasq --keep-in-foreground --no-resolv --port=0 --user=root \
    --interface=eth0 --bind-interfaces --dhcp-authoritative \
    --dhcp-range=10.10.2.100,10.10.2.200,255.255.255.0,1h \
    --dhcp-host=52:54:00:12:34:58,10.10.2.1 --dhcp-option=3 --dhcp-option=6,10.10.2.53 \
    --dhcp-option=121,10.10.98.0/24,10.10.2.10 \
    --dhcp-leasefile="$WORK/dnsmasq.leases" --log-dhcp --log-facility="$LOGS/dnsmasq.log" &
DNSMASQ_PID=$!

if [[ -n $UPDATE_DIR ]]; then
    (cd "$UPDATE_DIR" && exec python3 -m http.server 8000 --bind 0.0.0.0 > "$LOGS/http.log" 2>&1) &
    HTTP_PID=$!
fi

SSH=(ssh -q -i "$WORK/key" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 root@127.0.0.1)
on_router() { "${SSH[@]}" "$@"; }
wait_for() { # seconds description command...
    local t=$1 d=$2; shift 2
    local end=$((SECONDS + t))
    until "$@" >/dev/null 2>&1; do
        (( SECONDS < end )) || { echo "timed out after ${t}s waiting for: $d"; return 1; }
        sleep 2
    done
}

pass=0 fail=0
check() {
    local d=$1; shift
    if "$@" > "$WORK/out" 2>&1; then
        echo "  PASS  $d"; pass=$((pass + 1))
    else
        echo "  FAIL  $d"; sed 's/^/        /' "$WORK/out" | tail -20; fail=$((fail + 1))
    fi
}

echo "Booting the router (Secure Boot enrollment reboots it once)..."
wait_for 300 "SSH on the router" on_router true || { tail -60 "$LOGS/serial.log"; exit 1; }
wait_for 60 "boot to finish" sh -c "${SSH[*]} systemctl is-system-running --wait | grep -qE 'running|degraded'"

# ------------------------------------------------------------ the system
echo "System:"
check "boots version $VERSION"             sh -c "[ \"\$(${SSH[*]} cat /usr/lib/ephemeris/version)\" = '$VERSION' ]"
check "no failed services"                 sh -c "[ -z \"\$(${SSH[*]} systemctl --failed --plain --no-legend)\" ] || { ${SSH[*]} systemctl --failed; false; }"
check "ephemerisd runs as a service"         on_router systemctl is-active --quiet ephemerisd.service
check "Secure Boot is enabled"             sh -c "${SSH[*]} od -An -t u1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | grep -q 1"
check "root filesystem is read-only"       sh -c "! ${SSH[*]} touch /usr/bin/test-write"
# The router never updates or reboots by itself: Debian's sysupdate timers
# and services are masked (updates are started by an operator).
check "no automatic updates or reboots"    on_router 'for u in systemd-sysupdate.timer systemd-sysupdate.service systemd-sysupdate-reboot.timer systemd-sysupdate-reboot.service; do [ "$(systemctl is-enabled $u 2>/dev/null)" = masked ] || { echo "$u: $(systemctl is-enabled $u 2>&1)"; exit 1; }; done; ! systemctl list-timers --all --no-legend | grep -q sysupdate'
check "SSH with the admin password"        sshpass -p "$PASSWORD" ssh -q -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no root@127.0.0.1 true
check "wrong password refused"             sh -c "! sshpass -p wrong-password ssh -q -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no root@127.0.0.1 true"
check "ephctl on the router"                sh -c "${SSH[*]} ephctl status | grep -q lan-b"

# ------------------------------------------------------------ the web
echo "Web portal:"
WEB=https://127.0.0.1:8443
check "portal reachable over HTTPS"        curl -skf -o /dev/null $WEB/
check "TLS certificate generated"          sh -c "${SSH[*]} openssl x509 -in /var/lib/ephemeris/tls/cert.pem -noout -subject | grep -q ci-router"
check "plain HTTP only on loopback"        sh -c "! ${SSH[*]} ss -Hltn | awk '{print \$4}' | grep ':8080\$' | grep -v '^127\.0\.0\.1:'"
check "API refuses anonymous requests"     sh -c "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' $WEB/api/v1/status)\" = 401 ]"
check "unknown host names refused"         sh -c "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' -H 'Host: rebind.example' $WEB/)\" = 421 ]"
check "security headers sent"              sh -c "curl -skI $WEB/ | grep -qi \"content-security-policy: default-src 'none'; script-src 'self'\" && curl -skI $WEB/ | grep -qi strict-transport-security"
check "web login with the admin password"  sh -c "curl -skf -c '$WORK/cookies' -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"$PASSWORD\"}' $WEB/api/v1/login && curl -skf -b '$WORK/cookies' $WEB/api/v1/status | grep -q lan-a"
# Deployed with a SHA-512 crypt hash; the first login stores it as yescrypt
# (ASVS V11.4.2), for the web and for root's /etc/shadow alike.
check "password hash upgraded to yescrypt"  on_router 'grep -q "^[\$]y[\$]" /var/lib/ephemeris/admin.hash && grep -q "^root:[\$]y[\$]" /etc/shadow'
check "SSH password still works after it"   sshpass -p "$PASSWORD" ssh -q -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no root@127.0.0.1 true
check "session cookie is Secure"           grep -q '^#HttpOnly_127.0.0.1.*TRUE' "$WORK/cookies"
check "config file is private"             sh -c "[ \"\$(${SSH[*]} stat -c %a /var/lib/ephemeris/ephemeris.toml)\" = 600 ]"
check "portal works in a real browser"     env ROUTER_URL=$WEB/ ADMIN_PASSWORD="$PASSWORD" SHOTS="$LOGS" node "$HERE/portal-test.mjs"

# Automated security testing of the portal (OWASP WSTG): a passive ZAP
# baseline scan, and a TLS scan. Each fails on anything rated high; the
# full reports are kept with the test logs.
mkdir -p "$LOGS/scans" && chmod 777 "$LOGS/scans"
# Both images come from GitHub's registry (Docker Hub rate-limits shared CI
# runners), pinned to a version. Each scanner's own output is kept next to
# its report; if no report appears, its last lines say why. The mkosi
# action removes AppArmor's tools but the kernel still has it on, so Docker
# can't load its default profile: the scanners run without one.
ZAP_IMAGE=ghcr.io/zaproxy/zaproxy:2.17.0
TESTSSL_IMAGE=ghcr.io/testssl/testssl.sh:3.2
no_report() { # name log
    echo "$1 wrote no report. Last lines of its output:"
    tail -25 "$2"
    return 1
}
zap_scan() { # passive scan of the portal; fails on any High risk alert
    docker run --rm --network host --security-opt apparmor=unconfined -v "$LOGS/scans:/zap/wrk:rw" "$ZAP_IMAGE" \
        zap-baseline.py -t "$WEB/" -I -J zap.json -r zap.html > "$LOGS/scans/zap.log" 2>&1
    [[ -s $LOGS/scans/zap.json ]] || { no_report ZAP "$LOGS/scans/zap.log"; return; }
    python3 - "$LOGS/scans/zap.json" <<'PY'
import json, sys
alerts = [a for s in json.load(open(sys.argv[1])).get("site", []) for a in s.get("alerts", [])]
high = [a["name"] for a in alerts if int(a.get("riskcode", 0)) >= 3]
print(f"{len(alerts)} alert type(s); high risk: {high or 'none'}")
sys.exit(1 if high else 0)
PY
}
tls_scan() { # testssl.sh against the portal; fails on HIGH or CRITICAL
    docker run --rm --network host --security-opt apparmor=unconfined -v "$LOGS/scans:/out:rw" "$TESTSSL_IMAGE" \
        --quiet --color 0 --warnings off --jsonfile /out/testssl.json 127.0.0.1:8443 > "$LOGS/scans/testssl.log" 2>&1
    [[ -s $LOGS/scans/testssl.json ]] || { no_report testssl "$LOGS/scans/testssl.log"; return; }
    python3 - "$LOGS/scans/testssl.json" <<'PY'
import json, sys
# The certificate is self-signed on purpose (made on the router at first
# boot; its fingerprint is on the console): findings that follow from that
# are expected. No CA means no CRL or OCSP; it lasts ten years because
# nothing renews it; and testssl grades any untrusted certificate "T".
# Everything else counts: protocols, ciphers, known TLS vulnerabilities.
expected = ("cert_chain_of_trust", "cert_trust", "cert_caIssuers",
            "cert_revocation", "cert_extlifeSpan")
def ok(f):
    return f["id"].startswith(expected) or (f["id"] == "overall_grade" and f["finding"] == "T")
bad = [f"{f['id']}: {f['finding']}" for f in json.load(open(sys.argv[1]))
       if f.get("severity") in ("HIGH", "CRITICAL") and not ok(f)]
print("\n".join(bad) or "no high or critical findings")
sys.exit(1 if bad else 0)
PY
}
check "ZAP baseline: nothing high risk"     zap_scan
check "TLS scan: nothing high or critical"  tls_scan

# ------------------------------------------------------------ forwarding
echo "DHCP:"
check "lan-b gets its address by DHCP"     wait_for 90 "a lease on lan-b" on_router "ephctl dhcp | grep 'lan-b' | grep 'bound' | grep -q '10.10.2.1/24'"
check "option 121 route from the lease"    wait_for 30 "the lease's route" on_router "ephctl routes | grep '10.10.98.0/24' | grep -q '10.10.2.10'"
check "DNS server learned from the lease"  sh -c "${SSH[*]} ephctl --json dhcp | grep -q 10.10.2.53"
# A LAN host asks for an address; the script only records what it was told
# (ci-ha keeps its static address for the tests below).
printf '#!/bin/sh\n[ "$1" = bound ] && echo "$ip $router $dns" > %s/lease\nexit 0\n' "$WORK" > "$WORK/udhcpc.sh"
chmod +x "$WORK/udhcpc.sh"
MAC_A=$(ip netns exec ci-ha cat /sys/class/net/eth0/address)
check "a LAN host gets a lease"            ip netns exec ci-ha busybox udhcpc -i eth0 -n -q -t 5 -T 2 -s "$WORK/udhcpc.sh"
check "from the range, via the router, with learned DNS" \
                                           grep -qE '^10\.10\.1\.1(0[0-9]|10) 10\.10\.1\.1 10\.10\.2\.53$' "$WORK/lease"
check "the lease is listed on the router"  sh -c "${SSH[*]} ephctl dhcp | grep -qi '$MAC_A'"

echo "Forwarding:"
ip netns exec ci-ha ping -c1 -W1 10.10.2.10 >/dev/null 2>&1 || true   # first packet resolves ARP
check "ping the router"                    ip netns exec ci-ha ping -c3 -i0.2 -W1 10.10.1.1
check "ping through the router"            ip netns exec ci-ha ping -c5 -i0.2 -W1 10.10.2.10
check "TTL decremented"                    sh -c "ip netns exec ci-ha ping -c1 -W1 10.10.2.10 | grep -q 'ttl=63'"
# ICMP errors must come *from the router* (a host's own "Destination Host
# Unreachable" means it couldn't even reach its gateway).
check "Time Exceeded at TTL 1"             sh -c "ip netns exec ci-ha ping -c1 -W1 -t1 10.10.2.10 | grep -qi 'From 10.10.1.1 .*exceeded'"
check "Net Unreachable without a route"    sh -c "ip netns exec ci-ha ping -c1 -W1 8.8.8.8 | grep -qi 'From 10.10.1.1 .*net unreachable'"
check "lan-b reaches its gateway"          ip netns exec ci-hb ping -c2 -i0.2 -W1 10.10.2.1
check "lan-b can't start sessions"         sh -c "! ip netns exec ci-hb ping -c2 -i0.2 -W1 10.10.1.10"
ip netns exec ci-hb iperf3 -s -D -1 --logfile "$WORK/iperf-b.log"
sleep 0.5
check "TCP A->B (iperf3)"                  ip netns exec ci-ha iperf3 -c 10.10.2.10 -t3
grep -E "receiver" "$WORK/out" | sed 's/^/        /' || true
check "NAT: B sees the router's address"   grep -q "Accepted connection from 10.10.2.1," "$WORK/iperf-b.log"
check "NAT shown on the session"           sh -c "curl -skf -b '$WORK/cookies' '$WEB/api/v1/sessions?limit=50' | grep -q '\"nat\":\"10.10.2.1:'"
# Bounded resources (0.9.0): newest sessions first, at most 1000; a capped
# journal; the portal and API at a lower CPU priority than the workers.
check "sessions: newest first, at most 1000" sh -c "curl -skf -b '$WORK/cookies' '$WEB/api/v1/sessions?limit=5000' | python3 -c 'import json,sys; a=[s[\"age_secs\"] for s in json.load(sys.stdin)]; assert 0 < len(a) <= 1000 and a == sorted(a), a'"
check "journal size capped"                on_router "systemd-analyze cat-config systemd/journald.conf | grep -q '^SystemMaxUse=256M'"
check "management thread at lower priority" on_router 'p=$(systemctl show -p MainPID --value ephemerisd); for t in /proc/$p/task/*; do [ "$(cat $t/comm)" = eph-mgmt ] && cut -d" " -f19 $t/stat; done | grep -qx 10'
ip netns exec ci-hb iperf3 -s -D -1
sleep 0.5
check "TCP B->A on A's session"            ip netns exec ci-ha iperf3 -c 10.10.2.10 -t3 -R
# With a default route via host B, 8.8.8.8 is forwarded to B (which drops
# it): the router no longer answers Net Unreachable.
check "resources: CPU, memory, disk"       sh -c "${SSH[*]} ephctl --json system resources | grep -q '\"available\": [1-9]' && ${SSH[*]} ephctl system resources | grep -q '^Disk /var: .* free of'"
check "resources: capacity table"          sh -c "${SSH[*]} ephctl system resources | grep -q '^Next hops (forwarding table)'"
check "resources: worker threads measured" sh -c "${SSH[*]} ephctl --json system resources | grep -q '\"eph-worker-0\"'"
check "live route add"                     sh -c "${SSH[*]} ephctl route add 0.0.0.0/0 10.10.2.10 && ! ip netns exec ci-ha ping -c1 -W1 8.8.8.8 | grep -qi 'net unreachable'"
check "live route delete"                  sh -c "${SSH[*]} ephctl route del 0.0.0.0/0 && ip netns exec ci-ha ping -c1 -W1 8.8.8.8 | grep -qi 'From 10.10.1.1 .*net unreachable'"

# ------------------------------------------------------------ router access
# The portal and SSH on lan-a's own address (inside), through the host path
# (eph-host); never on lan-b, which is outside, whatever the config says.
echo "Router access on data-plane interfaces:"
sed 's|^address = "10.10.1.1/24"$|address = "10.10.1.1/24"\nmanagement = ["https", "ssh"]|' "$WORK/ephemeris.toml" > "$WORK/access.toml"
on_router "cat > /run/access.toml" < "$WORK/access.toml"
check "offer the portal and SSH on lan-a"   on_router "ephctl config load /run/access.toml && ephctl config commit"
check "portal from lan-a (10.10.1.1:8443)"  wait_for 30 "the portal on lan-a" sh -c "[ \"\$(ip netns exec ci-ha curl -sk -o /dev/null -w '%{http_code}' --max-time 5 https://10.10.1.1:8443/)\" = 200 ]"
check "SSH from lan-a (10.10.1.1:22)"       ip netns exec ci-ha ssh -q -i "$WORK/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes root@10.10.1.1 true
check "sshd sees the real client address"   on_router "journalctl -u ssh --no-pager | grep -q 'from 10.10.1.10 port'"
check "not on lan-b (outside): portal"      sh -c "! ip netns exec ci-hb curl -sk -o /dev/null --max-time 5 https://10.10.2.1:8443/"
check "not on lan-b (outside): SSH"         sh -c "! ip netns exec ci-hb ssh -q -i '$WORK/key' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes root@10.10.2.1 true"
sed 's|^address = "dhcp"$|address = "dhcp"\nmanagement = ["ssh"]|' "$WORK/access.toml" > "$WORK/access-wan.toml"
on_router "cat > /run/access-wan.toml" < "$WORK/access-wan.toml"
check "outside access is refused"           sh -c "${SSH[*]} ephctl config load /run/access-wan.toml 2>&1 | grep -q 'only be reached on inside interfaces'"
check "turn it off again"                   on_router "ephctl config rollback 1"
check "portal from lan-a closed again"      wait_for 15 "lan-a closed" sh -c "! ip netns exec ci-ha curl -sk -o /dev/null --max-time 3 https://10.10.1.1:8443/"

# ------------------------------------------------------------ SSH keys only
echo "SSH keys only:"
{ cat "$WORK/ephemeris.toml"; printf '\n[ssh]\npassword_login = false\n'; } > "$WORK/sshkeys.toml"
on_router "cat > /run/sshkeys.toml" < "$WORK/sshkeys.toml"
check "turn SSH passwords off"              on_router "ephctl config load /run/sshkeys.toml && ephctl config commit"
check "SSH password refused"                wait_for 15 "sshd to reload" sh -c "! sshpass -p '$PASSWORD' ssh -q -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o ConnectTimeout=5 root@127.0.0.1 true"
check "SSH key still works"                 on_router true
check "passwords back after rollback"       sh -c "${SSH[*]} ephctl config rollback 1 && sleep 2 && sshpass -p '$PASSWORD' ssh -q -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o ConnectTimeout=5 root@127.0.0.1 true"

# ------------------------------------------------------------ logging
# Categories, levels changed at run time, the files under /var/log/ephemeris
# (created by systemd, private, capped), structured journal entries, and a
# packet trace limited to one host.
echo "Logging:"
check "log directory private"              sh -c "[ \"\$(${SSH[*]} stat -c %a /var/log/ephemeris)\" = 700 ]"
check "audit.log has the web login"         on_router "grep -q 'audit .*web login: admin' /var/log/ephemeris/audit.log"
check "journal entries carry the category"  on_router "journalctl -u ephemerisd TARGET=audit --no-pager | grep -q 'web login'"
check "debug for a while"                   sh -c "${SSH[*]} ephctl log set route debug --for 2m | grep -q 'debug for 2m'"
check "levels show it, with its timer"      sh -c "${SSH[*]} ephctl log levels | grep '^route' | grep -q 'tracing packets.*[12]m'"
on_router ephctl log host 10.10.1.10 >/dev/null
ip netns exec ci-ha ping -c1 -W1 8.8.8.8 >/dev/null 2>&1 || true
check "packet trace: why it was dropped"    wait_for 10 "a route trace line" on_router "ephctl log show -c route | grep -q 'drop no-route: icmp 10.10.1.10 -> 8.8.8.8'"
check "packet trace in debug.log"           wait_for 10 "debug.log" on_router "grep -q 'DEBUG route .*drop no-route' /var/log/ephemeris/debug.log"
check "debug isn't in the journal"          sh -c "! ${SSH[*]} journalctl -u ephemerisd --no-pager | grep -q 'drop no-route'"
check "the change is audited"               on_router "ephctl log audit | grep -q 'log category route set to debug for 2m'"
check "reset"                               sh -c "${SSH[*]} ephctl log reset && ${SSH[*]} ephctl log levels | grep '^route' | grep -qv tracing"
check "journal kept 90 days at most"        on_router "systemd-analyze cat-config systemd/journald.conf | grep -q '^MaxRetentionSec=90day'"

# A config the data plane can't start with (a card that doesn't exist,
# written behind the API's back): the router must go back to the last one
# that worked by itself, keep management up, and say what happened.
on_router 'cp /var/lib/ephemeris/ephemeris.toml /run/good.toml && sed -i s/enp0s20/enp0s99/ /var/lib/ephemeris/ephemeris.toml && systemctl restart ephemerisd' || true
check "bad config falls back by itself"    wait_for 60 "the fallback" on_router "ephctl status | grep -q 'newer config failed'"
check "last good config restored"          on_router "cmp -s /var/lib/ephemeris/ephemeris.toml /run/good.toml && ls /var/lib/ephemeris/ephemeris.toml.failed-*"
# (The restart means lan-b asks for its lease again: allow it a moment.)
check "forwarding again after the fallback" wait_for 60 "forwarding" ip netns exec ci-ha ping -c3 -i0.2 -W1 10.10.2.10

# ------------------------------------------------------------ PPPoE
# A real, independent PPPoE implementation plays the ISP: rp-pppoe's
# pppoe-server with pppd, requiring CHAP and handing out 10.10.9.2 and a DNS
# server. lan-b switches from DHCP to PPPoE (a commit, applied live), and
# back afterwards (a rollback).
echo "PPPoE:"
modprobe ppp_generic 2>/dev/null || true
printf '"ephemeris" * "ci-s3cret" *\n' > /etc/ppp/chap-secrets
printf 'require-chap\nlcp-echo-interval 5\nlcp-echo-failure 3\nms-dns 10.10.9.53\nnoipdefault\nnodefaultroute\nmtu 1492\nmru 1492\ndebug\nlogfile %s/pppd.log\n' "$LOGS" > "$WORK/pppoe-options"
ip netns exec ci-hb pppoe-server -I eth0 -L 10.10.9.1 -R 10.10.9.2 -N 4 -O "$WORK/pppoe-options" \
    > "$LOGS/pppoe-server.log" 2>&1 || echo "pppoe-server didn't start" >> "$LOGS/pppoe-server.log"
sed 's/^address = "dhcp"$/address = "pppoe"/' "$WORK/ephemeris.toml" > "$WORK/pppoe.toml"
printf '\n[interface.pppoe]\nusername = "ephemeris"\npassword = "ci-s3cret"\n' >> "$WORK/pppoe.toml"
on_router "cat > /run/pppoe.toml" < "$WORK/pppoe.toml"
check "switch lan-b to PPPoE"              on_router "ephctl config load /run/pppoe.toml && ephctl config commit"
check "PPPoE session up (CHAP)"            wait_for 60 "a PPPoE session" on_router "ephctl wan | grep lan-b | grep pppoe | grep up | grep -q '10.10.9.2/32'"
check "DNS from IPCP"                      sh -c "${SSH[*]} ephctl --json wan | grep -q 10.10.9.53"
check "traffic over PPPoE (NAT)"           wait_for 30 "ping over PPPoE" ip netns exec ci-ha ping -c3 -i0.2 -W1 10.10.9.1
check "back to DHCP"                       on_router "ephctl config rollback 1"
check "forwarding again over DHCP"         wait_for 60 "forwarding" ip netns exec ci-ha ping -c3 -i0.2 -W1 10.10.2.10

# ------------------------------------------------------------ VLANs
# A second interface on lan-a's card: VLAN 10, next to the untagged lan-a.
# Host A gets a VLAN device for it. QEMU's virtio-net filters VLAN tags
# nobody registered, so this also checks the router opens the card up
# (promiscuous mode) rather than relying on the kernel's VLAN devices.
echo "VLANs:"
modprobe 8021q 2>/dev/null || true
printf '\n[[interface]]\nname = "lan-a10"\ndevice = "enp0s19"\nvlan = 10\naddress = "10.10.10.1/24"\n' \
    | cat "$WORK/ephemeris.toml" - > "$WORK/vlan.toml"
on_router "cat > /run/vlan.toml" < "$WORK/vlan.toml"
check "add a VLAN interface (restart)"     on_router "ephctl config load /run/vlan.toml && ephctl config commit && ephctl restart"
check "VLAN interface running"             wait_for 60 "lan-a10" on_router "ephctl status | grep lan-a10 | grep -q 'enp0s19.10'"
ip -n ci-ha link add link eth0 name eth0.10 type vlan id 10
ip -n ci-ha addr add 10.10.10.10/24 dev eth0.10
ip -n ci-ha link set eth0.10 up
check "ping the router on VLAN 10"         wait_for 30 "the router on VLAN 10" ip netns exec ci-ha ping -c3 -i0.2 -W1 10.10.10.1
check "untagged lan-a still works"         wait_for 60 "lan-a" ip netns exec ci-ha ping -c3 -i0.2 -W1 10.10.1.1
ip -n ci-ha route add 10.10.2.0/24 via 10.10.10.1 dev eth0.10
check "VLAN 10 routed out to lan-b"        wait_for 30 "forwarding from VLAN 10" ip netns exec ci-ha ping -c3 -i0.2 -W1 10.10.2.10
ip -n ci-ha route del 10.10.2.0/24 via 10.10.10.1 dev eth0.10
ip -n ci-ha link add link eth0 name eth0.20 type vlan id 20
ip -n ci-ha addr add 10.10.20.10/24 dev eth0.20
ip -n ci-ha link set eth0.20 up
# (Counted on the router with ephctl: the restart above ended the
# portal's login session.)
check "a VLAN not configured is dropped"   sh -c "! ip netns exec ci-ha ping -c2 -i0.2 -W1 10.10.20.1 && ${SSH[*]} ephctl --json status | grep -q '\"vlan\": [1-9]'"
ip -n ci-ha link del eth0.20
ip -n ci-ha link del eth0.10
check "remove it again (restart)"          on_router "ephctl config rollback 1 && ephctl restart"
check "forwarding again without VLANs"     wait_for 60 "forwarding" ip netns exec ci-ha ping -c3 -i0.2 -W1 10.10.2.10

# ------------------------------------------------------------ updates
if [[ -n $UPDATE_DIR ]]; then
    echo "A/B update to $UPDATE_VERSION:"
    check "newer version offered"          sh -c "${SSH[*]} ephctl system check | grep -q 'Newer version available: $UPDATE_VERSION\.'"
    check "check shows no log chatter"     sh -c "! ${SSH[*]} ephctl system check | grep -qiE 'discovered|acquir|gpg:'"
    check "update starts"                  sh -c "${SSH[*]} ephctl system update"
    # The new UKI is installed last, with a boot counter (+3-0): when it's
    # there, the whole update is in place.
    check "update installed"               wait_for 300 "new UKI" sh -c "${SSH[*]} 'ls \$(bootctl --print-esp-path)/EFI/Linux' | grep -q '_${UPDATE_VERSION}_x86-64+3-0.efi'"
    check "update job succeeded"           sh -c "${SSH[*]} systemctl show -p Result --value ephemeris-update.service | grep -q success"
    check "status says: installed, reboot"  wait_for 30 "installed state" sh -c "${SSH[*]} ephctl system status | grep -q '$UPDATE_VERSION is installed'"
    on_router ephctl system reboot >/dev/null 2>&1 || true
    sleep 10
    check "router comes back"              wait_for 300 "SSH after update reboot" on_router true
    check "runs $UPDATE_VERSION"           wait_for 30 "new version" sh -c "[ \"\$(${SSH[*]} cat /usr/lib/ephemeris/version)\" = '$UPDATE_VERSION' ]"
    check "new version blessed"            wait_for 120 "boot counter removed" sh -c "${SSH[*]} 'ls \$(bootctl --print-esp-path)/EFI/Linux' | grep -q '_${UPDATE_VERSION}_x86-64.efi\$'"
    check "config and password survive"    sshpass -p "$PASSWORD" ssh -q -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no root@127.0.0.1 grep -q lan-b /var/lib/ephemeris/ephemeris.toml
    check "still forwarding"               wait_for 60 "forwarding" ip netns exec ci-ha ping -c3 -i0.2 -W2 10.10.2.10
fi

on_router journalctl -b --no-pager > "$LOGS/journal.log" 2>&1 || true
# The boot before the A/B update reboot too: most checks run there.
on_router journalctl -b -1 --no-pager > "$LOGS/journal-previous-boot.log" 2>&1 || true
on_router systemctl poweroff >/dev/null 2>&1 || true
echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
