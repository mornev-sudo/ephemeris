#!/usr/bin/env bash
# Build the Ephemeris lab network on a Proxmox VE host: two isolated bridges and
# two client containers. The router itself comes from deploy-image.sh.
# Run as root on the PVE node.
#
#                       vmbr0 (your normal LAN, management + internet)
#                         │
#                ┌────────┴────────┐
#   client-a ────┤ vmbr10  r1  vmbr20 ├──── client-b
#   10.10.1.10   │ ens19       ens20 │     10.10.2.10
#   (LXC)        └─────────────────┘     (LXC)
#                 ephemeris-r1 (VM)
#                 ens18 = mgmt (DHCP on vmbr0)
#
# vmbr10 and vmbr20 are internal bridges with no physical port: the only way
# between them is through the router VM.
#
# Review the variables below before running. The script is safe to re-run:
# anything that already exists is skipped.
set -euo pipefail

NODE=$(hostname)
STORAGE=${STORAGE:-local-lvm}            # where VM/CT disks go
MGMT_BRIDGE=${MGMT_BRIDGE:-vmbr0}
LAN_A=${LAN_A:-vmbr10}
LAN_B=${LAN_B:-vmbr20}
CLIENT_A_ID=${CLIENT_A_ID:-9101}
CLIENT_B_ID=${CLIENT_B_ID:-9102}
# Client OS template. Debian 12 works on every Proxmox 8; older Proxmox
# releases reject newer Debian 13 point releases ("unsupported debian version").
CT_TEMPLATE=${CT_TEMPLATE:-debian-12-standard}

[[ $EUID -eq 0 ]] || { echo "run as root on the Proxmox host"; exit 1; }
command -v qm >/dev/null || { echo "this doesn't look like a Proxmox host"; exit 1; }

# --- 1. internal bridges ------------------------------------------------------
bridges_changed=0
for br in "$LAN_A" "$LAN_B"; do
    if ! pvesh get "/nodes/$NODE/network/$br" >/dev/null 2>&1; then
        echo "creating bridge $br"
        pvesh create "/nodes/$NODE/network" --iface "$br" --type bridge --autostart 1 \
            --comments "Ephemeris lab (no uplink)"
        bridges_changed=1
    fi
done
if [[ $bridges_changed -eq 1 ]]; then
    pvesh set "/nodes/$NODE/network"   # apply (ifreload)
fi

# --- 2. client containers -----------------------------------------------------
TEMPLATE=$(pveam list local 2>/dev/null | awk -v t="$CT_TEMPLATE" '$1 ~ t {print $1}' | tail -n1)
if [[ -z $TEMPLATE ]]; then
    pveam update >/dev/null
    name=$(pveam available --section system | awk -v t="$CT_TEMPLATE" '$2 ~ t {print $2}' | tail -n1)
    [[ -n $name ]] || { echo "no $CT_TEMPLATE template available (see: pveam available --section system)"; exit 1; }
    pveam download local "$name"
    TEMPLATE="local:vztmpl/$name"
fi

client() { # id hostname bridge ip/len gateway
    local id=$1 name=$2 br=$3 ip=$4 gw=$5
    if pct status "$id" >/dev/null 2>&1; then
        echo "container $id exists, skipping"; return
    fi
    echo "creating container $id ($name)"
    # Start on the management bridge so it can install tools from the internet...
    pct create "$id" "$TEMPLATE" --hostname "$name" --storage "$STORAGE" \
        --cores 2 --memory 1024 --unprivileged 1 \
        --net0 "name=eth0,bridge=$MGMT_BRIDGE,ip=dhcp" --start 1
    sleep 5
    pct exec "$id" -- bash -c 'apt-get update -qq && apt-get install -y -qq iperf3 ethtool tcpdump mtr-tiny traceroute >/dev/null'
    # Disable checksum/segmentation offload on boot. Inside one Proxmox host,
    # packets otherwise travel with their checksum left for "the NIC" to fill
    # in, and there is no NIC on this path. See docs/learn/05-proxmox-lab.md.
    pct exec "$id" -- bash -c 'cat > /etc/systemd/system/lab-offload-off.service <<UNIT
[Unit]
Description=Disable NIC offloads for the Ephemeris lab
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/ethtool -K eth0 tx off tso off gso off
[Install]
WantedBy=multi-user.target
UNIT
systemctl enable lab-offload-off.service >/dev/null 2>&1'
    # ...then move it onto its isolated lab bridge behind the router.
    pct set "$id" --net0 "name=eth0,bridge=$br,ip=$ip,gw=$gw"
    pct reboot "$id"
}
client "$CLIENT_A_ID" client-a "$LAN_A" 10.10.1.10/24 10.10.1.1
client "$CLIENT_B_ID" client-b "$LAN_B" 10.10.2.10/24 10.10.2.1

cat <<MSG

Lab network is up.
  Clients:  pct enter $CLIENT_A_ID   /   pct enter $CLIENT_B_ID

Next, deploy the router from a release image:
  SSH_KEY=/root/id_ed25519.pub ./deploy-image.sh
MSG
