#!/usr/bin/env bash
# Deploy a Ephemeris router VM on Proxmox VE from a released OS image.
# Run as root on the Proxmox host.
#
#   ./deploy-image.sh                                  # latest release
#   ./deploy-image.sh 0.3.0                            # specific version
#   IMAGE=/root/ephemeris_0.5.0.2_x86-64.qcow2 ./deploy-image.sh # local file
#   SSH_KEY=/root/id_ed25519.pub ./deploy-image.sh     # also install an SSH key
#
# It prints the generated admin password at the end.
#
# The VM gets three virtio NICs: ens18 = management (DHCP on MGMT_BRIDGE),
# ens19 = lan-a, ens20 = lan-b. Per-router settings (SSH key, hostname, router
# config) are handed to the image as systemd credentials through SMBIOS, so
# the image itself is identical for every router.
set -euo pipefail

REPO=${REPO:-mornev-sudo/ephemeris}
VERSION=${1:-latest}
VMID=${VMID:-9100}
NAME=${NAME:-ephemeris-r1}
STORAGE=${STORAGE:-local-lvm}
MGMT_BRIDGE=${MGMT_BRIDGE:-vmbr0}
LAN_A=${LAN_A:-vmbr10}
LAN_B=${LAN_B:-vmbr20}
CORES=${CORES:-4}
MEMORY=${MEMORY:-2048}
QUEUES=${QUEUES:-2}          # virtio queues per data NIC = ephemerisd workers
DISK=${DISK:-8G}
SSH_KEY=${SSH_KEY:-}         # optional public key file for root@router
CONFIG=${CONFIG:-}           # ephemeris.toml to install; default: two-port lab config
IMAGE=${IMAGE:-}             # use this qcow2 instead of downloading
REPLACE=${REPLACE:-0}        # 1 = destroy an existing VM with this VMID first
CACHE=/var/lib/vz/template/ephemeris

die() { echo "error: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run as root on the Proxmox host"
command -v qm >/dev/null || die "this doesn't look like a Proxmox host"
[[ -z $SSH_KEY || -s $SSH_KEY ]] || die "SSH_KEY=$SSH_KEY is not a readable public key file"
command -v openssl >/dev/null || die "openssl is needed to hash the admin password"

# --- 1. get the image ----------------------------------------------------------
if [[ -z $IMAGE ]]; then
    mkdir -p "$CACHE"
    if [[ $VERSION == latest ]]; then
        base="https://github.com/$REPO/releases/latest/download"
    else
        base="https://github.com/$REPO/releases/download/v$VERSION"
    fi
    dir=$CACHE/$VERSION
    mkdir -p "$dir"
    # The image file is named after its build, e.g. ephemeris_0.5.0.2_x86-64.qcow2;
    # the release's VERSION file says which build it holds.
    build=$(curl -fsSL "$base/VERSION") || die "can't read $base/VERSION (is the repo private? then download the image yourself and set IMAGE=)"
    file=ephemeris_${build}_x86-64.qcow2
    echo "downloading $base/$file"
    curl -fL --progress-bar -o "$dir/$file" "$base/$file" || die "download failed"
    curl -fsSL -o "$dir/SHA256SUMS" "$base/SHA256SUMS"
    # SHA256SUMS also lists the update files, which aren't needed here.
    (cd "$dir" && sha256sum -c --ignore-missing SHA256SUMS) || die "checksum mismatch"
    IMAGE=$dir/$file
fi
[[ -s $IMAGE ]] || die "no image at $IMAGE"

# --- 2. per-router configuration -----------------------------------------------
if [[ -n $CONFIG ]]; then
    [[ -s $CONFIG ]] || die "no config at $CONFIG"
    config_text=$(cat "$CONFIG")
else
    config_text=$(cat <<TOML
# Written by deploy-image.sh on first boot. Edit on the router:
#   /var/lib/ephemeris/ephemeris.toml, then: systemctl restart ephemerisd
[dataplane]
workers = $QUEUES

[[interface]]
name = "lan"
device = "ens19"
address = "10.10.1.1/24"
role = "inside"

# The lab's "internet" side: only replies get in, and traffic leaving
# through it is source-NATed to 10.10.2.1.
[[interface]]
name = "wan"
device = "ens20"
address = "10.10.2.1/24"
role = "outside"
TOML
)
fi

# The admin password: generated here, printed at the end, and handed to the
# VM only as a SHA-512 crypt hash. (Deployed without this script, the router
# generates its own and shows it on the console instead.)
PASSWORD=$(head -c 600 /dev/urandom | LC_ALL=C tr -dc 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789' | cut -c1-20 |
    sed 's/\(.....\)\(.....\)\(.....\)\(.....\)/\1-\2-\3-\4/')
PWHASH=$(printf '%s' "$PASSWORD" | openssl passwd -6 -stdin)

b64() { base64 -w0; }
# Each "-smbios type=11" string becomes a systemd credential inside the VM.
args="-smbios type=11,value=io.systemd.credential:system.hostname=$NAME"
args+=" -smbios type=11,value=io.systemd.credential.binary:ephemeris.admin_password_hash=$(printf '%s' "$PWHASH" | b64)"
[[ -z $SSH_KEY ]] || args+=" -smbios type=11,value=io.systemd.credential.binary:ssh.authorized_keys.root=$(b64 <"$SSH_KEY")"
args+=" -smbios type=11,value=io.systemd.credential.binary:ephemeris.config=$(printf '%s\n' "$config_text" | b64)"

# --- 3. create the VM ----------------------------------------------------------
if qm status "$VMID" >/dev/null 2>&1; then
    [[ $REPLACE == 1 ]] || die "VM $VMID exists (set REPLACE=1 to destroy and redeploy it)"
    echo "destroying existing VM $VMID"
    qm stop "$VMID" --skiplock 1 >/dev/null 2>&1 || true
    qm destroy "$VMID" --purge 1
fi
for br in "$MGMT_BRIDGE" "$LAN_A" "$LAN_B"; do
    ip link show "$br" >/dev/null 2>&1 || die "bridge $br missing (create-lab.sh makes the lab bridges)"
done

echo "creating VM $VMID ($NAME)"
# bios=ovmf + efidisk: UEFI firmware, which boots systemd-boot from the image's
# ESP. pre-enrolled-keys=0 leaves Secure Boot off (the image isn't signed yet).
qm create "$VMID" --name "$NAME" --ostype l26 --machine q35 \
    --bios ovmf --efidisk0 "$STORAGE:1,efitype=4m,pre-enrolled-keys=0" \
    --cpu host --cores "$CORES" --memory "$MEMORY" --balloon 0 \
    --scsihw virtio-scsi-single \
    --scsi0 "$STORAGE:0,import-from=$IMAGE,discard=on,iothread=1" \
    --boot order=scsi0 --serial0 socket --vga serial0 \
    --net0 "virtio,bridge=$MGMT_BRIDGE" \
    --net1 "virtio,bridge=$LAN_A,queues=$QUEUES" \
    --net2 "virtio,bridge=$LAN_B,queues=$QUEUES" \
    --agent enabled=1 --onboot 1 \
    --description "Ephemeris router, image $(basename "$(dirname "$IMAGE")") ($(date -I))"
qm disk resize "$VMID" scsi0 "$DISK"   # /var grows into this on first boot
qm set "$VMID" --args "$args" >/dev/null
qm start "$VMID"

# --- 4. wait for the management address ----------------------------------------
echo -n "waiting for the router to boot"
ip=
for _ in $(seq 1 60); do
    sleep 3
    echo -n .
    out=$(qm guest cmd "$VMID" network-get-interfaces 2>/dev/null) || continue
    ip=$(printf '%s' "$out" | perl -MJSON::PP -e '
        my $ifs = decode_json(join "", <STDIN>);
        for my $i (@$ifs) {
            next unless $i->{name} eq "ens18";
            for my $a (@{ $i->{"ip-addresses"} || [] }) {
                if ($a->{"ip-address-type"} eq "ipv4") { print $a->{"ip-address"}; exit }
            }
        }') && [[ -n $ip ]] && break
done
echo
cat <<MSG

  ==================================================================
    Ephemeris router "$NAME" (VM $VMID) is up

    Web portal : https://${ip:-<management address>}:8443/   user: admin
    SSH/console: ssh root@${ip:-<management address>}
    Password   : $PASSWORD

    This password is shown once. It is not stored on this host.
  ==================================================================
MSG
[[ -n $ip ]] || echo "No management IP reported yet; console: qm terminal $VMID"
