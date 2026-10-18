# 5. The Proxmox lab, and what virtualisation changes

## Topology

```
                       vmbr0 (your LAN: management + internet)
                         │
                ┌────────┴──────────┐
  client-a ─────┤ vmbr10  r1  vmbr20├───── client-b
  10.10.1.10    │ ens19       ens20 │      10.10.2.10
  (LXC 9101)    └───────────────────┘      (LXC 9102)
                ephemeris-r1 (VM 9100)
                ens18 = management (DHCP)
```

`vmbr10` and `vmbr20` are Linux bridges with **no physical port**, like two
unplugged switches. The only path between them is through the router VM, so
if client-a can reach client-b, our code routed it.

## Step by step

### 1. On the Proxmox host (as root): the lab network

Copy `lab/proxmox/create-lab.sh` and `lab/proxmox/deploy-image.sh` to the
host, then:

```bash
./create-lab.sh
```

This creates the bridges `vmbr10` and `vmbr20`, plus containers 9101 and
9102, each with iperf3, tcpdump and mtr.

### 2. On the Proxmox host: the router, from a release image

```bash
SSH_KEY=/root/id_ed25519.pub ./deploy-image.sh
```

This downloads the latest image (e.g. `ephemeris_0.5.0.2_x86-64.qcow2`) from GitHub Releases and
creates VM 9100 (UEFI, 3 virtio NICs). It generates an admin password, and
passes its hash, the hostname, a two-port router config and (optionally,
with `SSH_KEY=`) your SSH key into the VM as systemd credentials. It boots
the VM and prints its management IP and the password, once.

Deploying the qcow2 by hand instead (Proxmox GUI: import the disk, set
BIOS to OVMF/UEFI, add an EFI disk without pre-enrolled keys)? Then the
router generates the password itself on its first boot, shows it on the
console, and waits until you press Enter, so it can't scroll away unseen. Then:

```bash
ssh root@<router-ip>
```

```bash
journalctl -u ephemerisd -f
```

How the image works is covered in chapter 8.

*Developing instead?* For a mutable Debian VM where you build from source,
use the Debian cloud image with `lab/router/bootstrap.sh`, and
`lab/netns/selftest.sh` for a quick check. That's handy for fast
edit-build-run loops before cutting a release.

### 3. From the clients

```bash
pct enter 9101
```

```bash
ping 10.10.1.1          # the router's near side
```

```bash
ping 10.10.2.10         # through the router (first one may drop: ARP)
```

```bash
traceroute -n 10.10.2.10   # shows 10.10.1.1 as hop 1: Time Exceeded works
```

```bash
iperf3 -c 10.10.2.10 -P4   # run 'iperf3 -s' in client-b first
```

Watch the `ephemerisd` log: every few seconds it prints counters and the
neighbour (ARP) table.

## What's different in a VM, and why it matters

**virtio_net.** This is the paravirtual NIC. It's a fake device whose
"hardware" is really QEMU and the host kernel (vhost-net). It supports native
XDP, so our program runs in the guest's driver. Zero-copy AF_XDP for virtio
arrived in Linux 6.11–6.12 and also needs host support. If it isn't available
you get copy mode, which is still far faster than the normal stack.

**Multiqueue.** `queues=2` on a Proxmox NIC gives it 2 RX/TX queue pairs,
which RSS spreads flows across. Match `workers` in the config to it. If the
NIC has more queues than you have workers, traffic hashed to the extra queues
is dropped (the XDP program falls back to `XDP_DROP`). `ephemerisd`
warns about this at startup.

**The ceiling is the host, not your code.** Every packet into the VM crosses
the host's bridge, tap device and vhost thread. That's often 1–3 Mpps per
queue regardless of how fast the guest is. To measure *our* code rather than
virtio, Proxmox can pass a real NIC into the VM:

- *PCI passthrough* gives the whole NIC to the VM.
- *SR-IOV* gives the VM a "virtual function", a hardware slice of the NIC.

Intel X710/E810 and Mellanox ConnectX cards support both, plus AF_XDP
zero-copy. That's the setup for serious benchmarks.

**`cpu=host`.** Gives the guest the real CPU's features (AVX2 etc.) and
accurate cache info. The lab script sets it.

## The checksum-offload trap (the #1 "ping works but TCP doesn't" bug)

Modern NICs compute TCP/UDP checksums in hardware, so the OS leaves the
checksum field blank and marks the packet "please fill in" (`CHECKSUM_PARTIAL`).
They also accept 64 KB "super-packets" and split them (TSO/GSO).

Inside a single Proxmox host there's no real NIC on the path. Normally the
kernel quietly finishes the job where needed. But we take packets *before*
the kernel's normal path, so we can receive a TCP segment with a blank
checksum, forward it faithfully, and the receiver drops it as corrupt. Ping
works, because ICMP checksums are always computed in software. TCP silently
doesn't.

In **native** XDP mode, virtio_net tells the host "I can't accept partial
checksums or super-packets" (it turns off those guest offloads), so the host
fixes packets up before delivering them. In **generic** mode that doesn't
happen. Belt and braces: the lab clients run
`ethtool -K eth0 tx off tso off gso off` at boot, and the netns self-test
does the same.

Real router NICs don't have this problem with packets from real wires. It's
a virtual-lab artefact, but a very educational one.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `XDP attached … in Generic mode` | The driver refused native mode. Check `dmesg`. For virtio: `ethtool -K ens19 gro off lro off`. Make sure MTU ≤ 3000 |
| `bind(...): Device or resource busy` | Another XDP program or AF_XDP socket is on the queue. Check `ip link show ens19` / `bpftool net` |
| `has 4 RX queues but 2 workers` | `ethtool -L ens19 combined 2`, or raise `workers` |
| Ping to router works, through router doesn't | Watch `drops[neighbor-miss=…]`: the far host isn't answering ARP. Check its IP and gateway |
| `drops[not-for-us]` climbing | Frames for other MACs arrive (normal on a bridge with flooding); harmless |
| Ping works, TCP stalls | See the checksum-offload section above |
| `kernel-drops` / `fill-empty` climbing | The worker can't keep up, or the fill ring is starved. Add workers/queues, pin CPUs, try `busy_poll = true` |
| Lost SSH after starting | You listed the management NIC as a data interface. Use the Proxmox console (`qm terminal 9100`) and fix the config |

Useful tools on the router VM:

- `ip -d link show ens19`: shows the attached XDP program and its mode.
- `bpftool prog` / `bpftool map`: inspect loaded programs and maps.
- `ethtool -S ens19`: driver counters, including XDP ones.
- `perf top`: see where CPU time goes.
- `tcpdump` *on the clients*. On the router's data NICs tcpdump won't see
  incoming packets, because XDP redirects them before the point where tcpdump
  listens. That's a nice proof that the kernel stack really is bypassed.
