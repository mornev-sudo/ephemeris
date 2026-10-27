# Disclaimer
This project was originally designed to help me understand how highly performant systems are designed from a software point of view. The entire project is completely vide-coded, because the point is not to understand the coding process itself, but rather how networking functions are implemented in code, since handling networking traffic is probably the most time-sensitive type of processing that software does in general. 

Since this is vide-coded, I cannot recommend that this software is deployed in any type of production environment. Even though I do my best to not write slot, it's destined to be limited in functionality, and my testing for general use and edge cases is extremely limited. I'm a network engineer with 12+ years of deep network design and operating knowledge, but I am definitely not a software engineer. Therefor I understand how networking products are meant to function, and what features are important for things to *work*, but the stability of the software will be dubious at best.

# Ephemeris

*An ephemeris is a table of where every celestial body is at any given
moment. A router keeps the same kind of table for networks: where every
prefix is, and the best way to reach it right now.*

An open-source, high-performance SD-WAN router for Linux, built from first
principles as a learning project. Written in Rust. Packets move through
AF_XDP and a hand-assembled eBPF program, with no DPDK or libbpf dependency.

> **Status: Phases 0–3 and 4a, plus source NAT.** Stateful IPv4 routing between subnets, with a
> per-core session table and an "allow new sessions" policy per interface. It
> ships as an immutable, boot-tested OS image. It's managed through a REST
> API, a web portal and the `ephctl` CLI, with live route and policy changes
> and commit/confirm/rollback. It updates itself A/B-style with automatic fallback, and
> boots only Ephemeris-signed code (Secure Boot) and installs only signed updates. Sites
> connect over an SD-WAN overlay across several WAN links, with per-application path
> selection and automatic failover.
> It's verified by CI in QEMU (including a full update) and in a Proxmox lab.

## How it fits together

```
           ┌──────────────── ephemerisd (one process) ────────────────┐
config ──▶ │ config.rs ──▶ FIB (DIR-24-8) ──▶ shared, read-only     │
           │                                                        │
           │  worker 0 (core 1)          worker 1 (core 2)          │
           │  ┌──────────────────┐       ┌──────────────────┐       │
           │  │ Pipeline         │ ◀───▶ │ Pipeline         │  ARP  │
           │  │ UMEM (frames)    │ neigh │ UMEM (frames)    │ sync  │
           │  │ XSK ens19 q0     │       │ XSK ens19 q1     │       │
           │  │ XSK ens20 q0     │       │ XSK ens20 q1     │       │
           │  └────────▲─────────┘       └────────▲─────────┘       │
           └───────────┼──────────────────────────┼─────────────────┘
                       │ AF_XDP rings (zero-copy) │
   kernel  ┌───────────┴──────────────────────────┴─────────────────┐
           │ XDP program in NIC driver: "queue N → socket N"        │
           └────────────────────────────────────────────────────────┘
```

| Crate | What it is | Runs on |
|---|---|---|
| [`eph-packet`](crates/eph-packet) | Zero-copy Ethernet/ARP/IPv4/ICMP header access and checksums | anywhere |
| [`eph-fib`](crates/eph-fib) | DIR-24-8 longest-prefix-match routing table | anywhere |
| [`eph-dataplane`](crates/eph-dataplane) | The forwarding logic: bytes in, verdict out. Session table, TCP state machine. No I/O | anywhere |
| [`eph-xdp`](crates/eph-xdp) | AF_XDP sockets, UMEM, rings, and the XDP program, written directly on syscalls | Linux |
| [`ephemerisd`](crates/ephemerisd) | The daemon: config, workers, REST API + web portal, live config changes | Linux (`--check` anywhere) |
| [`ephctl`](crates/ephctl) | CLI client of the management API | anywhere |
| [`image/`](image) | mkosi definition of Ephemeris OS, the bootable router image | built on Linux / CI |

## Hardware requirements

| | Minimum | Recommended |
|---|---|---|
| **CPU** | x86-64, 2 cores | 2-4 cores; one more per extra worker |
| **RAM** | 2 GB | 4 GB |
| **Disk** | 8 GB | 16 GB |
| **Firmware** | UEFI (Secure Boot supported, keys enrolled automatically) | UEFI with Secure Boot |
| **Network** | 3 NICs: management, inside, outside | NICs with native XDP (see below), multi-queue for more than one worker |

The minimum is what CI boot-tests every build on: a 2-core, 2 GB VM.

- **CPU:** x86-64 only, no ARM build yet. A packet worker can spin at 100%
  (`busy_poll`, or under load), so it needs a core to itself. The other core
  runs the portal, DHCP and PPPoE, SD-WAN probing and the OS. Each extra
  worker needs another core and another NIC queue.
- **RAM:** the tables are reserved at start-up:
  - per worker, the session table (about 300 bytes per session) and about
    32 MB of packet buffers (two cards, the default ring size);
  - shared, the forwarding table: 32-48 MiB;
  - plus the OS, nginx and ephemerisd.

  By default (`sessions.max_per_worker = "auto"`) the session tables are
  sized from the memory free at start: half of what's left after the packet
  buffers, the forwarding table and 256 MiB for the system. On a 2 GB
  machine with one worker that's around 2 million sessions. A fixed size
  that doesn't fit is refused at start (the router falls back to the last
  config that worked); one that only just fits is logged as a warning.
- **Disk:** the layout is fixed:
  - EFI system partition: 512 MB;
  - two root slots for A/B updates: 1.5 GB each, plus 64 MB of verity data
    each;
  - `/var`: at least 2 GB. It grows into the rest of the disk on first
    boot, and holds config history, leases, the journal (capped at
    256 MiB) and update downloads.
- **Network:** the management NIC stays with Linux (SSH, the portal over
  HTTPS). The others belong to the data plane; inside interfaces can offer
  SSH and the portal on their own address too (`management`, chapter 19).
  - **Any NIC works:** without native XDP the router falls back to generic
    XDP in copy mode, which is slower but correct.
  - **Native XDP with zero-copy is the fast path:** virtio_net (Proxmox),
    Intel i40e, ice, ixgbe and igc, and Mellanox mlx5.
  - **Several workers need several NIC queues:** `ethtool -L <dev>
    combined N`, or `queues=N` on Proxmox virtio NICs.
- **Huge pages:** optional. Packet buffers use them when `vm.nr_hugepages`
  reserves some.

`lab/proxmox/deploy-image.sh` creates a VM that meets these: 4 cores,
2 GB of RAM and an 8 GB disk by default, 3 virtio NICs, and UEFI (OVMF).

## Quick start

On macOS, Linux or any other machine (unit tests plus config validation):

```bash
cargo test --workspace
```

```bash
cargo run -p ephemerisd -- --check -c config/ephemeris.example.toml
```

Hostile input: `cargo test` already pushes a few hundred thousand malformed
packets through the pipeline. For coverage-guided fuzzing (needs nightly
and `cargo install cargo-fuzz`):

```bash
cd fuzz && cargo +nightly fuzz run pipeline
```

In Proxmox, you deploy a pre-built image. [CI](.github/workflows/image.yml) builds and boot-tests
an image for every push to `main`. Tagging a commit `v*` promotes that tested image to a GitHub
Release ([release.yml](.github/workflows/release.yml)) without rebuilding it.

1. Copy `lab/proxmox/create-lab.sh` and `deploy-image.sh` to the PVE host.
2. On the PVE host: `./create-lab.sh` creates two isolated bridges and two client containers.
3. On the PVE host: `SSH_KEY=/root/id_ed25519.pub ./deploy-image.sh` downloads the latest image, creates the router VM and boots it.
4. `deploy-image.sh` prints the router's address and its generated admin password. Open `https://<router-ip>:8443/` (the certificate is self-signed: its fingerprint is printed on the console) and sign in as `admin`, or `ssh root@<router-ip>` and use `ephctl status`. (Deployed by hand instead, e.g. through the Proxmox GUI, the router shows the password once on its console and waits for you to press Enter.) From client-a: `ping 10.10.2.10`.

See [docs/learn/08-immutable-image.md](docs/learn/08-immutable-image.md) for how the image works,
and [docs/learn/05-proxmox-lab.md](docs/learn/05-proxmox-lab.md) for the lab and troubleshooting.
For hacking on the router in a plain Debian VM instead, `lab/router/bootstrap.sh` builds from source.

## Learning guide

Plain-language explanations of everything in here, in reading order:

1. [The big picture: what a router actually does](docs/learn/01-big-picture.md)
2. [Packets are just bytes](docs/learn/02-packets.md)
3. [The routing table and longest-prefix match](docs/learn/03-routing-table.md)
4. [Going fast on Linux: XDP, eBPF, and AF_XDP](docs/learn/04-fast-path.md)
5. [The Proxmox lab, and what virtualisation changes](docs/learn/05-proxmox-lab.md)
6. [Code tour: following one packet through the source](docs/learn/06-code-tour.md)
7. [Stateful routing: sessions, both directions, and many cores](docs/learn/07-sessions.md)
8. [The immutable image: shipping a router, not a server](docs/learn/08-immutable-image.md)
9. [The management plane: API, web portal, CLI, and changing a running router](docs/learn/09-management-plane.md)
10. [A/B updates: upgrading a router you can't walk up to](docs/learn/10-ab-updates.md)
11. [Chain of trust: Secure Boot and signed updates](docs/learn/11-secure-boot.md)
12. [SD-WAN: many links, one network, the best path per application](docs/learn/12-sdwan.md)
13. [NAT at the edge: inside, outside, and many hosts behind one address](docs/learn/13-nat.md)
14. [The packet filter and MSS adjust: what a certified firewall always drops](docs/learn/14-packet-filter.md)
15. [DHCP: handing out addresses, and getting one](docs/learn/15-dhcp.md)
16. [PPPoE: dialling the ISP](docs/learn/16-pppoe.md)
17. [VLANs: many networks on one cable](docs/learn/17-vlans.md)
18. [Logging: what the router says, and how to make it say more](docs/learn/18-logging.md)
19. [Reaching the router itself: the host path](docs/learn/19-router-access.md)

To see the whole data path at once: [docs/packet-walk.html](docs/packet-walk.html),
an interactive packet walk. It shows every stage in code order, the function
that runs it and where a packet can be dropped, with scenarios to step
through (NAT and PPPoE out, the reply, SSH to the router, SD-WAN, an ARP
miss…). GitHub shows it as source: download it, or open it from a clone, in
a browser.

## Roadmap

- [x] **Phase 0: packet path.** AF_XDP I/O, ARP, static routes with LPM, ICMP, per-core workers, Proxmox lab
- [x] **Phase 1: stateful.** Per-core session table (5-tuple, forward/reverse), symmetric RSS, TCP state machine, aging, timer wheel
- [x] **Phase 2: management.** API daemon (gRPC/REST), candidate/commit/rollback config, `ephctl` CLI, web portal, live route updates (pointer swap)
- [x] **Phase 3: immutable OS.**
  - [x] 3a: mkosi image (read-only erofs root + dm-verity, writable /var, UKI), CI build + QEMU boot test + releases, Proxmox deploy script
  - [x] 3b: A/B root slots, systemd-sysupdate, boot counting, health-gated blessing and automatic fallback (tested in CI)
  - [x] 3c: Secure Boot signed boot chain (auto-enrolled keys) and signed, verified updates
  - [x] HTTPS for the portal and API (nginx, TLS 1.2/1.3), hardened systemd units
  - [ ] later: TPM measured boot / remote attestation
- [x] **Edge router basics:** inside/outside interface roles, source NAT (PAT to the interface, pools, rules), form-based configuration in the portal
- [x] **Hardening:** Common Criteria baseline packet filter (martian and spoofed sources, source-route/record-route options, invalid fragments), per-interface TCP MSS adjust
- [x] **DHCP:** server on inside interfaces (ranges, reservations, persistent leases, DNS passed on from the WAN), client on outside interfaces (address, gateway and default route applied live; /32 leases with an on-link gateway, classless static routes from option 121)
- [x] **PPPoE:** outside interfaces dial their ISP (RFC 2516 discovery, LCP with keepalives, PAP / CHAP-MD5, IPCP with DNS), 1492 MTU and MSS handled, applied live
- [x] **Reporting:** open sessions, packets/s, throughput and drops sampled every 5 s; live graphs in the portal (last hour), the same numbers on the dashboard and in `ephctl status`
- [x] **Resources and capacity:** CPU (per core, per thread), memory and huge pages, disk, worker busy %, and every table's usage against its limit (FIB, sessions, neighbours, NAT, DHCP pools, tethers)
- [x] **Bounded resources:** every session expires (timeouts per protocol and state following the NAT RFCs, per-application overrides, at most a day idle, closed within 10 minutes; a full table drops unanswered sessions first), session views show the newest 1000 and are gathered only while viewed, a bounded control-plane queue, a capped journal and history, management at lower CPU priority
- [x] **VLANs (802.1Q):** several interfaces per card, each with its own tag (and at most one untagged), PPPoE over a VLAN, tag stripping and VLAN filtering handled on the NIC
- [x] **Logging:** a category per subsystem (17) with its own level, raised at run time with a timer; packet tracing in the data plane filtered by host and rate-limited; the journal (info and up, 90 days), a capped debug.log and audit.log in /var/log/ephemeris, `ephctl log`
- [x] **Router access on inside interfaces:** the portal and SSH on an inside interface's own address (`management = ["https", "ssh"]`, optionally limited to source prefixes), through a tun host path; never on outside interfaces (refused by the config and by the data plane)
- [ ] **Next for the edge:** destination NAT / port forwarding, `ephsh` router CLI
- [ ] **Performance and capacity:**
  - [ ] Benchmarks: a microbenchmark of the per-packet pipeline (CPU ceiling per core, no NIC), and a lab test with a traffic generator (pktgen / TRex) for real packets per second on Proxmox and on hardware NICs
  - [x] Memory-aware sizing: `sessions.max_per_worker = "auto"` (the default) sized from the RAM available at start, and a start-up check that refuses or warns when the reserved tables (sessions, FIB, packet buffers) exceed what the machine has
  - [ ] Scaling beyond one core per flow: spread PPPoE traffic (NICs can't hash inside PPPoE, so a PPPoE WAN lands on one queue) and SD-WAN tether traffic (one UDP flow per tether) across workers
  - [ ] Jumbo frames: interface MTUs above 1500 (bigger packet buffers, the NIC's own MTU raised)
- [ ] **Phase 4: SD-WAN.**
  - [x] 4a: UDP overlay tethers over multiple WANs, in-place encapsulation, probing (latency/jitter/loss), app-aware path selection with SLAs and hysteresis, failover, MSS clamping, path MTU
  - [x] 4b (first half): tether encryption and authentication with per-tether pre-shared keys (ChaCha20-Poly1305), replay protection
  - [x] Sites: hub / spoke / mesh roles decide who connects, tethers generated per WAN, routing through hubs, per-pair keys managed in the portal and `ephctl`, peers without a fixed address learned from their packets (works behind NAT)
  - [ ] 4b (second half): WireGuard-style handshake (forward secrecy, key rotation)
  - [ ] 4c: central controller; FRR/BGP for LAN-side routes

## Security

How to report a vulnerability, and how to verify a release (signatures,
build provenance, SBOM): [SECURITY.md](SECURITY.md). What the router
protects and how: [docs/threat-model.md](docs/threat-model.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
