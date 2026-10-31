# Threat model

What Ephemeris protects, where its trust boundaries are, how each could be
attacked, and what stops it. It follows OWASP's Secure by Design process
and uses STRIDE (Spoofing, Tampering, Repudiation, Information disclosure,
Denial of service, Elevation of privilege) to walk each boundary. Keep it
current: a feature that adds a boundary, or moves one, updates this file.

## What's worth protecting

| Asset | Why |
|---|---|
| Traffic between networks | Confidentiality and integrity of what passes through; the router must forward only what its policy allows |
| The filtering and NAT policy | An outside host must not reach inside hosts unless invited |
| Router control | Whoever controls the router controls the network: config, routes, SSH, updates |
| Credentials | Admin password hash, API token, the router's SD-WAN key pair and pre-shared keys, PPPoE password |
| The software itself | Secure Boot keys and the release-signing key decide what a router will run |
| Availability | A router that falls over takes every network behind it down |

## Trust boundaries

```text
            internet / ISP                         other sites
                 │  (B1: outside interfaces)            │ (B4: SD-WAN tethers)
   ┌─────────────┴──────────────────────────────────────┴────────────┐
   │ data plane (ephemerisd workers, AF_XDP)                         │
   │      │ (B5: host path, eph-host)       │ (B6: control plane:    │
   │      ▼                                 ▼  DHCP, PPPoE punts)    │
   │  sshd, nginx ──▶ API (ephemerisd, loopback)                     │
   └──────┬──────────────────────────────▲──────────────────────────┘
          │ (B2: inside interfaces)       │ (B3: management NIC)
       your networks                  operators
   (B7: build and release pipeline, outside the router: what it runs)
```

## B1: outside interfaces (the internet, the ISP)

The most exposed boundary: anyone on the internet can send packets here.

| Threat | Mitigation |
|---|---|
| **S** Spoofed sources (inside addresses, the router's own, martians) | Packet filter refuses martians, spoofed and router-owned sources, source routing, bad fragments (chapter 14) |
| **T/I** Unsolicited traffic to inside hosts | Outside interfaces only let replies in (`allow_new_sessions = false`); stateful sessions, TCP state checks; source NAT |
| **D** Floods, malformed packets | Bounded tables (sessions, NAT, neighbours, punt queues); rate-limited ICMP errors and ARP; every parser and the whole pipeline fuzzed (no packet may panic it) |
| **E** Reaching SSH or the portal | Never offered on outside interfaces: refused by the config and again per packet by the data plane (chapter 19) |
| **S/T** Rogue DHCP / PPPoE server on the ISP link | Accepted values validated; network-supplied text cleaned before it's logged or shown (log injection, terminal escapes) |

**Residual:** volumetric floods beyond line rate are out of the router's
hands, and need upstream filtering.

## B2: inside interfaces (your networks)

Trusted more, but not fully: a compromised laptop or a guest is here too.

| Threat | Mitigation |
|---|---|
| **S** ARP spoofing of the router or hosts | Neighbours learned only from on-link senders; a conflicting ARP isn't believed, it triggers a check |
| **E** Reaching SSH or the portal from any inside host | Off by default; per interface (`management`), optionally limited to source prefixes (`management_from`); only the interface's own address |
| **T** Forged log entries via DHCP hostnames | Cleaned at the source and escaped at the writer (ASVS V16.4.1) |
| **D** DHCP exhaustion, punt floods | Bounded lease pool and control queue; drops counted |

**Residual:** an inside host can still attack other inside hosts on the
same network: that's switching, not routing. Use VLANs to separate.

## B3: management NIC (operators)

| Threat | Mitigation |
|---|---|
| **S** Password guessing | Lockout per address, global slowdown, nginx rate limit; yescrypt hashes; common passwords refused |
| **S** Session theft | 256-bit tokens, HttpOnly + Secure + SameSite=Strict cookies; idle and absolute timeouts; all sessions end on password change |
| **T** CSRF, DNS rebinding, clickjacking | Origin and Host checks, a required custom header, frame-ancestors none, strict CSP |
| **I** Sniffing | HTTPS only (TLS 1.2/1.3), HSTS; plain HTTP stays on loopback |
| **R** Who changed what | Audit trail in its own file (`audit.log`), out of reach of other logs |
| **E** SSH with a stolen password | Key-only SSH available (`[ssh] password_login = false`) |

**Residual:** a single admin account (shared by everyone who manages the
router); per-person accounts and roles are future work.

## B4: SD-WAN tethers (other sites)

| Threat | Mitigation |
|---|---|
| **S/T** Forged or altered tether packets | An AEAD on every packet, probes included (AES-256-GCM or ChaCha20-Poly1305, chosen inside the authenticated handshake, so it can't be downgraded); packets that don't authenticate are dropped |
| **S** Posing as another site | Sites with a public key: a Noise `IKpsk2` handshake (WireGuard's pattern) proves the peer holds that key pair's private key, plus the pre-shared key if set. Sites without one: per-pair pre-shared keys |
| **I** A key stolen later decrypting recorded traffic | Sites with a public key: fresh session keys every two minutes from ephemeral X25519 keys that are then forgotten (forward secrecy) |
| **T** Replay | Per-sender counters within each session key; nonces never reused (new keys per session; run numbers for pre-shared keys). A replayed initiation gets an answer, but its keys are never used: the responder only switches to keys a packet has proven |
| **D** Handshake floods (each costs key exchanges) | mac1 (keyed with the receiver's public key) drops junk before any key exchange; at most 20 handshake messages a second per worker reach the control plane, and at most 5 initiations a second per site are answered |
| **T** Redirecting a tether to another address | A tether only follows its peer on packets that authenticate and aren't replays; handshake messages never move one; address announcements are sealed like data |
| **E** A tether used to reach the router's SSH or portal | The host path refuses anything that came through a tether |

**Residual:** sites still on a pre-shared key have no forward secrecy (a
stolen key decrypts recorded traffic): give them a public key. A stolen
router identity (`/var/lib/ephemeris/overlay-identity`) lets someone pose
as that router until its public key is replaced on the others. A flood of
initiations that pass mac1 (from someone who knows the public key) can
delay a site's rekey by up to the rate limit; WireGuard's cookie reply
isn't implemented yet.

## B5: the host path (data plane to sshd and nginx)

| Threat | Mitigation |
|---|---|
| **E** The host used to send arbitrary traffic out | Only replies from ports 22 and 8443, only towards an inside interface |
| **S** Packets forged into `eph-host` | The device is local to the router; only ephemerisd writes to it |

## B6: control plane inputs (DHCP, PPPoE)

| Threat | Mitigation |
|---|---|
| **D/E** Malformed DHCP or PPPoE messages | Bounds-checked parsers in safe Rust (fuzzed); bounded queue from the workers |

## Inside the router

| Threat | Mitigation |
|---|---|
| **E** A bug in packet handling becoming code execution | Packet parsing, routing and forwarding are safe Rust (`forbid(unsafe_code)`); the rest of the `unsafe` code is audited, documented and lint-enforced |
| **E** A compromised ephemerisd taking over the system | systemd sandbox: read-only system, its own state only, limited capabilities and address families |
| **T** Persistent tampering | Read-only root with dm-verity; Secure Boot; A/B slots with automatic fallback |
| **D** A worker crash | Release builds abort on panic and systemd restarts ephemerisd; fuzzing keeps packets from causing one |

## B7: build and release (what routers run)

| Threat | Mitigation |
|---|---|
| **T** A malicious dependency | `cargo-deny` (RustSec advisories, licences, crates.io only), Dependabot with a cooldown, `Cargo.lock` with `--locked` |
| **T** A compromised GitHub Action | Every action pinned to a commit |
| **E** A pull request reaching the signing keys | Keys only in the `release-signing` environment, usable from `v*` release tags alone (a release builds and tests its own image); other builds use throwaway keys |
| **T** A tampered image or update | Secure Boot signature; GPG-signed `SHA256SUMS`, checked by the router before installing; SLSA build provenance; SBOM per release |
| **T** An unexpected update | Routers never update or reboot by themselves: an operator starts both |

**Residual:** the maintainer's GitHub account is a single point of trust
(protect it with a hardware key); the signing keys are GitHub secrets, not
in an HSM.
