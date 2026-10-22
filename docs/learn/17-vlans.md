# 17. VLANs: many networks on one cable

## Why it exists

A router with three network cards can serve three networks. Most networks
want more than that: a LAN, a guest Wi-Fi, cameras and other IoT gear kept
apart, a management network for the switches. Buying a card per network
doesn't scale, and the switch is usually in another room anyway.

**VLANs** (IEEE 802.1Q) split one Ethernet into many. Every frame on the
cable between the switch and the router carries a small **tag** saying
which network it belongs to. The switch keeps the networks apart on its
other ports; the router treats each VLAN as an interface of its own, with
its own address, subnet, role, DHCP and MTU.

```toml
[[interface]]
name = "lan"
device = "ens19"
address = "10.10.1.1/24"          # untagged: the switch port's native VLAN

[[interface]]
name = "guest"
device = "ens19"                  # the same card...
vlan = 10                         # ...but frames tagged 10
address = "10.10.10.1/24"

[[interface]]
name = "cameras"
device = "ens19"
vlan = 20
address = "10.10.20.1/24"
allow_new_sessions = false        # cameras may answer, not start anything
```

One card carries any number of VLANs and **at most one untagged**
interface. On the switch, the port facing the router must be a **trunk**
that sends VLANs 10 and 20 tagged (and, for `lan`, its native VLAN
untagged).

In the portal: Configuration → **Interfaces**, pick the same **Network
card** again and fill in **VLAN**. `ephctl status`, the dashboard and the
logs show a VLAN interface as `ens19.10`, the way Linux names them.

Adding, removing or moving a VLAN interface changes which sockets the
router opens, so it takes effect after `ephctl restart` (the commit says
so). Everything else about it (address, role, DHCP...) changes live, like
any interface.

## The tag

Four bytes, slipped in between the source MAC and the type:

```
 0                 6                 12      14        16      18
+-----------------+-----------------+-------+---------+-------+---------
| destination MAC | source MAC      | 8100  | PCP|DEI | type  | payload
|                 |                 |       | |VID    | 0800  | (IPv4...)
+-----------------+-----------------+-------+---------+-------+---------
                                     tag protocol  ▲
                                     identifier    └ 3 bits priority, 1 bit
                                                     drop eligible, 12 bits
                                                     VLAN ID (1-4094)
```

- **0x8100** where the type would be says "a tag follows". The real type
  (IPv4, ARP, PPPoE) comes after it.
- **VLAN ID** 1-4094. 0 means "no VLAN, only a priority" (the router
  treats those frames as untagged); 4095 is reserved.
- **Priority (PCP)**: for switches that queue by it. The router ignores it
  coming in and sends 0.

Because the tag sits *inside* the Ethernet header, the frame grows by 4
bytes but the IP packet doesn't: the MTU of a VLAN interface is still 1500.

## How the data plane does it

Until now, interface = card = AF_XDP socket. VLANs break that: several
interfaces share one card, and one socket per worker on that card receives
all of their traffic. So a port gained two fields:

- `Port::card`: which card (socket) it sends and receives on;
- `Port::vlan`: its tag, or `None` for untagged.

**In:** the worker hands the pipeline the frame *and the card it came in
on*. The pipeline looks at the type:

- `0x8100`: find the port with that VLAN ID on that card. The tag is then
  removed by moving the two MAC addresses 4 bytes forward over it (12
  bytes copied, the packet itself doesn't move), and from there on it's a
  plain Ethernet frame on that port: ARP, DHCP, PPPoE, sessions, NAT and
  routing don't know VLANs exist.
- anything else: the card's untagged port.
- no such port (a VLAN nobody configured, or untagged traffic on a card
  with only VLANs): dropped, counted as `vlan`.

Finding the port is a scan of a handful of `(vid, port)` pairs per card:
for a few entries that's faster than any hash.

**Out:** the last step before a frame leaves. If the port has a VLAN, the
MACs move 4 bytes *back* into the frame's headroom and the tag goes in the
gap. Like PPPoE's header, the packet never moves. The order matters for
PPPoE over a VLAN, which many fibre ISPs use (often VLAN 10, 35 or 7):
first the PPPoE header, then the tag outside it.

```
from the LAN:     [dst|src|0800|IPv4 ...]
PPPoE wrap:   [dst|src|8864|PPPoE 8|IPv4 ...]
VLAN tag: [dst|src|8100|7|8864|PPPoE 8|IPv4 ...]
```

The worker then sends on the *card* the port belongs to
(`Pipeline::card_of`). The router's own frames (ARP requests, probes) are
tagged the same way, and frames the control plane builds (DHCP replies,
PPPoE discovery) get their tag in the worker just before they're sent.

## What the card has to be told

Two NIC features get in the way of seeing tags, so the router sets each
card up at start:

1. **VLAN stripping** (`rxvlan`): many cards take the tag off in hardware
   and put it in the receive descriptor, where XDP never looks. A tagged
   frame would then look untagged, and land on the wrong network. The
   router turns it off on every card (the old `ETHTOOL_SFLAGS` ioctl), and
   warns if it can't.
2. **VLAN filtering**: many cards (Intel's, and virtio under QEMU) drop
   tags nobody registered. Linux registers one when you create a VLAN
   device like `ens19.10`, but the router has no such devices: it reads
   the tags itself. So a card carrying VLANs is put in **promiscuous mode**,
   which lets every VLAN through. The request is held by a packet socket
   (`PACKET_ADD_MEMBERSHIP`), so it ends when the router stops, the way
   its XDP program detaches.

Promiscuous mode also lets in unicast frames for other MACs. On a switched
network there are few, and the pipeline drops them first thing
(`not-for-us`).

## Watching it

```bash
ephctl status
```

lists `guest` with device `ens19.10`. Per-interface packet and byte
counters (the Reporting tab) count each VLAN separately. Frames for
VLANs that aren't configured show up as the `vlan` drop counter: if it
grows, the switch is sending a VLAN the router doesn't know (or the
untagged traffic of a card with only VLAN interfaces).

## How it's tested

- **Unit tests:** pushing and popping a tag; routing between VLANs on one
  card and to another card; unknown VLANs, a missing tag and a truncated
  one; priority-tagged frames; ARP inside a VLAN (answers and requests
  are tagged); PPPoE inside a VLAN in both directions, with control
  traffic handed over untagged; control-plane frames tagged on the way
  out; and the config rules (one untagged per card, no VLAN twice, IDs
  1-4094, VLAN changes need a restart).
- **CI**, on the real image in QEMU: a VLAN 10 interface is added next to
  the untagged LAN on the same virtio card; a host with a Linux VLAN
  device pings the router on it and routes through it; the untagged LAN
  keeps working; a VLAN that isn't configured is dropped and counted.

## Limits

- One tag only: no QinQ (802.1ad, `0x88a8`, a tag inside a tag).
- No VLAN priority: PCP is ignored in and 0 out.
- Changing VLANs needs a restart.
- A card with VLANs runs in promiscuous mode. A few NICs also need
  `ethtool -K <dev> rx-vlan-filter off` before they pass every VLAN even
  then; the router doesn't try that itself.

## Exercises

1. Configure a VLAN the switch doesn't send. Which counter shows it, and
   what does it stay at? Now send it from a host. What changes?
2. Ping between two VLANs on the same card and watch the per-interface
   counters. The packet enters and leaves on the same cable: how many
   times does it cross it?
3. Why does the tag go *outside* the PPPoE header and not inside? What
   would the ISP's switch see the other way round?
