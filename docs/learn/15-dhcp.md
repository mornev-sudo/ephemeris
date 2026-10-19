# 15. DHCP: handing out addresses, and getting one

## The problem

Every device on a network needs an address, a subnet mask, a default
gateway and DNS servers. Typing those into every laptop and phone by hand
doesn't scale, and two devices given the same address break each other.
**DHCP** (RFC 2131) automates it. A device that just connected shouts "I
need an address!", and a server answers with one, lent for a while: a
**lease**.

Ephemeris does both sides:

- On **inside** interfaces it's a DHCP **server**, leasing addresses to
  your devices.
- On **outside** interfaces it can be a DHCP **client**, getting its own
  address from the ISP, as most home and business connections hand them out.

## The four-message dance

```
client                                   server
  │  DISCOVER  (from 0.0.0.0, to everyone)  │   "I need an address"
  │ ───────────────────────────────────────▶│
  │  OFFER     yiaddr=10.0.0.100            │   "you could have this one"
  │ ◀───────────────────────────────────────│
  │  REQUEST   "I'll take 10.0.0.100 from   │   (broadcast, so other servers
  │             server 10.0.0.1"            │    see their offers declined)
  │ ───────────────────────────────────────▶│
  │  ACK       lease 1 day, gateway, DNS    │   "it's yours"
  │ ◀───────────────────────────────────────│
```

The client has no address yet, so it sends from `0.0.0.0` to the broadcast
address `255.255.255.255`. That's why the data plane can't treat DHCP like
ordinary traffic: the anti-spoofing filter (chapter 14) would rightly drop a
packet from 0.0.0.0.

## How it fits in Ephemeris

DHCP is a control-plane protocol: a few packets per device per day. It
doesn't belong in the per-packet fast path. So:

1. Each port knows its DHCP role (`Port::dhcp`: off, server or client).
2. **First thing** in the IPv4 path, before the filter, the pipeline checks
   for UDP to port 67 on a serving port, or to port 68 on a client port.
   Those packets are **copied out** (`Pipeline::punts`) and dropped from
   the fast path. The counter is `dhcp-to-control`.
3. The workers pass them to one control-plane thread, the **DHCP service**
   ([`dhcp/service.rs`](../../crates/ephemerisd/src/dhcp/service.rs)).
4. Replies go back through worker 0 (`Control::Transmit`) and out of the
   right port.

The protocol logic itself is pure: messages and the time go in, frames and
events come out
([`server.rs`](../../crates/ephemerisd/src/dhcp/server.rs),
[`client.rs`](../../crates/ephemerisd/src/dhcp/client.rs)). So the tests
can run our client against our server for a whole lease lifetime in
microseconds, with no network at all.

## The server

```toml
[[interface]]
name = "lan"
device = "ens19"
address = "10.10.1.1/24"

[interface.dhcp]
range = "10.10.1.100-10.10.1.199"
lease_secs = 86400            # one day (the default)
dns = ["1.1.1.1"]             # optional: see below
domain = "home.arpa"          # optional

[[interface.dhcp.reservation]]
mac = "52:54:00:12:34:56"
address = "10.10.1.10"
name = "nas"
```

How it chooses an address for a client:

1. its **reservation**, if it has one (reservations may sit outside the
   range);
2. otherwise the address it had **last time** (devices like keeping theirs);
3. otherwise the one it **asks for**, if that's free;
4. otherwise the **first free** address in the range.

An offered address is held for a minute. If the client takes another
server's offer instead, ours is released straight away.

The router is **authoritative** on its LANs. A client that asks for an
address that isn't its to have (from another network, or someone else's)
gets a **NAK**, so it starts over instead of keeping a wrong address. A
client that finds its address already in use (it checks with ARP) sends a
**DECLINE**, and that address is set aside for ten minutes.

Leases are saved in `/var/lib/ephemeris/dhcp/leases-<interface>.json`, so a
restart or an update doesn't reshuffle your network.

**DNS:** the router doesn't run a DNS resolver itself. A LAN without its
own `dns` list gets the DNS servers the router received with its own WAN
lease. Point `dns` at your own resolver (a Pi-hole, say) to override that.

## The client

```toml
[[interface]]
name = "wan"
device = "ens20"
address = "dhcp"
role = "outside"
```

The client is a small state machine (RFC 2131 4.4):

```
INIT ─DISCOVER─▶ SELECTING ─OFFER─▶ REQUESTING ─ACK─▶ BOUND
                                                        │ T1 (half the lease)
                                                        ▼
                         ACK ◀── RENEWING  (ask our server directly)
                                    │ T2 (7/8 of the lease)
                                    ▼
                         ACK ◀── REBINDING (ask any server)
                                    │ lease expires
                                    ▼
                                  INIT: address gone
```

When it's bound, three things happen live, without a restart:
- the interface gets the address;
- the lease's gateway becomes the interface's gateway, and the **default
  route**, unless you've configured a static one, which always wins;
- NAT starts translating to the new address.

### Gateways outside the subnet: /32 leases and option 121

Not every lease looks like a home LAN's `/24`. ISPs (especially with
carrier-grade NAT) and cloud providers often hand out a **/32**, a subnet
of one address, with a gateway *outside* it, e.g. `100.64.12.34/32` and
gateway `100.64.0.1`. The gateway is still on the same link: the router can
ARP for it directly. It just isn't in the subnet.

The client keeps the mask exactly as given (/31 and /32 included; no mask
at all also means /32, rather than guessing). A gateway outside the subnet
is recorded as **on-link**: a connected /32 route to it on that interface,
the same way a PPPoE link's far end is handled (chapter 16). Then the
default route through it resolves like any other.

Servers can also send **classless static routes** (option 121, RFC 3442;
Microsoft's older servers use 249): extra routes, each with its own gateway,
or `0.0.0.0` for "on this link". The router asks for them. As the RFC
requires, when they're present the plain Router option is ignored, and the
default route comes from their `0.0.0.0/0` entry. A static route you
configure for the same prefix wins.

If a lease still can't be put into effect, the WAN status says so
(`ephctl wan`: `NOT APPLIED: <reason>`; the dashboard: "not applied"),
and the router tries again every 10 seconds. Before 0.9.1 that only went
to the log, and the interface quietly kept no address.

### A view, not a rewrite

The new settings are a *view* of the config, `Config::with_leases`. The
config file itself is never rewritten by DHCP, and every commit is applied
with the current lease folded in.

Static routes through a gateway on the DHCP network are fine: before the
first lease they **wait** (accepted, but not in the forwarding table), and
they take effect as soon as the lease shows the gateway is connected. Once
a lease exists, a commit is also checked against it, so a route through a
gateway that isn't reachable from the router is still refused.

The last address is remembered (`client-<interface>.json`), and asked for
again after a restart, so the ISP usually hands the same one back.

## Watching it

```bash
ephctl dhcp
```

shows what the router's own interfaces got (state, address, gateway, DNS,
time left), and every lease handed out on each LAN. The portal's **DHCP**
tab shows the same. Configuration → **DHCP server** edits the server.

## How it's tested

- **Unit tests:**
  - message encoding and decoding, with UDP checksums;
  - the server's choices (reservations, renewals, NAKs, declines, an
    exhausted pool);
  - our client against our server through a whole lease: renew, rebind,
    expire, NAK, and reboot asking for the old address.
- **CI** (`ci/e2e.sh`), on the real image:
  - the "ISP" side of the test network runs dnsmasq, and the router gets
    its outside address from it;
  - a test host on the LAN then runs a DHCP client against the router;
  - it must get an address from the range, the router as its gateway, and
    the DNS server the router learned from the ISP.

## Limits

- No relay support: the server only answers on its own link (`giaddr` set
  means a relay, and is ignored).
- No DHCPv6 (there's no IPv6 yet at all).
- Client: one default route, from the first DHCP interface that provides a
  gateway. Several DHCP WANs at once are fine for SD-WAN tethers (each uses
  its own interface's gateway), but only one carries the default route.
- The router doesn't check with ARP before offering an address. A device
  squatting on an address in the range is only noticed when a client
  declines it.

## Exercises

1. Run `ephctl dhcp` while a laptop joins the LAN, and watch its lease
   appear. Compare the time left after a renewal (at half the lease time).
2. Reserve an address for one device, commit, then make it renew (unplug and
   replug it). What does the server do with its old dynamic address?
3. Switch a WAN to `address = "dhcp"` and watch the routes: `ephctl routes`
   before and after the lease. Where does the default route come from?
