# 16. PPPoE: dialling the ISP

## Why it exists

DSL, and many fibre lines, don't just hand out an address to whoever plugs
in. The ISP wants to know **who** is connecting (a username and password),
and it wants a **session** it can account for and tear down. That's what
PPP did over dial-up modems. **PPPoE** (RFC 2516) runs the same PPP over
Ethernet.

On an outside interface Ephemeris can get its address three ways:

| `address =` | When |
|---|---|
| `"203.0.113.2/29"` | the ISP gave you fixed addresses |
| `"dhcp"` | cable, most fibre, LTE routers (chapter 15) |
| `"pppoe"` | DSL, and fibre that needs a login |

```toml
[[interface]]
name = "wan"
device = "ens20"
address = "pppoe"
role = "outside"
# mtu = 1492             # the default over PPPoE, and the most it allows

[interface.pppoe]
username = "you@isp"
password = "secret"
# service = "internet"   # only if your ISP asks for a Service-Name
```

(Configs from before 0.9.1 may set `mtu` under `[interface.pppoe]`; that
still works, and the interface's own `mtu` wins if both are set.)

In the portal: Configuration → **Interfaces**, then set the interface's
**Address** to PPPoE. Everything about an interface (card, role,
addressing, MTU, MSS) is edited in that one card.

## Two stages

### 1. Discovery: finding the ISP's concentrator

The router doesn't know whom to talk to yet, so it asks everyone:

```
router                                   access concentrator (the ISP's BRAS)
  PADI  (broadcast)  "any PPPoE service?" ───▶
                                          ◀─── PADO  "I'm bras-7; here's a cookie"
  PADR  (to bras-7)  "a session, please; your cookie" ───▶
                                          ◀─── PADS  "session 0x1a2b"
```

- **Host-Uniq:** a random tag the router puts in its requests and checks in
  the answers. That way it only reacts to replies to *its own* questions.
- **AC-Cookie:** echoed back to the concentrator, which uses it to resist
  floods of fake session requests.
- **PADT:** either side can send one to end the session at any time.

### 2. Session: PPP

From now on every frame carries the 6-byte PPPoE header (version, code,
**session id**, length) and a 2-byte PPP protocol number. Several protocols
run inside, one after another:

1. **LCP** (RFC 1661) sets the link up. Each side sends a
   *Configure-Request* listing what it wants, and the other answers Ack,
   Nak ("not that value, try this one") or Reject ("I don't know that
   option").
   - The router asks for an MRU of 1492 and a random *magic number*, which
     detects looped-back links.
   - The ISP's request says how the router must **authenticate**.
   - Ephemeris accepts PAP or CHAP-MD5. For anything else (MS-CHAP, EAP) it
     answers Nak and suggests CHAP-MD5, and options it doesn't know get a
     Reject.
2. **Authentication.** Either of two protocols:
   - **PAP** (RFC 1334) sends the username and password as they are, which
     is fine on a point-to-point link.
   - **CHAP** (RFC 1994) never sends the password. The ISP sends a random
     challenge, and the router answers with `MD5(id ‖ password ‖ challenge)`.
3. **IPCP** (RFC 1332, with RFC 1877 for DNS) gets the address. The router
   asks for `0.0.0.0` and DNS servers `0.0.0.0`. The ISP answers *Nak*
   with the real values, and the router asks again with those, which the
   ISP Acks.

Then the link is **up**. Every 10 seconds each side sends an LCP
*Echo-Request*. Thirty seconds without hearing anything means the line is
dead: the router sends a PADT and dials again, waiting 5 s at first and
backing off to a minute.

Protocols the router doesn't speak, like IPv6CP or compression (CCP), get
an LCP **Protocol-Reject**. That's how PPP says "not here". Ignoring them
would leave the ISP retrying forever.

## A point-to-point link

A PPPoE session isn't a LAN. There's exactly one other device on it, the
ISP's concentrator, so:

- **The router's address is a /32.** The ISP's end of the link (from IPCP)
  is the gateway and the only directly reachable neighbour. The forwarding
  table gets a /32 route to it, and the default route via it (unless you
  configured a static one).
- **No ARP:** every packet goes to the concentrator's MAC address, learned
  during discovery.
- **8 bytes less:** the PPPoE header and the PPP protocol number take 8 of
  Ethernet's 1500 bytes, so the link MTU is **1492**. That has two effects:
  - The router clamps the TCP MSS on that interface to 1452 automatically,
    so TCP connections never send segments that are too big.
  - Anything else too big is answered with "fragmentation needed, MTU 1492"
    (path MTU discovery). This check runs *before* NAT, so the error goes
    to the real sender rather than to the router's own public address.
  - SD-WAN tethers over a PPPoE link shrink their default overlay MTU by the
    same 8 bytes.

## How the data plane does it

The control plane (the address service, which also runs DHCP) handles all
of the above. The data plane only sees the result:

- **Port state:** `Port::pppoe` is `Off`, `Dialing` (everything PPPoE goes
  to the control plane) or `Up { session, peer, mtu }`.
- **In:** a frame with ethertype `0x8864`, our session id and PPP protocol
  `0x0021` (IPv4) is *unwrapped*. A plain Ethernet header is written 8
  bytes further into the frame, and the packet continues through the
  normal IPv4 path: filter, sessions, NAT, routing. Anything else on the
  PPPoE ethertypes is handed to the control plane (`pppoe-to-control` in
  the drop counters).
- **Out:** any frame leaving through a PPPoE port is *wrapped* by writing
  the 8 bytes into the frame's headroom, so the packet doesn't move. That
  covers forwarded traffic, the router's own ICMP, and SD-WAN tether
  traffic.

## Watching it

```bash
ephctl wan
```

lists every outside interface with its mode, state, address, gateway and
DNS servers. For PPPoE that includes the concentrator's name, the session
id, the MTU, and how long it's been up, or the last error ("CHAP login
refused", "the ISP stopped answering"). The dashboard's **Internet
connections** table shows the same.

## How it's tested

- **Unit tests:**
  - the PPPoE and PPP packet formats;
  - the client against a scripted ISP: CHAP and PAP logins, a wrong
    password (reported, then retried later), keepalives and a dead line,
    a PADT from the ISP, Protocol-Reject, and hanging up;
  - the data path: wrapping, unwrapping, the 1492 MTU and the control
    hand-off.
- **CI**, against **rp-pppoe and pppd** (the implementation most ISP test
  labs use) on the real image:
  - the router switches its outside interface from DHCP to PPPoE with a
    commit;
  - it logs in with CHAP, gets its address and DNS server;
  - it routes NATed traffic through the session;
  - then it rolls back to DHCP.

## Limits

- No RFC 4638 "baby jumbo" frames: some fibre ISPs allow a PPPoE MTU of
  1500 if the Ethernet side carries 1508-byte frames. Not yet supported.
- IPv4 only (IPv6CP is rejected for now).
- One session per interface. ISPs that want PPPoE on a VLAN (often 10, 35
  or 7 on fibre): give the interface `vlan = <id>` (chapter 17).

## Exercises

1. Run `ephctl wan` while pulling the line and plugging it back in. How
   long until the router notices, and how long until it's back?
2. Set a wrong password and commit. What does `ephctl wan` say? Where in
   the dance did it fail?
3. Look at `ephctl status` drop counters while the link is up: which
   counter grows with each keepalive, and why isn't it really a "drop"?
