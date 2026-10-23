# 19. Reaching the router itself: the host path

## The problem

The router's portal (nginx) and SSH server (sshd) are ordinary Linux
programs. Linux only sees the **management NIC**: the data-plane NICs
belong to AF_XDP, and every frame on them goes straight to ephemerisd
(chapter 4). So from the LAN, `https://10.10.1.1:8443/` goes nowhere: the
kernel never sees the packet.

Often the management NIC is a separate port in a rack, and the people who
look after the router are on the LAN. They need to reach the router on
the LAN address too.

```toml
[[interface]]
name = "lan"
device = "ens19"
address = "10.10.1.1/24"
management = ["https", "ssh"]        # the portal (8443) and/or SSH (22)
management_from = ["10.10.1.0/28"]   # optional: only these clients
```

In the portal: Configuration → Interfaces → **Access to the router**.

## Never from the outside

SSH and the portal are offered on **inside interfaces only**. The rule is
enforced twice:

1. **The config refuses it.** `management` on an interface with `role =
   "outside"` fails validation ("SSH and the portal can only be reached on
   inside interfaces"), whether it comes from the file, the portal or the
   API. The portal doesn't show the choice on an outside interface.
2. **The data plane checks every packet**, whatever the config says. A
   packet only goes to the host if:
   - it arrived on an inside interface;
   - it's addressed to *that interface's own* address, so a WAN packet
     to the LAN address doesn't qualify, and neither does a LAN client
     using another interface's address;
   - it's TCP to a port the interface offers, from an allowed source;
   - it didn't come through an SD-WAN tether.

   Replies go out only from those two services, and only towards an inside
   interface.

## How it works

The usual way for a software router to reach its own services is a **tap**
or **tun** device: a network interface whose "wire" is a file descriptor.
VPP and DPDK-based routers work the same way. Here it's a tun device
called `eph-host`.

```text
 laptop 10.10.1.50 ── lan ──▶ pipeline ──▶ eph-host ──▶ sshd / nginx
   dst 10.10.1.1:22               dst becomes 169.254.240.1:22
```

- **In:** the pipeline rewrites the destination to the interface's host-side
  address, `169.254.240.<interface number + 1>`, and hands the packet to
  `eph-host`. The source stays the laptop's, so sshd and nginx log the real
  client, and nginx's login rate limit and ephemerisd's lockouts work as
  usual.
- **Out:** Linux treats the whole `169.254.240.0/20` as its own (a `local`
  route) and sends anything *from* that range back into `eph-host` (an
  `ip rule` into routing table 240). The pipeline reads the source
  address, finds the interface from it, puts the interface's real address
  back, and sends the packet like any other: route, ARP, VLAN tag.
- **No state.** The host-side address says which interface a reply belongs
  to, so there's no table to fill or expire. (That's also why each
  interface has its own address in the range.)

`nic-setup` creates `eph-host`, the local route and the rule on every
start (as root, before ephemerisd). ephemerisd attaches to the device.

MSS adjust applies to these connections too: the laptop's SYN and sshd's
SYN-ACK are clamped to the interface's MSS, so a portal session over a
smaller-MTU link still works.

## Watching it

- `ephctl status`: the ACCESS column says which services each interface
  offers.
- `ephctl log show -c mgmt`: "host path ready" at start, or why not.
- The `to-host` drop counter counts packets handed to the host. (It's a
  hand-over, not a real drop.)
- `tcpdump -ni eph-host` on the router shows exactly what sshd and nginx
  see.

## Exercises

1. Turn on SSH for the LAN, then `ssh root@<lan address>` from a LAN host.
   What does `journalctl -u ssh` say the client address is? Why isn't it
   169.254.240.1?
2. Try the same address from the WAN side. Which check stops it, and what
   does `ephctl log set route debug` show for those packets?
3. Why does the reverse-path filter (`rp_filter`) let the laptop's packets
   into `eph-host`, when the laptop's address is nowhere near it? (Hint:
   look at the `ip rule` and which table it points to.)
