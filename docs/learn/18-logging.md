# 18. Logging: what the router says, and how to make it say more

## Two kinds of problem

When something doesn't work, it's one of two things:

- **a bug in the code**: the router does something it shouldn't;
- **a networking problem**: the router does exactly what it should, and
  the network around it isn't what you think (the ISP wants a VLAN, a
  host has a static address inside the DHCP pool, a route points the
  wrong way).

Both need the router to say *what it did and why*. But a router that
says everything all the time is useless: millions of packets a second
can't each be a log line. So routers log the way Junos `traceoptions` and
Cisco `debug` do: quiet by default, one switch per subsystem, and the
detailed switches turned on only while someone is looking.

## Categories and levels

Every line belongs to a **category**, and every category has a **level**:

| Level | Means | Example |
|---|---|---|
| `error` | something failed that shouldn't | the management API stopped |
| `warn` | something's wrong, the router copes | a DHCP client declined an address: something else uses it |
| `info` | something changed | a lease was handed out, a PPPoE session came up |
| `debug` | the steps along the way | DISCOVER, OFFER, REQUEST, ACK; why a packet was dropped |
| `trace` | every message | each LCP Configure-Request and its id |

A line is kept if its level is at or above its category's.

```bash
ephctl log levels
```

```
CATEGORY     GROUP     LEVEL  CONFIGURED  FOR  COVERS
system       system    info   info             start-up, shutdown, memory, NIC setup
config       system    info   info             commits, rollbacks, falling back...
audit        system    info   info             who did what: logins, changes, restarts
...
session      packets   warn   warn             sessions created, and packets refused...
dhcp-client  services  info   info             getting an address from the ISP by DHCP
pppoe        services  info   info             dialling the ISP: discovery, LCP, login, IPCP
```

The control-plane categories (DHCP, PPPoE, SD-WAN, config) default to
`info`: their events are rare and worth keeping. The packet categories
(session, nat, filter, icmp, arp) default to `warn`, because at `debug`
they describe individual packets.

In the code, a category is the `tracing` *target*:

```rust
info!(target: cat::DHCP_SERVER, iface, mac, "{ip} leased to {mac} for {secs}s");
```

## Turning detail on, for a while

```bash
ephctl log set dhcp-client debug          # for 10 minutes
ephctl log set pppoe trace --for 1h
ephctl log set session debug --for forever
ephctl log reset                          # back to the config
```

Debug and trace **switch themselves off** after `logging.debug_minutes`
(10 by default). A debug left on by mistake can't fill the disk weeks
later. A level that should stay goes in the config:

```toml
[logging]
levels = { dhcp-client = "debug" }
```

Every change is in the audit trail, with who made it.

## Packets: tracing in the data plane

The workers never write log lines themselves. Formatting text and
waiting on a file would cost more than forwarding the packet. Instead,
the packet categories are also **bits in the data plane**
(`eph_dataplane::trace`):

- **Off costs one bit test.** With the bit clear, nothing else happens.
- **On**, the pipeline records a small fixed-size event at the points
  that explain a packet's fate: every drop with its reason, a new
  session, a NAT translation, a neighbour learned or changed, an ARP
  request, an ICMP error sent. The worker turns the events into lines
  after each batch.
- **A host filter**, like a router's conditional debug: only packets to
  or from one address or prefix.
- **A rate limit**: 100 events a second per worker by default
  (`logging.trace_per_sec`). The rest are counted and reported as "N
  events not logged".

```bash
ephctl log host 10.10.1.50
ephctl log set route debug
ephctl log show -c route -f
```

```
2026-10-22T17:40:02.118Z DEBUG route       drop no-route: udp 10.10.1.50:5353 -> 8.8.8.8:53 in lan
2026-10-22T17:40:02.118Z DEBUG icmp        sent net-unreachable (3/0) to 10.10.1.50 about udp ...
```

The host filter goes away by itself once the last packet trace ends.

## In the portal

The **Logs** tab does the same as `ephctl log`:

- the recent lines, filtered by category, level and text, following new
  ones as they come;
- every category's level, a list to change it (debug and trace for the
  time you pick), its timer counting down, and the packet host filter;
- the audit trail, from audit.log.

## Where lines go

| Where | What | Kept |
|---|---|---|
| the journal | `info` and up, structured (`journalctl -u ephemerisd TARGET=pppoe`) | 256 MB or 90 days, with the rest of the system |
| `/var/log/ephemeris/debug.log` | every line kept, at any level | 64 MB (two rotating files of 32) |
| `/var/log/ephemeris/audit.log` | the `audit` category: logins, changes, restarts | 16 MB (two files of 8), out of reach of everything else |
| memory | the last 5000 lines | until ephemerisd restarts: `ephctl log show` |

Debug never goes to the journal. That's deliberate: the journal deletes
its oldest entries first, so a debug session there would push out weeks
of history, the audit trail included. In a file of its own with a fixed
size, it can only replace older debug output.

Whoever logs only formats the line and drops it into a bounded queue. One
thread, `eph-log`, writes the files. If logging falls behind (a flood),
lines are dropped and counted ("logging fell behind: N lines dropped"),
and nothing that logs ever waits.

## How much disk

A journal entry takes roughly 0.5-1 KB, a debug.log line about 150 bytes.

| What's on | Lines | Disk |
|---|---|---|
| a normal day (`info`) | a few a minute | under 5 MB a day in the journal: months of history |
| periodic stats (`stats_interval_secs = 10`, 10 sessions shown) | about 1 a second | about 60 MB a day: the journal holds about 4 days |
| one packet category at `debug` | up to 100/s per worker | debug.log fills (64 MB) in about an hour, then keeps the newest |

`/var` is at least 2 GB: the journal keeps 512 MB free, and debug.log
and audit.log together take at most 80 MB.

## Exercises

1. `ephctl log set dhcp-client debug`, then pull the WAN cable for a
   minute. What does the client try, and when does it give up on its
   lease?
2. Trace `session` for one host and open a web page. How many sessions
   does one page start? Which `nat` lines go with them?
3. Set a wrong PPPoE password at `trace`. At which LCP/auth message does
   it fail, and what does the ISP's refusal say?
