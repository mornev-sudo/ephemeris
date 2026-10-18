# 9. The management plane: API, web portal, CLI, and changing a running router

## Three planes, finally all present

| Plane | In Ephemeris | Speed it runs at |
|---|---|---|
| Data plane | Worker threads, `Pipeline::process` | Every packet (nanoseconds) |
| Control plane | Building the FIB and port table from config, and later from routing protocols | Every change (milliseconds) |
| Management plane | REST API, web portal, `ephctl` | Every human or tool request (seconds) |

Phase 2 adds the management plane and the first real control-plane action:
**changing a running router without stopping it**.

## One API, many front ends

```
 browser ──┐
 ephctl   ──┼──▶  REST API  /api/v1/...  ──▶  config manager  ──▶  ephemeris.toml
 (future   │     (ephemerisd, eph-mgmt thread)        │
 controller)┘                                       └──▶ new FIB / ports ──▶ workers
```

The web portal ([`web/index.html`](../../crates/ephemerisd/src/mgmt/web/index.html))
and the CLI ([`ephctl`](../../crates/ephctl/src/main.rs)) contain no router logic.
They only call the API ([`api.rs`](../../crates/ephemerisd/src/mgmt/api.rs)).
That's deliberate: the portal can never do something the CLI can't, and
when Phase 4 adds a central SD-WAN controller, it becomes a third client of
the same API. Every serious network OS (Junos, Arista EOS, VyOS) converged on
this design.

The API runs on its own thread with its own small async runtime (tokio).
The workers never wait for it and it never waits for them. They touch in
exactly two places:

1. **Workers publish a report** (counters, ARP table, a sample of sessions)
   about once a second, using `try_lock`. If the API happens to be reading
   at that moment, the worker skips that update rather than wait.
2. **The control plane sends messages** to workers (`Control::SetFib`,
   `Control::SetPorts`). Each worker checks its channel between packet
   batches.

## How a route change reaches the data plane

What happens when you run `ephctl route add 192.168.50.0/24 10.10.2.254`:

1. `ephctl` sends `POST /api/v1/routes` with its API token (the portal
   would send its session cookie instead).
2. The config manager edits the config file's text with **toml_edit**, a
   format-preserving editor, so your comments and layout survive.
3. The new text is fully validated: it is parsed, and the routes are
   *resolved*. The gateway must be on a connected subnet. An invalid change
   stops here with a message, and nothing has changed.
4. The change is **committed**. The old file is saved to
   `/var/lib/ephemeris/config-history/`, and the new one is written atomically
   (write a temp file, then rename, so a power cut leaves either the old or
   the new file, never half of each).
5. The control plane builds a **brand new FIB** (DIR-24-8, chapter 3) and
   sends an `Arc` (a reference-counted pointer) to every worker.
6. Each worker, between two batches, swaps its pointer and bumps
   `fib_gen`. Sessions keep flowing. Their cached next hops (chapter 7)
   notice the generation changed and look up the route again on their next
   packet.
7. The old FIB is freed automatically when the last worker drops its
   pointer.

No locks on the fast path, no packets lost, no restart. This is the
"build new, swap pointer" (RCU) pattern from chapter 3, in practice.

## What can change live, and what can't

[`Config::live_applicable`](../../crates/ephemerisd/src/config.rs) draws the line:

| Live (instant) | Needs a restart |
|---|---|
| Static routes | Adding or removing interfaces, or changing their device |
| Interface addresses | Number of workers, ring sizes, XDP mode |
| `allow_new_sessions` policy | Session table size and timeouts |

The rule of thumb: things that are *data* (tables) can be swapped. Things
that shaped *memory or threads at startup* (UMEMs, sockets, preallocated
session tables) can't. A commit tells you which kind it was. For the second
kind it saves the change and asks you to run `ephctl restart`. systemd
(`Restart=always`) starts the daemon again within 2 seconds.

## The candidate / commit workflow

Borrowed from Junos, because it fixes the classic way to break a remote
router (editing the live config line by line until something breaks):

```bash
ephctl config edit                  # opens $EDITOR on a *candidate* copy
                                   # → validated, diff shown, nothing applied yet
ephctl config commit                # apply it
ephctl config commit --confirm 120  # apply it, but roll back in 2 min unless...
ephctl config confirm               # ...you confirm it still works
ephctl config rollback 1            # restore the previous version
ephctl config history               # list saved versions
```

**Commit confirmed** is the important one. Suppose you change the address
of the interface you're managing the router through, and get it wrong. You
can no longer reach the router to fix it. With `--confirm 120`, the router
undoes the change by itself 2 minutes later, because you never confirmed.
Network engineers rely on this every day.

The web portal's Configuration tab does the same thing with forms:
interfaces, routes, NAT, sessions and the data plane. Every edit goes into
the candidate, and nothing changes on the router until **Review & commit**.
The review shows either the validation errors, or the exact diff of the
config file plus whether it applies live or needs a restart. Behind the
forms, the browser sends the configuration as structured data
(`PUT /api/v1/config/model`). The router rewrites only the sections that
changed, in place, so the file stays readable and hand-written comments
around them survive.

## When a config won't start

Validation catches most mistakes before a commit. Some only show up when
the data plane actually starts, for example a network card that was
removed, or a driver that refuses XDP. The management plane lives in the
same process as the data plane, so without a safety net one bad config
would take the portal and API down with it.

So [`startup.rs`](../../crates/ephemerisd/src/startup.rs) keeps the **last
good** config. That's the version the data plane last started with, or
last applied live.

- **A newer config fails to start:** it's kept as
  `ephemeris.toml.failed-<time>`, and the last good version is put back.
  Then ephemerisd exits, and systemd starts it again, this time with
  the working config. The dashboard and `ephctl status` say what happened.
- **Even the last good config fails:** there's nothing better to go back
  to, so ephemerisd runs the **management plane only**. The portal, API and
  `ephctl` all work, and the dashboard shows why nothing is being routed.
  Fix the config, commit, then restart.

Each start also prepares the network cards the config names (link up,
kernel addresses removed, queues set), so a card added in the portal works
after a plain restart.

## Security, Phase 2 edition

- **Two ways to authenticate.**
  - **People** sign in to the portal as `admin` with the admin password,
    which is generated at deployment. The router keeps only its SHA-512
    crypt hash, the same format and file (`/etc/shadow`) that console and
    SSH logins use. Signing in creates a random 256-bit session in an
    `HttpOnly` cookie, which page scripts can't read, so an XSS bug couldn't
    steal it. Failed logins wait a second, to slow down guessing.
  - **Tools** (`ephctl`, scripts) use the API token in
    `/var/lib/ephemeris/api-token` (root only) as `Authorization: Bearer …`.
  - Secrets are compared in constant time, so response timing doesn't leak
    how much of a guess was right.
- **CSRF protection.** A malicious page you visit could make your browser
  send a request to the router, and the browser would attach the session
  cookie. So the cookie is `SameSite=Strict`, and every cookie-authenticated
  change must also carry an `X-Ephemeris` header. Other sites can't add custom
  headers to cross-site requests.
- **HTTPS only, and only on the management NIC.** ephemerisd serves plain
  HTTP on `127.0.0.1:8080` alone (that's what `ephctl` on the router uses).
  The network gets the portal and API through **nginx on port 8443**, over
  TLS 1.2/1.3 with a self-signed certificate generated on first boot (its
  fingerprint is on the console). nginx passes the client's address on, and
  ephemerisd believes that header only from loopback. The data-plane NICs have
  no kernel IP address at all (XDP takes their packets before the kernel's
  IP stack sees them). Over HTTPS the session cookie is also `Secure`, and
  responses carry HSTS.
- **Guessing is slow and noisy.** After 5 wrong passwords from an address it
  is locked out for 15 minutes; when more than 30 wrong passwords a minute
  arrive from everywhere, all web logins pause for the rest of the minute.
  nginx also limits login attempts per address. Every login, failure and
  change is logged (journal, `audit` target) with the client's address.
- **Sessions are short-lived.** A session ends after 30 minutes without use
  or 12 hours in all, at most 16 exist at once, and changing the password
  ends all of them (whoever changed it gets a new one).
- **DNS rebinding and other sites.** A request for a host name that isn't an
  address, `localhost`, the router's own name or one listed in
  `management.hostnames` is refused (421), and a state-changing request from
  a browser must come from the portal's own origin.
- **Bounded work.** Request bodies are capped at 512 KiB and configurations
  at 256 KiB / 5000 lines, the config diff has a fixed memory budget, at
  most 64 requests run at once, and a provisional commit's `confirm` window
  is at most an hour.
- **The portal treats every value as text.** It never inserts data as
  HTML, so a crafted hostname or session can't inject script (XSS). A strict
  Content-Security-Policy backs that up: the script is a file of its own
  (`/app.js`), and no inline script may run at all.
- **Not yet:** per-user accounts and roles.

## Try it

```bash
# on the router
ephctl status
ephctl sessions
ephctl route add 192.168.50.0/24 10.10.2.254
ephctl routes
ephctl config history

# in your browser
https://<router-ip>:8443/     (user admin, the password from deployment)
ephctl system password          (change it; also changes root's password)
ephctl system password --reset  (forgotten it: as root on the router, no old password needed)
```

Keep the Dashboard open while client-a runs `iperf3`. The forwarding rate
updates every 2 seconds, and the Sessions tab shows the flow with its byte
counters climbing in both directions.

## Exercises

1. **Watch a FIB swap under load.** Run a 60-second `iperf3`, and in the
   middle add and delete a route several times. The transfer shouldn't hiccup.
2. **Break it safely.** Use `ephctl config edit` to change lan-a's address to
   a different subnet, and commit with `--confirm 60`. client-a loses
   connectivity. Don't confirm, wait, and watch it come back.
3. **Add an endpoint.** Expose `GET /api/v1/drops` with per-worker drop
   counters, and show them in the portal. This touches the report, the API
   and the UI: a good tour of all three.
