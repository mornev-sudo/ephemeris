# The controller contract (draft)

**Status: draft, not implemented.** This describes how an Ephemeris router
is managed by a controller: one place from which an organisation runs all
its routers. It's the router's side of the contract: what a router
promises, and what it accepts. Any controller that speaks it can manage
Ephemeris routers. How a controller organises sites, templates or users is
up to the controller, and not described here.

Everything here may still change until the first router release that
implements it; the protocol is versioned from then on (see
[Versioning](#versioning)).

## Principles

1. **The router is authoritative for its own config.** The controller
   proposes; the router checks, applies and keeps its history, exactly as
   for a change made in the portal or with `ephctl`. Everything a controller
   does goes through the same candidate → diff → commit path
   ([chapter 9](learn/09-management-plane.md)).
2. **A controller can never strand a router.** Every push is a *confirmed
   commit*: if the router can't reach the controller again with the new
   config, or the controller doesn't confirm it in time, the router rolls
   back by itself. A remote router is never left unreachable by a bad push.
3. **The router connects out.** The router opens the connection to the
   controller, never the other way round. That works behind NAT and CGNAT,
   needs no open ports on the router, and works without a management
   network (`[management] outbound = "dataplane"`).
4. **One set of rules.** A config is checked by the same code on both
   sides: the config model and its validation live in an open crate
   (`eph-config`, see [Router-side work](#router-side-work)) that a
   controller links against. If the controller says a config is valid, the
   router agrees.
5. **Local access stays.** A managed router still has its portal, SSH and
   console. Local changes are allowed and reported to the controller, which
   shows them as drift; the controller can't lock the local admin out.
6. **Trust is limited.** Taking over a controller must not mean taking over
   the routers' software: updates are still only installed if signed by the
   Ephemeris release key, and Secure Boot still decides what boots. See
   [Security](#security).

## Identity and enrolment

Each router has a **management identity**: an Ed25519 key pair made on
first use and kept in `/var/lib/ephemeris/` (like the SD-WAN identity,
which stays separate). Its public key is the router's id towards the
controller.

Enrolment, once per router:

1. An administrator creates an **enrolment token** in the controller: a
   random secret, valid once, for a short time (e.g. 24 hours), bound to
   the organisation and optionally to a site.
2. The router is given the controller's URL, the token and the controller
   certificate's SHA-256 fingerprint, in one string:

   ```text
   eph-enrol:v1:<url>#<token>@<sha256-fingerprint>
   ```

   by any of: `ephctl controller enrol <string>`, the portal, or a systemd
   credential at first boot (`ephemeris.controller`), like the update URL.

   - `<url>`: the controller's base URL, `https://` only, with no user
     info, query or fragment (so it contains no `#` or `@`).
   - `<token>`: 32 random bytes in base64url without padding (43
     characters from `A-Z a-z 0-9 - _`).
   - `<sha256-fingerprint>`: the SHA-256 of the controller certificate's
     DER-encoded SubjectPublicKeyInfo, as 64 lowercase hex characters. It's
     the same value the router then keeps as `[controller] pin`, which
     adds the `sha256:` prefix.

   Parse it by splitting at the first `#`, then the token from the
   fingerprint at the `@` after it; anything that doesn't match exactly is
   refused.
3. The router connects, checks the controller's certificate against the
   fingerprint, and sends `enrol` with the token and its management public
   key:

   ```json
   {"type": "enrol", "id": 1, "token": "<43 characters>", "key": "<64 lowercase hex>"}
   ```

   `key` is the router's Ed25519 management public key (as
   `ephctl controller identity` shows it; not the SD-WAN key), and must be
   the key of the TLS client certificate on this connection, which proves
   the router holds it. The controller records it and answers
   `{"type": "result", "id": 1, "ok": {"router_id": 12}}`. The router then
   sends `hello` on the same connection.
4. From then on the router authenticates with that key and the token is
   spent.

The router presents its client certificate (self-signed, its management
key) on **every** connection, the enrolling one included; a controller
refuses connections without one.

The router stores the result in its config:

```toml
[controller]
url = "https://controller.example.net/"
# The controller's certificate key, pinned at enrolment: "sha256:" and
# the enrolment string's fingerprint (64 lowercase hex characters). A
# controller moving to a new key announces it over the old connection
# first.
pin = "sha256:<64 hex characters>"
```

Removing `[controller]` (locally) unenrols the router. A controller can't
change or remove this section in a push: that would let it hand the router
to someone else.

## The connection

- **Transport:** HTTPS to the controller, upgraded to a WebSocket
  (`wss://<url>/v1/router`), TLS 1.3 only. Server authentication by the
  pinned key; client authentication by the router's certificate.
- **Messages:** JSON, one per WebSocket text frame:
  `{"type": "...", "id": <u64>, ...}`. Requests from either side carry an
  `id`; the answer repeats it with `"type": "result"` and either `"ok"` or
  `"error": {"code": "...", "message": "..."}`.
- **Request ids** count up from 1 on each connection, separately for each
  side, so the router's `enrol` is 1 and its `hello` after it is 2.
- **Keep-alive:** WebSocket ping and pong frames (not JSON messages), in
  both directions, every 30 s. Either side closes the connection after
  90 s without any frame from the other, and the router reconnects.
- **Limits:** a message is at most 1 MiB (a config is at most 256 KiB);
  the first message (`enrol` or `hello`) comes within 10 s of the TLS
  handshake.
- **Reconnecting:** exponential backoff from 1 s up to 5 min, with
  jitter, so a controller restart doesn't bring every router back in the
  same second.
- **One connection per router.** A second one from the same identity
  replaces the first.

### Hello

The first message after connecting, from the router:

```json
{
  "type": "hello", "id": 1, "protocol": 1,
  "router": {"version": "0.13.0-abc1234", "hostname": "cpt-br1"},
  "config": {"version": 42, "sha256": "...", "schema": "0.13"},
  "pending_confirm": null,
  "capabilities": ["config", "telemetry", "update", "sdwan"]
}
```

`config.version` is the router's own history number; `sha256` is of the
running config file's text. The controller answers with what it expects
(the version and hash it last pushed, `null` before its first push) and
whether a push is waiting:

```json
{"type": "result", "id": 1, "ok": {"protocol": 1, "router_id": 12,
  "expected_config": {"version": 42, "sha256": "..."}, "push_waiting": false}}
```

### Errors

| Code | Meaning | Then |
|---|---|---|
| `invalid_token` | the token is wrong, used, revoked or expired (one code, so it doesn't say which) | the controller closes the connection |
| `already_enrolled` | `enrol` from a key that's enrolled already | the router sends `hello` instead |
| `not_enrolled` | `hello` from a key the controller doesn't know | the controller closes the connection; the router keeps reconnecting with backoff and shows "not enrolled" in its status. It never re-enrols by itself: that takes a new token from an administrator |
| `unsupported_protocol` | the controller doesn't speak the router's `protocol` | the controller closes the connection |
| `bad_request` | a malformed message, or a field out of range | |
| `unknown_type` | a message type the receiver doesn't know | |
| `conflict` | a push whose `base_sha256` isn't the running config's (see [Config](#config)) | |

## Config

The controller sends complete configs, never patches: the router keeps the
history and the diff, as for any other change.

**Push** (controller → router):

```json
{
  "type": "config.push", "id": 7,
  "base_sha256": "...",
  "config": "<the complete ephemeris.toml>",
  "confirm_within_secs": 300,
  "comment": "template branch-v3, ticket 1234"
}
```

The router:

1. Refuses it if `base_sha256` isn't its running config's (someone changed
   it locally since: `"code": "conflict"`, with the running config's
   version and hash, so the controller can show the drift and decide).
2. Validates it exactly as `PUT /config` does; errors come back as they
   would in the portal.
3. Keeps its own `[controller]` section, whatever the push says.
4. Commits it as a confirmed commit (`confirm_within_secs`, 30 s to
   1 h), applying it live or after a restart, as `POST /config/commit`
   does.
5. Answers with the diff, how it was applied (`live` or
   `restart-required`) and the new version and hash.

The controller then sends **`config.confirm`** once the router is back
and healthy with the new config: still connected (or reconnected), and,
for its own checks, whatever it considers healthy (sessions, tethers up).
Without it, the router rolls back when the timer runs out, and says so in
its next `hello`.

**Restart-required pushes** (interfaces, workers, table sizes): the push
says `"restart": true` and the router restarts itself after committing;
the confirm timer runs across the restart.

**Local changes** while managed: the router sends `config.changed`
(version, hash, who: `local:admin` or `local:ssh`) after every commit not
made by the controller. The controller decides what to do with the drift
(adopt it into its records, or push its own back).

**Reading:** `config.get` returns the running config, its version and
hash; `config.history` the list of versions (as `GET /config/history`).

## Telemetry

The router sends these unasked. They carry no `id` and get no answer.

**`status`**: the router's state, exactly what `GET /status` returns.

```json
{"type": "status", "status": { ... }}
```

- Sent every 30 s, and when the state changes (an interface, WAN lease,
  PPPoE session or tether up or down, an address changed, a commit), at
  most once every 5 s. At most 256 KiB.
- The body grows with releases: a controller ignores fields it doesn't
  know. `drops` and `counters` are open-ended maps (new drop reasons
  appear with new releases).

**`stats`**: the samples since the last `stats` message, as
`GET /stats/history` returns them.

```json
{"type": "stats", "interval_secs": 5, "interfaces": ["wan", "lan"], "samples": [ ... ]}
```

- Each sample: `t` (Unix seconds, UTC: the end of the interval its rates
  average over), `sessions`, `rx_pps`, `tx_pps`, `rx_bps`, `tx_bps`,
  `drops_per_sec`, `drops_total`, `ports` (one `{rx_pps, tx_pps, rx_bps,
  tx_bps}` per interface, in the order of `interfaces`), `cpu_pct`,
  `mem_used`, `mem_total` (bytes), `process_cpu_pct` (100 = one core) and
  `workers_busy_pct` (one per worker, 0 to 100).
- Sent every 5 min. The router keeps an hour of samples (720), so after a
  reconnect it sends at most that, never an older backlog; at most 720
  samples a message. A controller drops samples with a `t` at or before
  the newest it has, so a resend is harmless.

**`event`**: something that happened.

```json
{"type": "event", "at": "2026-11-02T02:00:00Z", "kind": "tether.down", "detail": {"tether": "lte", "site": "jhb"}}
```

- `at`: RFC 3339, UTC. `kind`: dotted lowercase. `detail`: a flat object
  of strings and numbers, at most 4 KiB.
- Kinds so far: `path.changed`, `tether.up`, `tether.down`,
  `wan.lease.gained`, `wan.lease.lost`, `pppoe.up`, `pppoe.down`,
  `config.committed`, `config.rolled_back`, `config.failed_at_start`,
  `update.progress`. New releases add kinds; a controller keeps the ones it
  doesn't know as text.
- **Floods are coalesced on the router:** the same kind for the same
  subject (one tether, one interface) within 10 s becomes one event, with
  `"repeats": n` in its `detail`. The router sends at most 60 events a
  minute and counts the rest; a controller may refuse more than 120 a
  minute per router.

Status and stats are best-effort: if the connection is down, the router
keeps its own history (as now) and sends what it still holds when it's
back.

The controller can ask for more when someone is looking: `sessions.get`
(as `GET /sessions`), `routes.get`, `dhcp.get`, `wan.get`, `overlay.get`.

## Operations

| Request | Does |
|---|---|
| `system.update.check` | as `POST /system/update/check` |
| `system.update` | install the newest release into the idle slot, from the router's configured update source (which may be the controller, see below) |
| `system.reboot` | reboot, optionally at a given time (`"at": "2026-11-02T02:00:00Z"`) |
| `restart` | restart ephemerisd |
| `overlay.identity` | the router's SD-WAN public key |

**Update source.** A controller may serve release files itself, for
staged rollouts and sites without internet access: it pushes
`[system] update_url` (a config setting replacing the boot-time
credential). Whatever the source, the router only installs updates signed
by the Ephemeris release key (chapter 11). The controller chooses *when*,
never *what*.

**SD-WAN.** The controller collects each router's SD-WAN public key and
pushes each router the `[[site]]` entries for the others (addresses,
links, prefixes, public keys), as ordinary config. Nothing new is needed
on the router for that beyond `overlay.identity`.

## Versioning

- **`protocol`** in `hello`: the message set. A router speaks one
  protocol version; a controller should speak the current one and the one
  before.
- **`config.schema`:** the router's config format, named by the release
  that defined it (`"0.13"`). The controller builds configs with the
  `eph-config` crate of that version.
- **`capabilities`:** what this router supports; a controller only sends
  what's listed.

## Security

- **Controller → router is limited to this contract.** No shell, no
  arbitrary commands, no file access. Everything a controller can do, the
  portal can do too, and it's all in the router's audit log
  (`controller:<name>` as the actor).
- **What a stolen controller can't do:** install software not signed by
  the release key, change what boots, change or remove `[controller]`, or
  read the admin password (only its hash exists, and it's never sent).
- **What it can do:** change configs within the rules above, so it can
  disrupt or redirect traffic. That's inherent to central management;
  protect the controller accordingly, and every change remains visible and
  revertible on each router.
- **Enrolment tokens** are single-use and short-lived. The certificate pin
  stops a token being used against an impostor controller.
- **Secrets in configs** (PPPoE passwords, SD-WAN pre-shared keys) go to
  the router the same way the portal sends them. The controller should
  store them encrypted.

## Router-side work

In this repo, in this order:

1. **`eph-config` crate:** move the config model, parsing and validation
   out of `ephemerisd` into a library crate, unchanged in behaviour, so a
   controller can link against it.
2. **Management identity** (Ed25519) and `ephctl controller identity`.
3. **`[controller]` section, enrolment** and the connection (WebSocket,
   pinning, reconnects, `hello`).
4. **Config push** with conflict check, `[controller]` kept, confirmed
   commits across restarts, `config.changed`.
5. **Telemetry:** `status`, `stats`, `event`.
6. **Operations**, and `[system] update_url` as a config setting.
7. **Tests:** a minimal test controller in `ci/` that enrols a router,
   pushes a config, lets one roll back, and checks telemetry, in the
   end-to-end test.

## Open questions

- Commit-confirmed across a restart: today's confirm timer lives in
  ephemerisd; it needs to survive the restart a push asks for.
- How long a router keeps working when its controller is gone for good:
  forever (the default assumption: it's just a router with a config).
- Whether the controller may push `[management]` and `[ssh]` (e.g. keys
  only): useful fleet-wide, but a bad push could lock local access out;
  the confirm timer covers it if the controller connection survives.
