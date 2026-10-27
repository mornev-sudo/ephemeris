# 10. A/B updates: upgrading a router you can't walk up to

## The problem

A branch-office router is often hours away from anyone who could plug in a
console cable. An update that leaves it unbootable means a site offline and
someone on a plane. So router updates need two properties:

1. **Atomic:** the router runs either the old version or the new one, never
   a half-installed mix.
2. **Reversible without help:** if the new version is broken, the router
   goes back to the old one *by itself*.

Package managers (`apt upgrade`) provide neither: they modify the running
system file by file. The answer used by phones, Chromebooks, cars and
network appliances is **A/B slots**.

## Two copies of the OS

```
 ┌──────┬──────────────┬────────┬──────────────┬────────┬──────────────┐
 │ ESP  │ root slot A  │ verity │ root slot B  │ verity │ /var         │
 │      │ ephemeris_v1   │   A    │ ephemeris_v2   │   B    │ config, logs │
 │ UKIs:│ (running)    │        │ (installed,  │        │ (shared by   │
 │ v1   │              │        │  not yet     │        │  both)       │
 │ v2+3 │              │        │  booted)     │        │              │
 └──────┴──────────────┴────────┴──────────────┴────────┴──────────────┘
```

- The image is built with slot A filled
  ([`mkosi.repart/10-root.conf`](../../image/mkosi.repart/10-root.conf)).
  On first boot, `systemd-repart` creates an **empty slot B** labelled
  `_empty` ([`/usr/lib/repart.d/`](../../image/mkosi.extra/usr/lib/repart.d)).
- Each slot's **partition label carries its version** (`ephemeris_<version>`).
  That's how the updater tells the slots apart.
- Each slot has its own verity hash partition. The ESP holds one **UKI**
  (kernel image) per installed version, and each UKI contains the root hash
  of *its* slot. Choosing a UKI therefore chooses a slot. No partition table
  edits, no "active slot" flag.
- `/var` is shared, so your config, SSH keys and logs carry over.

The slots have a fixed size (1.5 GiB): updates alternate between them, so
every future version must fit in either one.

The first CI run of the update test hit a classic detail: **GPT partition
labels are limited to 36 characters**, and `ephemeris_<version>_verity` was
38. That's why versions are short, like `0.7.1-9003193` (release, then
commit; see chapter 8), and why `image/build.sh` refuses longer ones.

## Installing an update: systemd-sysupdate

[`/usr/lib/sysupdate.d/`](../../image/mkosi.extra/usr/lib/sysupdate.d) holds
three *transfer* files, one per piece:

| Transfer | Downloads | Writes to |
|---|---|---|
| `10-root-verity` | `ephemeris_<v>_x86-64.root-x86-64-verity.<uuid>.raw.xz` | the idle verity partition |
| `11-root` | `ephemeris_<v>_x86-64.root-x86-64.<uuid>.raw.xz` | the idle root slot |
| `20-uki` | `ephemeris_<v>_x86-64.efi` | `/EFI/Linux/ephemeris_<v>_x86-64+3-0.efi` |

`systemd-sysupdate update` does the following:

1. Downloads `SHA256SUMS` from the GitHub release, which lists all versions
   on offer.
2. Picks the newest version that is newer than the running one.
3. Writes the pieces into the slot that is *not* running (`ProtectVersion=%A`
   guarantees it never overwrites the running version), checking every
   file's SHA-256.
4. Sets each partition's **UUID** from the filename. Those UUIDs are derived
   from the root hash, which is how the new UKI's initrd finds "its" slot.
5. Installs the UKI **last**. Until the UKI exists, nothing can boot the
   half-written slot, so a power cut mid-download is harmless.

The router keeps forwarding throughout. Nothing changes until you reboot.

## Booting it, and not getting stuck: boot counting

The new UKI is installed as `ephemeris_<v>_x86-64+3-0.efi`. That `+3-0` is a
**boot counter**: 3 tries left, 0 used.

```
reboot ──▶ systemd-boot picks the newest entry with tries left: v2 (+3-0)
           and renames it to +2-1 *before* starting it
              │
              ▼
           v2 boots ──▶ ephemeris-healthy.service: is ephemerisd up and stable?
              │                         │
          yes ▼                     no  ▼
   boot-complete.target       FailureAction=reboot ──▶ next try (+1-2), (+0-3)…
   systemd-bless-boot renames         after 3 failures, v2 has no tries left:
   it to plain ephemeris_v2.efi         systemd-boot boots v1 again. Back online.
   (v2 is now "good")
```

[`ephemeris-healthy.service`](../../image/mkosi.extra/usr/lib/systemd/system/ephemeris-healthy.service)
is the important judgement call: *what counts as healthy?* Ours says
"ephemerisd started and stayed up for 15 seconds without restarting". A
production router would also check that it can reach its controller, that
its tethers are up, and so on. A bad health check is dangerous both ways:

- too lax, and broken versions get blessed;
- too strict, and good versions get rolled back.

### Two lessons the CI test taught

The update test failed twice before it passed, and both failures are worth
knowing about.

1. **Compression has to be one the router understands.** The first
   artifacts were zstd-compressed. Debian 13's `systemd-pull` doesn't
   decompress zstd, so it wrote the *compressed bytes* straight into slot B.
   On reboot, dm-verity compared the slot against the root hash in the new
   UKI, found a mismatch, and refused to boot it. That's the verity chain
   doing its job, catching a corrupted OS before running a single byte of
   it. The artifacts are xz now.
2. **"Emergency mode" is wrong for a router.** That failed boot then sat in
   emergency mode, waiting for someone to log in at the console. With
   nobody there, the boot counter never got its next try. The image now
   reboots out of emergency and rescue mode after 30 seconds, both in the
   main system and in the initrd
   ([`mkosi.initrd.conf/`](../../image/mkosi.initrd.conf)), so a broken
   version is retried and then abandoned without anyone touching the router.

## Updating your router

```bash
ephctl system check      # what's installed, what's available
ephctl system update     # install the newest release into the idle slot
ephctl system status     # "update: 0.7.2-… is installed" when it's done
ephctl system reboot     # switch to it
```

The portal's **System** tab has the same buttons, and an **Update** card
showing where things stand:

| State | Meaning |
|---|---|
| Nothing pending | no update installed and waiting |
| Installing… | downloading and writing the idle slot; the router keeps forwarding on the current version |
| Ready: reboot to switch | installed: the boot loader will start it next. Nothing happens until you reboot |
| Install failed | the reason, and where to look (`journalctl -u ephemeris-update`) |

**Install never reboots by itself.** You choose when the minute of downtime
happens. Nor does the router update by itself: Debian's own automatic
update and reboot timers (`systemd-sysupdate.timer`,
`systemd-sysupdate-reboot.timer`) are masked in the image, and CI checks
that they stay that way. "Ready" is read from the boot loader itself: its default entry is a
version other than the one running. Clicking Reboot during an install asks
first. Rebooting then is safe, because the new boot entry is only written at
the very end: the router simply comes back on the current version.
`ephctl system reboot` refuses during an install unless you add `--force`.

**The update source.** By default routers fetch from
`https://github.com/mornev-sudo/ephemeris/releases/latest/download/`. You can
point a router at any HTTP server holding a release's files instead (an
offline network, a staged rollout) with the `ephemeris.update_url`
credential:

```bash
qm set 9100 --args "$(qm config 9100 | sed -n 's/^args: //p') \
  -smbios type=11,value=io.systemd.credential:ephemeris.update_url=http://192.168.3.10:8000/"
```

`ephemeris-update-source.service` then writes overrides to `/run/sysupdate.d/`.
CI uses exactly this to serve a test update from the build machine.

## How CI proves it works

On every push, [the workflow](../../.github/workflows/image.yml) builds
version *V* and a second image *V.1*, and serves *V.1*'s update files over
HTTP from the CI machine. The router VM, running *V* with the
`ephemeris.update_url` credential pointing at that server, is then updated the
way an operator would do it ([`ci/e2e.sh`](../../ci/e2e.sh)):
`ephctl system check` must offer *V.1*, `ephctl system update` installs it,
and `ephctl system reboot` switches to it. CI then checks that the router
runs *V.1* from the other slot, that the boot was blessed (boot counter
gone), and that config, password and forwarding all survived.

So the full path (download, write the idle slot, boot counting, health
gate, blessing) runs on a real kernel and real UEFI firmware before any
release goes out.

## What Phase 3c added (chapter 11)

- **Signed updates.** `SHA256SUMS` is signed with the release key, and
  routers refuse anything unsigned (the transfers no longer say `Verify=no`).
- **Secure Boot.** systemd-boot and the UKIs are signed, so the firmware
  refuses to boot an image we didn't build. Combined with dm-verity's root
  hash inside the UKI, the whole chain is trusted, from firmware to the last
  byte of the OS.
- **Routers on v0.1.0 can't update themselves.** That image predates the A/B
  layout. Redeploy them once from a newer image; every later version can
  then update in place.
