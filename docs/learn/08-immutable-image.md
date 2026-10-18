# 8. The immutable image: shipping a router, not a server

## The problem with "install Debian, then apt install our stuff"

Every router you set up by hand ends up slightly different: a package updated
on a different day, a config file someone tweaked over SSH, a library left
behind by an old install. After a year of this, two "identical" routers are
not identical, and when one misbehaves you can't say what it's running.
This is **configuration drift**.

Network appliances (Cisco, Juniper, every SD-WAN box) avoid it the same way.
The **whole operating system is one versioned file**. You don't upgrade
packages; you replace the image. Version 0.3.0 is exactly the same bits on
every router in the world.

## What our image looks like inside

```
 one disk (GPT partition table)
 ┌──────────┬──────────────────────┬──────────────┬─────────────────────────┐
 │   ESP    │  root (erofs)        │ root-verity  │  var (ext4)             │
 │  vfat    │  READ-ONLY           │ hash tree    │  writable               │
 │          │  /usr /etc /bin ...  │              │  /var/lib/ephemeris/      │
 │ systemd- │  ephemerisd, kernel    │              │    ephemeris.toml (config)│
 │ boot     │  modules, sshd...    │              │    ssh/ (host key, keys)│
 │ UKI      │                      │              │  /var/log/journal       │
 └──────────┴──────────────────────┴──────────────┴─────────────────────────┘
   firmware     identical on every router            unique to this router
   reads this
```

The defining rule: **everything that's the same on every router lives in
the read-only root; everything unique to one router lives in `/var`**. An
update replaces the left side and keeps the right.

## The pieces, one by one

**mkosi** ([`image/mkosi.conf`](../../image/mkosi.conf)) is systemd's image
builder. You give it a distribution, a package list, and extra files
([`image/mkosi.extra/`](../../image/mkosi.extra)), and it produces a bootable
disk. It's a declarative recipe instead of a pile of install commands, so
builds are reproducible.

**systemd-repart** ([`image/mkosi.repart/`](../../image/mkosi.repart)) lays
out the partitions. One small `.conf` file per partition says its type, its
filesystem and what to copy into it.

**erofs** is the root filesystem. It's read-only by design, so there's no
code in it for writing, and it's compact. Linux itself can't modify it, let
alone an attacker or a mistyped command.

**dm-verity** is the tamper-proofing. At build time we hash every 4 KiB
block of the root partition, then hash the hashes, and so on up to a single
**root hash**. That tree is stored in the `root-verity` partition. At runtime
the kernel checks every block it reads against the tree. Flip one bit of
`/usr/bin/ephemerisd` on disk and reading it fails with an I/O error. The
router can't silently run modified code.

**UKI (unified kernel image) and systemd-boot.** The kernel, the initrd (the
tiny early-boot system that finds and unlocks the root filesystem) and the
kernel command line, *including the root hash*, are bundled into one EFI
file on the ESP. systemd-boot is the boot menu that starts it. Because the
root hash is inside the UKI, signing that one file (Secure Boot, Phase 3c)
extends trust all the way down to every byte of the OS.

**/var on its own partition.** It's ext4 and writable. On first boot,
`systemd-repart` grows it to fill whatever disk size you gave the VM, and
`ephemeris-grow-var.service` grows the filesystem to match.

It's mounted *in the initrd* (`x-initrd.mount` in
[`fstab`](../../image/mkosi.extra/etc/fstab)), before the real system even
starts. The first CI boot test found out why the hard way:
`systemd-resolved` starts very early, uses a private `/tmp` backed by
`/var/tmp`, and failed because `/var` was still an empty, read-only
directory at that point. Splitting the OS into read-only and writable parts
means thinking about *when* each part becomes available, not just where it
lives.

## How one image becomes many different routers

If the image is byte-identical everywhere, how does each router get its own
SSH key, hostname and interface addresses? Through **systemd credentials**:
small named values handed to the OS at boot from *outside* the disk.

[`deploy-image.sh`](../../lab/proxmox/deploy-image.sh) passes them through
the VM's firmware tables (SMBIOS type 11, set with `qm set --args`):

| Credential | Becomes |
|---|---|
| `ssh.authorized_keys.root` | `/var/lib/ephemeris/ssh/authorized_keys.root`, refreshed every boot |
| `system.hostname` | the hostname |
| `ephemeris.config` | `/var/lib/ephemeris/ephemeris.toml`, written on first boot only |
| `ephemeris.admin_password_hash` | the admin password (SHA-512 crypt hash; the plain password is printed by the deploy script and never reaches the VM) |

Inside the image, [`tmpfiles.d/ephemeris.conf`](../../image/mkosi.extra/usr/lib/tmpfiles.d/ephemeris.conf)
does the writing. It's a declarative list: "this file, from that credential".

The same idea covers everything else that must be unique:

- **SSH host key.** Generated into `/var` on first boot
  (`ephemeris-ssh-keygen.service`). The keys that package installation created
  at build time are deleted, otherwise every router would share one host key.
- **Machine ID.** Derived from the VM's SMBIOS UUID
  (`systemd.machine_id=firmware`), since it can't be written to `/etc`.
- **DHCP identity.** Keyed on the MAC address, so the management IP stays
  stable.

This is the same model cloud providers use to turn one AMI or VM image into
millions of distinct servers.

## The build pipeline

Building and releasing are two separate steps: **build once, promote the
tested bytes**.

```
git push (main)
        │
        ▼  .github/workflows/image.yml (on GitHub's Linux machines)
  1. cargo fmt / clippy / test       ← nothing is built if a test fails
  2. image/build.sh <version>        ← cargo build + mkosi → .raw → .qcow2
  3. boot test in QEMU               ← UEFI + virtio-scsi, like Proxmox
  4. artifact "ephemeris-image"        ← the tested image, kept 90 days

git tag v0.5.0 <commit> && git push origin v0.5.0
        │
        ▼  .github/workflows/release.yml (takes about a minute)
  5. find the passing image run for that commit, download its artifact,
     check it's release 0.5.0, verify the checksum, publish it as
     GitHub Release v0.5.0
```

**Every image says which release it is.** The release version lives in one
place, `version` in the workspace [`Cargo.toml`](../../Cargo.toml). CI names
each image `<release>.<build number>`, e.g. `0.5.0.123`: release 0.5.0, the
123rd CI build. The build number keeps every newer build sorting as newer,
which A/B updates rely on. The version is kept short because it ends up in
GPT partition labels, which hold at most 36 characters. So the exact commit
is stored next to it rather than in it. On a router:

| Where | Shows |
|---|---|
| Console login prompt | `Ephemeris 0.5.0.123` |
| `ephctl status`, portal header and System tab | `v0.5.0`, build `0.5.0.123 (commit dca7076)` |
| `/usr/lib/ephemeris/version`, `/usr/lib/ephemeris/commit` | the raw values |

To release: set the new version in `Cargo.toml`, push, wait for CI to pass,
then tag that commit `v<version>`. The release workflow refuses a tag that
doesn't match the image's release, so a `v0.6.0` tag can't be put on a
0.5.0 image by mistake. The tag is otherwise just a name attached to an image
that already exists and already passed its tests. That's also why a release
can't contain anything that wasn't boot-tested: there's no build step left
to sneak a change in.

Step 3 matters most. There is **nothing test-related inside the image**:
CI tests the exact bytes that get released, from the outside
([`ci/e2e.sh`](../../ci/e2e.sh)). It boots the image the way Proxmox does
(UEFI with Secure Boot, virtio NICs, credentials like `deploy-image.sh`
passes them), plugs its LAN ports into network namespaces on the CI machine,
and then acts as the network and the operator:

- the real systemd services start, with nothing failed,
- SSH works with the generated password,
- the web portal works in a real browser (Playwright: sign in, every tab,
  add and remove a route, sign out),
- packets are forwarded, TTL and ICMP behave, the stateful policy holds,
  and iperf3 runs both ways,
- a live route change via `ephctl` takes effect,
- `ephctl system update` installs a newer image, and after a reboot the
  router runs it and has blessed it.

Lesson learned the hard way: an earlier version of this test started
`ephemerisd` by hand inside the image. The real systemd unit had a sandbox
(`ProtectSystem=strict`) that made `/var/lib/ephemeris` read-only, so the
service crash-looped on every real router while CI stayed green. **Test what
you ship, the way it ships.**

## Deploying

```bash
# once: the lab network (bridges + client containers)
./create-lab.sh
# each router (latest release; or pass a version like 0.2.0)
SSH_KEY=/root/id_ed25519.pub ./deploy-image.sh
# replace the router with a newer image (config on /var is NOT kept this way; 3b fixes that)
REPLACE=1 SSH_KEY=/root/id_ed25519.pub ./deploy-image.sh 0.3.0
```

## What's deliberately missing (Phase 3b and 3c)

- **In-place updates.** Right now upgrading means redeploying the VM.
  Phase 3b adds a second root partition (A/B). `systemd-sysupdate` downloads
  the new version into the idle slot and you reboot into it. **Boot
  counting** (`+3` in the UKI file name) means a version that fails to boot
  3 times is abandoned, and the router falls back to the previous one. `/var`
  (and so your config) survives.
- **Secure Boot.** Signing the UKI with our key and enrolling the key in the
  VM's firmware, so the firmware refuses to boot anything we didn't sign.
- **A console password.** The image has no password logins at all, only SSH
  keys. That's safer, but if SSH breaks you're limited to the Proxmox serial
  console. Phase 2's API and web UI is the long-term answer.

## Building locally

On any Linux machine with cargo, [mkosi](https://github.com/systemd/mkosi)
and `qemu-img` (for example your dev VM):

```bash
image/build.sh dev
```

The image appears at `image/mkosi.output/ephemeris-x86_64.qcow2`. Copy it to
the Proxmox host and run `IMAGE=/path/to/it ./deploy-image.sh`.
