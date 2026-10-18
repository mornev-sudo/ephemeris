# 11. Chain of trust: Secure Boot and signed updates

## The question

dm-verity (chapter 8) guarantees the root filesystem matches its root hash.
But the root hash lives in the UKI's kernel command line. What stops someone
from swapping in a UKI with a different root hash, pointing at a different,
malicious root filesystem? And what stops a fake update server from handing
a router a malicious "update"?

The answer is to make every link in the chain checked by the one before it,
all the way back to something that can't be changed from software.

```
 UEFI firmware ── checks signature of ──▶ systemd-boot ── checks ──▶ UKI
 (holds our certificate                    (signed)                  (signed: kernel + initrd
  in its "db" key store)                                              + cmdline + root hash)
                                                                          │
                                                       dm-verity checks every block
                                                       of root against the root hash
                                                                          ▼
                                                                  root filesystem
                                                                  (ephemerisd, sshd, ...)

 GitHub release ── SHA256SUMS.gpg ──▶ systemd-sysupdate checks it against the
                                      public key inside the (verified) root, then
                                      every file against SHA256SUMS
```

Change one byte anywhere (firmware aside) and something refuses to run it.

## The two keys

Both are generated once, on the maintainer's machine. The private halves
should exist in exactly two places: an offline backup, and the CI system's
secrets (GitHub Actions here). Only the public halves are in this
repository.

| Key | Type | Signs | Checked by | Public half lives in |
|---|---|---|---|---|
| Secure Boot | RSA-2048 + X.509 certificate | systemd-boot and every UKI | the UEFI firmware | [`image/mkosi.crt`](../../image/mkosi.crt), then the VM's firmware |
| Release | OpenPGP ed25519 | each release's `SHA256SUMS` | `systemd-sysupdate` (via gpg) | [`/etc/systemd/import-pubring.gpg`](../../image/mkosi.extra/etc/systemd) in the image |

Why two? They protect different things, are checked by different code,
and could be rotated independently. Using a separate key per purpose is a
basic rule of key management.

## Secure Boot in a VM, and enrollment

UEFI Secure Boot is driven by key stores in the firmware:

- **db** lists the certificates whose signatures may boot.
- **KEK** and **PK** control who may change db.

A PC normally ships with Microsoft's keys. A Proxmox VM created with
`pre-enrolled-keys=0` starts with **empty** key stores. That's called
*setup mode*: Secure Boot isn't enforced yet, and the first party to enroll
keys takes ownership.

`SecureBootAutoEnroll=yes` in [`mkosi.conf`](../../image/mkosi.conf) puts our
certificate on the ESP. On the very first boot, systemd-boot sees setup mode
(it only does this automatically inside VMs), enrolls our certificate as
PK, KEK and db, and resets the VM. From then on, Secure Boot is **on** and
the firmware boots only binaries signed with the Ephemeris key: not Microsoft's,
not a stock Debian kernel, not anyone else's.

Check it on a router:

```bash
bootctl status | grep -i "secure boot"
```

## Signed updates

Every release now includes `SHA256SUMS.gpg`, a detached signature over
`SHA256SUMS` made with the release key ([`image/build.sh`](../../image/build.sh)
with `SIGN_RELEASE=1`).

The transfer files no longer say `Verify=no`. So before installing
anything, `systemd-sysupdate`:

1. downloads `SHA256SUMS` and `SHA256SUMS.gpg`,
2. runs `gpg --verify` against `/etc/systemd/import-pubring.gpg`, which is
   on the verity-protected root, so the key itself can't have been tampered
   with,
3. refuses the update if the signature is missing or wrong, and
4. otherwise checks every downloaded file's SHA-256 against the now-trusted
   list.

HTTPS still protects the download in transit, but security no longer
*depends* on it. An update mirror, a cache or a hijacked DNS name can't
inject anything, because they can't sign it.

## What it protects against, and what it doesn't

| Threat | Stopped by |
|---|---|
| Someone edits files on the router's disk while it's off | dm-verity (root) |
| Someone replaces the UKI with one pointing at their own root | Secure Boot (UKI signature) |
| Someone replaces systemd-boot | Secure Boot |
| A fake or compromised update server | Release signature |
| Someone with root on a *running* router | **Not** stopped: they can do anything until the next reboot. The reboot brings back the verified image, but `/var` (config) is theirs. |
| Someone who steals the private keys | **Not** stopped. That's why the backup folder matters. |
| Someone with Proxmox host access | **Not** stopped. The hypervisor owns the VM's firmware and memory. On bare metal, a TPM and measured boot are the next layer. |

## Key hygiene, in practice

- **Keep the key backup offline**, for example in a password manager or on
  an encrypted USB drive, and nowhere else on the machine that made it.
- The private keys are never committed. `image/mkosi.key` is in
  `.gitignore`, and CI writes it from the secret for the duration of one job.
- **Pull requests from forks don't receive secrets**, so they can't produce
  signed images. That's deliberate.
- **Rotation:** for the release key, ship an image containing *both* the old
  and the new public key, then start signing with the new one. Rotating the
  Secure Boot key means enrolling a new db entry on each router, which is
  harder. That's why the certificate is valid for 10 years.

## Exercises

1. On a router, run `bootctl status`. Find the "Secure Boot" line and the
   list of boot entries, showing both installed versions.
2. Prove the update check works. Serve a release folder, edit one line of
   its `SHA256SUMS`, point a test router at it (`ephemeris.update_url`), and
   run `ephctl system check`. sysupdate refuses the manifest.
3. In a throwaway VM, try booting a stock Debian cloud image on a disk whose
   efidisk has already enrolled the Ephemeris key. The firmware refuses with a
   security violation.
