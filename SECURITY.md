# Security policy

Ephemeris is a learning project (see the disclaimer in the README), but its
security is taken seriously: it routes and filters real traffic, and it is
reached over the network.

## Reporting a vulnerability

Please report it privately, not in a public issue: use **Report a
vulnerability** on the repository's **Security** tab (GitHub's private
vulnerability reporting). Include what you found, how to reproduce it, and
the version (`ephctl status`, or the image name).

You'll get an answer within a week. Once a fix is ready it ships in a
release, the advisory is published, and you're credited unless you'd rather
not be.

## What's in scope

- The data plane (anything a packet can make the router do).
- The management plane: the web portal, the API, `ephctl`, SSH access.
- The image: Secure Boot, signed updates, the A/B update process.
- The build and release pipeline.

## Supported versions

Only the latest release gets fixes. Routers update to it with `ephctl
system update` (or the portal's System tab).

## Verifying a release

Every release image is:

- **signed**: routers only install an update whose `SHA256SUMS.gpg`
  verifies against the release key built into the image, and only boot
  images signed for Secure Boot;
- **attested**: GitHub keeps a signed record (SLSA build provenance) that
  the files were built by this repository's workflow from the tagged
  commit. Check one with
  `gh attestation verify <file> -R mornev-sudo/ephemeris`;
- **described**: the release includes an SBOM, the Debian package manifest
  (`.manifest`) and the Rust dependencies (`.rust.cdx.json`, CycloneDX).

The threat model behind all of this is in
[docs/threat-model.md](docs/threat-model.md).
