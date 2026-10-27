#!/usr/bin/env bash
# Build the Ephemeris OS image. Linux only (mkosi needs Linux).
#
#   image/build.sh [version]     (OUT=dir to choose the output directory)
#
# Produces, in image/mkosi.output/ by default:
#   ephemeris_<v>_x86-64.qcow2                                the disk image, for new routers
#   ephemeris_<v>_x86-64.root-x86-64.<uuid>.raw.xz           \
#   ephemeris_<v>_x86-64.root-x86-64-verity.<uuid>.raw.xz     } what systemd-sysupdate
#   ephemeris_<v>_x86-64.efi                                  /  downloads to update one
#   SHA256SUMS, SHA256SUMS.gpg (signed when SIGN_RELEASE=1), VERSION
#
# CI runs exactly this (.github/workflows/image.yml). Locally you need cargo,
# mkosi (https://github.com/systemd/mkosi), qemu-img and xz.
set -euo pipefail

VERSION=${1:-dev}
# The version becomes part of GPT partition labels, "ephemeris_<v>_verity",
# and GPT labels hold at most 36 characters.
label="ephemeris_${VERSION}_verity"
if (( ${#label} > 36 )); then
    echo "version '$VERSION' is too long: partition label '$label' is ${#label} > 36 characters" >&2
    exit 1
fi
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=$ROOT/image
STAGE=$IMAGE/stage
OUT=$(realpath -m "${OUT:-$IMAGE/mkosi.output}")

echo "== building ephemerisd and ephctl"
cargo build --release --locked -p ephemerisd -p ephctl --manifest-path "$ROOT/Cargo.toml"

echo "== staging files into the image tree"
rm -rf "$STAGE"
install -D -m 0755 "$ROOT/target/release/ephemerisd"      "$STAGE/usr/bin/ephemerisd"
install -D -m 0755 "$ROOT/target/release/ephctl"         "$STAGE/usr/bin/ephctl"
install -D -m 0644 "$ROOT/config/ephemeris.example.toml"   "$STAGE/usr/lib/ephemeris/ephemeris.example.toml"
echo "$VERSION" > "$STAGE/usr/lib/ephemeris/version"
# The exact source it was built from (not in the version: labels are short).
echo "${COMMIT:-$(git -C "$ROOT" rev-parse --short=7 HEAD 2>/dev/null || echo unknown)}" > "$STAGE/usr/lib/ephemeris/commit"

extra=()
if [[ ! -f $IMAGE/mkosi.key ]]; then
    echo "!! image/mkosi.key not found: building an UNSIGNED image (no Secure Boot)." >&2
    echo "!! Routers that enrolled the Ephemeris key will refuse to boot it." >&2
    extra+=(--secure-boot=no)
fi

echo "== building image $VERSION"
rm -rf "$OUT"
mkdir -p "$OUT"
(cd "$IMAGE" && mkosi --force --image-version="$VERSION" --output-directory="$OUT" \
    --extra-tree="$STAGE:/" "${extra[@]}" build)

base="ephemeris_${VERSION}_x86-64"
cd "$OUT"
echo "== converting $base.raw to qcow2"
qemu-img convert -c -O qcow2 "$base.raw" "$base.qcow2"

echo "== compressing update artifacts"
# The root slot is a fixed 1.5 GiB, mostly zeros: compresses very well.
# xz, not zstd: systemd-pull in Debian 13 can't decompress zstd and would
# write the compressed bytes straight into the partition.
for f in "$base".root-*.raw; do
    xz -T0 -3 "$f"
done

echo "$VERSION" > VERSION
# The SBOM: mkosi's package manifest (Debian packages) and, if CI made one,
# the Rust dependencies (image/rust.cdx.json, CycloneDX). Listed in
# SHA256SUMS, so they're signed with the image.
sbom=()
[[ -f $base.manifest ]] && sbom+=("$base.manifest")
if [[ -f $IMAGE/rust.cdx.json ]]; then
    cp "$IMAGE/rust.cdx.json" "$base.rust.cdx.json"
    sbom+=("$base.rust.cdx.json")
fi
sha256sum "$base.qcow2" "$base".root-*.raw.xz "$base.efi" "${sbom[@]}" > SHA256SUMS
# Sign the manifest: routers only install updates whose SHA256SUMS.gpg
# verifies against the release key baked into the image.
if [[ ${SIGN_RELEASE:-0} == 1 ]]; then
    gpg --batch --yes --detach-sign --output SHA256SUMS.gpg SHA256SUMS
else
    echo "!! SIGN_RELEASE!=1: SHA256SUMS is not signed; routers will refuse this as an update." >&2
fi
rm -f "$base.raw"   # the qcow2 replaces it
ls -lh
