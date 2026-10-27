#!/bin/sh
# Rebuilds the oracle outputs in this directory, and checks the fixture, from
# plaso's NTFS test image (Apache-2.0). Runs on Debian with
#   apt-get install sleuthkit libfsntfs-utils qemu-utils curl
# The Sleuth Kit 4.12.1 (`usnjls`) and libfsntfs 20240501 (`fsntfsinfo`)
# wrote the committed files.
set -eu

PLASO_COMMIT=e105c77da06a8716b224324253d92ea63c620f2a
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsSL -o "$work/usnjrnl.qcow2" \
    "https://raw.githubusercontent.com/log2timeline/plaso/$PLASO_COMMIT/test_data/usnjrnl.qcow2"
qemu-img convert -O raw "$work/usnjrnl.qcow2" "$work/usnjrnl.raw"

# The NTFS volume starts at sector 63; $UsnJrnl is MFT entry 29, $J its
# attribute 128-3.
icat -o 63 "$work/usnjrnl.raw" 29-128-3 > "$work/J"
cmp "$work/J" "$here/../fixtures/plaso/UsnJrnl.raw"

# usnjls exits 1 where it stops reading (see tests/oracle.rs).
TZ=UTC usnjls -l -o 63 "$work/usnjrnl.raw" 29 > "$here/usnjls.txt" || true
fsntfsinfo -o $((63 * 512)) -U "$work/usnjrnl.raw" > "$here/fsntfsinfo.txt"
