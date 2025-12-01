#!/usr/bin/env bash
set -euo pipefail

# Fetch a static CRS bundle for bn254 (G1/G2) and grumpkin G1.
# Sizes (byte ranges):
# - bn254_g1.dat: 2^20 + 1 points -> bytes 0-67,108,927 (~64 MB)
# - bn254_g2.dat: full file (128 bytes)
# - grumpkin_g1.flat.dat: 2^18 points -> bytes 0-16,777,215 (~16 MB)
#
# Default destination is ~/.bb-crs; override with DEST or CRS_PATH.

DEST="${DEST:-${CRS_PATH:-$HOME/.bb-crs}}"
mkdir -p "$DEST"

echo "Fetching CRS into $DEST"

bn254_g1="$DEST/bn254_g1.dat"
bn254_g2="$DEST/bn254_g2.dat"
grumpkin_g1="$DEST/grumpkin_g1.flat.dat"

curl -fLs -H "Range: bytes=0-67108927" -o "$bn254_g1" https://crs.aztec.network/g1.dat
curl -fLs -o "$bn254_g2" https://crs.aztec.network/g2.dat
curl -fLs -H "Range: bytes=0-16777215" -o "$grumpkin_g1" https://crs.aztec.network/grumpkin_g1.dat

chmod a-w "$bn254_g1" "$bn254_g2" "$grumpkin_g1"

echo "Done. Sizes:"
stat_cmd="stat -c %s"
if [[ "$(uname)" == "Darwin" ]]; then
  stat_cmd="stat -f %z"
fi
echo "bn254_g1.dat: $($stat_cmd "$bn254_g1") bytes"
echo "bn254_g2.dat: $($stat_cmd "$bn254_g2") bytes"
echo "grumpkin_g1.flat.dat: $($stat_cmd "$grumpkin_g1") bytes"
