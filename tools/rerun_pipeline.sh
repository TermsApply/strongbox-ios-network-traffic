#!/bin/bash
# rerun_pipeline.sh - re-run the original HAR exports through the current pseudonymiser with one salt.
# Version 1.1.
#
# Usage:
#   ./rerun_pipeline.sh file1.har [file2.har ...]          (results in ./results)
#   OUTPUT_DIR=/other/dir KNOWN=known_LOCAL.txt ./rerun_pipeline.sh *.har
# Requires next to it: pseudonymise_har.py, prepare_har_for_publication.py.
#
# Authors' decisions of 9 Oct 2026:
#   - one salt outside the repository: ~/.strongbox-salt (variable SALT); the script stops if the
#     salt file does not exist (a new salt would make labels incomparable with earlier files),
#   - device model and server addresses in clear (--clear-groups model,server),
#   - results: results/anon/ (*.anon.har, *.report.txt), results/publication/ (*.pub.har, report, .sha256).
# The originals are only read; their SHA-256 is checked after each file.
# Time shifting and run codes are applied later, on the computer that holds the shift map
# (prepare_har_for_publication.py --shift-time ... --run-code ...).

set -euo pipefail
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"   # pseudonymise_har.py and prepare_har_for_publication.py next to this file
OUT="${OUTPUT_DIR:-$PWD/results}"          # output directory (default ./results)
SALT="${SALT:-$HOME/.strongbox-salt}"
KNOWN="${KNOWN:-}"
CLEAR_GROUPS="${CLEAR_GROUPS:-model,server}"
PUB_GROUPS="${PUB_GROUPS:-purchase_dates,price,currency_storefront,original_version,os_build,superwall_profile,local_time}"

[ $# -ge 1 ] || { echo "Usage: $0 file.har [...]"; exit 1; }
[ -f "$SALT" ] || { echo "Salt file not found: $SALT. Set SALT=/path/to/salt or move the existing salt file to this path. A new salt would make labels incomparable with earlier files." >&2; exit 1; }
[ -n "$KNOWN" ] && [ ! -f "$KNOWN" ] && { echo "--known file missing: $KNOWN"; exit 1; }
mkdir -p "$OUT/anon" "$OUT/publication" "$OUT/pcap-extracts"

for HAR in "$@"; do
  echo "=== $HAR"
  BEFORE=$(shasum -a 256 "$HAR" | cut -d' ' -f1)
  ARGS=(--salt "$SALT" --clear-groups "$CLEAR_GROUPS" --output "$OUT/anon")
  [ -n "$KNOWN" ] && ARGS+=(--known "$KNOWN")
  python3 "$SCRIPTS/pseudonymise_har.py" "$HAR" "${ARGS[@]}"
  AFTER=$(shasum -a 256 "$HAR" | cut -d' ' -f1)
  [ "$BEFORE" = "$AFTER" ] || { echo "ERROR: checksum of the original changed: $HAR"; exit 3; }
  BASE=$(basename "${HAR%.har}")
  python3 "$SCRIPTS/prepare_har_for_publication.py" "$OUT/anon/${BASE}.anon.har" \
    --salt "$SALT" --server keep --groups "$PUB_GROUPS" --output "$OUT/publication"
done

(cd "$OUT/anon" && shasum -a 256 *.anon.har *.report.txt > SHA256SUMS.txt)
(cd "$OUT/publication" && shasum -a 256 *.pub.har > SHA256SUMS.txt)
shasum -a 256 "$@" > "$OUT/SHA256SUMS_originals_LOCAL.txt"
echo
echo "Done. Salt: $SALT (do not share). Results: $OUT/anon, $OUT/publication; checksums of originals: $OUT/SHA256SUMS_originals_LOCAL.txt"
echo "Read the LEFTOVERS section of every $OUT/anon/*.report.txt before publication."
