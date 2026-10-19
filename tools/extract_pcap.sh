#!/bin/bash
# extract_pcap.sh - extract from an rvi0 capture, limited to the hosts of the studied app.
# Version 2.1.0 (changes: CHANGELOG.md).
#
# Usage:
#   ./extract_pcap.sh RUN.pcapng [background.pcapng]
#   OUTPUT_DIR=results/pcap-extracts ./extract_pcap.sh originals/RUN.pcapng
#
# background.pcapng = capture of "background" traffic with the app closed (optional, recommended).
# The output prefix is the capture file name without extension; name the capture by its run code
# (e.g. S17.pcapng) so that shift_extract_times.py recognises the files.
#
# Variables (optional):
#   TSHARK=path           tshark program (default: searched in Wireshark.app, Homebrew, PATH)
#   PATTERN=regex         studied hosts (default as in 1.x)
#   OUTPUT_DIR=directory  where to write the results (default: next to the input file)
#   QUIC_ALL=1            in *_syn-quic.csv all QUIC packets to the server,
#                         not only packets that start a connection (long header)
#
# tshark runs with LC_ALL=C, so numbers use a decimal point regardless of system locale.
#
# Output files (prefix = run name):
#   *_tls-connections.csv     TO SHARE: time, host (SNI), server IP, port, stream number
#   *_dns.csv                 TO SHARE: DNS queries for hosts matching the pattern
#   *_dns-answers.csv         TO SHARE: DNS answers (A/AAAA addresses) for hosts matching the pattern
#   *_syn-quic.csv            TO REVIEW: starts of TCP (SYN) and QUIC connections of all apps:
#                             time, protocol, server address, port, stream, host (when known
#                             from SNI/DNS of this run). Filter out other addresses before sharing.
#   *_sni-new.txt             TO REVIEW: hosts present in the run, absent from the background
#   *_sni-all_LOCAL.txt       DO NOT SHARE: all hosts of the device
#   *_tshark-errors_LOCAL.txt DO NOT SHARE: tshark error messages (empty = no errors)
#   *_strongbox.pcapng        DO NOT SHARE unless needed: packets only to/from servers matching the pattern
#
# The CSV files contain neither the source address (your IP) nor packet contents.
# *_syn-quic.csv holds only packets towards the server (SYN without ACK, QUIC to port 443),
# so the "address" column is always the server address, not the phone's.

set -euo pipefail
export LC_ALL=C

EXTRACT_VERSION="2.1.0"

# --- tshark -----------------------------------------------------------------
find_tshark() {
  local k
  for k in "${TSHARK:-}" /Applications/Wireshark.app/Contents/MacOS/tshark \
           /opt/homebrew/bin/tshark /usr/local/bin/tshark "$(command -v tshark 2>/dev/null || true)"; do
    if [ -n "$k" ] && [ -x "$k" ]; then
      echo "$k"
      return 0
    fi
  done
  return 1
}
if ! TSHARK="$(find_tshark)"; then
  echo "tshark (Wireshark) not found. Install Wireshark or set TSHARK=/path/to/tshark." >&2
  exit 1
fi

PATTERN="${PATTERN:-superwall|revenuecat|sentry|strongbox|duckduckgo|pwned|simplelogin|gstatic|googleapis}"

[ $# -ge 1 ] || { echo "Usage: $0 RUN.pcapng [background.pcapng]"; exit 1; }
IN="$1"
BACKGROUND="${2:-}"
[ -r "$IN" ] || { echo "File missing or not readable: $IN" >&2; exit 1; }
[ -z "$BACKGROUND" ] || [ -r "$BACKGROUND" ] || { echo "File missing or not readable: $BACKGROUND" >&2; exit 1; }

NAME="$(basename "${IN%.*}")"
OUTPUT_DIR="${OUTPUT_DIR:-$(dirname "$IN")}"
mkdir -p "$OUTPUT_DIR"
P="$OUTPUT_DIR/$NAME"
ERRORS="${P}_tshark-errors_LOCAL.txt"
: > "$ERRORS"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# -n: no name resolution (tshark sends no DNS queries of its own)
ts() { "$TSHARK" -n "$@" 2>>"$ERRORS"; }

# Common CSV settings. occurrence=f: only the first occurrence of a field, so that a
# field with several values (e.g. ICMP with a second IP header) does not break the columns.
CSV=(-T fields -E separator=, -E header=y -E quote=d -E occurrence=f)

# Writes the header if tshark returned no rows (behaviour depends on the version).
header() {
  local file="$1" line="$2"
  if [ ! -s "$file" ]; then
    echo "$line" > "$file"
  fi
}
rows() { local n; n=$(wc -l < "$1"); echo $((n - 1)); }

sni_list() {
  ts -r "$1" -Y 'tls.handshake.type == 1 && tls.handshake.extensions_server_name' \
    -T fields -E occurrence=f -e tls.handshake.extensions_server_name
}

echo "extract_pcap.sh $EXTRACT_VERSION; tshark: $TSHARK"
echo "1/7 All hosts (SNI) with connection counts - local file"
sni_list "$IN" > "$TMP/sni_in.txt" || true
sort "$TMP/sni_in.txt" | uniq -c | sort -rn > "${P}_sni-all_LOCAL.txt"
ECH=$(grep -c -x 'cloudflare-ech\.com' "$TMP/sni_in.txt" || true)

echo "2/7 Hosts absent from the background"
if [ -n "$BACKGROUND" ]; then
  sni_list "$BACKGROUND" > "$TMP/sni_background.txt" || true
  comm -23 <(sort -u "$TMP/sni_in.txt") <(sort -u "$TMP/sni_background.txt") > "${P}_sni-new.txt"
else
  echo "(no background capture given - skipped)" > "${P}_sni-new.txt"
fi

echo "3/7 Connections to hosts matching: $PATTERN"
ts -r "$IN" \
  -Y "tls.handshake.type == 1 && tls.handshake.extensions_server_name matches \"($PATTERN)\"" \
  "${CSV[@]}" \
  -e frame.time_epoch -e tls.handshake.extensions_server_name \
  -e ip.dst -e ipv6.dst -e tcp.dstport -e udp.dstport -e tcp.stream \
  > "${P}_tls-connections.csv" || true
header "${P}_tls-connections.csv" "frame.time_epoch,tls.handshake.extensions_server_name,ip.dst,ipv6.dst,tcp.dstport,udp.dstport,tcp.stream"

echo "4/7 DNS queries for hosts matching the pattern"
ts -r "$IN" \
  -Y "dns.flags.response == 0 && dns.qry.name matches \"($PATTERN)\"" \
  "${CSV[@]}" \
  -e frame.time_epoch -e dns.qry.name -e dns.qry.type \
  > "${P}_dns.csv" || true
header "${P}_dns.csv" "frame.time_epoch,dns.qry.name,dns.qry.type"

echo "5/7 DNS answers (addresses) for hosts matching the pattern"
# all addresses of an answer in one column, separated by a space
ts -r "$IN" \
  -Y "dns.flags.response == 1 && dns.qry.name matches \"($PATTERN)\"" \
  -T fields -E separator=, -E header=y -E quote=d -E occurrence=a -E aggregator=' ' \
  -e frame.time_epoch -e dns.qry.name -e dns.a -e dns.aaaa \
  > "${P}_dns-answers.csv" || true
header "${P}_dns-answers.csv" "frame.time_epoch,dns.qry.name,dns.a,dns.aaaa"

echo "6/7 Starts of TCP (SYN) and QUIC connections - all apps"
if [ "${QUIC_ALL:-0}" = "1" ]; then
  QUIC_FILTER="quic && udp.dstport == 443"
else
  QUIC_FILTER="quic && udp.dstport == 443 && quic.header_form == 1"
fi
ts -r "$IN" \
  -Y "(tcp.flags.syn == 1 && tcp.flags.ack == 0) || ($QUIC_FILTER)" \
  "${CSV[@]}" \
  -e frame.time_epoch -e ip.dst -e ipv6.dst -e tcp.dstport -e udp.dstport -e tcp.stream -e udp.stream \
  > "$TMP/syn_quic_raw.csv" || true
# address -> host map from SNI (connections) and DNS answers of this run
awk -F, '
  function unq(s) { gsub(/"/, "", s); return s }
  function add(a, h) { if (a == "" || h == "") return; if (index(" " map[a] " ", " " h " ") == 0) map[a] = (map[a] == "" ? h : map[a] " " h) }
  FNR == 1 { file++; next }
  file == 1 { add(unq($3), unq($2)); add(unq($4), unq($2)); next }
  file == 2 { h = unq($2); n = split(unq($3) " " unq($4), adr, " "); for (i = 1; i <= n; i++) add(adr[i], h); next }
  file == 3 {
    t = unq($1); a4 = unq($2); a6 = unq($3); tp = unq($4); up = unq($5); tst = unq($6); ust = unq($7)
    address = (a4 != "" ? a4 : a6)
    if (tp != "") { proto = "TCP-SYN"; port = tp; str = tst } else { proto = "QUIC"; port = up; str = ust }
    printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", t, proto, address, port, str, map[address]
  }
  BEGIN { print "time_epoch,protocol,address,port,stream,host" }
' "${P}_tls-connections.csv" "${P}_dns-answers.csv" "$TMP/syn_quic_raw.csv" > "${P}_syn-quic.csv"

echo "7/7 Narrowed PCAP file (only servers matching the pattern)"
IP4=$(tail -n +2 "${P}_tls-connections.csv" | cut -d, -f3 | tr -d '"' | grep -v '^$' | sort -u | paste -sd, - || true)
IP6=$(tail -n +2 "${P}_tls-connections.csv" | cut -d, -f4 | tr -d '"' | grep -v '^$' | sort -u | paste -sd, - || true)
FILTER=""
[ -n "$IP4" ] && FILTER="ip.addr in {$IP4}"
if [ -n "$IP6" ]; then
  [ -n "$FILTER" ] && FILTER="$FILTER || "
  FILTER="${FILTER}ipv6.addr in {$IP6}"
fi
if [ -n "$FILTER" ]; then
  ts -r "$IN" -Y "$FILTER" -w "${P}_strongbox.pcapng" || true
else
  echo "   No connections match the pattern - file not created."
fi

echo
echo "Done (results in: $OUTPUT_DIR)."
echo "Connections matching the pattern (SNI): $(rows "${P}_tls-connections.csv")"
echo "DNS queries matching the pattern: $(rows "${P}_dns.csv"); DNS answers: $(rows "${P}_dns-answers.csv")"
echo "Starts of TCP/QUIC connections (all apps): $(rows "${P}_syn-quic.csv")"
echo "SNI 'cloudflare-ech.com' (ECH, host name hidden): ${ECH:-0}"
echo "To share: ${P}_tls-connections.csv, ${P}_dns.csv, ${P}_dns-answers.csv"
echo "To review before sharing: ${P}_sni-new.txt, ${P}_syn-quic.csv (they contain traffic of other apps)"
if [ -s "$ERRORS" ]; then
  echo "WARNING: tshark reported errors - see $ERRORS (results may be incomplete)." >&2
fi
