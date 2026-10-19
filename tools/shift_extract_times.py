#!/usr/bin/env python3
"""shift_extract_times.py - shifts timestamps in PCAP extracts (CSV) by the same values that
prepare_har_for_publication.py --shift-time applied to the HAR file of the same run.

Usage:
    python3 shift_extract_times.py time_shifts_LOCAL.json IN_DIR OUT_DIR [--legacy-input FILE.json] [--ip-map FILE.json]

Input files are named <run code>_<suffix> (as written by extract_pcap.sh when the capture file is
named by its run code), e.g. S17_tls-connections.csv. Known run codes and suffixes: RUNS and
SUFFIXES below. With --legacy-input, input names and CSV column names from an older naming scheme
are translated as described in the JSON file (section "extracts": prefixes, suffixes, columns).
Output files are always named <run code>_<suffix>.

The offset of a run with a HAR file is taken from the key RUN:<code> of the shift map, which
prepare_har_for_publication.py --run-code writes. Captures without a HAR file (T1, T2) get their
own random offset under PCAP:<code> (added to the JSON file on first use).

CSV rows with a private (RFC 1918) or link-local/ULA IPv6 address (fe80::/10, fc00::/7) are
dropped (EUI-64 addresses contain the MAC of devices on the local network); in *.txt files such
addresses are replaced with the label <<LAN>>. Text files are not time-shifted (relative times).

*_sni-new.txt lists every TLS server name of the run that is absent from the background capture,
including other apps and services on the device (their names show what else is installed and,
through CDN node names, the country of the network exit). Only names matching SNI_KEEP (the hosts
the report is about, plus proxyman.com as the marker of the Proxyman for iOS tool) and, per run,
SNI_KEEP_RUN (favicon hosts of the test database) are kept; the number of removed names is written
in a first comment line.

*_syn-quic.csv lists the starts of TCP connections and QUIC packets of all apps on the device; for
addresses that no studied host name pointed to, the column host is empty. Such rows (server
addresses of other apps and services) are dropped; a row is kept only if every name in its host
column matches SNI_KEEP or SNI_KEEP_RUN of the run. The number of dropped rows is printed.

*_tcp-conversations.txt (tshark -z conv,tcp) lists every TCP conversation of the capture. From
version 1.7 only conversations with a server address that a studied host name pointed to in the same
run (ip.dst/ipv6.dst of *_tls-connections.csv, dns.a/dns.aaaa of *_dns-answers.csv) are kept, plus
conversations between two local addresses; the number of removed conversations is written in a
first comment line.

With --ip-map (decision of 18 Oct 2026), every public server address in the CSV columns and in
*_tcp-conversations.txt is replaced with the label <<IP_n>> from the same map that
prepare_har_for_publication.py --server label uses for the HAR files (the same address gives the
same label everywhere; new addresses are added to the map). Without --ip-map the addresses stay
in clear (behaviour of versions up to 1.6).
"""
import argparse
import csv
import glob
import json
import os
import re
import sys

VERSION = "1.7"
# local network addresses: do not publish (RFC 1918, IPv6 link-local and ULA)
LOCAL_ADDRESS = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|(?:fe[89ab][0-9a-f]|f[cd][0-9a-f]{2}):[0-9a-f:]*)", re.IGNORECASE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prepare_har_for_publication import draw_shift, load_shifts, save_shifts, load_ip_map, save_ip_map, ip_label  # noqa: E402

# run code of the capture -> key of the shift map (None = own offset under PCAP:<code>)
RUNS = {
    "A0": "RUN:A0",
    "S02": "RUN:S02",
    "S01-install": "RUN:S01",   # installation phase before S01, same run
    "S01": "RUN:S01",
    "S11b": "RUN:S11b",
    "S17": "RUN:S17",
    "S18": "RUN:S18",
    "T3": "RUN:T3",
    "T1": None,
    "T2": None,
}
SUFFIXES = ("tls-connections.csv", "dns.csv", "dns-answers.csv", "syn-quic.csv", "sni-new.txt",
            "tcp-conversations.txt")
TIME_COLUMNS = ("frame.time_epoch", "time_epoch")
# server names kept in *_sni-new.txt (whole name, lower case)
SNI_KEEP = re.compile(
    r"(?:[a-z0-9-]+\.)*(?:revenuecat\.com|superwall\.me|superwall\.com|superwalleditor\.com"
    r"|stripe\.com|stripe\.network|sentry\.io|strongboxsafe\.com|duckduckgo\.com"
    r"|haveibeenpwned\.com|pwnedpasswords\.com|simplelogin\.io|simplelogin\.com|proxyman\.com)"
    r"|fonts\.googleapis\.com|fonts\.gstatic\.com")
# per run: favicon hosts from the entries of the test database (S18, favicon option switched on)
SNI_KEEP_RUN = {"S18": {"proton.me"}}
RE_HOST_NAME = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\.?")
# CSV columns with server addresses (one address, or several separated by spaces in DNS answers)
ADDRESS_COLUMNS = ("ip.dst", "ipv6.dst", "dns.a", "dns.aaaa", "address")
RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
RE_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
# a conversation line of tshark -z conv,tcp: "<addr>:<port>   <->   <addr>:<port>   ..."
RE_CONV_LINE = re.compile(r"^(\S+?):(\d+)\s+<->\s+(\S+?):(\d+)\s")


def output_name(name, legacy):
    """Returns (run code, suffix) for an input file name, or None if it is not recognised."""
    prefixes = dict((legacy or {}).get("prefixes") or {})
    prefixes.update({c: c for c in RUNS})
    suffixes = dict((legacy or {}).get("suffixes") or {})
    suffixes.update({s: s for s in SUFFIXES})
    for p in sorted(prefixes, key=len, reverse=True):
        if name.startswith(p + "_") and name[len(p) + 1:] in suffixes:
            return prefixes[p], suffixes[name[len(p) + 1:]]
    return None


def filter_sni(text, code):
    """Returns (text, kept, removed): the server names of *_sni-new.txt limited to SNI_KEEP and
    SNI_KEEP_RUN[code], with one comment line in front. Comment lines of the input are dropped;
    other lines that are not a host name (e.g. the note of extract_pcap.sh that no background capture
    was given) are kept as comment lines."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    names = [ln for ln in lines if RE_HOST_NAME.fullmatch(ln)]
    notes = [f"# {ln}" for ln in lines if not RE_HOST_NAME.fullmatch(ln)]
    extra = SNI_KEEP_RUN.get(code, set())
    kept = [h for h in names if SNI_KEEP.fullmatch(h.lower()) or h.lower() in extra]
    removed = len(names) - len(kept)
    head = (f"# TLS server names absent from the background capture, limited to the hosts named in the report "
            f"and proxyman.com (marker of Proxyman for iOS); {removed} other names removed "
            f"(other apps and services on the device)")
    return "\n".join([head] + notes + kept) + "\n", len(kept), removed


def keep_syn_row(host, code):
    """True if the host column of a *_syn-quic.csv row names only hosts of the report (one or more
    names separated by spaces); False for an empty column (connection of another app or service)."""
    names = host.split()
    extra = SNI_KEEP_RUN.get(code, set())
    return bool(names) and all(SNI_KEEP.fullmatch(h.lower()) or h.lower() in extra for h in names)


def label_cell(value, ip_map):
    """Replaces every address in a CSV cell (space-separated list) with its label."""
    out = []
    for part in value.split(" "):
        lab = ip_label(part, ip_map) if part else None
        out.append(lab if lab is not None else part)
    return " ".join(out)


def addresses_in_csv(path, header_map):
    """Set of public server addresses (normalised) in the address columns of a CSV file."""
    found = set()
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = [header_map.get(k, k) for k in next(reader)]
        cols = [i for i, k in enumerate(header) if k in ADDRESS_COLUMNS]
        for row in reader:
            for i in cols:
                if i < len(row):
                    for part in row[i].split(" "):
                        if part and not LOCAL_ADDRESS.search(part):
                            try:
                                found.add(str(__import__("ipaddress").ip_address(part)))
                            except ValueError:
                                pass
    return found


def filter_conversations(text, known, ip_map):
    """Returns (text, kept, removed) for *_tcp-conversations.txt: conversations whose remote address
    is not in `known` (addresses of the studied hosts in this run) are removed, unless both ends are
    local addresses. Addresses are replaced with <<LAN>> (local) or, with ip_map, with <<IP_n>>."""
    import ipaddress
    out, kept, removed = [], 0, 0
    for line in text.splitlines():
        m = RE_CONV_LINE.match(line)
        if not m:
            out.append(line)
            continue
        a1, a2 = m.group(1), m.group(3)
        local = [bool(LOCAL_ADDRESS.search(x)) for x in (a1, a2)]
        remote = [x for x, loc in zip((a1, a2), local) if not loc]
        ok = True
        for x in remote:
            try:
                ok = ok and str(ipaddress.ip_address(x)) in known
            except ValueError:
                ok = False
        if not ok:
            removed += 1
            continue
        kept += 1
        for x, loc in zip((a1, a2), local):
            if not loc and ip_map is not None:
                line = line.replace(x, ip_label(x, ip_map), 1)
        out.append(line)
    head = (f"# TCP conversations limited to the server addresses of the hosts named in the report "
            f"(from the TLS and DNS extracts of this run) and to the local network; {removed} other conversations removed "
            f"(other apps and services on the device)")
    return "\n".join([head] + out) + "\n", kept, removed


def main():
    ap = argparse.ArgumentParser(description=f"Shift timestamps in PCAP extracts (version {VERSION}).")
    ap.add_argument("shifts", help="shift map JSON (local, do not publish)")
    ap.add_argument("input_dir")
    ap.add_argument("output_dir")
    ap.add_argument("--legacy-input", metavar="JSON_FILE", help="translate older input file and column names (section 'extracts')")
    ap.add_argument("--ip-map", metavar="JSON_FILE", help="address -> label map shared with prepare_har_for_publication.py --server label (local, do not publish); public server addresses are replaced with <<IP_n>>")
    a = ap.parse_args()
    ip_map = load_ip_map(a.ip_map) if a.ip_map else None
    ip_map_before = json.dumps(ip_map, sort_keys=True) if ip_map is not None else None
    legacy = None
    if a.legacy_input:
        with open(a.legacy_input, encoding="utf-8") as f:
            legacy = json.load(f).get("extracts")
        if legacy is None:
            sys.exit(f"ERROR: {a.legacy_input} has no section 'extracts'")
    columns = (legacy or {}).get("columns") or {}

    shifts = load_shifts(a.shifts)
    files = {c: [] for c in RUNS}   # code -> [(input path, output name)]
    seen = {}
    for path in sorted(glob.glob(os.path.join(a.input_dir, "*.csv")) + glob.glob(os.path.join(a.input_dir, "*.txt"))):
        name = os.path.basename(path)
        hit = output_name(name, legacy)
        if hit is None:
            print(f"NOTE: not recognised, skipped: {name}", file=sys.stderr)
            continue
        code, suffix = hit
        out = f"{code}_{suffix}"
        if out in seen:
            sys.exit(f"ERROR: {seen[out]} and {name} both map to {out} - remove one of them from {a.input_dir}")
        seen[out] = name
        files[code].append((path, out))
    missing = [c for c, f in files.items() if not f]
    if len(missing) == len(RUNS):
        sys.exit(f"ERROR: no files for any run code in {a.input_dir} (pattern <code>_<suffix>; older names: --legacy-input)")
    if missing:
        print(f"NOTE: no input files for: {', '.join(missing)} (skipped)", file=sys.stderr)
    os.makedirs(a.output_dir, exist_ok=True)
    for code, key in RUNS.items():
        if not files[code]:
            continue
        key = key or f"PCAP:{code}"
        if key not in shifts:
            if key.startswith("RUN:"):
                sys.exit(f"ERROR: no key {key} in {a.shifts} - first run prepare_har_for_publication.py "
                         f"--run-code {key[4:]} --shift-time {a.shifts} for the HAR file of this run")
            shifts[key] = draw_shift()
        delta = int(shifts[key])
        n_csv = n_txt = 0
        # addresses of the studied hosts in this run (for *_tcp-conversations.txt), from the input CSV files
        known = set()
        for path, out in files[code]:
            if out.endswith("_tls-connections.csv") or out.endswith("_dns-answers.csv"):
                known |= addresses_in_csv(path, columns)
        for path, out in files[code]:
            if out.endswith(".csv"):
                n_csv += 1
                with open(path, newline="", encoding="utf-8") as src:
                    reader = csv.reader(src)
                    header = [columns.get(k, k) for k in next(reader)]
                    idx = [i for i, k in enumerate(header) if k in TIME_COLUMNS]
                    addr_cols = [i for i, k in enumerate(header) if k in ADDRESS_COLUMNS] if ip_map is not None else []
                    host_col = header.index("host") if out.endswith("_syn-quic.csv") and "host" in header else None
                    if out.endswith("_syn-quic.csv") and host_col is None:
                        sys.exit(f"ERROR: {path} has no column 'host' - cannot drop rows of other apps")
                    rows, dropped, foreign = [], 0, 0
                    for row in reader:
                        if any(LOCAL_ADDRESS.search(x) for x in row):
                            dropped += 1
                            continue
                        if host_col is not None and not keep_syn_row(row[host_col] if host_col < len(row) else "", code):
                            foreign += 1
                            continue
                        for i in idx:
                            if i < len(row) and row[i]:
                                row[i] = f"{float(row[i]) + delta:.6f}"
                        for i in addr_cols:
                            if i < len(row) and row[i]:
                                row[i] = label_cell(row[i], ip_map)
                        rows.append(row)
                with open(os.path.join(a.output_dir, out), "w", newline="", encoding="utf-8") as dst:
                    cw = csv.writer(dst, quoting=csv.QUOTE_ALL)
                    cw.writerow(header)
                    cw.writerows(rows)
                if dropped:
                    print(f"  {out}: dropped {dropped} rows with a local address")
                if host_col is not None:
                    print(f"  {out}: kept {len(rows)} rows of the studied hosts, dropped {foreign} rows of other apps")
            else:
                n_txt += 1
                # sni-new, tcp-conversations (relative times): not shifted; local addresses -> <<LAN>>
                with open(path, encoding="utf-8") as src:
                    text = src.read()
                if out.endswith("_sni-new.txt"):
                    text, kept, removed = filter_sni(text, code)
                    print(f"  {out}: kept {kept} server names, removed {removed}")
                if out.endswith("_tcp-conversations.txt"):
                    if not known:
                        sys.exit(f"ERROR: {out}: no *_tls-connections.csv / *_dns-answers.csv of run {code} in {a.input_dir} - cannot tell the conversations of the studied hosts apart")
                    text, kept, removed = filter_conversations(text, known, ip_map)
                    print(f"  {out}: kept {kept} conversations of the studied hosts or the local network, removed {removed}")
                text, n = LOCAL_ADDRESS.subn("<<LAN>>", text)
                with open(os.path.join(a.output_dir, out), "w", encoding="utf-8") as dst:
                    dst.write(text)
                if n:
                    print(f"  {out}: replaced {n} local addresses with the label <<LAN>>")
        print(f"{code}: shift as {key} ({n_csv} CSV, {n_txt} TXT)")
    save_shifts(a.shifts, shifts)
    if ip_map is not None and json.dumps(ip_map, sort_keys=True) != ip_map_before:
        save_ip_map(a.ip_map, ip_map)


if __name__ == "__main__":
    main()
