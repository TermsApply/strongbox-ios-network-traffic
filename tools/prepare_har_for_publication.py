#!/usr/bin/env python3
"""
prepare_har_for_publication.py - prepare a pseudonymised HAR (*.anon.har) for publication.

Usage:
    python3 prepare_har_for_publication.py run.anon.har
    python3 prepare_har_for_publication.py run.anon.har --output publication/data
    python3 prepare_har_for_publication.py file.anon.har --server keep --salt ~/private/.pseudonymisation_salt

What it does:
  1. keeps only entries of the studied hosts (api.revenuecat.com, *.superwall.me,
     *.superwall.com, user-content.superwalleditor.com, fonts.googleapis.com,
     fonts.gstatic.com, js.stripe.com),
  2. removes entries of the studied hosts sent by ANOTHER app (header
     X-Client-Bundle-ID / X-Bundle-ID or a bundleId field different from --bundle),
  3. removes the response body of static resources (superwalleditor, fonts, stripe);
     size, mimeType and status stay,
  4. masks purchase dates, price, original_application_version and the other field
     groups of pseudonymise_har.py (currency, model, OS build, Superwall profile,
     local time) - also in files from versions 1.x, where they were in clear;
     change with --groups; entry timestamps STAY unless --shift-time is given,
  5. removes the server address (default), or with --server label --ip-map JSON replaces it
     with a label <<IP_n>> (n given in order of first appearance; the same address gives the
     same label in every file, so "same address" comparisons between runs and with the PCAP
     extracts stay possible; the map is local, do not publish); removes _clientAddress,
     _clientPort, _remoteDeviceIP;
     masks the CDN point of presence (X-Amz-Cf-Pop and cdn-pop in Server-Timing) always,
     and the Superwall parameter sw_cache_key (a 13-digit timestamp in paywall resource URLs)
     always and in every place (URL, queryString, Referer, $paywall_url, bodies),
  6. checks the result for raw patterns (UUID, e-mail, IP, JWT, long digit strings); on a
     hit it does NOT write the .pub.har file (exit code 2), unless --force,
  7. with --shift-time, shifts timestamps by a constant per-file offset (found by input
     file name or by the alias RUN:<code>; a conflict between the two is an error),
     including epochs written as a 10/13-digit string in headers, queryString and cookies;
     a bare date or time of day next to a date-time in the same object (e.g. Superwall
     device.utcDate and device.utcTime next to device.utcDateTime) is rewritten from the
     shifted date-time, and masked if it did not agree with it; any other bare time of day
     in a body is masked (it cannot be shifted without its date),
  8. with --legacy-input, translates input written by an older pseudonymiser version
     (non-English label types and log.comment) before processing; label hashes are not
     changed (the hash is computed from the value only, not from the type).

Output (next to the input or in --output):
    run.pub.har           - file for publication
    run.pub.report.txt    - check report (no values)
    run.pub.har.sha256    - SHA-256 in sha256sum / shasum -c format
"""
import argparse
import collections
import datetime as _dt
import hashlib
import hmac
import ipaddress
import json
import os
import random as _random
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pseudonymise_har as P  # noqa: E402  (shared patterns and field groups)

VERSION = "1.6.0"
SCRIPT = "prepare_har_for_publication.py"
INPUT_MARKER = "pseudonymise_har.py"

STUDIED_HOSTS = (
    r"^(api\.revenuecat\.com|([a-z0-9-]+\.)*superwall\.me|([a-z0-9-]+\.)*superwall\.com"
    r"|user-content\.superwalleditor\.com|fonts\.googleapis\.com|fonts\.gstatic\.com|js\.stripe\.com)$"
)
HOSTS_WITHOUT_BODY = (
    r"^(user-content\.superwalleditor\.com|fonts\.googleapis\.com|fonts\.gstatic\.com|js\.stripe\.com)$"
)
# At minimum purchase_dates, price and original_version must be masked. By default all
# groups of pseudonymise_har.py are masked (except "server", which has its own option
# --server), because files from versions 1.x have them in clear, and the publication rules
# do not allow publishing demandScore/demandTier values.
DEFAULT_GROUPS = ",".join(g for g in P.FIELD_GROUPS if g != "server")
CLIENT_FIELDS = ("_clientAddress", "_clientPort", "_remoteDeviceIP")
BUNDLE_HEADERS = {"xclientbundleid", "xbundleid", "xappbundleid"}
SERVER_HEADERS = {"xamzcfpop"}
SERVER_TIMING_HEADERS = P.SERVER_TIMING_HEADERS   # cdn-pop;desc=... (same POP as X-Amz-Cf-Pop)


class Publication:
    def __init__(self, groups, salt=None, bundle="com.markmcguill.strongbox"):
        self.groups = groups
        self.keys = {}
        for g in groups:
            for k in P.FIELD_GROUPS[g]["keys"]:
                self.keys[k] = g
        self.salt = salt
        self.bundle = bundle
        self.masked = collections.defaultdict(collections.Counter)
        self.already_labelled = collections.Counter()

    def placeholder(self, group, v):
        label_type = P.FIELD_GROUPS[group]["type"] or "MASKED"
        if self.salt is None:
            return f"<<MASKED_{label_type}>>"
        s = str(v)
        h = hmac.new(self.salt, s.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:P.HASH_LENGTH]
        return f"<<{label_type}_{h}_L{len(s)}>>" if len(s) >= P.MIN_LENGTH_WITH_L else f"<<{label_type}_{h}>>"

    def mask(self, key, v):
        g = self.keys.get(P.normalise(key)) if isinstance(key, str) else None
        if not g or v is None or isinstance(v, bool) or v == "":
            return v, False
        if isinstance(v, str) and P.RE_PROTECTED.fullmatch(v):
            self.already_labelled[key] += 1
            return v, False
        if isinstance(v, (dict, list)):
            return v, False
        if P.normalise(key) in P.FIELD_GROUPS[g].get("partial", ()):
            new = P.RE_BUILD.sub(lambda m: m.group(1) + self.placeholder(g, m.group(2)), str(v))
            if new == str(v):
                return v, False
            self.masked[g][key] += 1
            return new, True
        self.masked[g][key] += 1
        return self.placeholder(g, v), True

    def json(self, o):
        if isinstance(o, dict):
            result = {}
            for k, v in o.items():
                if isinstance(v, (dict, list)):
                    result[k] = self.json(v)
                elif isinstance(v, str) and v.strip()[:1] in "{[" and len(v.strip()) > 2:
                    try:
                        result[k] = json.dumps(self.json(json.loads(v)), ensure_ascii=False, separators=(",", ":"))
                        continue
                    except ValueError:
                        result[k] = self.mask(k, v)[0]
                else:
                    result[k] = self.mask(k, v)[0]
            return result
        if isinstance(o, list):
            return [self.json(x) for x in o]
        return o

    def body_text(self, text):
        if not text:
            return text
        try:
            return json.dumps(self.json(json.loads(text)), ensure_ascii=False, separators=(",", ":"))
        except ValueError:
            pass
        lines = text.split("\n")
        if len(lines) > 1:
            result, hits = [], 0
            for ln in lines:
                try:
                    obj = json.loads(ln)
                    if isinstance(obj, (dict, list)):
                        result.append(json.dumps(self.json(obj), ensure_ascii=False, separators=(",", ":")))
                        hits += 1
                        continue
                except ValueError:
                    pass
                result.append(ln)
            if hits:
                return "\n".join(result)
        return text

    def pairs(self, items):
        for el in items or []:
            if isinstance(el, dict) and isinstance(el.get("value"), str):
                el["value"] = self.mask(el.get("name", ""), el["value"])[0]


def mask_server_timing_pop(value, pub):
    """Masks cdn-pop;desc=<POP> in a Server-Timing value. Returns (value, number masked)."""
    count = [0]

    def sub(m):
        if P.RE_PROTECTED.fullmatch(m.group(3)):
            return m.group(0)
        count[0] += 1
        return m.group(1) + m.group(2) + pub.placeholder("cdn_pop", m.group(3))
    return P.RE_SERVER_TIMING_POP.sub(sub, value), count[0]


# sw_cache_key=<value> in a paywall resource URL, wherever the URL occurs: the request URL and its
# queryString (labelled by the pseudonymiser as a sensitive key), the Referer header, $paywall_url in
# events and url fields of the static configuration (in clear up to pseudonymise_har.py 2.2.0).
# The value is a 13-digit timestamp (most likely the publication time of the paywall version, H) and
# is not shifted with the run, so in clear it bounds the real run time and links runs (audit of
# 17 Oct 2026). Always masked, the same way in every place: <<MASKED_NUM>> without --salt (also over
# labels already in the input, so that one parameter looks the same everywhere in the file); with
# --salt the HMAC label of pseudonymise_har.py (labels already in the input are kept: same salt,
# same label).
RE_CACHE_KEY_VALUE = re.compile(r"(\bsw_cache_key(?:=|%3[Dd]))(\d+|<<[A-Za-z0-9_]+>>|%3[Cc]%3[Cc][A-Za-z0-9_]+%3[Ee]%3[Ee])")
CACHE_KEY_NAME = "sw_cache_key"


def cache_key_placeholder(value, pub):
    if pub.salt is None:
        return "<<MASKED_NUM>>"
    if not value.isdigit():
        return value   # already a label (same salt gives the same label)
    h = hmac.new(pub.salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:P.HASH_LENGTH]
    return f"<<NUM_{h}_L{len(value)}>>" if len(value) >= P.MIN_LENGTH_WITH_L else f"<<NUM_{h}>>"


def mask_cache_key(o, pub, counter, key=None):
    """Returns o with every sw_cache_key value masked (strings, JSON nested in strings, and
    {"name": "sw_cache_key", "value": ...} pairs). counter[place] += 1 for every value changed."""
    if isinstance(o, dict):
        def place(k):
            if k == "value" and isinstance(o.get("name"), str):
                return o["name"]          # header or query parameter: its name
            return "body" if k == "text" else k
        result = {k: mask_cache_key(v, pub, counter, place(k)) for k, v in o.items()}
        if result.get("name") == CACHE_KEY_NAME and isinstance(result.get("value"), str):
            new = cache_key_placeholder(result["value"], pub)
            if new != result["value"]:
                counter["queryString"] += 1
                result["value"] = new
        return result
    if isinstance(o, list):
        return [mask_cache_key(x, pub, counter, key) for x in o]
    if isinstance(o, str) and CACHE_KEY_NAME in o:
        def sub(m):
            v = m.group(2)
            if v.startswith("%"):
                v = "<<" + v[6:-6] + ">>"
            new = cache_key_placeholder(v, pub)
            if new == v:
                return m.group(0)
            counter[str(key)] += 1
            return m.group(1) + new
        return RE_CACHE_KEY_VALUE.sub(sub, o)
    return o


def entry_bundles(e):
    """Returns the set of bundle identifiers declared in the request."""
    found = set()
    for h in e.get("request", {}).get("headers", []) or []:
        if isinstance(h, dict) and P.normalise(h.get("name", "")) in BUNDLE_HEADERS and isinstance(h.get("value"), str):
            found.add(h["value"])
    text = (e.get("request", {}).get("postData") or {}).get("text")
    if text:
        try:
            def walk(o):
                if isinstance(o, dict):
                    for k, v in o.items():
                        if isinstance(k, str) and P.normalise(k) == "bundleid" and isinstance(v, str):
                            found.add(v)
                        walk(v)
                elif isinstance(o, list):
                    for x in o:
                        walk(x)
            walk(json.loads(text))
        except ValueError:
            pass
    return {b for b in found if b and not P.RE_PROTECTED.fullmatch(b)}


# --------------------------------------------------------------------------
# Input from an older pseudonymiser version (--legacy-input)
# --------------------------------------------------------------------------
# The JSON file (kept private, next to the data it describes) has a section "har":
#   "script_name":   file name of the older pseudonymiser, as written in log.comment,
#   "comment_regex": regular expression for its log.comment with named groups
#                    version, scheme, fingerprint, groups,
#   "label_types":   {"old label type": "new label type"},
#   "group_names":   {"old field group name": "new name"} (also the word for "none").
# Labels are renamed only as complete labels <<TYPE_hash[_Llength]>> or <<TYPE<n>>>;
# the hash part and the _L part stay byte-identical.

def load_legacy(path, section):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    if section not in d:
        sys.exit(f"ERROR: {path} has no section '{section}'")
    return d[section]


def translate_legacy_har(text, legacy):
    """Returns (translated text, number of renamed labels). Changes only complete labels
    of the listed types; everything else stays byte-identical."""
    types = legacy.get("label_types") or {}
    if not types:
        return text, 0
    rx = re.compile(r"<<(%s)((?:_[0-9a-f]{%d}(?:_L\d+)?)|\d+)>>"
                    % ("|".join(re.escape(t) for t in sorted(types, key=len, reverse=True)), P.HASH_LENGTH))
    count = [0]

    def sub(m):
        count[0] += 1
        return f"<<{types[m.group(1)]}{m.group(2)}>>"
    return rx.sub(sub, text), count[0]


def translate_legacy_comment(comment, legacy):
    """Rewrites the log.comment of the older pseudonymiser into the text that
    pseudonymise_har.py writes itself. No match = error (nothing is guessed)."""
    m = re.fullmatch(legacy["comment_regex"], comment)
    if not m:
        sys.exit("ERROR: log.comment of the input does not match comment_regex of --legacy-input")
    names = legacy.get("group_names") or {}
    groups = [names.get(g.strip(), g.strip()) for g in m.group("groups").split(",") if g.strip()]
    groups = [g for g in groups if g != "none"]
    unknown = set(groups) - set(P.FIELD_GROUPS)
    if unknown:
        sys.exit(f"ERROR: unknown field groups after translation: {', '.join(sorted(unknown))}")
    return P.pseudonymised_comment(m.group("version"), m.group("scheme"), m.group("fingerprint"), groups)


# --------------------------------------------------------------------------
# Time shift (authors' decision, 9 Oct 2026): a constant, random offset per file,
# so that the producer cannot match the authors' records by exact timestamps.
# Order and intervals within a file stay. The offset value stays local.
# --------------------------------------------------------------------------
RE_ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})\b")
RE_DATE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b(?!T)")
RE_HTTP_DATE = re.compile(r"\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}:\d{2}:\d{2}) GMT\b")
EPOCH_KEYS = re.compile(r"(_ms|Ms|_us|_epoch|timestamp|ts)$")


def draw_shift(rng=_random):
    """At least 3 and less than 31 days, backward or forward: 3 to 30 whole days plus a random
    number of seconds within a day (0 to 86399), with the sign applied to the whole value.
    Before 1.2.1 the sign was applied to the days only, so a backward shift could be as small
    as 2 days and 1 second; the order of the random calls is unchanged."""
    days = rng.randint(3, 30)
    sign = rng.choice((-1, 1))
    return sign * (days * 86400 + rng.randint(0, 86399))


def shift_text(s, delta):
    def iso(m):
        d = _dt.datetime.strptime(m.group(1) + "T" + m.group(2), "%Y-%m-%dT%H:%M:%S") + _dt.timedelta(seconds=delta)
        return d.strftime("%Y-%m-%dT%H:%M:%S") + (m.group(3) or "") + m.group(4)
    s = RE_ISO.sub(iso, s)

    def http(m):
        d = _dt.datetime.strptime(f"{m.group(2)} {m.group(3)} {m.group(4)} {m.group(5)}", "%d %b %Y %H:%M:%S") + _dt.timedelta(seconds=delta)
        return d.strftime("%a, %d %b %Y %H:%M:%S GMT")
    s = RE_HTTP_DATE.sub(http, s)

    def date(m):
        try:
            return (_dt.datetime.strptime(m.group(1), "%Y-%m-%d") + _dt.timedelta(seconds=delta)).strftime("%Y-%m-%d")
        except ValueError:
            return m.group(0)
    return RE_DATE.sub(date, s)


# Bare dates and times of day. A bare time of day ("HH:MM:SS") matches none of the rules above and
# would stay unshifted; a bare date is shifted by whole days only. Next to a date-time in the same
# object (Superwall enrich: device.utcDate and device.utcTime next to device.utcDateTime) both would
# disagree with the shifted date-time and give away the real time of day or the size of the offset
# (found 17 Oct 2026). They are therefore rewritten from the shifted date-time of the same object;
# if they did not agree with it in the input, they are masked. Any other bare time of day in a
# body is masked, because it cannot be shifted consistently without its date.
RE_BARE_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
RE_BARE_TIME = re.compile(r"\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?")
MASKED_CLOCK = "<<MASKED_CLOCK>>"
# (action, key) -> count; action: "derived" (rewritten from the date-time), "masked: disagreed with
# the date-time", "masked: bare time of day". Reset by main() for each file.
CLOCK_STATS = collections.Counter()


def clock_parts(original, shifted):
    """original/shifted: the same JSON object before and after shift(). For every key whose
    normalised name ends with "datetime" and whose value is an ISO date-time, the siblings
    <prefix>Date and <prefix>Time (any spelling) are rewritten from the shifted value."""
    for k, v in original.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        nk = P.normalise(k)
        if not nk.endswith("datetime"):
            continue
        m, sm = RE_ISO.fullmatch(v.strip()), RE_ISO.fullmatch(str(shifted.get(k, "")).strip())
        if not m or not sm:
            continue
        prefix = nk[:-8]
        old_time = m.group(2) + (m.group(3) or "")
        new_time = sm.group(2) + (sm.group(3) or "")
        for sib, sv in original.items():
            if not isinstance(sib, str) or not isinstance(sv, str) or sib == k:
                continue
            ns = P.normalise(sib)
            if ns == prefix + "date" and RE_BARE_DATE.fullmatch(sv):
                agrees, derived = sv == m.group(1), sm.group(1)
            elif ns == prefix + "time" and RE_BARE_TIME.fullmatch(sv):
                agrees, derived = old_time.startswith(sv), new_time[:len(sv)]
            else:
                continue
            if ns == prefix + "time":
                # shift() masked it as a bare time of day; it is handled here instead
                bare = ("masked: bare time of day", sib)
                CLOCK_STATS[bare] -= 1
                if CLOCK_STATS[bare] <= 0:
                    del CLOCK_STATS[bare]
            if agrees:
                shifted[sib] = derived
                CLOCK_STATS[("derived from " + k, sib)] += 1
            else:
                shifted[sib] = MASKED_CLOCK
                CLOCK_STATS[("masked: disagreed with " + k, sib)] += 1


def shift(o, delta, key=None):
    if isinstance(o, dict):
        result = {k: shift(v, delta, k) for k, v in o.items()}
        clock_parts(o, result)
        return result
    if isinstance(o, list):
        return [shift(x, delta, key) for x in o]
    if isinstance(o, bool) or o is None:
        return o
    if isinstance(o, (int, float)) and isinstance(key, str) and EPOCH_KEYS.search(key):
        if 1e15 <= abs(o) < 1e17:   # microseconds
            return o + delta * 1_000_000
        if 1e12 <= abs(o) < 1e14:   # milliseconds
            return o + delta * 1000
        if 1e9 <= abs(o) < 1e11:    # seconds
            return o + delta
        return o
    if isinstance(o, str):
        st = o.strip()
        if st[:1] in "{[" and len(st) > 2:
            try:
                return json.dumps(shift(json.loads(st), delta, key), ensure_ascii=False, separators=(",", ":"))
            except ValueError:
                pass
        if RE_BARE_TIME.fullmatch(st):
            # bare time of day; replaced by clock_parts() if the object has a matching date-time
            CLOCK_STATS[("masked: bare time of day", str(key))] += 1
            return MASKED_CLOCK
        return shift_text(o, delta)
    return o


# Epochs written as a digit string in headers, queryString and cookies (e.g. RevenueCat headers).
# shift() shifts numbers only under keys matching EPOCH_KEYS, and shift_text() only text dates,
# so such values would stay unshifted. General rule: the whole value is 10 digits (s) or 13 digits
# (ms) and the epoch falls within 2020-2035. The list below holds the headers known from the data;
# a header outside the list that meets the rule is shifted too, but the report marks it for checking.
EPOCH_HEADERS = ("x-rc-last-refresh-time", "x-revenuecat-request-time")
RE_EPOCH_DIGITS = re.compile(r"\d{10}|\d{13}")
EPOCH_FROM = 1577836800   # 2020-01-01T00:00:00Z
EPOCH_TO = 2082758400     # 2036-01-01T00:00:00Z (exclusive), i.e. 2020-2035


def epoch_divisor(s):
    """1 (seconds) or 1000 (ms) if s is a 10/13-digit string with an epoch in 2020-2035; otherwise None."""
    if not isinstance(s, str) or not RE_EPOCH_DIGITS.fullmatch(s):
        return None
    k = 1000 if len(s) == 13 else 1
    return k if EPOCH_FROM <= int(s) // k < EPOCH_TO else None


def shift_epoch_pairs(e, delta, counter, listed_unchanged):
    """Shifts digit-string epochs in headers/queryString/cookies of entry e (in place), keeping the
    number of digits. counter[(field, name)] += 1 for each shifted value; listed_unchanged[name] for
    headers from EPOCH_HEADERS whose value does not meet the rule (they stay unchanged)."""
    for side in ("request", "response"):
        for field in ("headers", "queryString", "cookies"):
            for el in e.get(side, {}).get(field) or []:
                if not isinstance(el, dict):
                    continue
                v, name = el.get("value"), el.get("name", "")
                k = epoch_divisor(v)
                if k is None:
                    if field == "headers" and str(name).lower() in EPOCH_HEADERS:
                        listed_unchanged[name] += 1
                    continue
                new = str(int(v) + delta * k).zfill(len(v))
                el["value"] = new
                counter[(field, name)] += 1
                if field == "queryString" and isinstance(e["request"].get("url"), str):
                    # the same value in the URL (queryString is its parsed form)
                    e["request"]["url"] = re.sub(r"(?<=[?&]%s=)%s(?=&|#|$)" % (re.escape(str(name)), v),
                                                 new, e["request"]["url"])


def epochs_in_body(o, numbers, strings, key=None):
    """Only counts (does not change): epochs 2020-2035 in a JSON body that shift() does not shift -
    numbers (s/ms/us) under keys outside EPOCH_KEYS and 10/13-digit strings under any key."""
    if isinstance(o, dict):
        for k, v in o.items():
            epochs_in_body(v, numbers, strings, k)
    elif isinstance(o, list):
        for x in o:
            epochs_in_body(x, numbers, strings, key)
    elif isinstance(o, str):
        st = o.strip()
        if st[:1] in "{[" and len(st) > 2:
            try:
                epochs_in_body(json.loads(st), numbers, strings, key)
                return
            except ValueError:
                pass
        if epoch_divisor(st) is not None:
            strings[str(key)] += 1
    elif isinstance(o, (int, float)) and not isinstance(o, bool):
        if isinstance(key, str) and EPOCH_KEYS.search(key):
            return
        if any(EPOCH_FROM <= o / d < EPOCH_TO for d in (1, 1000, 1_000_000)):
            numbers[str(key)] += 1


def epochs_in_text(text, numbers, strings):
    """JSON body or JSON lines (NDJSON)."""
    if not isinstance(text, str) or not text:
        return
    try:
        epochs_in_body(json.loads(text), numbers, strings)
        return
    except ValueError:
        pass
    for ln in text.split("\n"):
        try:
            obj = json.loads(ln)
        except ValueError:
            continue
        if isinstance(obj, (dict, list)):
            epochs_in_body(obj, numbers, strings)


def resolve_shift(shifts, file_key, alias=None, rng=_random):
    """Returns (delta, map_changed, source). Source: "name" (key = input file name),
    "alias RUN:<code>" (input file under a new name, offset known from the run code) or "draw".
    Different values under name and alias = error (neither is overwritten)."""
    by_name = shifts.get(file_key)
    by_alias = shifts.get(alias) if alias else None
    if by_name is not None and by_alias is not None and int(by_name) != int(by_alias):
        sys.exit(f"ERROR: the shift map has different values for {file_key} and {alias} - not overwriting; "
                 f"check the map (one run must have one offset)")
    if by_name is not None:
        delta, source = int(by_name), "name"
    elif by_alias is not None:
        delta, source = int(by_alias), f"alias {alias}"
    else:
        delta, source = int(draw_shift(rng)), "draw"
    changed = False
    for k in (file_key, alias):
        if k and shifts.get(k) != delta:
            shifts[k] = delta
            changed = True
    return delta, changed, source


def load_ip_map(path):
    """Address -> label map (local file, do not publish). {} if the file does not exist."""
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_ip_map(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.chmod(path, 0o600)


def ip_label(address, ip_map):
    """Label <<IP_n>> of a server address; a new address gets the next number. IPv6 addresses
    are normalised (compressed, lower case) before the lookup. Returns None if the text is not
    an IP address."""
    try:
        key = str(ipaddress.ip_address(address.strip()))
    except ValueError:
        return None
    if key not in ip_map:
        ip_map[key] = f"<<IP_{len(ip_map) + 1}>>"
    return ip_map[key]


def load_shifts(path):
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_shifts(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.chmod(path, 0o600)


def raw_pattern_check(har, min_digits=15, skip_fields=()):
    """Looks for raw patterns outside labels. Returns Counter (type, path) -> n.
    skip_fields: names of fields deliberately in clear (e.g. server address with --server keep)."""
    hits = collections.Counter()

    def string(s, path):
        rest = P.RE_PROTECTED.sub(" ", s)
        if P.RE_UUID.search(rest):
            hits[("UUID", path)] += 1
        if P.RE_EMAIL.search(rest):
            hits[("e-mail", path)] += 1
        if P.RE_JWT.search(rest):
            hits[("JWT", path)] += 1
        for m in P.RE_IPV4.finditer(rest):
            if all(int(o) <= 255 for o in m.group(0).split(".")):
                hits[("IPv4", path)] += 1
                break
        for m in P.RE_IPV6_CANDIDATE.finditer(rest):
            if P.is_ipv6(m.group(0)):
                hits[("IPv6", path)] += 1
                break
        if min_digits:
            for m in re.finditer(r"(?<![0-9A-Za-z.])\d{%d,}(?![0-9A-Za-z.])" % min_digits, rest):
                if not P.looks_like_time(m.group(0)):
                    hits[("long digits", path)] += 1
                    break

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("startedDateTime",) or k in skip_fields:
                    continue
                if isinstance(k, str) and P.strong_pattern(k, min_digits):
                    hits[("identifier key", path)] += 1
                    k = "<key>"
                walk(v, f"{path}.{k}")
        elif isinstance(o, list):
            for x in o:
                walk(x, path + "[]")
        elif isinstance(o, str):
            st = o.strip()
            if st[:1] in "{[" and len(st) > 2:
                try:
                    walk(json.loads(st), path + "~json")
                    return
                except ValueError:
                    pass
            string(o, path)
        elif isinstance(o, int) and not isinstance(o, bool) and min_digits:
            if len(str(abs(o))) >= min_digits and not P.looks_like_time(o):
                hits[("long digits", path)] += 1

    for e in har["log"]["entries"]:
        walk(e, "entry")
    return hits


def main():
    ap = argparse.ArgumentParser(description=f"Prepare *.anon.har for publication (version {VERSION}).")
    ap.add_argument("har", help="*.anon.har file from pseudonymise_har.py")
    ap.add_argument("--output", help="output directory (default: next to the input file)")
    ap.add_argument("--hosts", default=STUDIED_HOSTS, help="regex of hosts that are kept")
    ap.add_argument("--strip-content", default=HOSTS_WITHOUT_BODY, help="regex of hosts whose response body is removed")
    ap.add_argument("--groups", default=DEFAULT_GROUPS,
                    help=f"field groups to mask (from pseudonymise_har.py --list-groups), default {DEFAULT_GROUPS}")
    ap.add_argument("--server", choices=["remove", "keep", "label"], default="remove",
                    help="server address: remove (default), keep, or label (<<IP_n>> from --ip-map; decision of 18 Oct 2026); X-Amz-Cf-Pop is always masked")
    ap.add_argument("--ip-map", metavar="JSON_FILE", help="with --server label: address -> label map (local, do not publish); new addresses are added; the same file gives the same labels on a re-run and in shift_extract_times.py")
    ap.add_argument("--bundle", default="com.markmcguill.strongbox", help="bundle of the studied app")
    ap.add_argument("--salt", help="salt file: HMAC labels compatible with pseudonymise_har.py instead of <<MASKED_TYPE>>")
    ap.add_argument("--show-foreign-hosts", action="store_true", help="list names of removed hosts in the report (local use only)")
    ap.add_argument("--shift-time", metavar="JSON_FILE", help="shift all timestamps by a constant, random value per file; values are stored in JSON_FILE (local, do not publish); the same file gives the same offset on a re-run")
    ap.add_argument("--run-code", metavar="CODE", help="run code: output files CODE.pub.har/.pub.report.txt/.pub.har.sha256, and 'source: CODE.anon.har' in the comment and report instead of the input file name (export names contain times); the --shift-time map key stays the input file name, plus the alias RUN:CODE")
    ap.add_argument("--legacy-input", metavar="JSON_FILE", help="translate input written by an older pseudonymiser version (label types, log.comment) as described in JSON_FILE; hashes are unchanged")
    ap.add_argument("--force", action="store_true", help="accept a file without '.anon.har' in its name and write the output despite check hits")
    a = ap.parse_args()

    if a.server == "label" and not a.ip_map:
        sys.exit("--server label requires --ip-map JSON_FILE")
    ip_map = load_ip_map(a.ip_map) if a.server == "label" else None
    ip_map_before = json.dumps(ip_map, sort_keys=True) if ip_map is not None else None
    if not a.har.endswith(".anon.har") and not a.force:
        sys.exit("Input must be a *.anon.har file (from pseudonymise_har.py). Other file: --force.")
    groups = [g.strip() for g in a.groups.split(",") if g.strip()]
    unknown = set(groups) - set(P.FIELD_GROUPS)
    if unknown:
        sys.exit(f"Unknown groups: {', '.join(sorted(unknown))}")

    with open(a.har, "rb") as f:
        raw = f.read()
    input_sha = hashlib.sha256(raw).hexdigest()
    text_in = raw.decode("utf-8-sig")
    legacy = load_legacy(a.legacy_input, "har") if a.legacy_input else None
    legacy_labels = 0
    if legacy:
        text_in, legacy_labels = translate_legacy_har(text_in, legacy)
    har = json.loads(text_in)
    entries = har.get("log", {}).get("entries")
    if entries is None:
        sys.exit("This does not look like a HAR file (no log.entries).")
    source_comment = har["log"].get("comment", "")
    if legacy:
        if legacy["script_name"] not in source_comment:
            sys.exit("ERROR: --legacy-input given, but log.comment of the input does not name the older pseudonymiser.")
        source_comment = translate_legacy_comment(source_comment, legacy)
    if INPUT_MARKER not in source_comment and not a.force:
        sys.exit(f"No {INPUT_MARKER} marker in log.comment - the file does not look pseudonymised "
                 "(older version: --legacy-input; other file: --force).")

    salt = None
    if a.salt:
        with open(a.salt, "rb") as f:
            salt = f.read()
    pub = Publication(groups, salt=salt, bundle=a.bundle)
    re_hosts = re.compile(a.hosts)
    re_strip = re.compile(a.strip_content) if a.strip_content else None

    kept = collections.Counter()
    removed_hosts = collections.Counter()
    foreign_bundle = collections.Counter()
    foreign_bundle_ids = set()
    removed_body = collections.Counter()
    removed_chars = collections.Counter()
    removed_fields = collections.Counter()
    cache_keys = collections.Counter()   # place -> number of sw_cache_key values masked
    result = []
    for e in entries:
        try:
            host = urlsplit(e.get("request", {}).get("url", "")).hostname or "?"
        except ValueError:
            host = "?"
        if not re_hosts.search(host):
            removed_hosts[host] += 1
            continue
        foreign = {b for b in entry_bundles(e) if b != a.bundle}
        if foreign:
            foreign_bundle[host] += 1
            foreign_bundle_ids |= foreign
            continue
        req, res = e.get("request", {}), e.get("response", {})
        cont = res.get("content") or {}
        if re_strip and re_strip.search(host) and "text" in cont:
            removed_body[host] += 1
            removed_chars[host] += len(cont.get("text") or "")
            cont.pop("text", None)
            cont.pop("encoding", None)
            cont["comment"] = f"content removed by {SCRIPT} (static resource)"
        else:
            if isinstance(cont.get("text"), str):
                cont["text"] = pub.body_text(cont["text"])
        pd = req.get("postData")
        if isinstance(pd, dict) and isinstance(pd.get("text"), str):
            pd["text"] = pub.body_text(pd["text"])
            pub.pairs(pd.get("params"))
        pub.pairs(req.get("headers"))
        pub.pairs(res.get("headers"))
        pub.pairs(req.get("queryString"))
        for field in CLIENT_FIELDS:
            if field in e:
                del e[field]
                removed_fields[field] += 1
        if a.server == "remove":
            for field in ("serverIPAddress", "_serverAddress"):
                if e.get(field):
                    e[field] = ""
                    removed_fields[field] += 1
        elif a.server == "label":
            for field in ("serverIPAddress", "_serverAddress"):
                if isinstance(e.get(field), str) and e[field] and not e[field].startswith("<<"):
                    lab = ip_label(e[field], ip_map)
                    if lab is None:
                        sys.exit(f"ERROR: {field} is not an IP address (entry {e.get('_id', '?')})")
                    e[field] = lab
                    removed_fields[f"{field} (labelled)"] += 1
        # CDN point of presence masked regardless of --server (decision 9 Oct 2026: addresses in clear,
        # X-Amz-Cf-Pop not); CloudFront repeats the same value in Server-Timing (cdn-pop;desc=...)
        for items in (req.get("headers"), res.get("headers")):
            for h in items or []:
                if not isinstance(h, dict) or not isinstance(h.get("value"), str):
                    continue
                name = P.normalise(h.get("name", ""))
                if name in SERVER_HEADERS and not h["value"].startswith("<<"):
                    h["value"] = "<<MASKED_CDN>>"
                    removed_fields[h.get("name")] += 1
                elif name in SERVER_TIMING_HEADERS:
                    h["value"], n = mask_server_timing_pop(h["value"], pub)
                    if n:
                        removed_fields[f"{h.get('name')} (cdn-pop)"] += n
        e = mask_cache_key(e, pub, cache_keys)
        kept[host] += 1
        result.append(e)

    # epochs in bodies that shift() does not cover - report only, no changes
    epoch_numbers, epoch_strings = collections.Counter(), collections.Counter()
    for e in result:
        epochs_in_text((e.get("request", {}).get("postData") or {}).get("text"), epoch_numbers, epoch_strings)
        epochs_in_text((e.get("response", {}).get("content") or {}).get("text"), epoch_numbers, epoch_strings)
    epoch_pairs, epoch_listed_unchanged = collections.Counter(), collections.Counter()

    delta = None
    if a.shift_time:
        file_key = os.path.basename(a.har)
        shifts = load_shifts(a.shift_time)
        # offset by file name or by the alias RUN:<code> (new input name after renaming);
        # a conflict between both entries is an error instead of a silent overwrite
        alias = f"RUN:{a.run_code}" if a.run_code else None
        delta, changed, delta_source = resolve_shift(shifts, file_key, alias)
        if changed:
            save_shifts(a.shift_time, shifts)
        if delta_source != "name":
            print(f"NOTE: offset for {file_key} taken from {delta_source}", file=sys.stderr)
        CLOCK_STATS.clear()
        result = [shift(e, delta) for e in result]
        for e in result:
            shift_epoch_pairs(e, delta, epoch_pairs, epoch_listed_unchanged)
        result.sort(key=lambda e: e.get("startedDateTime", ""))
    har["log"]["entries"] = result
    har["log"].pop("pages", None)
    time_note = ("Timestamps shifted by a constant, random value (at least 3 and less than 31 days, forward or backward) specific to this file; "
                 "intervals unchanged, entries sorted by time; do not compare times between files."
                 if delta is not None else "Entry timestamps unchanged.")
    server_note = {"remove": " Server addresses removed.", "keep": " Server addresses in clear.",
                   "label": " Server addresses (field group server, left in clear by the pseudonymiser) replaced at publication with labels <<IP_n>> (the same address gives the same label in every published file)."}[a.server]
    legacy_note = ("; label types and field group names of the input translated to English (hashes unchanged)"
                   if legacy else "")
    source_name = f"{a.run_code}.anon.har" if a.run_code else os.path.basename(a.har)
    har["log"]["comment"] = (
        f"{source_comment} | Prepared for publication: {SCRIPT} {VERSION}; "
        f"source: {source_name} (SHA-256 {input_sha}){legacy_note}. {time_note}{server_note}"
    )
    if ip_map is not None and json.dumps(ip_map, sort_keys=True) != ip_map_before:
        save_ip_map(a.ip_map, ip_map)
    text = json.dumps(har, ensure_ascii=False, indent=1) + "\n"
    skip = ("serverIPAddress", "_serverAddress") if a.server == "keep" else ()
    hits = raw_pattern_check(json.loads(text), skip_fields=skip)

    base = re.sub(r"(\.anon)?\.har$", "", a.har, flags=re.IGNORECASE)
    if a.run_code:
        base = os.path.join(os.path.dirname(a.har), a.run_code)
    if a.output:
        os.makedirs(a.output, exist_ok=True)
        base = os.path.join(a.output, os.path.basename(base))
    pub_file = base + ".pub.har"
    data = text.encode("utf-8")
    output_sha = hashlib.sha256(data).hexdigest()
    write = not hits or a.force

    r = [f"PUBLICATION CHECK REPORT: {source_name}"]
    r.append(f"Script: {SCRIPT} {VERSION}")
    r.append(f"Input SHA-256: {input_sha}")
    m = re.search(r"pseudonymise_har\.py ([0-9.]+)", source_comment)
    r.append(f"Pseudonymiser version of the input: {m.group(1) if m else 'unknown (1.x did not record a version)'}")
    if legacy:
        r.append(f"Input from an older pseudonymiser version translated (--legacy-input): "
                 f"{legacy_labels} labels renamed (hash and length unchanged), log.comment rewritten")
    if write:
        r.append(f"Output file: {os.path.basename(pub_file)}")
        r.append(f"Output SHA-256: {output_sha}")
    else:
        r.append("Output file: NOT WRITTEN (check hits, see below)")
    r.append(f"Entries: {len(entries)} in input, {len(result)} in output")
    r.append("")
    r.append("ENTRIES PER HOST (kept)")
    for h, n in sorted(kept.items(), key=lambda x: (-x[1], x[0])):
        r.append(f"  {n:4d}  {h}")
    r.append("")
    r.append("REMOVED")
    r.append(f"  entries of hosts out of scope: {sum(removed_hosts.values())} ({len(removed_hosts)} hosts)")
    if a.show_foreign_hosts:
        for h, n in sorted(removed_hosts.items(), key=lambda x: (-x[1], x[0])):
            r.append(f"      {n:4d}  {h}")
    r.append(f"  entries of studied hosts sent by another app (bundle): {sum(foreign_bundle.values())} "
             f"({len(foreign_bundle_ids)} different bundles)")
    for h, n in sorted(foreign_bundle.items()):
        r.append(f"      {n:4d}  {h}")
    r.append("  response body of static resources (size, mimeType, status kept):")
    if removed_body:
        for h in sorted(removed_body):
            r.append(f"      {removed_body[h]:4d} entries, {removed_chars[h]} characters  {h}")
    else:
        r.append("      none")
    r.append("  fields:")
    for p, n in sorted(removed_fields.items()):
        r.append(f"      {p}: {n}")
    r.append("")
    r.append(f"FIELDS MASKED (groups: {', '.join(groups)}; placeholder: {'HMAC label' if salt else '<<MASKED_TYPE>>'})")
    if pub.masked:
        for g in groups:
            for k, n in sorted(pub.masked.get(g, {}).items()):
                r.append(f"  {g}: {k}: {n}")
    else:
        r.append("  no raw values to mask")
    if pub.already_labelled:
        r.append("  already masked in the input file: " + ", ".join(f"{k} ({n})" for k, n in sorted(pub.already_labelled.items())))
    r.append("")
    r.append("LEFT IN CLEAR")
    if delta is not None:
        r.append("  timestamps SHIFTED by a constant, random value per file (--shift-time); value only in the local file; intervals unchanged, entries sorted by time")
    else:
        r.append("  startedDateTime, time, timings, Date header, time fields in bodies (created_at, *_time, *_ms):")
        r.append("  exact timestamps (authors' decision).")
    server_text = {"keep": "in clear (--server keep)", "remove": "removed",
                   "label": f"replaced with labels <<IP_n>> (--server label; {removed_fields.get('serverIPAddress (labelled)', 0)} entries; "
                            f"map shared by all published files, in the local file, holding {len(ip_map or {})} addresses after this file)"}[a.server]
    r.append(f"  server address: {server_text}; "
             "CDN point of presence (X-Amz-Cf-Pop, cdn-pop in Server-Timing): always masked")
    r.append("  sw_cache_key (paywall resource URLs): always masked, in every place"
             + (" (" + ", ".join(f"{k}: {n}" for k, n in sorted(cache_keys.items())) + ")" if cache_keys else " (none in clear in the input)"))
    others = [g for g in P.FIELD_GROUPS if g not in groups and g != "cdn_pop"]   # cdn_pop: masked above, always
    r.append(f"  field groups not masked in this step: {', '.join(others)}")
    r.append("  (in files from pseudonymise_har.py 2.x they are usually already masked in the input)")
    r.append("")
    r.append("EPOCHS AS DIGIT STRINGS IN headers/queryString/cookies (10 or 13 digits, years 2020-2035)")
    if delta is None:
        r.append("  not shifted (no --shift-time)")
    elif epoch_pairs:
        r.append("  shifted like startedDateTime, number of digits unchanged (field: name: count):")
        for (field, name), n in sorted(epoch_pairs.items(), key=lambda x: (x[0][0], str(x[0][1]).lower())):
            note = "" if field == "headers" and str(name).lower() in EPOCH_HEADERS else "  [not in EPOCH_HEADERS - check]"
            r.append(f"    {field}: {name}: {n}{note}")
        r.append(f"  total: {sum(epoch_pairs.values())}")
    else:
        r.append("  none")
    if epoch_listed_unchanged:
        r.append("  listed headers with a value outside the rule (unchanged): " + ", ".join(f"{k} ({n})" for k, n in sorted(epoch_listed_unchanged.items())))
    r.append("BARE DATES AND TIMES OF DAY (key: count)")
    if delta is None:
        r.append("  not changed (no --shift-time)")
    elif CLOCK_STATS:
        for (action, k), n in sorted(CLOCK_STATS.items()):
            r.append(f"  {action}: {k}: {n}")
    else:
        r.append("  none")
    r.append("EPOCHS IN BODIES OUTSIDE THE SHIFT RULES (NOT CHANGED - to check)")
    r.append("  numbers under keys outside EPOCH_KEYS: " + (", ".join(f"{k} ({n})" for k, n in sorted(epoch_numbers.items())) or "none"))
    r.append("  10/13-digit strings: " + (", ".join(f"{k} ({n})" for k, n in sorted(epoch_strings.items())) or "none"))
    r.append("")
    r.append("RAW PATTERN CHECK (type | path | count)")
    if hits:
        for (t, s), n in sorted(hits.items()):
            r.append(f"  {t} | {s} | {n}")
    else:
        r.append("  no hits")

    with open(base + ".pub.report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(r) + "\n")
    if write:
        with open(pub_file, "wb") as f:
            f.write(data)
        with open(pub_file + ".sha256", "w", encoding="utf-8") as f:
            f.write(f"{output_sha}  {os.path.basename(pub_file)}\n")
        print(f"Written: {pub_file}")
        print(f"Written: {pub_file}.sha256")
    print(f"Written: {base}.pub.report.txt")
    print(f"Entries: {len(entries)} -> {len(result)}; check hits: {sum(hits.values())}")
    if hits:
        print("WARNING: the check found raw patterns - see the report." + ("" if a.force else " The .pub.har file was not written."))
        sys.exit(2)


if __name__ == "__main__":
    main()
