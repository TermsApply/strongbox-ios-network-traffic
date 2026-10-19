#!/usr/bin/env python3
"""
pseudonymise_har.py - pseudonymise a HAR export before sharing it.

Usage:
    python3 pseudonymise_har.py input.har
    python3 pseudonymise_har.py input.har --known known.txt --skip 'proxyman\\.com'
    python3 pseudonymise_har.py input.har --only 'superwall|revenuecat|sentry'
    python3 pseudonymise_har.py input.har --salt ~/private/.pseudonymisation_salt --output data/anon
    python3 pseudonymise_har.py input.har --clear-groups server,model
    python3 pseudonymise_har.py --list-groups

Output (next to the input file or in the --output directory):
    input.anon.har      - HAR with values replaced by labels
    input.report.txt    - what was replaced, label table, what was left in clear,
                          list of leftovers to check

Principle: field names, structure, times, hosts and paths are kept. Values of
identifiers, tokens, IP addresses and e-mail addresses are replaced by a label
<<TYPE_xxxxxxxx_Ln>>, where xxxxxxxx is an HMAC digest with a local salt and n is
the length of the original (only from 16 characters). The same value gives the
same digest in all files processed with the same salt and the same label SCHEME.

Version 2: fields that were in clear before (purchase dates, price, currency,
model, OS build number, Superwall profile, server address, local time) are masked
in groups; each group can be left in clear with --clear-groups. The script version,
label scheme and salt fingerprint are written to the report and to log.comment.

Version 2.1.0: English names for the script, options, field groups, label types
and report; behaviour and label digests unchanged.

Version 2.2.0: the CDN point of presence is also masked where CloudFront repeats it
in the Server-Timing header (cdn-pop;desc=...), with the same label as in X-Amz-Cf-Pop.

Version 2.3.0: the Superwall parameter sw_cache_key (a 13-digit timestamp in paywall
resource URLs) is labelled wherever such a URL occurs in text (Referer header, event
parameters, configuration bodies), with the same label as the query parameter.

Version 2.4.0: the Superwall event parameters $attr_demandScore, $attr_demandTier and
$attr_ipContinent belong to the group superwall_profile (until 2.3.0 left in clear).

The salt stays with you. Do not share the salt file or the original HAR.
The script does not guarantee completeness: before sharing, read the
LEFTOVERS section of the report.
"""
import argparse
import base64
import collections
import datetime
import gzip
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import sys
from urllib.parse import parse_qsl, quote, quote_plus, unquote, urlsplit, urlunsplit

# --------------------------------------------------------------------------
# Version
# --------------------------------------------------------------------------

VERSION = "2.4.0"
# Label scheme: the formula a label is built from. As long as the scheme does not
# change, the same value with the same salt has the same digest - also across
# script versions. E1 = HMAC-SHA256(salt, UTF-8 value), first 8 hex characters,
# suffix _L<length> from 16 characters. Identical to versions 1.x.
LABEL_SCHEME = "E1"
HASH_LENGTH = 8
MIN_LENGTH_WITH_L = 16

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

# Keys whose values are kept (not user data, needed for the analysis).
# Matching: key/header name with non-alphanumeric characters removed, lower case,
# contains any of the strings below. "X-Bundle-ID", "bundleId" and "bundle_id"
# are therefore treated the same way (in clear everywhere or nowhere).
KEEP_DEFAULT = {
    "productid", "productidentifier", "bundleid", "bundleidentifier",
    "entitlementid", "offeringid", "packageid", "activeproducts",
}

# Fragments of key/header names that mark a sensitive value (lower case).
SENSITIVE_FRAGMENTS = re.compile(
    r"token|secret|passw|auth|signature|receipt|jws|cookie|session|e_?mail"
    r"|ip_?addr|device_?name|user_?name|alias|idfa|idfv|vendor|fingerprint"
    r"|install|distinct|anonymous|serial|udid|ssid|api_?key|public_?key"
    r"|latitude|longitude|postal|zip_?code|city|x-forwarded-for|x-real-ip"
    r"|nonce|etag|report-to|^nel$|cf-ray|url-?scheme|locale|language|region"
    r"|country|time_?zone|days_?since|cache_?key|first_?seen|installed_?at"
    # since 2.0.0: personal data in RevenueCat attributes ($displayName, $phoneNumber...)
    # and push notification tokens
    # (display_name without "$" is a product name in a RevenueCat offering - kept in clear)
    r"|^\$(display_?name|full_?name|first_?name|last_?name|nick_?name)$"
    r"|phone_?number|apns|fcm_?token|push_?token"
)
SENSITIVE_ENDINGS_LOWER = re.compile(r"(^|[_\-.$\s])(id|ids|uuid|guid|ip|key|lat|lon|lng|user)$")
SENSITIVE_ENDINGS_CAMEL = re.compile(r"(Id|ID|Ids|Uuid|UUID|Guid|Key)$")

# Keys whose value carries no name (e.g. RevenueCat attributes
# {"$displayName": {"value": "..."}}): sensitivity is decided by the parent key.
VALUE_KEYS = {"value", "val", "v"}

# Field groups that were in clear in versions 1.x. Keys after normalisation
# (lower case, no characters other than letters and digits), EXACT match.
FIELD_GROUPS = collections.OrderedDict([
    ("purchase_dates", {
        "type": "DATE",
        "description": "RevenueCat purchase, expiry and refund dates, first/last contact",
        "keys": {
            "purchasedate", "originalpurchasedate", "expiresdate", "expirationdate",
            "refundedat", "graceperiodexpiresdate", "billingissuesdetectedat",
            "unsubscribedetectedat", "autoresumedate", "firstseen", "lastseen",
            "purchasedatems", "originalpurchasedatems", "expiresdatems",
            "expirationdatems", "refundedatms", "latestpurchasedate",
            "originalpurchasedatemillis", "purchasedatemillis", "expiresdatemillis",
        },
    }),
    ("price", {
        "type": "PRICE",
        "description": "purchase price and amount",
        "keys": {
            "price", "amount", "introductoryprice", "localizedprice", "pricestring",
            "rawprice", "displayprice", "priceinpurchasedcurrency",
        },
    }),
    ("currency_storefront", {
        "type": "CURRENCY",
        "description": "device and store currency, App Store storefront country",
        "keys": {
            "currency", "currencycode", "devicecurrencycode", "devicecurrencysymbol",
            "storefrontcurrency", "storefront", "xstorefront", "xdevicecurrencycode",
            "xdevicecurrencysymbol", "storefrontcountrycode",
        },
    }),
    ("original_version", {
        "type": "VERSION",
        "description": "original_application_version (build from the first installation)",
        "keys": {"originalapplicationversion", "originalappversion"},
    }),
    ("model", {
        "type": "MODEL",
        "description": "device model (e.g. iPhoneNN,N)",
        "keys": {"devicemodel", "xdevicemodel", "xplatformdevice", "model", "hardwaremodel"},
    }),
    ("os_build", {
        "type": "BUILD",
        "description": "OS build number; in X-Platform-Version only the (Build ...) part is masked",
        "keys": {"osbuild", "osbuildnumber", "systembuild", "systembuildversion",
                 "xplatformversion", "platformversion"},
        "partial": {"xplatformversion", "platformversion"},
    }),
    ("superwall_profile", {
        "type": "PROFILE",
        "description": "seed, demandScore, demandTier, ipContinent, also as $attr_* (Superwall)",
        "keys": {"seed", "demandscore", "demandtier", "devicedemandscore",
                 "devicedemandtier", "ipcontinent", "deviceipcontinent",
                 "attrdemandscore", "attrdemandtier", "attripcontinent"},
    }),
    ("server", {
        "type": None,  # type from the value (IP) - same label as this address elsewhere
        "description": "server address (serverIPAddress, _serverAddress)",
        "keys": {"serveripaddress", "serveraddress"},
    }),
    ("cdn_pop", {
        "type": "CDN",
        "description": "CDN point of presence (X-Amz-Cf-Pop, and cdn-pop in Server-Timing) - reveals the approximate location of the user, not of the server",
        "keys": {"xamzcfpop"},
    }),
    ("local_time", {
        "type": "LOCALTIME",
        "description": "local device time from enrich (reveals the time zone)",
        "keys": {"localdatetime", "localtime", "localdate", "devicelocaldatetime",
                 "devicelocaltime", "devicelocaldate"},
    }),
])

# Structural HAR fields that are not touched (at every level of the entry object).
HAR_UNCHANGED = {
    "_serverPort", "startedDateTime", "time", "method", "httpVersion",
    "mimeType", "status", "statusText", "version", "pageref", "encoding",
}
HAR_SERVER_ADDRESS = {"serverIPAddress", "_serverAddress"}

# Hosts whose responses are static code/resources (paywall, fonts, Stripe).
# No entropy check, no HEX/B64/digit patterns, labels kept out of the report table.
NO_ENTROPY_DEFAULT = (
    r"(^|\.)(user-content\.superwalleditor\.com|js\.stripe\.com"
    r"|fonts\.googleapis\.com|fonts\.gstatic\.com)$"
)

# Value patterns (independent of the key name).
RE_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# IPv6 candidate (also with "::"); verified with the ipaddress module
RE_IPV6_CANDIDATE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
RE_HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])")
RE_B64 = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")
RE_B64_URL = re.compile(r"[A-Za-z0-9_-]{40,}")
RE_SETTING_NAME = re.compile(r"[a-z]+(?:_[a-z]+){1,6}")
RE_LABEL = re.compile(r"<<[A-Z0-9]+_[0-9a-f]{8}(?:_L\d+)?>>")
# everything in <<...>>: labels and replacements from --known
RE_PROTECTED = re.compile(r"<<[A-Za-z0-9_]+>>")
RE_SUSPICIOUS = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
RE_SUSPICIOUS_URL = re.compile(r"[A-Za-z0-9+_-]{24,}")
RE_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
RE_FLOAT = re.compile(r"[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?")
RE_FORM = re.compile(
    r"[A-Za-z_][A-Za-z0-9_.\[\]-]*=[^&\s]*(?:&[A-Za-z_][A-Za-z0-9_.\[\]-]*=[^&\s]*)+"
)
# identifiers with an SDK prefix, e.g. $SuperwallDevice:<IDFV>
RE_PREFIX = re.compile(r"^(\$[A-Za-z][A-Za-z0-9]*:)(.+)$", re.DOTALL)
RE_BUILD = re.compile(r"(\b[Bb]uild\s+)([0-9]{1,3}[A-Z][0-9A-Za-z]{1,8})")
RE_TIME_KEY = re.compile(
    r"(date|time|timestamp|_at$|At$|_ms$|^ts$|seen|observedat|duration)", re.IGNORECASE
)
# CloudFront repeats the point of presence of X-Amz-Cf-Pop in Server-Timing, e.g.
# cdn-pop;desc="XXX99-X9" or desc="XXX99-X99" (quoted or not); masked with the group cdn_pop.
RE_SERVER_TIMING_POP = re.compile(r'(\bcdn-pop\s*;\s*desc=)("?)([^",;\s]+)', re.IGNORECASE)
SERVER_TIMING_HEADERS = {"servertiming"}
# Superwall paywall resource URLs carry sw_cache_key=<13-digit number> (most likely the time the
# paywall version was published on the service side). As a query parameter of the request URL it is
# labelled (sensitive key name); the same URL repeated in free text (Referer header, $paywall_url in
# events, url fields of the static configuration) left it in clear up to 2.2.0. The number is a
# timestamp: in clear it allows bounding the real run time from below and linking runs (audit of
# 17 Oct 2026). It is labelled everywhere with the label of the query parameter.
RE_SW_CACHE_KEY = re.compile(r"(\bsw_cache_key(?:=|%3[Dd]))(\d+)")
# prefixes the report may show (structural, not user data)
PREFIXES_FOR_REPORT = re.compile(r"^(\$[A-Za-z][A-Za-z0-9]*:|pk_)")


def normalise(key) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def looks_like_time(n: int) -> bool:
    """Unix timestamp in s/ms/us/ns from about 2017-2031."""
    try:
        n = abs(int(n))
    except (TypeError, ValueError):
        return False
    for divisor in (1, 10**3, 10**6, 10**9):
        if 1.5e9 <= n / divisor <= 1.95e9:
            return len(str(n)) in (10, 13, 16, 19)
    return False


def is_ipv6(s: str) -> bool:
    if s.count(":") < 2 or not re.search(r"[0-9A-Fa-f]", s):
        return False
    try:
        ipaddress.IPv6Address(s)
        return True
    except ValueError:
        return False


def pseudonymised_comment(version, scheme, fingerprint, clear_groups) -> str:
    """Text written to log.comment of the *.anon.har file."""
    return (
        f"Pseudonymised: pseudonymise_har.py {version}, label scheme {scheme}, "
        f"salt fingerprint {fingerprint}. Field groups left in clear: {', '.join(sorted(clear_groups)) or 'none'}. "
        "Values <<TYPE_hash_Llength>> replace the originals; compare hashes (8 hex characters) "
        "only between files with the same label scheme and salt fingerprint."
    )


class Pseudonymiser:
    def __init__(self, salt: bytes, keep: set, known: list, clear_groups=(),
                 dates_mode="label", min_digits=15, split_prefixes=True):
        self.salt = salt
        self.keep = keep
        self.known = known  # list of (value, label)
        self.keep_pattern = None
        self.clear_groups = set(clear_groups)
        self.dates_mode = dates_mode
        self.min_digits = min_digits
        self.split_prefixes = split_prefixes
        self.no_entropy_re = None
        self.host = "?"
        self.static = False         # processing a host response without entropy check
        # label -> report data (without the original)
        self.labels = collections.OrderedDict()
        self.paths = collections.defaultdict(set)     # host -> {place:path}
        self.leftovers = []                           # (host, entry no., place, shape, length)
        self.counters = collections.Counter()
        self.static_labels = 0
        self.registry = {}                            # label -> sha256 of the original (memory only)
        self.collisions = collections.Counter()
        self.long_digits = []                         # (host, place, length, label)
        self.masked = collections.defaultdict(collections.Counter)  # group -> field -> n
        self.clear_by_choice = collections.defaultdict(collections.Counter)
        self.clear_kept = collections.Counter()       # keys from the KEEP list
        self.clear_time = collections.Counter()       # time keys with a value in clear
        self.clear_digits_time = collections.Counter()  # long numbers taken as a timestamp
        self.clear_keys = collections.defaultdict(collections.Counter)  # host -> key -> n
        self.group_of_key = {}
        for g, d in FIELD_GROUPS.items():
            for k in d["keys"]:
                self.group_of_key[k] = g

    # ---- labels ----------------------------------------------------------
    def digest(self, s: str) -> str:
        return hmac.new(self.salt, s.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:HASH_LENGTH]

    def label(self, value, type: str, where: str, force_type: str = None) -> str:
        """type: only 'COOKIE' is taken into account (compatibility with 1.x); in all
        other cases the type follows from the value itself, so that the same value has
        the same label everywhere. force_type: field group type (DATE, PRICE...)."""
        s = str(value)
        if not s or RE_LABEL.fullmatch(s):
            return s
        digest = self.digest(s)
        type = force_type or (type if type == "COOKIE" else value_type(s))
        lab = f"<<{type}_{digest}_L{len(s)}>>" if len(s) >= MIN_LENGTH_WITH_L else f"<<{type}_{digest}>>"
        fingerprint = hashlib.sha256(s.encode("utf-8", "replace")).digest()
        previous = self.registry.setdefault(lab, fingerprint)
        if previous != fingerprint:
            self.collisions[lab] += 1
        self.counters[type] += 1
        if self.static:
            self.static_labels += 1
            return lab
        info = self.labels.setdefault(
            lab, {"format": describe_format(s), "n": 0, "hosts": set()}
        )
        info["n"] += 1
        info["hosts"].add(self.host)
        self.paths[self.host].add(where)
        return lab

    def label_whole(self, value: str, where: str) -> str:
        """Value under a sensitive key. A known SDK prefix stays in clear."""
        if self.split_prefixes and isinstance(value, str):
            m = RE_PREFIX.match(value)
            if m:
                return m.group(1) + self.label(m.group(2), "ID", where)
        return self.label(value, "ID", where)

    def is_sensitive(self, key: str) -> bool:
        if not isinstance(key, str):
            return False
        lower = key.lower()
        norm = re.sub(r"[^a-z0-9]", "", lower)
        if any(z in norm for z in self.keep):
            return False
        return bool(
            SENSITIVE_FRAGMENTS.search(lower)
            or SENSITIVE_ENDINGS_LOWER.search(lower)
            or SENSITIVE_ENDINGS_CAMEL.search(key)
        )

    def is_kept(self, key) -> bool:
        return isinstance(key, str) and any(z in normalise(key) for z in self.keep)

    # ---- field groups ----------------------------------------------------
    def group(self, key):
        if not isinstance(key, str):
            return None
        return self.group_of_key.get(normalise(key))

    def mask_group(self, group: str, v, key: str, where: str):
        if v is None or isinstance(v, bool) or v == "":
            return v
        if isinstance(v, str) and RE_LABEL.fullmatch(v):
            return v
        if group in self.clear_groups:
            self.clear_by_choice[group][key] += 1
            return v
        d = FIELD_GROUPS[group]
        self.masked[group][key] += 1
        if group == "purchase_dates" and self.dates_mode == "month":
            m = month(v)
            if m:
                return m
        if normalise(key) in d.get("partial", ()):
            # e.g. "Version 26.5 (Build 23F77)": only the build number is masked
            new = RE_BUILD.sub(
                lambda m: m.group(1) + self.label(m.group(2), "ID", where, force_type=d["type"]),
                str(v),
            )
            if new == str(v):
                self.masked[group][key] -= 1
                if not self.masked[group][key]:
                    del self.masked[group][key]
                return v
            return new
        return self.label(v, "ID", where, force_type=d["type"])

    def note_clear(self, key, value=None):
        if not isinstance(key, str) or self.static:
            return
        if isinstance(value, str) and RE_PROTECTED.search(value):
            return  # value already contains a label (e.g. file processed again)
        if strong_pattern(key, self.min_digits):
            key = "<key that is an identifier>"  # the key name is not quoted
        if self.is_kept(key):
            self.clear_kept[key] += 1
        elif RE_TIME_KEY.search(key):
            self.clear_time[key] += 1
        else:
            self.clear_keys[self.host][key] += 1

    # ---- patterns in any text --------------------------------------------
    def patterns(self, text: str, where: str, url: bool = False) -> str:
        if not text:
            return text
        # sw_cache_key in a URL inside text: the same label as the query parameter (label_whole)
        text = RE_SW_CACHE_KEY.sub(lambda m: m.group(1) + self.label_whole(m.group(2), where), text)
        if not url and RE_PERCENT.search(text):
            # %XX decoding only for detection: the decoded text goes to the
            # output only if something in it was replaced
            dec = unquote(text)
            if dec != text:
                result = self._patterns(dec, where, url)
                if result != dec:
                    return result
        return self._patterns(text, where, url)

    def _patterns(self, text: str, where: str, url: bool) -> str:
        def replace(type):
            return lambda m: self.label(m.group(0), type, where)

        text = RE_JWT.sub(replace("JWT"), text)
        text = RE_EMAIL.sub(replace("EMAIL"), text)
        text = RE_UUID.sub(replace("UUID"), text)
        text = RE_IPV4.sub(
            lambda m: self.label(m.group(0), "IP", where)
            if all(int(o) <= 255 for o in m.group(0).split("."))
            else m.group(0),
            text,
        )
        text = RE_IPV6_CANDIDATE.sub(
            lambda m: self.label(m.group(0), "IP", where) if is_ipv6(m.group(0)) else m.group(0),
            text,
        )
        if self.static:
            return text

        # B64 before HEX: a hex string inside a longer base64 token is not
        # replaced separately (in 1.x clear fragments were left next to the label)
        def b64(m):
            w = m.group(0)
            if re.search(r"\d", w) and re.search(r"[a-z]", w) and re.search(r"[A-Z]", w):
                return self.label(w, "B64", where)
            return w

        text = (RE_B64_URL if url else RE_B64).sub(b64, text)
        text = RE_HEX.sub(replace("HEX"), text)
        text = self.digits(text, where)
        return text

    def digits(self, text: str, where: str) -> str:
        """Strings of >= min_digits digits (transaction identifiers etc.)."""
        if not self.min_digits or self.static:
            return text
        pattern = re.compile(r"(?<![0-9A-Za-z.])\d{%d,}(?![0-9A-Za-z.])" % self.min_digits)

        def replace(m):
            w = m.group(0)
            if looks_like_time(w):
                if not where.startswith("second-pass"):
                    self.clear_digits_time[where] += 1
                return w
            lab = self.label(w, "NUM", where)
            self.long_digits.append((self.host, where, len(w), lab))
            return lab

        return pattern.sub(replace, text)

    # ---- JSON from request/response bodies -------------------------------
    def json_key(self, k, path):
        if not isinstance(k, str) or not k:
            return k
        return self.patterns(k, f"key:{path}")

    def json_value(self, v, key, path, parent_key=None):
        if isinstance(v, dict):
            result = {}
            for k, x in v.items():
                nk = self.json_key(k, path)
                result[nk] = self.json_value(x, k, f"{path}.{nk}", parent_key=key)
            return result
        if isinstance(v, list):
            return [self.json_value(x, key, f"{path}[]", parent_key) for x in v]
        where = f"body:{path}"
        effective = key
        if isinstance(key, str) and key.lower() in VALUE_KEYS and parent_key:
            effective = parent_key
        if isinstance(v, bool) or v is None:
            return v
        if isinstance(v, str):
            st = v.strip()
            if st[:1] in "{[" and len(st) > 2:  # JSON nested in a string
                try:
                    inner = json.loads(st)
                    return json.dumps(
                        self.json_value(inner, key, path + "~json", parent_key),
                        ensure_ascii=False, separators=(",", ":"),
                    )
                except ValueError:
                    pass
        g = self.group(effective)
        if g:
            return self.mask_group(g, v, effective, where)
        if isinstance(v, (int, float)):
            if self.is_sensitive(effective):
                return self.label(v, "NUM", where)
            if isinstance(v, int) and self.min_digits and not self.static and len(str(abs(v))) >= self.min_digits:
                if looks_like_time(v):
                    self.clear_digits_time[where] += 1
                    return v
                lab = self.label(v, "NUM", where)
                self.long_digits.append((self.host, where, len(str(abs(v))), lab))
                return lab
            self.note_clear(effective)
            return v
        if isinstance(v, str):
            # configuration switch name (e.g. toggles[].key = "enable_text_interaction"):
            # snake_case words without digits under the key "key" are a setting name, not an identifier
            if isinstance(key, str) and key.lower() == "key" and RE_SETTING_NAME.fullmatch(v):
                self.note_clear(key)
                return v
            if self.is_sensitive(effective):
                return self.label_whole(v, where)
            w = self.patterns(v, where)
            if w == v:
                self.note_clear(effective, v)
            return w
        return v

    def body_text(self, text: str, mime: str) -> str:
        if not text:
            return text
        # 1. whole JSON document
        try:
            return json.dumps(
                self.json_value(json.loads(text), None, "$"),
                ensure_ascii=False, separators=(",", ":"),
            )
        except ValueError:
            pass
        # 2. JSON on consecutive lines (e.g. Sentry envelope)
        lines = text.split("\n")
        if len(lines) > 1:
            result, hits = [], 0
            for ln in lines:
                try:
                    obj = json.loads(ln)
                    if isinstance(obj, (dict, list)):
                        result.append(json.dumps(
                            self.json_value(obj, None, "$line"),
                            ensure_ascii=False, separators=(",", ":")))
                        hits += 1
                        continue
                except ValueError:
                    pass
                result.append(self.patterns(ln, "body:$text"))
            if hits:
                return "\n".join(result)
        # 3. form: only with a form mimeType or an explicit a=1&b=2 shape
        #    (in 1.x base64 ending with "=" was taken for a form and damaged)
        if "x-www-form-urlencoded" in (mime or "") or RE_FORM.fullmatch(text):
            pairs = parse_qsl(text, keep_blank_values=True)
            if pairs:
                return "&".join(
                    f"{quote(self.patterns(k, 'form:key'), safe='<>')}="
                    f"{quote(self.pair(k, v, 'form'), safe='<>')}"
                    for k, v in pairs
                )
        # 4. plain text
        return self.patterns(text, "body:$text")

    def pair(self, name: str, value: str, kind: str) -> str:
        where = f"{kind}:{name}"
        g = self.group(name)
        if g:
            return self.mask_group(g, value, name, where)
        if self.is_sensitive(name):
            return self.label_whole(value, where)
        w = self.patterns(value, where)
        if kind.endswith("header") and normalise(name) in SERVER_TIMING_HEADERS:
            w = self.server_timing_pop(w, name, where)
        if w == value and not self.static:
            self.note_clear(f"{kind}:{name}", value)
        return w

    def server_timing_pop(self, value: str, name: str, where: str) -> str:
        """Masks the cdn-pop description in a Server-Timing value like X-Amz-Cf-Pop
        (same group, same label for the same value)."""
        def sub(m):
            if RE_PROTECTED.fullmatch(m.group(3)):
                return m.group(0)
            return m.group(1) + m.group(2) + self.mask_group("cdn_pop", m.group(3), name, where)
        return RE_SERVER_TIMING_POP.sub(sub, value)

    # ---- URL -------------------------------------------------------------
    def url(self, u: str) -> str:
        try:
            p = urlsplit(u)
        except ValueError:
            return self.patterns(u, "url", url=True)
        netloc = p.netloc
        if "@" in netloc:  # credentials in the address
            creds, _, rest = netloc.rpartition("@")
            netloc = self.label(unquote(creds), "ID", "url:credentials") + "@" + rest
        path = p.path
        # RevenueCat: /v1/subscribers/<app_user_id>[/...]
        path = re.sub(
            r"(/subscribers/)([^/]+)",
            lambda m: m.group(1) + self.label_whole(unquote(m.group(2)), "url:/subscribers/*"),
            path,
        )
        path = self.patterns(path, "url:path", url=True)
        query = p.query
        if query:
            pairs = parse_qsl(query, keep_blank_values=True)
            query = "&".join(
                f"{quote(self.patterns(k, 'query:key'), safe='<>')}="
                f"{quote(self.pair(k, v, 'query'), safe='<>')}"
                for k, v in pairs
            )
        return urlunsplit((p.scheme, netloc, path, query, ""))

    # ---- HAR entry -------------------------------------------------------
    def pair_list(self, items, kind, always=False):
        for el in items or []:
            if not isinstance(el, dict) or "name" not in el:
                continue
            name = str(el.get("name", ""))
            if "value" in el and isinstance(el["value"], str):
                if always:
                    el["value"] = self.label(el["value"], "COOKIE", f"{kind}:{name}")
                else:
                    el["value"] = self.pair(name, el["value"], kind)

    def body(self, container, mime_field="mimeType"):
        if not isinstance(container, dict) or not container.get("text"):
            return
        text = container["text"]
        raw = None
        if container.get("encoding") == "base64":
            try:
                raw = base64.b64decode(text)
            except Exception:
                raw = None
        if raw is None:
            raw = text.encode("utf-8", "surrogatepass") if isinstance(text, str) else b""
        if raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        try:
            readable = raw.decode("utf-8")
        except UnicodeDecodeError:
            # HMAC with the salt (in 1.x: SHA-256 without salt)
            digest = hmac.new(self.salt, raw, hashlib.sha256).hexdigest()[:HASH_LENGTH]
            container["text"] = f"<<BINARY_{digest}_L{len(raw)}>>"
            container.pop("encoding", None)
            self.counters["BINARY"] += 1
            return
        container["text"] = self.body_text(readable, container.get(mime_field, ""))
        container.pop("encoding", None)

    def rest(self, obj, key=None):
        """Remaining entry fields (including non-standard Proxyman fields)."""
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                if k in HAR_UNCHANGED:
                    result[k] = v
                elif k in HAR_SERVER_ADDRESS or self.group(k):
                    result[k] = self.mask_group(self.group(k), v, k, f"har:{k}") \
                        if isinstance(v, (str, int, float)) else self.rest(v, k)
                else:
                    result[k] = self.rest(v, k)
            return result
        if isinstance(obj, list):
            return [self.rest(x, key) for x in obj]
        if isinstance(obj, str) and not RE_LABEL.fullmatch(obj):
            st = obj.strip()
            if st[:1] in "{[" and len(st) > 2:  # e.g. WebSocket messages with JSON
                try:
                    json.loads(st)
                    return self.body_text(st, "")
                except ValueError:
                    pass
            return self.patterns(obj, f"har:{key}")
        return obj

    def entry(self, e: dict) -> dict:
        req, res = e.get("request", {}), e.get("response", {})
        try:
            self.host = urlsplit(req.get("url", "")).hostname or "?"
        except ValueError:
            self.host = "?"
        if "url" in req:
            req["url"] = self.url(req["url"])
        if res.get("redirectURL"):
            res["redirectURL"] = self.url(res["redirectURL"])
        self.pair_list(req.get("headers"), "request-header")
        self.pair_list(res.get("headers"), "response-header")
        self.pair_list(req.get("queryString"), "query")
        self.pair_list(req.get("cookies"), "cookie", always=True)
        self.pair_list(res.get("cookies"), "cookie", always=True)
        pd = req.get("postData")
        if isinstance(pd, dict):
            if pd.get("text") and "x-www-form-urlencoded" not in (pd.get("mimeType") or ""):
                pd.pop("params", None)  # duplicate of the body; postData.text is kept
            self.pair_list(pd.get("params"), "form")
            self.body(pd)
        self.static = bool(self.no_entropy_re and self.no_entropy_re.search(self.host))
        try:
            self.body(res.get("content"))
        finally:
            self.static = False
        # everything not handled above
        handled_req = {"url", "headers", "queryString", "cookies", "postData"}
        handled_res = {"headers", "cookies", "content", "redirectURL"}
        for k in list(req):
            if k not in handled_req and k not in HAR_UNCHANGED:
                req[k] = self.rest(req[k], k)
        for k in list(res):
            if k not in handled_res and k not in HAR_UNCHANGED:
                res[k] = self.rest(res[k], k)
        for k in list(e):
            if k in ("request", "response") or k in HAR_UNCHANGED:
                continue
            if k in HAR_SERVER_ADDRESS and isinstance(e[k], str):
                e[k] = self.mask_group("server", e[k], k, f"har:{k}")
            else:
                e[k] = self.rest(e[k], k)
        return e

    # ---- second pass: everything that is left ------------------------------
    def skipped_in_check(self):
        skip = set(HAR_UNCHANGED)
        if "server" in self.clear_groups:
            skip |= HAR_SERVER_ADDRESS
        return skip

    def entropic(self, text: str, where: str) -> str:
        """Replaces strings not replaced so far that look like identifiers."""
        source = text
        if RE_PERCENT.search(text):
            text = unquote(text)
        pattern = RE_SUSPICIOUS_URL if "://" in text else RE_SUSPICIOUS

        def replace(m):
            w = m.group(0)
            if self.keep_pattern and self.keep_pattern.search(w):
                return w
            if entropy(w) >= 3.6 and re.search(r"\d", w):
                return self.label(w, "ID", where)
            return w

        parts = RE_LABEL.split(text)
        labels = RE_LABEL.findall(text)
        result = []
        for i, part in enumerate(parts):
            result.append(pattern.sub(replace, part))
            if i < len(labels):
                result.append(labels[i])
        result = "".join(result)
        # decoded text only if something was replaced
        return result if result != text else source

    def second_pass(self, o, key="entry", skip=None):
        skip = self.skipped_in_check() if skip is None else skip
        if isinstance(o, dict):
            return {
                k: (v if k in skip else self.second_pass(v, k, skip))
                for k, v in o.items()
            }
        if isinstance(o, list):
            return [self.second_pass(x, key, skip) for x in o]
        if isinstance(o, str) and o:
            where = f"second-pass:{key}"
            return self.entropic(self.patterns(o, where, url="://" in o), where)
        return o

    # ---- check after pseudonymisation ------------------------------------
    def _check_string(self, o: str, path: str, no, beside=True):
        is_url = "://" in o
        if beside and RE_LABEL.search(o):
            # fragments left next to labels (partial masking)
            for fr in RE_LABEL.split(o):
                for m in re.finditer(r"[A-Za-z0-9+_.-]{10,}" if is_url else r"[A-Za-z0-9+/_.-]{10,}", fr):
                    w = m.group(0).strip(".")
                    if RE_FLOAT.fullmatch(w) or looks_like_name(w):
                        continue
                    if re.search(r"\d", w) and re.search(r"[A-Za-z]", w) and entropy(w) >= 3.0:
                        self.leftovers.append((self.host, no, path + " (next to label)", shape(w), len(w)))
        without = RE_LABEL.sub(" ", o)
        for m in (RE_SUSPICIOUS_URL if "://" in without else RE_SUSPICIOUS).finditer(without):
            w = m.group(0)
            if self.keep_pattern and self.keep_pattern.search(w):
                continue
            if entropy(w) >= 3.6 and re.search(r"\d", w) and not w.startswith("http"):
                self.leftovers.append((self.host, no, path, shape(w), len(w)))
        if self.min_digits:
            for m in re.finditer(r"(?<![0-9A-Za-z.])\d{%d,}(?![0-9A-Za-z.])" % self.min_digits, without):
                if not looks_like_time(m.group(0)):
                    self.leftovers.append((self.host, no, path + " (long digits)", "digits", len(m.group(0))))

    def _check_json(self, o, path, no):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(k, str) and strong_pattern(k, self.min_digits):
                    self.leftovers.append((self.host, no, f"{path} (key)", shape(k), len(k)))
                nk = k if isinstance(k, str) and not strong_pattern(k, self.min_digits) else "<key>"
                self._check_json(v, f"{path}.{nk}", no)
        elif isinstance(o, list):
            for x in o:
                self._check_json(x, path + "[]", no)
        elif isinstance(o, str):
            st = o.strip()
            if st[:1] in "{[" and len(st) > 2:
                try:
                    self._check_json(json.loads(st), path + "~json", no)
                    return
                except ValueError:
                    pass
            self._check_string(o, path, no)
        elif isinstance(o, int) and not isinstance(o, bool) and self.min_digits:
            if len(str(abs(o))) >= self.min_digits and not looks_like_time(o):
                self.leftovers.append((self.host, no, path + " (long digits)", "digits", len(str(abs(o)))))

    def _check_body(self, text: str, path: str, no):
        try:
            self._check_json(json.loads(text), path + ":$", no)
            return
        except ValueError:
            pass
        lines = text.split("\n")
        for i, ln in enumerate(lines):
            try:
                obj = json.loads(ln)
                if isinstance(obj, (dict, list)):
                    self._check_json(obj, f"{path}:$line", no)
                    continue
            except ValueError:
                pass
            self._check_string(ln, path, no)

    def find_leftovers(self, e: dict, no, static=False):
        skip = self.skipped_in_check()

        def walk(o, path):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k in skip:
                        continue
                    s = f"{path}.{k}"
                    if s == "entry.response.content.text" and static:
                        continue
                    if isinstance(v, str) and s in ("entry.response.content.text", "entry.request.postData.text"):
                        self._check_body(v, s, no)
                        continue
                    walk(v, s)
            elif isinstance(o, list):
                for x in o:
                    # headers, query, cookies: field name in the path
                    if isinstance(x, dict) and isinstance(x.get("name"), str) and not strong_pattern(x["name"], self.min_digits):
                        walk(x, f"{path}[{x['name']}]")
                    else:
                        walk(x, path)
            elif isinstance(o, str):
                # static resource addresses (file names with hashes) without the
                # "next to label" check; full high-entropy tokens are checked
                self._check_string(o, path, no, beside=not (static and path == "entry.request.url"))
        walk(e, "entry")


def looks_like_name(w: str) -> bool:
    """Key/variable names such as ipV4ObservedAt, utf8Encoded (few digits)."""
    return bool(re.fullmatch(r"[A-Za-z_$][A-Za-z_$]*\d{0,2}[A-Za-z_$]*", w)) and sum(c.isdigit() for c in w) <= 2


def strong_pattern(s: str, min_digits=15) -> bool:
    """UUID, e-mail, JWT, IP, hex32+ or long digits outside a label."""
    without = RE_PROTECTED.sub(" ", s)
    if RE_UUID.search(without) or RE_EMAIL.search(without) or RE_JWT.search(without) or RE_HEX.search(without):
        return True
    for m in RE_IPV4.finditer(without):
        if all(int(o) <= 255 for o in m.group(0).split(".")):
            return True
    for m in RE_IPV6_CANDIDATE.finditer(without):
        if is_ipv6(m.group(0)):
            return True
    if min_digits:
        for m in re.finditer(r"(?<![0-9A-Za-z.])\d{%d,}(?![0-9A-Za-z.])" % min_digits, without):
            if not looks_like_time(m.group(0)):
                return True
    return False


def shape(w: str) -> str:
    """Kind of characters, without quoting the value."""
    if re.fullmatch(r"\d+", w):
        return "digits"
    if re.fullmatch(r"[0-9a-fA-F]+", w):
        return "hex"
    if RE_UUID.fullmatch(w):
        return "UUID"
    if re.fullmatch(r"[A-Za-z0-9+/=]+", w):
        return "base64/alphanumeric"
    if re.fullmatch(r"[A-Za-z0-9_-]+", w):
        return "base64url/alphanumeric"
    return "mixed characters"


def month(v):
    """ISO date or timestamp (s/ms) -> 'YYYY-MM'."""
    if isinstance(v, str):
        m = re.match(r"^(\d{4}-\d{2})-\d{2}", v)
        if m:
            return m.group(1)
        if re.fullmatch(r"\d{10}|\d{13}", v):
            v = int(v)
        else:
            return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        n = float(v)
        if n > 1e11:
            n /= 1000.0
        try:
            return datetime.datetime.fromtimestamp(n, tz=datetime.timezone.utc).strftime("%Y-%m")
        except (OverflowError, OSError, ValueError):
            return None
    return None


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(s).values())


def value_type(s: str) -> str:
    # as in 1.x (scheme E1); the only difference: shortened IPv6 (with "::")
    # gets type IP instead of ID - the digest stays the same
    if RE_UUID.fullmatch(s):
        return "UUID"
    if RE_JWT.fullmatch(s):
        return "JWT"
    if RE_EMAIL.fullmatch(s):
        return "EMAIL"
    if RE_IPV4.fullmatch(s) or is_ipv6(s):
        return "IP"
    if re.fullmatch(r"\d+", s):
        return "NUM"
    if re.fullmatch(r"[0-9a-fA-F]{16,}", s):
        return "HEX"
    return "ID"


def describe_format(s: str) -> str:
    """Format description for the report. Does not quote characters of the value,
    except known structural prefixes (e.g. $SuperwallDevice:)."""
    if RE_UUID.fullmatch(s):
        return "UUID"
    if RE_JWT.fullmatch(s):
        return "JWT"
    if re.fullmatch(r"\d+", s):
        return "digits"
    if re.fullmatch(r"[0-9a-fA-F]+", s):
        return "hex"
    if RE_EMAIL.fullmatch(s):
        return "e-mail"
    if RE_IPV4.fullmatch(s) or is_ipv6(s):
        return "IP address"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}([T ][\d:.]+)?Z?", s):
        return "ISO date"
    m = PREFIXES_FOR_REPORT.match(s)
    if m:
        return f"prefix '{m.group(1)}' + rest"
    if re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return "base64/alphanumeric"
    if re.fullmatch(r"[A-Za-z0-9+/=_.:-]+", s):
        return "alphanumeric with separators"
    return "text"


def salt_fingerprint(salt: bytes) -> str:
    """Shows whether two files were made with the same salt. Neither the salt nor
    the labels can be reconstructed from it."""
    # Fixed domain-separation string, kept byte for byte from the earlier versions so that
    # the published salt fingerprint (ab1aa7958ba0) stays valid and fingerprints stay
    # comparable across versions. Do not change it. It is Polish for
    # "salt-fingerprint/anonymise_har"; the second part is the script's former name.
    return hmac.new(salt, b"odcisk-soli/anonimizuj_har", hashlib.sha256).hexdigest()[:12]


def load_salt(path: str):
    """Returns (salt, is_new)."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read(), False
    salt = os.urandom(32)
    with open(path, "wb") as f:
        f.write(salt)
    os.chmod(path, 0o600)
    print(f"WARNING: created a NEW salt: {os.path.abspath(path)}", file=sys.stderr)
    print("         Labels will not match files processed earlier with another salt.", file=sys.stderr)
    print("         If this is a mistake (e.g. run from another directory), pass the right file with --salt.", file=sys.stderr)
    return salt, True


def load_known(path):
    """File: one value per line; optionally a custom label after a tab."""
    known = []
    if not path:
        return known
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.rstrip("\n")
            if not ln.strip() or ln.startswith("#"):
                continue
            parts = ln.split("\t")
            value = parts[0].strip()
            lab = parts[1].strip() if len(parts) > 1 else None
            if len(value) >= 3:
                known.append((value, lab))
    known.sort(key=lambda x: -len(x[0]))
    return known


def known_variants(value: str):
    """Forms in which the value can appear in the serialised HAR."""
    w = [value, quote(value, safe=""), quote_plus(value)]
    js = json.dumps(value, ensure_ascii=False)[1:-1]
    w += [js, json.dumps(js, ensure_ascii=False)[1:-1]]
    result = []
    for x in w:
        if x and x not in result:
            result.append(x)
    return result


def outside_protected(text: str, function):
    """Applies function to the text, skipping <<...>> fragments."""
    parts = RE_PROTECTED.split(text)
    protected = RE_PROTECTED.findall(text)
    result = []
    for i, part in enumerate(parts):
        result.append(function(part))
        if i < len(protected):
            result.append(protected[i])
    return "".join(result)


def list_groups() -> str:
    r = ["Field groups masked by default (leave in clear: --clear-groups name1,name2):", ""]
    for g, d in FIELD_GROUPS.items():
        r.append(f"  {g:20s} {d['description']}")
        r.append(f"  {'':20s} keys (after normalisation): {', '.join(sorted(d['keys']))}")
    return "\n".join(r)


def main():
    ap = argparse.ArgumentParser(description=f"Pseudonymise a HAR file (version {VERSION}).")
    ap.add_argument("har", nargs="?")
    ap.add_argument("--known", help="file with your own values to remove (device name, Apple ID, public IP, SSID...)")
    ap.add_argument("--only", help="host regex: keep only matching entries")
    ap.add_argument("--skip", default=r"(^|\.)proxyman\.com$", help="host regex: remove matching entries")
    ap.add_argument("--keep", default="", help="additional key names whose values are kept (comma-separated)")
    ap.add_argument("--keep-pattern", default="", help="regex: strings matching it are not replaced in the second pass, e.g. '^pk_'")
    ap.add_argument("--salt", default=".pseudonymisation_salt", help="salt file (created on first use; a relative path is relative to the current directory)")
    # new in 2.0.0
    ap.add_argument("--clear-groups", default="", help="field groups to leave in clear (comma-separated; 'all' = as in 1.x); list: --list-groups")
    ap.add_argument("--purchase-dates-mode", choices=["label", "month"], default="label",
                    help="label (default) or month: only YYYY-MM is kept")
    ap.add_argument("--no-entropy-hosts", default=NO_ENTROPY_DEFAULT,
                    help="host regex: responses are static code/resources; no entropy check and no HEX/B64/digit patterns ('' disables)")
    ap.add_argument("--min-digits", type=int, default=15, help="strings of at least this many digits are replaced as NUM (0 disables)")
    ap.add_argument("--no-prefix-split", action="store_true",
                    help="as in 1.x: '$SuperwallDevice:<id>' under a sensitive key gets one label for the whole value")
    ap.add_argument("--output", help="output directory (default: next to the input file)")
    ap.add_argument("--list-groups", action="store_true", help="print the field groups and exit")
    ap.add_argument("--version", action="version", version=f"pseudonymise_har.py {VERSION} (label scheme {LABEL_SCHEME})")
    a = ap.parse_args()

    if a.list_groups:
        print(list_groups())
        return
    if not a.har:
        ap.error("give a HAR file")

    clear = {g.strip() for g in a.clear_groups.split(",") if g.strip()}
    if "all" in clear:
        clear = set(FIELD_GROUPS)
    unknown = clear - set(FIELD_GROUPS)
    if unknown:
        sys.exit(f"Unknown groups in --clear-groups: {', '.join(sorted(unknown))}. List: --list-groups")

    with open(a.har, encoding="utf-8-sig") as f:
        har = json.load(f)
    entries = har.get("log", {}).get("entries")
    if entries is None:
        sys.exit("This does not look like a HAR file (no log.entries).")

    keep = KEEP_DEFAULT | {re.sub(r"[^a-z0-9]", "", k.lower()) for k in a.keep.split(",") if k.strip()}
    known = load_known(a.known)
    salt, new_salt = load_salt(a.salt)
    ps = Pseudonymiser(salt, keep, known, clear_groups=clear, dates_mode=a.purchase_dates_mode,
                       min_digits=max(0, a.min_digits), split_prefixes=not a.no_prefix_split)
    ps.no_entropy_re = re.compile(a.no_entropy_hosts) if a.no_entropy_hosts else None

    if a.keep_pattern:
        ps.keep_pattern = re.compile(a.keep_pattern)

    result, skipped = [], collections.Counter()
    per_host = collections.Counter()
    static_idx = []  # indices of entries from hosts without entropy check
    for e in entries:
        try:
            host = urlsplit(e.get("request", {}).get("url", "")).hostname or "?"
        except ValueError:
            host = "?"
        if a.skip and re.search(a.skip, host):
            skipped[host] += 1
            continue
        if a.only and not re.search(a.only, host):
            skipped[host] += 1
            continue
        e = ps.entry(e)
        static = bool(ps.no_entropy_re and ps.no_entropy_re.search(host))
        static_body = None
        if static:
            cont = e.get("response", {}).get("content")
            if isinstance(cont, dict) and "text" in cont:
                static_body = cont.pop("text")
        e = ps.second_pass(e)
        if static_body is not None:
            e["response"]["content"]["text"] = static_body
        if static:
            static_idx.append(len(result))
        per_host[host] += 1
        result.append(e)

    fingerprint = salt_fingerprint(salt)
    har["log"]["entries"] = result
    har["log"].pop("pages", None)
    har["log"]["comment"] = pseudonymised_comment(VERSION, LABEL_SCHEME, fingerprint, clear)
    text = json.dumps(har, ensure_ascii=False, indent=1)

    # the user's own values - on the whole file, case-insensitive,
    # skipping existing labels
    known_hits = collections.Counter()
    for i, (value, lab) in enumerate(known, 1):
        label_text = f"<<{lab or 'KNOWN' + str(i)}>>"
        for variant in known_variants(value):
            pattern = re.compile(re.escape(variant), re.IGNORECASE)
            counter = [0]

            def substitute(part, pattern=pattern, label_text=label_text, counter=counter):
                new, n = pattern.subn(label_text, part)
                counter[0] += n
                return new

            text = outside_protected(text, substitute)
            known_hits[label_text] += counter[0]

    # check
    for no, e in enumerate(json.loads(text)["log"]["entries"]):
        try:
            ps.host = urlsplit(e.get("request", {}).get("url", "")).hostname or "?"
        except ValueError:
            ps.host = "?"
        ps.find_leftovers(e, no, static=no in set(static_idx))
    known_left = []
    for w, _ in known:
        for variant in known_variants(w):
            if re.search(re.escape(variant), RE_PROTECTED.sub(" ", text), re.IGNORECASE):
                known_left.append(w)
                break

    base = re.sub(r"\.har$", "", a.har, flags=re.IGNORECASE)
    if a.output:
        os.makedirs(a.output, exist_ok=True)
        base = os.path.join(a.output, os.path.basename(base))
    anon_file = base + ".anon.har"
    if os.path.abspath(anon_file) == os.path.abspath(a.har):
        sys.exit("The output file would overwrite the input file. Give another directory with --output.")
    out_bytes = text.encode("utf-8")
    with open(anon_file, "wb") as f:
        f.write(out_bytes)
    with open(a.har, "rb") as f:
        sha_original = hashlib.sha256(f.read()).hexdigest()

    r = []
    r.append(f"PSEUDONYMISATION REPORT: {os.path.basename(a.har)}")
    r.append(f"Script: pseudonymise_har.py {VERSION}, label scheme {LABEL_SCHEME}")
    r.append(f"Salt fingerprint: {fingerprint}" + ("   WARNING: salt created in this run (NEW SALT)" if new_salt else ""))
    r.append(f"Original SHA-256: {sha_original}")
    r.append(f"Output file: {os.path.basename(anon_file)}")
    r.append(f"Output SHA-256: {hashlib.sha256(out_bytes).hexdigest()}")
    r.append(f"Entries: {len(entries)} in the original, {len(result)} after the filter")
    r.append("")
    r.append("SETTINGS")
    r.append(f"  masked field groups: {', '.join(g for g in FIELD_GROUPS if g not in clear) or 'none'}")
    r.append(f"  field groups in clear (--clear-groups): {', '.join(sorted(clear)) or 'none'}")
    r.append(f"  purchase dates: {a.purchase_dates_mode}")
    r.append(f"  hosts without entropy check: {a.no_entropy_hosts or 'none'}")
    r.append(f"  long digit strings from: {ps.min_digits or 'disabled'}")
    r.append(f"  prefix splitting ($SuperwallDevice: etc.): {'yes' if ps.split_prefixes else 'no (as 1.x)'}")
    r.append("")
    r.append("ENTRIES PER HOST")
    for h, n in per_host.most_common():
        r.append(f"  {n:4d}  {h}")
    if skipped:
        r.append("SKIPPED HOSTS")
        for h, n in skipped.most_common():
            r.append(f"  {n:4d}  {h}")
    r.append("")
    r.append("REPLACEMENTS BY TYPE")
    for t, n in ps.counters.most_common():
        r.append(f"  {n:5d}  {t}")
    for lab, n in known_hits.items():
        r.append(f"  {n:5d}  {lab} (from the --known file)")
    r.append("")
    r.append("MASKED FIELD GROUPS (group -> field: count)")
    if ps.masked:
        for g in FIELD_GROUPS:
            if g in ps.masked:
                r.append(f"  {g}")
                for k, n in sorted(ps.masked[g].items()):
                    r.append(f"      {k}: {n}")
    else:
        r.append("  none")
    r.append("")
    r.append("LABELS (same label = same original value)")
    r.append("  occurrences | format of the original | hosts")
    for lab, i in sorted(ps.labels.items(), key=lambda x: (-len(x[1]["hosts"]), -x[1]["n"])):
        fmt = i["format"] if "_L" in lab else "(short value)"
        r.append(f"  {lab:28s} {i['n']:4d} | {fmt:28s} | {', '.join(sorted(i['hosts']))}")
    if ps.static_labels:
        r.append(f"  Left out of the table: {ps.static_labels} labels from responses of hosts without entropy check.")
    r.append("")
    r.append("LABELS ON MORE THAN ONE HOST")
    shared = [(lab, i) for lab, i in ps.labels.items() if len(i["hosts"]) > 1]
    if shared:
        for lab, i in shared:
            r.append(f"  {lab}  ->  {', '.join(sorted(i['hosts']))}")
    else:
        r.append("  none")
    r.append("")
    r.append(f"LONG DIGIT STRINGS (>= {ps.min_digits}) REPLACED AS NUM (host | place | length | label)")
    if ps.long_digits:
        seen = set()
        for h, g, n, lab in ps.long_digits:
            if (h, g, lab) in seen:
                continue
            seen.add((h, g, lab))
            r.append(f"  {h} | {g} | {n} | {lab}")
    else:
        r.append("  none")
    r.append("")
    r.append("LABEL COLLISIONS (different values, same label)")
    if ps.collisions:
        for lab, n in ps.collisions.items():
            r.append(f"  WARNING: {lab} - {n} additional different values. This label does not identify a single value.")
    else:
        r.append("  none")
    r.append("")
    r.append("PLACES WHERE VALUES WERE REPLACED (host -> field)")
    for h in sorted(ps.paths):
        r.append(f"  {h}")
        for s in sorted(ps.paths[h]):
            r.append(f"      {s}")
    r.append("")
    r.append("LEFT IN CLEAR (deliberately not masked)")
    r.append("  1. HAR structure fields: startedDateTime, time, timings, method, status, httpVersion,")
    r.append("     mimeType, sizes (bodySize, headersSize, content.size), _clientPort, _serverPort.")
    r.append("     Exact entry timestamps are kept (authors' decision).")
    if ps.clear_by_choice or clear:
        r.append("  2. Field groups left in clear by choice (--clear-groups):")
        for g in sorted(clear):
            fields = ps.clear_by_choice.get(g, {})
            desc = ", ".join(f"{k} ({n})" for k, n in sorted(fields.items())) or "did not occur"
            r.append(f"      {g}: {desc}")
    else:
        r.append("  2. Field groups left in clear by choice: none")
    r.append("  3. Keys from the KEEP list (product, package and bundle identifiers):")
    r.append("      " + (", ".join(f"{k} ({n})" for k, n in sorted(ps.clear_kept.items())) or "did not occur"))
    r.append("  4. Time fields in bodies (values in clear):")
    r.append("      " + (", ".join(f"{k} ({n})" for k, n in sorted(ps.clear_time.items())) or "did not occur"))
    if ps.clear_digits_time:
        r.append(f"  5. Long numbers taken as a Unix timestamp (kept): {sum(ps.clear_digits_time.values())}")
        for g, n in sorted(ps.clear_digits_time.items()):
            r.append(f"      {g}: {n}")
    else:
        r.append("  5. Long numbers taken as a Unix timestamp: none")
    r.append("  6. Other keys with an unchanged value (host -> key (count)):")
    for h in sorted(ps.clear_keys):
        r.append(f"      {h}: " + ", ".join(f"{k} ({n})" for k, n in sorted(ps.clear_keys[h].items())))
    if static_idx:
        r.append("  7. Responses of hosts without entropy check: only the JWT, e-mail, UUID and IP patterns were applied.")
    r.append("")
    r.append("LEFTOVERS TO CHECK BEFORE SHARING")
    if known_left:
        r.append(f"  WARNING: {len(known_left)} values from the --known file still occur in the output!")
    else:
        r.append("  Values from the --known file: 0 occurrences in the output." if known else "  No --known file given (device name, Apple ID, public IP etc. were not searched for).")
    if ps.leftovers:
        r.append("  Strings that were not replaced (host | entry no. | field or JSON path | shape | length):")
        seen = set()
        for h, no, s, k, n in ps.leftovers:
            if (h, no, s, k, n) in seen:
                continue
            seen.add((h, no, s, k, n))
            r.append(f"    {h} | {no} | {s} | {k} | {n}")
    else:
        r.append("  No unreplaced high-entropy strings found.")
    with open(base + ".report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(r) + "\n")

    print(f"Written: {anon_file}")
    print(f"Written: {base}.report.txt")
    print(f"Version {VERSION}, scheme {LABEL_SCHEME}, salt fingerprint {fingerprint}")
    print(f"Labels: {len(ps.labels)}, on several hosts: {len(shared)}, leftovers: {len(set(ps.leftovers))}, collisions: {len(ps.collisions)}")
    if known_left:
        print("WARNING: the output still contains values from the --known file. Do not share the file.")
        sys.exit(2)
    if ps.collisions:
        print("WARNING: label collisions detected - see the LABEL COLLISIONS section of the report.")
        sys.exit(3)


if __name__ == "__main__":
    main()
