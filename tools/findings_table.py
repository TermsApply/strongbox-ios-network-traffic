#!/usr/bin/env python3
"""findings_table.py - tabulates facts from HAR files for the findings in section 3 of the report.

Usage:
    python3 tools/findings_table.py data/*.pub.har > findings_table.md
    python3 tools/findings_table.py --before 0 --after 60 data/*.pub.har

Events per cold start are counted in the window used in the report (README, section 3.2): from
--before seconds (default 1) before `app_launch` to --after seconds (default 20) after it, or up
to the next `app_launch` if that comes earlier (the next launch itself is not counted). The
request columns (RC ... adservices) count HAR entries from 5 s before `app_launch` to 60 s after
it, or to 1 s before the next `app_launch`.

Prints only counts, field names, event names, labels and times - never original values.
Times are those of the input files: on the published *.pub.har files they are shifted per file
(see README, section 2), so they must not be compared between files. Run on the authors'
unpublished *.anon.har files, the output contains real times and is not published.
"""
import argparse
import collections
import datetime
import json
import re
from urllib.parse import urlsplit

VERSION = "1.2"
SDK = ("api.revenuecat.com", "api.superwall.me", "collector.superwall.me",
       "enrichment-api.superwall.com", "subscriptions-api.superwall.com")
RESOURCES = ("user-content.superwalleditor.com", "fonts.gstatic.com", "fonts.googleapis.com", "js.stripe.com")
LIFECYCLE = ("app_install", "app_launch", "app_open", "app_close", "session_start", "device_attributes", "first_seen")
STANDARD = re.compile(r"^(app_|session_|device_|user_|first_seen|subscriptionStatus|customerInfo|enrichment_|redemption_|config_|paywall|shimmer|trigger_|transaction|surveyResponse|deepLink|touches|identityAlias|reset|restore|freeTrial|subscription|nonRecurring|identify|attributes|superwall)")


def ts(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


def analyse(path, before=1.0, after=20.0):
    with open(path, encoding="utf-8") as f:
        har = json.load(f)
    E = har["log"]["entries"]
    name = re.sub(r"\.(anon|pub)\.har$", "", path.split("/")[-1])
    for e in E:
        e["_t"] = ts(e["startedDateTime"])
        e["_h"] = urlsplit(e["request"]["url"]).hostname or "?"
    E.sort(key=lambda e: e["_t"])
    ev = []  # (time, name, parameter keys, entry index)
    for i, e in enumerate(E):
        if e["_h"] == "collector.superwall.me" and e["request"].get("postData", {}).get("text"):
            try:
                body = json.loads(e["request"]["postData"]["text"])
            except ValueError:
                continue
            for x in body.get("events", []):
                ev.append((ts(x["created_at"]) if x.get("created_at") else e["_t"], x.get("event_name", "?"), set(x.get("parameters", {}).keys()), i))
    ev.sort(key=lambda z: z[0])
    starts = [z[0] for z in ev if z[1] == "app_launch"]
    print(f"\n## {name}  (entries {len(E)}, events {len(ev)}, cold starts = app_launch: {len(starts)})")
    print(f"| start (UTC) | RC | api.sw | collector | enrich | subs-api | resources | events -{before:g} s..+{after:g} s | lifecycle | paywall_* | redeem | receipts | adservices |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for k, s in enumerate(starts):
        end = min(s + datetime.timedelta(seconds=60), starts[k + 1] - datetime.timedelta(seconds=1)) if k + 1 < len(starts) else s + datetime.timedelta(seconds=60)
        window = [e for e in E if s - datetime.timedelta(seconds=5) <= e["_t"] <= end]
        h = collections.Counter(e["_h"] for e in window)
        # events: [s - before, s + after), cut at the next app_launch (README, section 3.2)
        ev_end = s + datetime.timedelta(seconds=after)
        if k + 1 < len(starts):
            ev_end = min(ev_end, starts[k + 1])
        z = [x for x in ev if s - datetime.timedelta(seconds=before) <= x[0] < ev_end]
        n = collections.Counter(x[1] for x in z)
        cycle = ",".join(k for k in LIFECYCLE if n.get(k))
        pw = ",".join(f"{k}" for k in sorted(n) if k.startswith("paywall_"))
        redeem = sum(1 for e in window if e["request"]["url"].endswith("/redeem") and e["request"]["method"] == "POST")
        rec = sum(1 for e in window if "/receipts" in e["request"]["url"] and e["request"]["method"] == "POST")
        ads = sum(1 for e in window if "adservices" in e["request"]["url"])
        print(f"| {s.strftime('%m-%d %H:%M:%S')} | {h['api.revenuecat.com']} | {h['api.superwall.me']} | {h['collector.superwall.me']} | {h['enrichment-api.superwall.com']} | {h['subscriptions-api.superwall.com']} | {sum(h[x] for x in RESOURCES)} | {len(z)} | {cycle} | {pw or '-'} | {redeem} | {rec} | {ads} |")
    # non-standard events (the app's own)
    other = collections.Counter((x[1], x[0].strftime('%H:%M:%S')) for x in ev if not STANDARD.match(x[1]))
    print("Events outside the SDK standard:", ", ".join(f"`{k}` {t}" for (k, t), v in sorted(other.items(), key=lambda a: a[0][1])) or "none")
    db = [x for x in ev if re.search(r"database|unlock|vault", x[1], re.I)]
    print("Events with 'database/unlock/vault' in the name:", len(db))
    # device_attributes: field names
    da = [x for x in ev if x[1] == "device_attributes"]
    if da:
        keys = sorted(set().union(*[x[2] for x in da]))
        wanted = ["$vendorId", "$aliasId", "$deviceId", "$appTransactionId", "$appInstallDate", "$deviceModel", "$osVersion", "$deviceLanguageCode", "$regionCode", "$deviceCurrencyCode", "$timezoneOffset", "$interfaceStyle", "$radioType", "$isLowPowerModeEnabled", "$ipCountry", "$ipCity", "$demandScore", "$demandTier", "$device_ipAddress"]
        print("device_attributes - fields present from the list for findings 2/5:", ", ".join(k for k in wanted if k in keys), "| missing:", ", ".join(k for k in wanted if k not in keys) or "-", f"| fields in total: {len(keys)}")
    # enrich: response fields
    for e in E:
        if "enrich" in e["request"]["url"] and e["response"].get("content", {}).get("text"):
            try:
                r = json.loads(e["response"]["content"]["text"])
            except ValueError:
                continue
            print("enrich - response fields:", ", ".join(sorted(r.get("device", r).keys())))
            break
    # static_config (response 200; 304 has no body)
    for e in E:
        if "static_config" in e["request"]["url"] and e["response"].get("content", {}).get("text"):
            try:
                c = json.loads(e["response"]["content"]["text"])
            except ValueError:
                continue
            pw = c.get("paywall_responses", [])
            tr = c.get("trigger_options", [])
            rules = [r for t_ in tr for r in t_.get("rules", [])]
            ent = sum(1 for r in rules if "activeEntitlements" in json.dumps(r))
            tog = {x.get("key"): x.get("enabled") for x in c.get("toggles", [])}
            print(f"static_config: paywall_responses {len(pw)} ({', '.join(sorted(p.get('identifier', '?') for p in pw))}), trigger_options {len(tr)} ({', '.join(t_.get('event_name', '?') for t_ in tr)}), rules {len(rules)}, with activeEntitlements {ent}; toggles {tog}; attribution_options {c.get('attribution_options')}; tests {c.get('tests')}; disable_preload {c.get('disable_preload')}")
            break
    alias = sum(1 for x in ev if "aliasId" in x[2] or "$aliasId" in x[2])
    print(f"events with an aliasId field: {alias}/{len(ev)}; with vendorId: {sum(1 for x in ev if 'vendorId' in x[2] or '$vendorId' in x[2])}")
    # RC: $attConsentStatus, original_app_user_id
    att = sum(1 for e in E if e["_h"] == "api.revenuecat.com" and "attConsentStatus" in (e["request"].get("postData", {}).get("text") or ""))
    orig = set()
    for e in E:
        t = e["response"].get("content", {}).get("text") or ""
        if e["_h"] == "api.revenuecat.com" and "original_app_user_id" in t:
            orig |= set(re.findall(r'"original_app_user_id":"([^"]+)"', t))
    print(f"RC: requests with $attConsentStatus {att}; original_app_user_id labels: {sorted(orig)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=f"Tabulate facts from HAR files (version {VERSION}).")
    ap.add_argument("har", nargs="+", help="*.pub.har (or *.anon.har) files")
    ap.add_argument("--before", type=float, default=1.0, help="event window start, seconds before app_launch (default 1)")
    ap.add_argument("--after", type=float, default=20.0, help="event window end, seconds after app_launch (default 20)")
    a = ap.parse_args()
    for p in a.har:
        analyse(p, a.before, a.after)
