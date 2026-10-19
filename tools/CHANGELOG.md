# CHANGELOG – tools

Format: version, date, changes. The version of `pseudonymise_har.py` is written to its report and to `log.comment` of every `*.anon.har` file.

Before 16 Oct 2026 the scripts, their options, field groups, label types, report texts and output file names were in Polish. This changelog uses the current English names throughout, also for earlier versions. Version numbers continue across the renaming.

## Renaming of 16 Oct 2026

| Script | Version | Earlier version |
|---|---|---|
| `pseudonymise_har.py` | 2.1.0 | 2.0.2 |
| `prepare_har_for_publication.py` | 1.2.0 | 1.1.4 |
| `shift_extract_times.py` | 1.4 | 1.3 |
| `extract_pcap.sh` | 2.1.0 | 2.0.0 |
| `clean_metadata.py` | 1.1 | 1.0 |
| `rerun_pipeline.sh` | 1.1 | 1.0 (no version number) |
| `findings_table.py` | 1.1 | 1.0 (no version number, not published) |

## pseudonymise_har.py

### 2.4.0 – 2026-10-19
- The Superwall event parameters `$attr_demandScore` and `$attr_demandTier` (in the `paywall_open` event) and `$attr_ipContinent` belong to the field group `superwall_profile` (keys `attrdemandscore`, `attrdemandtier`, `attripcontinent`), so they get a `PROFILE` label like `$demandScore`, `$demandTier` and `$device_demandScore`. Until 2.3.0 the normalised key names were not in the group and the values were left in clear (one occurrence each of `$attr_demandScore` and `$attr_demandTier`, in one file; `$attr_ipContinent` did not occur). Group description updated. Salt fingerprint and other labels unchanged.
- The published files were not re-pseudonymised (that needs the salt); `prepare_har_for_publication.py` 1.6.0 masks the two values in the existing `*.anon.har` files.
- Test: `test_attr_demand_fields_profile_group`; `test_legacy_input_gives_same_entries` accepts the one known difference (2.0.2 input: `<<MASKED_PROFILE>>`, 2.4.0 input: `PROFILE` label). The synthetic HAR has the two parameters in the `app_launch` event.

### 2.3.0 – 2026-10-17
- The Superwall parameter `sw_cache_key` (`sw_cache_key=<13 digits>` in the addresses of paywall resources; most likely the time the paywall version was published on the service side, H) is labelled wherever such an address occurs in text: the `Referer` header, `$paywall_url` in event parameters and `url` fields of the static configuration. The label is the one the query parameter of the request URL already had (`NUM`, sensitive key name), so the same value has the same label in every place. Up to 2.2.0 only the request URL and its `queryString` were labelled. The value is a timestamp that is not shifted with the run; in clear it allows bounding the real run time and linking runs.
- The published files were not re-pseudonymised (that needs the salt); `prepare_har_for_publication.py` 1.4.0 masks the value in the existing `*.anon.har` files.
- Test: `test_pseudonymiser_labels_cache_key_everywhere`.

### 2.2.0 – 2026-10-17
- The CDN point of presence is also masked in the `Server-Timing` response header (`cdn-pop;desc="XXX99-X9"` or `desc="XXX99-X99"`, quoted or not), in the group `cdn_pop` and with the same label as the same value in `X-Amz-Cf-Pop`. Up to 2.1.0 `X-Amz-Cf-Pop` was masked, but CloudFront repeats the same value in `Server-Timing`, which stayed in clear (`cdn-rid` there was already masked as a random token). `--clear-groups cdn_pop` leaves both in clear. Other labels unchanged.
- The published files were not re-pseudonymised (that needs the salt); `prepare_har_for_publication.py` 1.3.0 masks the value in the existing `*.anon.har` files.
- Test: `test_pseudonymiser_masks_server_timing_pop`.

### 2.1.0 – 2026-10-16
- Translated to English: file name, docstring, comments, help, messages, report, identifiers. Behaviour unchanged.
- Label types: `DATE`, `PRICE`, `CURRENCY`, `VERSION`, `BUILD`, `PROFILE`, `LOCALTIME`, `BINARY`, `KNOWN<n>` (other types unchanged). The hash is computed from the value only, not from the type, so the hash part and the `_L` part of every label are the same as in 2.0.2 (same salt, label scheme E1).
- Field groups: `purchase_dates`, `price`, `currency_storefront`, `original_version`, `model`, `os_build`, `superwall_profile`, `server`, `cdn_pop`, `local_time`; `all` for all groups.
- Options: `--known`, `--only`, `--skip`, `--keep`, `--keep-pattern`, `--salt`, `--clear-groups`, `--purchase-dates-mode {label,month}`, `--no-entropy-hosts`, `--min-digits`, `--no-prefix-split`, `--output`, `--list-groups`, `--version`. Default salt file: `.pseudonymisation_salt` (relative to the current directory, as before).
- Report file: `*.report.txt`. `log.comment` is written by the new function `pseudonymised_comment()`.
- The fixed string from which the salt fingerprint is computed is unchanged, so the same salt gives the same fingerprint as in 2.0.2.
- Checked on a synthetic HAR in 7 option variants: output byte-identical to 2.0.2 after mapping the label types and replacing `log.comment`; salt fingerprint identical.
- Later on 16 Oct 2026, without a version change (comment only): `salt_fingerprint()` explains in English that the fixed string from which the fingerprint is computed is Polish for "salt-fingerprint/anonymise_har" and is kept byte for byte, because changing it would change the published salt fingerprint `ab1aa7958ba0`.

### 2.0.2 – 2026-10-09
- Names of configuration toggles (`toggles[].key`, snake_case words without digits under the key `key`) stay in clear. In 2.0.1 they were masked as identifiers (the key "key" matched the sensitive pattern). Labels of other values unchanged. Test: `test_config_toggle_name_stays`.

### 2.0.1 – 2026-10-09
- New group `cdn_pop` (`X-Amz-Cf-Pop`, type `CDN_`), split off from the group `server`. Decision of 9 Oct 2026: server addresses in clear, CDN point of presence masked, because it reveals the approximate location of the user.

### 2.0.0 – 2026-10-09

Label compatibility:
- Label scheme **E1** unchanged (HMAC-SHA256, 8 hex characters, `_L` from 16 characters). Values replaced as a whole have, with the same salt, **the same hash as in 1.x** (e.g. `ipCountry`, IDFV).
- Labels differ from 1.x in these cases:
  - fields from the new groups (below) have the types of their group (now `DATE_`, `PRICE_`, `CURRENCY_`, `VERSION_`, `MODEL_`, `BUILD_`, `PROFILE_`, `LOCALTIME_`); `first_seen` was `ID_` in 1.x with the same hash,
  - identifiers with an SDK prefix under a sensitive key: `$SuperwallDevice:<<UUID_…>>` instead of a single label `<<ID_…_L53>>` (old behaviour: `--no-prefix-split`),
  - RevenueCat path `/subscribers/$RCAnonymousID:<<HEX_…>>` instead of `<<ID_…_L47>>`,
  - `BINARY_`: HMAC hash with the salt instead of SHA-256 without salt,
  - IPv6 in short form: type `IP` instead of `ID` (same hash),
  - base64 tokens containing a hex string: one `B64`/`HEX` label for the whole token instead of a label for a fragment.
- New: version, label scheme and salt fingerprint in the report and in `log.comment`. Creating a new salt gives a warning (console and report).

New masking (groups, all masked by default; `--clear-groups name,…` or `all`; list: `--list-groups`):
- `purchase_dates` (`purchase_date`, `original_purchase_date`, `expires_date`, `refunded_at`, `first_seen`, `last_seen` and others); `--purchase-dates-mode month` keeps `YYYY-MM`,
- `price` (`price`, `amount`, `introductory_price` and others),
- `currency_storefront` (device and store currency, `X-Storefront`),
- `original_version` (`original_application_version`),
- `model` (`deviceModel`, `X-Device-Model`, `X-Platform-Device`),
- `os_build` (build number in `X-Platform-Version` and `osBuild` fields),
- `superwall_profile` (`seed`, `demandScore`, `demandTier`, `ipContinent`),
- `server` (`serverIPAddress`, `_serverAddress`, `X-Amz-Cf-Pop`),
- `local_time` (`localDateTime`, `localTime`, `localDate`).

Other detection changes:
- strings of ≥ 15 digits → `NUM` (option `--min-digits`), except Unix timestamps; report section LONG DIGIT STRINGS with the JSON path,
- dictionary keys go through the patterns (UUID, digits, hex…),
- RevenueCat attributes `{"$x": {"value": …}}`: sensitivity by the parent key; new fragments of sensitive keys: `$displayName`, `$firstName` etc., `phone_number`, `apns`, `fcm_token`, `push_token`,
- IPv6 in short form (`::`),
- credentials in URLs (`user:password@host`),
- the entry `comment` field and JSON in Proxyman fields (e.g. `_webSocketMessages`),
- `--known`: also URL-encoded and JSON-escaped forms; existing labels are protected.

False alarms and bugs:
- responses of hosts in `--no-entropy-hosts` (default superwalleditor, js.stripe.com, fonts.googleapis.com, fonts.gstatic.com): only JWT/e-mail/UUID/IP patterns, no entropy check, no LEFTOVERS section, labels outside the table (their number is given),
- the leftover check in JSON bodies checks parsed values: exponential numbers (`$paywall_response_load_duration`) and key names (`$device_ipV4ObservedAt`) are no longer reported,
- the report does not quote beginnings of values: LEFTOVERS give shape, length, entry number and JSON path; the format column shows only structural prefixes (`$…:`, `pk_`),
- report paths use pseudonymised key names (in 1.x a key that was an identifier could reach the PLACES section),
- a form is recognised only with a form `mimeType` or the shape `a=1&b=2` (base64 ending in `=` is no longer damaged),
- `%XX` decoding only for detection (text without data stays byte-identical),
- detection of label collisions within a run (section LABEL COLLISIONS, exit code 3).

Report:
- new sections: SETTINGS, MASKED FIELD GROUPS, LONG DIGIT STRINGS, LABEL COLLISIONS, LEFT IN CLEAR,
- SHA-256 of the output file.

Interface: all earlier arguments unchanged. New options: `--clear-groups`, `--purchase-dates-mode`, `--no-entropy-hosts`, `--min-digits`, `--no-prefix-split`, `--output`, `--list-groups`, `--version`. Exit codes: 2 (values from `--known` in the output, as in 1.x), 3 (label collision).

### 1.x – before 2026-10-09

Versions without a number. According to working notes there were at least three; T3 used the third.

## extract_html_text.py

### 1.0 – 2026-10-18
- Published version of the helper used since 16 Oct 2026 for the text files in `sources/` (then with a Polish name and Polish comments; output unchanged): the main text of a saved HTML page (a raw Wayback Machine capture, `id_` address) as blocks from the last block starting with START before the first block starting with END; links as their text; `<br>` as a line break; with `lists`, list markers ("1." for `<ol>`, "-" for `<ul>`) and an indent of 3 spaces per level. Usage: `extract_html_text.py FILE.html START END blank|line [lists]`. Test: `TestExtractHtmlText`.

## prepare_har_for_publication.py

### 1.6.0 – 2026-10-19
- The `$attr_demandScore` and `$attr_demandTier` parameters of the `paywall_open` event (and `$attr_ipContinent`) are masked in the group `superwall_profile`; the script takes the field groups from `pseudonymise_har.py` 2.4.0, the code of this script is unchanged except for the version. Until 1.5.1 they were left in clear (one occurrence each, in one file).
- The published files were regenerated with 1.6.0 from the same `*.anon.har` files, with the same options, the same time-shift map and the same address map. The pseudonymised input was not re-pseudonymised, so these two values are masked with the placeholder `<<MASKED_PROFILE>>`, not with a label. Apart from them only `log.comment` and the report (script version) changed.
- Test: `test_attr_demand_fields_profile_group`.

### 1.5.1 – 2026-10-18
- Texts only: `log.comment` says that the field group `server`, left in clear by the pseudonymiser, is replaced at publication with labels `<<IP_n>>` (the sentence "Field groups left in clear: … server" from the pseudonymiser no longer reads as a contradiction); the report says that the address map is shared by all published files and gives its size after the file. Test expectation updated.

### 1.5.0 – 2026-10-18
- `--server label --ip-map JSON_FILE`: `serverIPAddress` and `_serverAddress` are replaced with labels `<<IP_n>>` (n in order of first appearance; the same address gives the same label in every file and on a re-run; IPv6 addresses normalised before the lookup). The map is a local file (mode 600), not published; `shift_extract_times.py` 1.7 uses the same map for the PCAP extracts. Decision of 18 Oct 2026 (`DECYZJE.md` 8): the sets of CDN addresses in the runs with and without the VPN are disjoint, so addresses in clear could have pointed to the exit country of the VPN. `--server keep` and `remove` unchanged.
- `log.comment` and the report say "intervals unchanged, entries sorted by time" instead of "intervals and order within the file unchanged" (the entries are sorted by `startedDateTime` after the shift; the Proxyman export is not in time order), and name how the server address was treated.
- Test: `test_server_label_with_ip_map`.

### 1.4.0 – 2026-10-17
- `sw_cache_key` is masked always and in the same way in every place: the request URL, `queryString`, the `Referer` header, `$paywall_url` in events, `url` fields of the static configuration (also URL-encoded, `sw_cache_key%3D…`). Without `--salt` every value, including the labels already in the input, becomes `<<MASKED_NUM>>`, so that one parameter looks the same everywhere in a file; with `--salt` a digit value gets the HMAC label of `pseudonymise_har.py` (`NUM`) and labels already in the input stay. Up to 1.3.0 the value was left in clear outside the request URL as a documented exception to the time shift (1463 values in 9 files, next to 30 labelled values in the request URL and 30 in `queryString`).
- Report: "LEFT IN CLEAR" has the line "sw_cache_key (paywall resource URLs): always masked, in every place" with the number of values masked per place.
- The 10 published HAR files were re-run with the unchanged shift map. Compared with the files of 1.3.0: same entries in the same order; only the `sw_cache_key` values (1523: 1463 in clear and 60 labels, now all `<<MASKED_NUM>>`) and `log.comment` (version number) differ. No `sw_cache_key` value in clear remains.
- Test: `test_publication_masks_cache_key_left_by_older_pseudonymiser`.

### 1.3.0 – 2026-10-17
- Time shift: a bare date or time of day next to a date-time in the same JSON object is rewritten from the shifted date-time (`<prefix>Date` and `<prefix>Time` next to `<prefix>DateTime`, any spelling). In the published files this concerns the Superwall `enrich` request (`device.utcDate`, `device.utcTime` next to `device.utcDateTime`), 20 objects in 9 files. Up to 1.2.1 `utcTime` matched no shift rule and kept the real time of day in all 20, and `utcDate` was moved by whole days only, so in 14 objects (6 files) it was one day off the shifted `utcDateTime` of the same object. If the parts do not agree with the date-time in the input, they are replaced by `<<MASKED_CLOCK>>`; any other bare time of day in a body is also replaced by `<<MASKED_CLOCK>>`, because it cannot be shifted without its date (none in the published files). New report section "BARE DATES AND TIMES OF DAY".
- The CDN point of presence is masked also in `Server-Timing` (`cdn-pop;desc=…`), not only in `X-Amz-Cf-Pop`: `<<MASKED_CDN>>` without `--salt`, an HMAC label of the group `cdn_pop` with `--salt`; labels already in the input are left. 93 values in 9 published files. The report counts them under "fields" as `Server-Timing (cdn-pop)`.
- Report: "field groups not masked in this step" no longer lists `cdn_pop`, which is always masked.
- The 10 published HAR files were re-run with the unchanged shift map. Compared with the files of 16 Oct 2026: same entries in the same order; only `device.utcTime` (20), `device.utcDate` (14), the `Server-Timing` header (93) and `log.comment` (version number) differ. Afterwards no time of day, date-time or epoch of the real run time occurs in the published files (checked against the unpublished `*.anon.har` without printing values; the only unchanged 13-digit values are the `sw_cache_key` parameters, documented as an exception).
- Tests: `test_publication_masks_server_timing_pop_left_by_older_pseudonymiser`, `test_clock_parts_follow_shifted_date_time`, `test_clock_parts_backward_shift`.

### 1.2.1 – 2026-10-16
- `draw_shift()`: the sign is applied to the whole offset (whole days plus seconds), not to the days only. Range of a new offset: at least 3 days and less than 31 days, forward or backward. Until 1.2.0 a backward offset could be as small as 2 days and 1 second, and an offset of 30 whole days plus seconds was more than the documented "3 to 30 days". The order of the random calls is unchanged, so a forward draw gives the same value as before.
- Existing offsets in the shift map are not changed. All 12 offsets used for the published files (10 runs with HAR files, T1, T2) are at least 3 and less than 31 days (checked without printing them); the earlier wording "3 to 30 days" did not describe this range exactly.
- `log.comment` of the published files: "at least 3 and less than 31 days, forward or backward" instead of "3 to 30 days". The 10 published HAR files were re-run with the unchanged map: only `log.comment` (this sentence and the version number) differs.
- Test: `test_draw_shift_range` (edge values and 5000 seeded draws); `test_time_shift` checks the new range.
- A local variable renamed to `label_type` (an English word; no change in behaviour).

### 1.2.0 – 2026-10-16
- Translated to English: file name, docstring, comments, help, messages, report, identifiers.
- Options: `--output`, `--hosts`, `--strip-content`, `--groups`, `--server {remove,keep}`, `--bundle`, `--salt`, `--show-foreign-hosts`, `--shift-time JSON_FILE`, `--run-code CODE`, `--force`. Report file: `*.pub.report.txt`. Placeholders without salt: `<<MASKED_TYPE>>`, `<<MASKED_CDN>>`.
- Alias in the shift map: `RUN:<code>`.
- New option `--legacy-input JSON_FILE`: input written by an older pseudonymiser version (non-English label types and `log.comment`) is translated before processing: only complete labels are renamed (hash and `_L` part unchanged), and `log.comment` is parsed with the regular expression from the JSON file and rewritten with `pseudonymised_comment()`; a mismatch is an error. The output `log.comment` and the report say that the input was translated. The JSON file describing the authors' earlier input is not published (no such input is published).
- Re-run on the 10 published HAR files with the unchanged shift map: after mapping the label types back, all entries, values, times and order are identical to the files of 10 Oct 2026; only `log.comment`, the static-resource `content.comment` and the label type names differ. Reports: same numbers, except the count of removed characters of static resources, which is lower by one per binary label (`BINARY` is one character shorter than its earlier name).

### 1.1.4 – 2026-10-10
- Finding the time shift: until now the map key was only the input file name; a file under a new name (e.g. after renaming the originals) got a new random offset, and the run-code alias was overwritten without warning. Now `resolve_shift()`: first the file name, then the alias `RUN:<code>` (with a message on stderr); a draw only if neither exists; different values under name and alias end with an error and nothing is written. Output data unchanged (10 files re-run: only the version number in `log.comment` differs; map unchanged). Test: `test_shift_by_alias_and_conflict`.

### 1.1.3 – 2026-10-10
- Time-shift fix: epochs written as digit strings in headers were not shifted (`shift()` covers only numbers under keys matching `EPOCH_KEYS`, `shift_text()` only text dates). This affected `X-RC-Last-Refresh-Time` (request, 40 values) and `x-revenuecat-request-time` (response, 87 values) in 9 of 10 `*.pub.har` files (A0 has neither); in versions 1.1.0–1.1.2 the difference between the header and `startedDateTime` equalled the file's random offset and so revealed it.
- Rule: in `headers`, `queryString` and `cookies` (request and response) a value that is entirely a 10-digit (s) or 13-digit (ms) string with an epoch in 2020–2035 is shifted by the same offset as `startedDateTime`, keeping the number of digits; a shifted `queryString` value is also replaced in `request.url`. Explicit list `EPOCH_HEADERS` (both RevenueCat headers); a header outside the list shifted by the general rule is marked in the report "[not in EPOCH_HEADERS - check]", and a listed header with a value outside the rule is listed as unchanged.
- Report: new sections "EPOCHS AS DIGIT STRINGS…" (number of shifted values per name) and "EPOCHS IN BODIES OUTSIDE THE SHIFT RULES" – numbers under keys outside `EPOCH_KEYS` and 10/13-digit strings in JSON bodies are only counted, not changed. In the 10 files both counters are 0 (13-digit fragments `sw_cache_key=` in paywall URLs are the paywall publication time on the producer's side and stay unchanged, as since 1.1.0).
- The 10 published files re-run: only these 127 values and the version number in `log.comment` changed; shift map unchanged. Test: `test_epoch_headers_shifted`.

### 1.1.2 – 2026-10-10
- With `--run-code` and `--shift-time` the shift map also gets the alias `RUN:<code>` with the same value, so that `shift_extract_times.py` 1.2 does not need the input file name. Output data unchanged (checked byte for byte for 10 files). Test: `test_run_code` extended.

### 1.1.1 – 2026-10-09
- Report: the sentence about the server address and `X-Amz-Cf-Pop` called both "in clear", although the POP is always masked; now "server address: in clear/removed; X-Amz-Cf-Pop: always masked". "user's decision" → "authors' decision". New option `--run-code CODE`: output files and "source:" in the comment named by the run code (until then done by hand); shift map key unchanged. Output data unchanged (only the version number in `log.comment` and the report differ). Test: `test_run_code`.

### 1.1.0 – 2026-10-09
- `--shift-time JSON_FILE`: a constant, random shift of all timestamps per file (3 to 30 whole days plus up to one day, forward or backward; for the exact range and its correction see 1.2.1), stored locally; ISO 8601, HTTP Date headers, `YYYY-MM-DD` dates, epochs in ms/µs/s under keys `*_ms`, `*_us`, `ts`, `timestamp`. `sw_cache_key` values (cache key of paywall resources) unchanged. New script `shift_extract_times.py` applies the same values to the PCAP extracts of the same run. Test: `test_time_shift`.

### 1.0.2 – 2026-10-09
- `X-Amz-Cf-Pop` always masked (`<<MASKED_CDN>>`), regardless of `--server`; values already masked with a `CDN_` label stay.

### 1.0.1 – 2026-10-09
- Fix: with `--server keep` the final check reported `serverIPAddress`/`_serverAddress` as raw IPv4 and did not write the `.pub.har` file. Fields deliberately in clear are now skipped in the check. Test: `test_server_keep_writes_file`.

### 1.0.0 – 2026-10-09
- First version: filter of studied hosts, removal of entries of other apps (bundle), removal of static resource bodies, masking of field groups (by default all except `server`), removal of the server address and of Proxyman client fields, raw pattern check, check report, `.sha256` file.

## shift_extract_times.py

### 1.7 – 2026-10-18
- `--ip-map JSON_FILE`: public server addresses in the CSV columns `ip.dst`, `ipv6.dst`, `dns.a`, `dns.aaaa` (several addresses separated by spaces) and `address`, and the remote end of every conversation in `*_tcp-conversations.txt`, are replaced with the labels `<<IP_n>>` of the map shared with `prepare_har_for_publication.py --server label` (new addresses are added to the map). Without the option the addresses stay in clear.
- `*_tcp-conversations.txt`: only conversations whose remote address is one of the addresses of the studied hosts in the same run (from `*_tls-connections.csv` and `*_dns-answers.csv` of the run) or whose both ends are local are kept; the number of removed conversations is written in a first comment line (T2: 11 removed, 35 kept). A run with this file but without its TLS/DNS CSV files is an error.
- Test: `test_extracts_ip_labels_and_tcp_conversations`.

### 1.6 – 2026-10-17
- `*_syn-quic.csv`: rows whose `host` column is empty (server addresses that no host of the report pointed to, i.e. connections of other apps and services on the device) are dropped; a row stays only if every name in its `host` column matches `SNI_KEEP` or `SNI_KEEP_RUN` of the run. An extract without the column `host` is an error. Published extracts: 930 rows dropped and 197 kept in 10 files (A0 42/9, S02 40/25, S01-install 173/0, S01 54/27, S11b 67/30, S17 48/29, S18 19/21, T3 44/26, T1 320/0, T2 123/30, dropped/kept); in T1 and S01-install only the header remains. The kept rows are byte-identical to 1.5; the other extracts are unchanged.
- Test: `test_syn_quic_rows_of_other_apps_dropped`; `test_shift_extracts_legacy_names` uses an input with the column `host`.

### 1.5 – 2026-10-17
- `*_sni-new.txt` is limited to the server names the report is about (`SNI_KEEP`: RevenueCat, Superwall, `superwalleditor.com`, `fonts.googleapis.com`, `fonts.gstatic.com`, Stripe, Sentry, `strongboxsafe.com`, DuckDuckGo, Have I Been Pwned, SimpleLogin), `proxyman.com` as the marker of the Proxyman for iOS tool, and per run `SNI_KEEP_RUN` (S18: `proton.me`, favicon of an entry of the test database). Until 1.4 the file listed every name absent from the background capture, including other apps and services on the devices and a CDN node name that indicates the country of the network exit. A first comment line gives the number of removed names. Published extracts: 82 names removed and 74 kept in 10 files; in T1 and S01-install no name remains. The CSV files are unchanged (byte-identical to 16 Oct 2026).
- Test: `test_sni_new_limited_to_report_hosts`.

### 1.4 – 2026-10-16
- Translated to English: file name, docstring, comments, messages, identifiers; command line parsed with argparse (same positional arguments: shift map, input directory, output directory).
- Input files are recognised as `<run code>_<suffix>`; known run codes and suffixes are listed in the script (`RUNS`, `SUFFIXES`). Output names are always `<run code>_<suffix>`: `_tls-connections.csv`, `_dns.csv`, `_dns-answers.csv`, `_syn-quic.csv`, `_sni-new.txt`, `_tcp-conversations.txt`. The script no longer contains capture file names.
- New option `--legacy-input JSON_FILE`: older input file names (capture names, non-English suffixes) and CSV column names are translated as described in the JSON file (not published).
- The CSV header of `*_syn-quic.csv` is written as `time_epoch,protocol,address,port,stream,host`.
- Shift map keys: `RUN:<code>` for runs with a HAR file, `PCAP:<code>` for T1 and T2.
- Two input files that map to the same output name are an error.
- Re-run on the 51 published extracts with the unchanged shift map: all data rows identical; only file names and the `*_syn-quic.csv` header changed.
- From 16 Oct 2026 the offsets this script draws for new captures (T1/T2 style, `PCAP:<code>`) come from `draw_shift()` of `prepare_har_for_publication.py` 1.2.1: at least 3 and less than 31 days. This file is unchanged; existing offsets are not changed.

### 1.3 – 2026-10-10
- Captures without input files are listed on stderr; if no capture has files, the script ends with an error before drawing offsets for T1/T2. Until then, after renaming files the script wrote nothing, printed "shift as …" and added new random `PCAP:T1/T2` offsets. The output lists the number of processed files per capture. Output for the then-current names unchanged. Test: `test_shift_extracts_missing_files`.

### 1.2 – 2026-10-10
- Map from capture to run code instead of the `*.anon.har` file name; offset from the key `RUN:<code>`. Reason: version 1.1 (copied to the publication) contained the original Proxyman export names with times, which the report deliberately omits (found while assembling the test site on 10 Oct). Output byte-identical.

### 1.1 – 2026-10-09
- CSV rows with a local network address (RFC 1918, IPv6 link-local `fe80::/10`, ULA `fc00::/7`) are dropped: link-local addresses in EUI-64 form contain the MAC of devices on the home network (found in the `*_syn-quic.csv` files of A0, S02, S11b and T2 – 37 rows in total). In `*_tcp-conversations.txt` local addresses are replaced with the label `<<LAN>>` (T2: 66 occurrences, including the phone's address). Constant `VERSION`. Found in the metadata review of 9 Oct 2026.

## extract_pcap.sh

### 2.1.0 – 2026-10-16
- Translated to English: file name, comments, messages, variables.
- Output files: `*_tls-connections.csv`, `*_dns.csv`, `*_dns-answers.csv`, `*_syn-quic.csv` (header `time_epoch,protocol,address,port,stream,host`), `*_sni-new.txt`; private: `*_sni-all_LOCAL.txt`, `*_tshark-errors_LOCAL.txt`; `*_strongbox.pcapng`.
- Environment variables: `TSHARK`, `PATTERN`, `OUTPUT_DIR`, `QUIC_ALL`.
- The script runs with `LC_ALL=C`: numbers with a decimal point regardless of system locale; `sort` and `comm` use byte order.
- Not yet run on a real capture (no tshark on the authors' publishing computer); the fake-tshark tests pass.

### 2.0.0 – 2026-10-09
- New `*_syn-quic.csv` (time, protocol, server address, port, stream, host from SNI/DNS). It contains TCP SYN without ACK and QUIC to port 443 with a long header; `QUIC_ALL=1` gives all QUIC packets to the server.
- New `*_dns-answers.csv` (A/AAAA addresses for hosts matching the pattern).
- CSV header written for an empty result, so the counter no longer shows `-1`.
- `tshark` errors go to a private errors file instead of `/dev/null`.
- Finding `tshark`: `$TSHARK`, Wireshark.app, `/opt/homebrew/bin`, `/usr/local/bin`, `PATH`; a missing program ends the run with a message.
- `-n` (no name resolution) and `-E occurrence=f` (one value per field).
- Output directory variable.
- Number of `cloudflare-ech.com` SNIs in the summary (measurement for the ECH hypothesis).
- Columns of `*_tls-connections.csv` and `*_dns.csv` unchanged from 1.x.

## clean_metadata.py

### 1.1, later on 2026-10-16 (no version change)
- A local variable renamed to `chunk_type` (an English word; no change in behaviour; `--check` output on `sources/` identical).

### 1.1 – 2026-10-16
- Translated to English: file name, docstring, messages, identifiers. Options: `--check`, `--clean`, `--title`, `--skip`, `--no-xattr`. Constant `VERSION`, shown in `--help` and in the summary line.
- `--check` on the published sources gives the same results as 1.0.

### 1.0 – 2026-10-09
- New script (no dependencies): `--check` lists metadata of PDF (Info dictionary, XMP), PNG (text chunks, eXIf, tIME) and extended file attributes; `--clean` overwrites Info fields with spaces of the same length (xref unchanged), rewrites PNG without metadata chunks, removes xattrs. Used on 9 Oct on the sources (5 PDF, 2 PNG).

## rerun_pipeline.sh

### 1.1 – 2026-10-16
- Translated to English. Environment variables: `OUTPUT_DIR` (default `./results`), `SALT` (default `~/.strongbox-salt`), `KNOWN`, `CLEAR_GROUPS` (default `model,server`), `PUB_GROUPS`. Output: `results/anon/`, `results/publication/`, `results/pcap-extracts/`, `results/SHA256SUMS_originals_LOCAL.txt`.
- New: the script stops if the salt file does not exist, instead of letting the pseudonymiser create a new salt.

### 1.0 – 2026-10-09
- Loop over the original HAR files: pseudonymisation and publication preparation with one salt; SHA-256 of each original checked before and after.

## findings_table.py

### 1.2 – 2026-10-17
- Events per cold start are counted in the window of the report: from 1 s before `app_launch` to 20 s after it, or up to the next `app_launch` if earlier (`--before`, `--after`; defaults 1 and 20). Up to 1.1 the window was from `app_launch` to 60 s after it or to 1 s before the next `app_launch`, which gives 37–64 events on the published files instead of the 41–73 of the report. With the new defaults the published files give 41–73 over the 20 starts with event content. The column header names the window. The request columns keep their window (5 s before `app_launch` to 60 s after it or to 1 s before the next one), now stated in the docstring.
- Test: `test_findings_event_window_matches_report`.

### 1.1 – 2026-10-16
- Translated to English and published. Runs on the published `*.pub.har` files; prints only counts, field and event names, labels and times. On `*.pub.har` the times are shifted per file. On the authors' unpublished `*.anon.har` files the output contains real times; that output is not published.

### 1.0 – 2026-10-09
- Table of facts for the findings of section 3 of the report (not published at that time).

## Tests (not published)

### 2026-10-18
- `test_tools.py` – 52 tests: 2 new (`--server label` with the shared address map; address labels and the filtering of `*_tcp-conversations.txt` in the extracts).

### 2026-10-17, later
- `test_tools.py` – 50 tests: 3 new (`sw_cache_key` in both scripts, filtering of `*_syn-quic.csv`), which fail with the scripts of 1.3.0/1.5/2.2.0.

### 2026-10-17
- `test_tools.py` – 47 tests: 41 earlier and 6 new for the audit of 17 Oct 2026 (CDN point of presence in `Server-Timing` in both scripts, bare date and time next to a shifted date-time forward and backward over midnight, event window of `findings_table.py`, filtering of `*_sni-new.txt`). The 6 new tests fail with the scripts of 16 Oct 2026.

### 2026-10-16
- `test_tools.py` – 41 tests after the correction of `draw_shift()` (new `test_draw_shift_range`); before it, 40 tests (36 earlier, translated, and 4 new: `pseudonymised_comment()`, `--legacy-input` of `prepare_har_for_publication.py` against the archived 2.0.2 pseudonymiser, `--legacy-input` of `shift_extract_times.py` with a duplicate-name error, `findings_table.py` on a `.pub.har` file). `make_synthetic_har.py` with English fictional values.

### 2026-10-09
- Synthetic HAR generator with fictional values; 29 tests (pseudonymisation, determinism, new field groups, superwalleditor, long digits, `--known`, collisions, publication, `extract_pcap.sh` with a fake `tshark`).
