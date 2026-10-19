# Extracts from the packet captures (rvictl + Wireshark)

Only extracts are published, without packet contents:

- `*_tls-connections.csv`: TLS ClientHello – time, SNI, server address, port, stream number;
- `*_dns.csv` and `*_dns-answers.csv`: DNS queries and answers for hosts matching the pattern;
- `*_syn-quic.csv`: starts of TCP connections (SYN) and QUIC packets to port 443 to the hosts named in the report – time, protocol, server address, port, stream number, and in the column `host` the name(s) of the host that pointed to that address in the same capture (SNI of a ClientHello or a DNS answer; several names separated by spaces if they share the address). The capture also contains such packets of other apps and services on the device; those rows (an address that no host of the report pointed to, with an empty `host` column) were removed at publication. In T1 and S01-install no row remains. The QUIC rows are QUIC packets with a long header, not connections: one QUIC connection can appear in several rows with the same stream number;
- `*_sni-new.txt`: TLS server names of the run absent from the background capture, **limited to the hosts named in the report** (RevenueCat, Superwall, the paywall resource hosts, Stripe, Sentry, Strongbox, DuckDuckGo, Have I Been Pwned, SimpleLogin), `proxyman.com` (kept as a marker of the Proxyman for iOS tool; it appears in A0, S02, S17 and S18) and, in S18, `proton.me` (favicon of an entry of the test database). The names of other apps and services on the devices were removed; the first line (`#`) gives their number. In T1 and S01-install no name remains;
- `T2_tcp-conversations.txt`: TCP connection statistics (`tshark -z conv,tcp`), relative times, **limited to the conversations with the server addresses of the hosts named in the report** (addresses taken from `T2_tls-connections.csv` and `T2_dns-answers.csv`) and to conversations inside the local network; the first line gives the number of conversations removed (11, with servers of other apps and services on the device; 35 kept).

Host pattern: superwall, revenuecat, sentry, strongbox, duckduckgo, pwned, simplelogin, gstatic, googleapis.

File names start with the run code. The files were produced by `extract_pcap.sh` 2.0.0 (the version before the renaming of 16 October 2026); `tools/shift_extract_times.py` gave them the file and column names that `tools/extract_pcap.sh` 2.1.0 writes (data rows unchanged) and, from version 1.5, limited `*_sni-new.txt` and, from version 1.6, `*_syn-quic.csv` as described above; from version 1.7 it limits `T2_tcp-conversations.txt` as described above and replaces server addresses with labels. Which capture served as the background reference for `*_sni-new.txt` was not recorded in the extracts.

Timestamps (`frame.time_epoch`, `time_epoch`) are shifted by the same constant value as the HAR file of the same run (`tools/shift_extract_times.py`); T1 and T2 have their own offsets. The CSV files do not record the source address (the phone). Rows with local network addresses (RFC 1918, IPv6 link-local and ULA) are dropped at publication; in `T2_tcp-conversations.txt` the phone's address and other local addresses are replaced with the label `<<LAN>>`. Public server addresses (columns `ip.dst`, `ipv6.dst`, `dns.a`, `dns.aaaa`, `address`, and the remote end in `T2_tcp-conversations.txt`) are replaced with labels `<<IP_n>>` from the same map as the `serverIPAddress` field of the HAR files: the same address gives the same label in every published file, so addresses can still be compared between hosts, runs and file types.

`T2_tcp-conversations.txt` was produced with a locale that uses a decimal comma: a comma inside a number marks the decimal part (e.g. `591,5516` = 591.5516 s), and a space separates thousands (`7 616 bytes`). `extract_pcap.sh` 2.1.0 runs `tshark` with `LC_ALL=C`; the published file has not been regenerated with it.

| Run code | Device | HAR file of the same run | Notes |
|---|---|---|---|
| A0 | A | A0.pub.har | start, 1.5 min on the home screen |
| S02 | A | S02.pub.har | 3 cold starts |
| S01-install | B | – | installation phase before S01; no SNI of the studied hosts |
| S01 | B | S01.pub.har | first launch |
| S11b | A | S11b.pub.har | crash reporting option off/on |
| S17 | B | S17.pub.har | fresh installation |
| S18 | B | S18.pub.har | database unlock, favicons |
| T1 | B | – | app closed, 5 min |
| T2 | B | – | 3 cold starts without Proxyman |
| T3 | B | T3.pub.har | 3 cycles with unlock |

No packet capture: A5 (A5.pub.har), A8 (A8.pub.har), C8 (C8.pub.har). The published HAR files and extracts carry run codes (A0 … C8); the names of the Proxyman exports and of the capture files are omitted because they contain export times or working titles.
