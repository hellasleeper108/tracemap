# tracemap Roadmap

## ✓ Phase 1 — Core Map (v0.1)

- Live TCP connection polling via `ss`
- Batch geolocation via ip-api.com with DB cache
- Animated great-circle arcs on a dark Leaflet.js map
- Process color-coding and click-to-fly sidebar
- SQLite persistence, DNS cache, auto-refresh

## ✓ Phase 2 — Threat Intelligence & Alerts (v0.2)

- AbuseIPDB threat scoring with red/amber/green badges
- VirusTotal multi-source scoring
- Tor exit-node detection (torproject.org bulk list)
- VPN provider heuristics via org/ISP name matching
- Configurable alert rules engine (country, threat score, new IP, new process)
- Alert actions: desktop notification, webhook, Slack, email
- Timeline playback: hourly connection history, scrub to any timestamp

## ✓ Phase 3 — Bandwidth, Docker & Firewall (v0.3)

- Live bandwidth tracking (bytes-in/out per connection via `ss -i`)
- Docker container detection via `/proc/<pid>/cgroup` + Docker socket
- Container name badges in the UI
- iptables firewall integration: block / unblock IPs from the UI
- Blocked IPs panel
- Multi-host monitoring: Hub aggregates remote Agents over HTTP with API-key auth

## ✓ Phase 4 — Polish & Export (v0.4)

- IP Notes: per-IP free-text annotations stored in SQLite
- Data export: JSON and CSV for connections and threats
- Daily report listing (`/api/reports`)
- Database statistics endpoint (`/api/db/stats`)
- Geo status endpoint (`/api/geo/status`)
- Full integration test suite (18 smoke checks)
- Complete README and API reference

---

## ✓ Phase 5 — Advanced Features (v0.5)

- **PCAP Capture** — `tcpdump`-based per-IP packet capture; download `.pcap` files from the UI via `/api/pcap/{ip}`
- **IPv6 Support** — Full IPv6 in geo lookup, firewall (`ip6tables`), and arc rendering
- **REST API Key Auth** — Optional Bearer-token (`--api-key`) on all endpoints; `/metrics` exempt for Prometheus scrapers
- **WebSocket Push** — `/ws/connections` feed replacing 5-second polling; falls back to polling automatically
- **Geo Heatmap Overlay** — Density heatmap layer toggled from the map toolbar
- **Connection Graph / Topology View** — Force-directed SVG graph showing host ↔ process ↔ IP relationships
- **Prometheus `/metrics` Endpoint** — Connection counts, threat scores, bandwidth, alert rates as Prometheus metrics
- **TLS Fingerprinting** — `/api/tls/{ip}` extracts TLS version, cipher, RTT from `/proc/net/tcp*` and `ss`; no root required
- **Offline MaxMind GeoLite2** — `--geoip-db` / `--geoip-asn` flags for air-gapped `.mmdb` lookups
- **History Retention Config** — `--history-days` flag prunes old logs; background pruning thread runs hourly

---

## Status: v0.5 — Project complete
