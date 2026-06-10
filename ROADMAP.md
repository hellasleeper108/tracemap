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

## Phase 5 — Planned Features

| Feature | Description | Effort |
|---------|-------------|--------|
| **PCAP Capture** | Capture raw packets per connection using `tcpdump`/`libpcap`; download `.pcap` files from the UI | High |
| **IPv6 Visualisation** | Full IPv6 support in arc rendering, geo lookup, and firewall rules | Medium |
| **REST API Key Auth** | Optional Bearer-token authentication for all API endpoints (not just agent mode) | Low |
| **WebSocket Push** | Replace 5-second polling with a WebSocket feed; sub-second UI updates | Medium |
| **Geo Heatmap Overlay** | Density heatmap layer showing connection frequency by country/region | Medium |
| **Connection Graph / Topology View** | Force-directed graph showing host ↔ IP ↔ process relationships | High |
| **Prometheus `/metrics` Endpoint** | Expose connection counts, threat scores, bandwidth, and alert rates as Prometheus metrics | Low |
| **TLS Fingerprinting** | Extract JA3/JA3S fingerprints from TLS handshakes to identify client/server software | High |
| **Offline MaxMind GeoLite2** | Support `--geoip-db` / `--geoip-asn` for air-gapped deployments using MaxMind `.mmdb` files | Medium |
| **History Retention Config** | `--history-days` flag to prune old connection logs; hourly aggregation to reduce DB size | Low |
