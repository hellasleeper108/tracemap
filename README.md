# tracemap

Live network connection visualizer that plots active TCP connections on a world map with threat intelligence, alert rules, and multi-host monitoring.

## Features

**Live Map**
- Animated great-circle arcs from host to remote IPs
- Process color-coding (each process gets a distinct arc color)
- Click an IP to fly-to and open the detail panel
- Real-time sidebar with connection list, search, and filtering

**Threat Intelligence**
- AbuseIPDB and VirusTotal scoring per IP (requires API keys via env vars)
- Tor exit-node detection (auto-refreshed from torproject.org)
- VPN provider detection via org/ISP name heuristics
- Composite abuse score with red/amber/green badge in the UI

**Alert Rules**
- Configurable rules triggered by country, threat score, new IP, or new process
- Actions: desktop notification, webhook POST, Slack, or email
- Full CRUD via `/api/alerts/rules` or the simpler `/api/rules`

**Bandwidth Tracking**
- Live bytes-in / bytes-out per connection sourced from `ss` extended output
- Per-connection bps gauges and top-bandwidth-users summary in `/api/stats`

**Docker Awareness**
- Detects Docker container IDs via `/proc/<pid>/cgroup`
- Queries the Docker socket to resolve container names
- Container name badge shown for each dockerised process

**Firewall Integration**
- Block any IP with one click: inserts an `iptables OUTPUT DROP` rule
- Blocked IPs panel; unblock via the same UI or `DELETE /api/block/{ip}`

**Multi-Host Monitoring (Hub / Agent)**
- Run agents on remote hosts with `--agent` (binds to 0.0.0.0, optional API key)
- Central hub with `--hub agents.json` polls agents and merges their connections
- Each remote connection is tagged with its `agent_label`

**IP Notes**
- Annotate any IP with a persistent free-text note
- `GET /api/notes/{ip}` / `POST /api/notes/{ip}` stored in SQLite

**Data Export**
- `GET /api/export/connections?format=json` — full connection log as JSON
- `GET /api/export/connections?format=csv` — CSV with `ip,port,process,seen_at`
- `GET /api/export/threats?format=json` — threat cache as JSON

**Daily Reports**
- Midnight JSON summaries written to `~/.local/share/tracemap/reports/`
- Listed via `GET /api/reports`

**Geo Enrichment**
- Online geolocation via ip-api.com (batched, 7-day DB cache)
- Country, city, lat/lon, ASN/org, ISP per IP
- Country flag emoji in the connection list

**History & Timeline Playback**
- Every connection is logged to SQLite with a timestamp
- `GET /api/history/timeline` — hourly unique-IP counts for the past 24 h
- `GET /api/connections/at/{ts}` — replay connections near any past Unix timestamp
- Per-IP history via `GET /api/history/{ip}`

## Requirements

- Python 3.10+ (stdlib only — zero pip dependencies)
- Linux (uses `ss` from iproute2)
- iproute2 (`ss` command)
- Optional: root / `CAP_NET_ADMIN` for iptables blocking

## Quick Start

```bash
git clone https://github.com/hellasleeper108/tracemap.git
cd tracemap
python3 tracemap.py
# open http://localhost:9999
```

## CLI Reference

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port` | int | `9999` | HTTP server port |
| `--db` | PATH | `~/.local/share/tracemap/tracemap.db` | SQLite database path |
| `--alerts-file` | PATH | — | Load alert rules from a JSON file at startup |
| `--agent` | flag | — | Agent mode: bind to 0.0.0.0, enable API-key auth |
| `--agent-key` | KEY | — | API key required in `X-Agent-Key` header (agent mode) |
| `--hub` | PATH | — | Hub mode: JSON file listing remote agents to poll |

## API Reference

| Method | Path | Description | Response |
|--------|------|-------------|----------|
| GET | `/` | Map UI | HTML |
| GET | `/api/connections` | Live connection snapshot | `{connections:[…], host:{…}, last_updated, threat_enabled}` |
| GET | `/api/connections/at/{ts}` | Historical connections near timestamp | `[{ip,port,process,…}]` |
| GET | `/api/stats` | Aggregated statistics | `{total, unique_ips, top_countries, top_orgs, threat_summary, bw_total_recv, …}` |
| GET | `/api/history/timeline` | Hourly unique-IP counts (last 24 h) | `[{hour_ts, count}]` |
| GET | `/api/timeline` | Alias for `/api/history/timeline` | same |
| GET | `/api/history/{ip}` | Per-IP connection history | `{ip, first_seen, events:[…]}` |
| GET | `/api/threat/{ip}` | Threat cache entry | `{ip, abuse_score, reports, checked_at}` |
| GET | `/api/threats` | All threat cache entries | `[{ip, abuse_score, …}]` |
| GET | `/api/traceroute/{ip}` | Cached traceroute result | `{status, hops:[…]}` |
| POST | `/api/traceroute/{ip}` | Trigger async traceroute | `{status}` |
| GET | `/api/alerts/rules` | All alert rules | `[{id, rule_type, condition, action, enabled}]` |
| POST | `/api/alerts/rules` | Create rule (legacy schema) | `{id, rule_type, …}` |
| PATCH | `/api/alerts/rules/{id}` | Update rule fields | `{id, …}` |
| DELETE | `/api/alerts/rules/{id}` | Delete rule | `{ok:true}` |
| GET | `/api/alerts/events` | Alert event history | `[{id, rule_type, ip, msg, ts}]` |
| GET | `/api/alerts/pending` | Unsent events (marks sent) | `[…]` |
| GET | `/api/alerts/unread` | Unread count | `{count}` |
| POST | `/api/alerts/read` | Mark alerts read | `{ok:true}` |
| GET | `/api/rules` | Alert rules (simple schema) | `[{id, rule_type, …}]` |
| POST | `/api/rules` | Create rule `{name,type,value,action}` | `{id,…}` (201) |
| GET | `/api/notes/{ip}` | Get IP annotation | `{ip, note}` |
| POST | `/api/notes/{ip}` | Save IP annotation `{note}` | `{ok:true}` |
| GET | `/api/export/connections` | Export log (`?format=json\|csv`) | list or CSV |
| GET | `/api/export/threats` | Export threats (`?format=json`) | list |
| GET | `/api/reports` | List daily report files | `[{file, date}]` |
| GET | `/api/db/stats` | DB row counts and file size | `{row_counts, db_size_bytes}` |
| GET | `/api/geo/status` | Geo lookup source | `{source}` |
| GET | `/api/firewall/status` | Firewall availability and blocked list | `{available, blocked:[…]}` |
| GET | `/api/blocked` | Blocked IPs | `[{ip, blocked_at}]` |
| POST | `/api/block/{ip}` | Block an IP via iptables | `{ok, msg}` |
| DELETE | `/api/block/{ip}` | Unblock an IP | `{ok, msg}` |
| GET | `/api/agents` | Hub agent status | `[{url, label, last_ok, error}]` |

## Alert Rules

**Simple schema** (`POST /api/rules`):
```json
{
  "name":   "Block China",
  "type":   "country",
  "value":  "CN",
  "action": {"type": "desktop"}
}
```

**Legacy schema** (`POST /api/alerts/rules`):
```json
{
  "rule_type":  "threat_score",
  "condition":  {"min_score": 75},
  "action":     {"type": "webhook", "url": "https://hooks.example.com/alert"}
}
```

**Rule types:** `country`, `threat_score`, `new_ip`, `new_process`

**Action types:**

| Type | Extra fields | Description |
|------|-------------|-------------|
| `desktop` | — | Browser desktop notification |
| `webhook` | `url` | HTTP POST JSON payload |
| `slack` | `url` | Slack Incoming Webhook |
| `email` | `to`, `subject` | SMTP email (requires SMTP env vars) |

## Hub / Agent Mode

Run an agent on each monitored host:
```bash
python3 tracemap.py --agent --agent-key mysecret --port 9998
```

Create `agents.json` listing remote agents:
```json
[
  {"url": "http://host1:9998", "key": "mysecret", "label": "web-01"},
  {"url": "http://host2:9998", "key": "mysecret", "label": "db-01"}
]
```

Start the hub:
```bash
python3 tracemap.py --hub agents.json
```

**Docker Compose example:**
```yaml
version: "3.9"
services:
  hub:
    build: .
    command: python3 tracemap.py --hub /etc/tracemap/agents.json --port 9999
    ports: ["9999:9999"]
    volumes:
      - ./agents.json:/etc/tracemap/agents.json

  agent-web:
    build: .
    command: python3 tracemap.py --agent --agent-key secret --port 9998
    network_mode: host
```

## Offline GeoIP

Offline MaxMind GeoLite2 support is planned for Phase 5. The current release uses ip-api.com (free tier, 45 req/min, batched — sufficient for typical usage).

## Installation

**1. Run directly**
```bash
python3 tracemap.py
```

**2. pip install**
```bash
pip install .
tracemap
```

## Docker

```yaml
version: "3.9"
services:
  tracemap:
    build: .
    command: python3 tracemap.py --port 9999
    ports: ["9999:9999"]
    network_mode: host
    volumes:
      - tracemap_data:/root/.local/share/tracemap
volumes:
  tracemap_data:
```

## License

MIT
