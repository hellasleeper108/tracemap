# tracemap — Phase 4 Roadmap

Phase 4 is a set of five optional feature groups that each stand alone and can be shipped independently. They extend the already-complete Phases 1–3 without requiring changes to existing APIs or data formats.

---

## 4.1 Persistence & Reporting

**Goal:** Let operators export data and receive automated summaries.

### 4.1.1 CSV / JSON Export
- `GET /api/export/connections?format=csv|json&since=<ts>` streams the `connections_log` table
- `GET /api/export/threats?format=csv|json` dumps `threat_cache` + `threat_sources`
- Export button in the stats dashboard; respects active filters
- Chunked streaming response (no full-table memory load)

### 4.1.2 Daily Threat Summary
- New `report.py` module; `summary_loop()` thread fires at local midnight
- Aggregates last 24 h: unique IPs, top countries, new malicious IPs, top processes
- Writes plaintext/JSON to `~/.local/share/tracemap/reports/YYYY-MM-DD.json`
- Exposed at `GET /api/reports` (list) and `GET /api/reports/<date>`
- `--no-reports` flag to disable

### 4.1.3 IP Notes / Tags
- New `notes` table: `ip TEXT PK, note TEXT, updated_at INTEGER`
- `GET /api/notes/<ip>`, `POST /api/notes/<ip>` (body: `{note}`)
- Pencil icon in sidebar row opens an inline textarea; saved on blur
- Note text shown in popup and sidebar below the org line
- Notes searchable via the existing search bar

---

## 4.2 Geo Enrichment

**Goal:** Faster, richer, offline-capable location data.

### 4.2.1 Offline MaxMind GeoLite2
- `geo.py` detects a local `GeoLite2-City.mmdb` (path via `--geoip-db`)
- Uses `struct`-based binary reader (stdlib only, no `geoip2` package) for IP→lat/lon/country/city
- Falls back to ip-api.com when no local DB is present
- `GET /api/geo/status` reports which source is active and DB age

### 4.2.2 ASN Lookup
- `GeoLite2-ASN.mmdb` optional alongside city DB
- Adds `asn` and `as_name` fields to each connection
- Displayed as a secondary org line in sidebar when present
- `/api/stats` includes `top_asns` in the same style as `top_orgs`

### 4.2.3 Country Flag Emoji
- `geo.py` helper `flag(cc)` converts ISO-3166 country code to regional-indicator emoji
- Flag rendered before country name in sidebar rows and map popup
- No new dependency — pure Unicode arithmetic

---

## 4.3 Notification Channels

**Goal:** Route alerts to Slack, webhooks, and email, not only desktop notifications.

Current alert `action` field accepts `{"type":"desktop"}`. Phase 4.3 adds three new types.

### 4.3.1 Webhook Action
- `action = {"type":"webhook", "url":"https://…", "method":"POST"}`
- `alerts.py` `_dispatch_webhook()`: stdlib `urllib.request`, JSON body, 5 s timeout
- Retry once on network error; log failure but do not crash the alert loop

### 4.3.2 Slack Action
- `action = {"type":"slack", "url":"https://hooks.slack.com/…"}`
- Formats a Slack Block Kit message with IP, rule type, score, and a direct link
- Implemented as a thin wrapper over the webhook dispatcher above

### 4.3.3 Email Action
- `action = {"type":"email", "to":"user@example.com"}`
- SMTP config in `tracemap.py` args: `--smtp-host`, `--smtp-port`, `--smtp-user`, `--smtp-pass`, `--smtp-from`
- `alerts.py` `_dispatch_email()` uses `smtplib` + `email.mime.text` (stdlib)
- Gracefully skips if SMTP not configured

### UI
- Rules modal shows action type badge next to each rule
- `Add Rule` form gains an `action` dropdown: Desktop / Webhook / Slack / Email
- Additional input fields appear per action type (URL, recipient)

---

## 4.4 Performance & Retention

**Goal:** Keep the database lean and queries fast over long-running deployments.

### 4.4.1 Connection Pool
- Replace per-query `_connect()` open/close with a `threading.local()` pool
- One connection per thread, re-used across queries; closed on thread exit
- Eliminates repeated WAL checkpoint overhead on busy poll cycles

### 4.4.2 Configurable History Retention
- `--history-days N` (default: 30) stored in DB as a config key
- `db.prune_old_connections(days)` deletes `connections_log` rows older than N days
- Runs at startup and once daily via a lightweight `prune_loop()` thread
- `GET /api/db/stats` returns `{row_counts, db_size_bytes, oldest_entry}`

### 4.4.3 Hourly Aggregation
- `db.aggregate_hour(hour_ts)` collapses `connections_log` rows older than 24 h into a summary table `connection_hourly (hour_ts, ip, count)`
- Timeline query uses `connection_hourly` for buckets older than 24 h; raw log for recent
- Reduces table size by ~95 % for long-running instances with many connections

---

## 4.5 Packaging

**Goal:** Install and deploy tracemap like a proper tool, not a cloned repo.

### 4.5.1 `pyproject.toml`
- PEP 517 build with `[project.scripts] tracemap = "tracemap:main"`
- `pip install .` or `pip install -e .` installs a `tracemap` binary
- Minimum Python 3.10 declared; no runtime dependencies

### 4.5.2 systemd Service Unit
- `packaging/tracemap.service` template with `%h` home dir expansion
- `ExecStart=/usr/local/bin/tracemap --port 9999`
- `install` Makefile target copies unit to `~/.config/systemd/user/`; `systemctl --user enable --now tracemap`

### 4.5.3 Docker Image (Hub mode)
- `Dockerfile`: `python:3.12-slim`, copies source, `EXPOSE 9999`, `CMD ["python3","tracemap.py","--agent"]`
- `.dockerignore` excludes `*.db`, `__pycache__`, `.claude`
- `docker-compose.yml` example: one hub + two agent containers on a bridge network
- `README.md` hub-mode section updated with Docker instructions

### 4.5.4 Install Script
- `install.sh`: checks Python ≥ 3.10, copies files to `~/.local/lib/tracemap`, symlinks binary to `~/.local/bin/tracemap`
- Optional `--systemd` flag wires up the service unit
- Uninstall: `tracemap --uninstall`

---

## Implementation order (suggested)

| Order | Feature | Effort | Value |
|-------|---------|--------|-------|
| 1 | 4.1.3 IP Notes | Low | High |
| 2 | 4.2.3 Country flags | Low | Medium |
| 3 | 4.4.1 Connection pool | Low | High |
| 4 | 4.4.2 Retention / prune | Low | High |
| 5 | 4.1.1 CSV/JSON export | Medium | High |
| 6 | 4.3.1 Webhook alerts | Medium | High |
| 7 | 4.3.2 Slack alerts | Low | High |
| 8 | 4.3.3 Email alerts | Medium | Medium |
| 9 | 4.5.1 pyproject.toml | Low | Medium |
| 10 | 4.5.2 systemd unit | Low | Medium |
| 11 | 4.2.3 MaxMind offline | Medium | High |
| 12 | 4.4.3 Hourly aggregation | Medium | Medium |
| 13 | 4.1.2 Daily reports | Medium | Medium |
| 14 | 4.2.2 ASN lookup | Low | Medium |
| 15 | 4.5.3 Docker image | Low | Medium |
| 16 | 4.5.4 Install script | Medium | Low |
