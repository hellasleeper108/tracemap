# tracemap

Like ol' school traceroute — but on a map. Watches your machine's live network connections and plots every peer IP on an interactive world map, in real time.

![Dark world map showing arc lines from host to connected IPs with a sidebar listing connection details](.github/screenshot.png)

## What it does

- Reads all established TCP connections from `ss`
- Filters to public IPs only, geolocates them in batch via [ip-api.com](http://ip-api.com)
- Serves a dark Leaflet.js map at `localhost:9999`
- Draws animated great-circle arc lines from your host to every peer
- Color-codes connections by process (Brave, Python, etc.)
- Sidebar lists each IP with city, country, org/ISP, and the process that owns the socket
- Click any sidebar row to fly to it on the map
- Auto-refreshes every 5 seconds — new connections appear, dropped ones disappear

## Requirements

- Python 3.x (stdlib only — no pip installs)
- `ss` (part of `iproute2`, standard on Linux)
- Internet access (for ip-api.com geolocation + Leaflet CDN on first load)

## Usage

```bash
python3 tracemap.py
```

Opens `http://localhost:9999` in your browser automatically.

To see process names for connections owned by other users (system services, etc.), run with sudo:

```bash
sudo python3 tracemap.py
```

Press `Ctrl+C` to stop.

## How it works

```
ss -tnp state established
    │
    ▼
Filter private/loopback IPs
    │
    ▼
Batch geolocate via ip-api.com (cached, max 100/request)
    │
    ▼
/api/connections  ◄── browser polls every 5s
    │
    ▼
Leaflet.js renders arcs + markers on dark CartoDB tiles
```

The backend is pure Python stdlib — no Flask, no dependencies. The frontend is a single self-contained HTML page served inline.

## Geolocation limits

ip-api.com free tier allows 45 requests/minute. tracemap batches all new IPs into a single request per poll cycle, so you'd need to see 4,500 new unique IPs per minute to hit the limit — well beyond normal usage.

## License

MIT
