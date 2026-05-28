#!/usr/bin/env python3
"""
tracemap.py — Live network connection visualizer on a world map.
Run with: python3 tracemap.py
Then open http://localhost:9999 in a browser.
"""

import json
import re
import subprocess
import ipaddress
import threading
import time
import webbrowser
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 9999
REFRESH_INTERVAL = 5  # seconds between connection polls
GEO_BATCH_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,org,isp"
HOST_GEO_URL  = "http://ip-api.com/json/?fields=status,query,country,city,lat,lon,org"


# ── Data collection ────────────────────────────────────────────────────────────

def parse_peer(addr_port: str):
    """Return (ip, port) from ss peer column, handling IPv4 and IPv6."""
    if addr_port.startswith("["):
        # IPv6 bracketed: [::1]:80
        m = re.match(r"\[(.+)\]:(\d+)", addr_port)
        if m:
            return m.group(1), m.group(2)
    else:
        # IPv4 or bare IPv6: 1.2.3.4:443
        idx = addr_port.rfind(":")
        if idx != -1:
            return addr_port[:idx], addr_port[idx + 1:]
    return None, None


def extract_process(proc_field: str) -> str:
    """Pull process name from ss users:(("name",pid=N,fd=N)) field."""
    m = re.search(r'users:\(\("([^"]+)"', proc_field)
    return m.group(1) if m else ""


def is_public(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False


def get_connections() -> list[dict]:
    """Return list of {ip, port, process, local_port} for established connections."""
    try:
        result = subprocess.run(
            ["ss", "-tnp", "state", "established"],
            capture_output=True, text=True, timeout=5
        )
    except Exception:
        return []

    conns = []
    for line in result.stdout.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 4:
            continue
        local_col  = parts[2]
        peer_col   = parts[3]
        proc_field = " ".join(parts[4:]) if len(parts) > 4 else ""

        ip, port = parse_peer(peer_col)
        if not ip or not is_public(ip):
            continue

        _, local_port = parse_peer(local_col)
        conns.append({
            "ip":         ip,
            "port":       port,
            "local_port": local_port or "",
            "process":    extract_process(proc_field),
        })

    # Deduplicate by (ip, port) keeping the first occurrence
    seen = set()
    unique = []
    for c in conns:
        key = (c["ip"], c["port"])
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def geolocate(ips: list[str]) -> dict[str, dict]:
    """Batch-geolocate a list of IPs. Returns {ip: geo_dict}."""
    if not ips:
        return {}
    payload = json.dumps([{"query": ip} for ip in ips[:100]]).encode()
    req = urllib.request.Request(
        GEO_BATCH_URL, data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            results = json.loads(resp.read())
        return {r["query"]: r for r in results if r.get("status") == "success"}
    except urllib.error.URLError as e:
        print(f"[geo] batch request failed: {e}")
        return {}


def get_host_geo() -> dict:
    try:
        with urllib.request.urlopen(HOST_GEO_URL, timeout=8) as resp:
            data = json.loads(resp.read())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {"lat": 0, "lon": 0, "query": "unknown", "city": "Unknown", "country": ""}


# ── Shared state ───────────────────────────────────────────────────────────────

_lock          = threading.Lock()
_geo_cache: dict[str, dict] = {}
_connections:  list[dict]   = []
_host_geo:     dict         = {}
_last_updated: float        = 0.0


def updater_loop():
    global _connections, _host_geo, _last_updated

    # Get host location once
    host = get_host_geo()
    with _lock:
        _host_geo = host

    while True:
        conns = get_connections()

        # Find IPs not yet in cache
        with _lock:
            unknown = [c["ip"] for c in conns if c["ip"] not in _geo_cache]

        if unknown:
            new_geo = geolocate(list(dict.fromkeys(unknown)))  # deduplicated
            with _lock:
                _geo_cache.update(new_geo)

        # Enrich connections with geo data
        enriched = []
        with _lock:
            for c in conns:
                geo = _geo_cache.get(c["ip"])
                if geo:
                    enriched.append({**c, **geo})
                # Skip IPs with no geo yet (will appear next cycle)

        with _lock:
            _connections  = enriched
            _last_updated = time.time()

        time.sleep(REFRESH_INTERVAL)


# ── HTML frontend ──────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Network Trace Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  background: #0d1117;
  color: #c9d1d9;
  display: flex;
  height: 100vh;
  overflow: hidden;
}
#map { flex: 1; }
#sidebar {
  width: 300px;
  background: #161b22;
  border-left: 1px solid #30363d;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
#header {
  padding: 14px 16px 12px;
  border-bottom: 1px solid #30363d;
  flex-shrink: 0;
}
#header h1 {
  font-size: 11px;
  letter-spacing: 3px;
  text-transform: uppercase;
  color: #58a6ff;
  margin-bottom: 4px;
}
#stats { font-size: 11px; color: #8b949e; }
#host-info {
  padding: 10px 16px;
  border-bottom: 1px solid #30363d;
  font-size: 11px;
  color: #8b949e;
  flex-shrink: 0;
}
#host-info .label { color: #3fb950; font-weight: bold; }
#conn-list { flex: 1; overflow-y: auto; }
.conn {
  padding: 9px 16px;
  border-bottom: 1px solid #1c2128;
  cursor: pointer;
  transition: background 0.15s;
}
.conn:hover { background: #1c2128; }
.conn .ip   { font-size: 12px; color: #79c0ff; font-weight: bold; }
.conn .loc  { font-size: 11px; color: #8b949e; margin-top: 2px; }
.conn .proc { font-size: 10px; color: #3fb950; margin-top: 2px; }
.conn .org  { font-size: 10px; color: #d2a8ff; margin-top: 1px;
              white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
#footer {
  padding: 8px 16px;
  border-top: 1px solid #30363d;
  font-size: 10px;
  color: #484f58;
  flex-shrink: 0;
}
::-webkit-scrollbar { width: 3px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }

/* Leaflet popup dark theme */
.leaflet-popup-content-wrapper {
  background: #161b22;
  color: #c9d1d9;
  border: 1px solid #30363d;
  border-radius: 6px;
  font-family: inherit;
  font-size: 12px;
  box-shadow: 0 4px 16px rgba(0,0,0,0.6);
}
.leaflet-popup-tip { background: #161b22; }
.leaflet-popup-content b { color: #58a6ff; }
.leaflet-popup-close-button { color: #8b949e !important; }
</style>
</head>
<body>
<div id="map"></div>
<div id="sidebar">
  <div id="header">
    <h1>Network Trace Map</h1>
    <div id="stats">Connecting&hellip;</div>
  </div>
  <div id="host-info"><span class="label">HOST</span> &mdash; loading&hellip;</div>
  <div id="conn-list"></div>
  <div id="footer">Refreshes every 5s &bull; ip-api.com geolocation</div>
</div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const map = L.map('map', { center: [20, 0], zoom: 2, zoomControl: true, attributionControl: false });
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 19 }).addTo(map);

// Host marker style
const hostIcon = L.divIcon({
  className: '',
  html: '<div style="width:14px;height:14px;background:#3fb950;border:2px solid #fff;border-radius:50%;box-shadow:0 0 8px #3fb950;"></div>',
  iconSize: [14, 14], iconAnchor: [7, 7]
});

const peerIcon = (color='#ff7b72') => L.divIcon({
  className: '',
  html: `<div style="width:10px;height:10px;background:${color};border:1px solid rgba(255,255,255,0.4);border-radius:50%;box-shadow:0 0 6px ${color};"></div>`,
  iconSize: [10, 10], iconAnchor: [5, 5]
});

let hostMarker = null, hostLatLng = null;
let peerMarkers = {};   // ip → marker
let arcLines = [];

function gcArc(from, to, steps=60) {
  // Approximate great-circle arc with a vertical bulge
  const pts = [];
  const midLat  = (from[0] + to[0]) / 2;
  const midLon  = (from[1] + to[1]) / 2;
  const dist    = Math.hypot(to[0]-from[0], to[1]-from[1]);
  const bulge   = Math.min(dist * 0.25, 30);  // cap at 30°

  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const lat = from[0] + (to[0]-from[0])*t + bulge * Math.sin(Math.PI*t);
    const lon = from[1] + (to[1]-from[1])*t;
    pts.push([lat, lon]);
  }
  return pts;
}

function popupHtml(c) {
  return `<b>${c.ip}</b><br>
    <span style="color:#8b949e">:${c.port}</span><br>
    ${c.city ? c.city + ', ' : ''}${c.country || '?'}<br>
    ${c.org || c.isp || ''}
    ${c.process ? '<br><span style="color:#3fb950">⚙ ' + c.process + '</span>' : ''}`;
}

async function refresh() {
  let data;
  try {
    const r = await fetch('/api/connections');
    data = await r.json();
  } catch(e) { return; }

  // Host
  if (data.host && data.host.lat && !hostMarker) {
    hostLatLng = [data.host.lat, data.host.lon];
    hostMarker = L.marker(hostLatLng, { icon: hostIcon, zIndexOffset: 1000 })
      .addTo(map)
      .bindPopup(`<b>YOU</b><br>${data.host.query}<br>${data.host.city}, ${data.host.country}`);
    document.getElementById('host-info').innerHTML =
      `<span class="label">HOST</span> &mdash; ${data.host.query} &mdash; ${data.host.city}, ${data.host.country}`;
  }

  // Remove old arcs
  arcLines.forEach(l => map.removeLayer(l));
  arcLines = [];

  const seen = new Set();
  const list = document.getElementById('conn-list');
  list.innerHTML = '';

  // Colour-code by process
  const procColors = {};
  const palette = ['#ff7b72','#ffa657','#d2a8ff','#79c0ff','#56d364','#f0883e'];
  let colorIdx = 0;
  function colorFor(proc) {
    if (!proc) return '#ff7b72';
    if (!procColors[proc]) procColors[proc] = palette[colorIdx++ % palette.length];
    return procColors[proc];
  }

  data.connections.forEach(c => {
    seen.add(c.ip);
    const color = colorFor(c.process);

    // Marker
    if (!peerMarkers[c.ip]) {
      peerMarkers[c.ip] = L.marker([c.lat, c.lon], { icon: peerIcon(color) }).addTo(map);
    }
    peerMarkers[c.ip].setPopupContent(popupHtml(c));
    if (!peerMarkers[c.ip].getPopup()) peerMarkers[c.ip].bindPopup(popupHtml(c));

    // Arc
    if (hostLatLng) {
      const pts  = gcArc(hostLatLng, [c.lat, c.lon]);
      const line = L.polyline(pts, { color, weight: 1.2, opacity: 0.5, dashArray: '5,5' }).addTo(map);
      arcLines.push(line);
    }

    // Sidebar row
    const row = document.createElement('div');
    row.className = 'conn';
    row.innerHTML = `
      <div class="ip" style="color:${color}">${c.ip}<span style="color:#484f58">:${c.port}</span></div>
      <div class="loc">${c.city ? c.city + ', ' : ''}${c.country || '?'} (${c.countryCode || '?'})</div>
      ${c.process ? `<div class="proc">⚙ ${c.process}</div>` : ''}
      ${c.org ? `<div class="org">🏢 ${c.org}</div>` : ''}
    `;
    row.onclick = () => { map.setView([c.lat, c.lon], 5); peerMarkers[c.ip].openPopup(); };
    list.appendChild(row);
  });

  // Prune stale markers
  Object.keys(peerMarkers).forEach(ip => {
    if (!seen.has(ip)) { map.removeLayer(peerMarkers[ip]); delete peerMarkers[ip]; }
  });

  const t = new Date(data.last_updated * 1000);
  document.getElementById('stats').textContent =
    `${data.connections.length} connection${data.connections.length !== 1 ? 's' : ''} · ${t.toLocaleTimeString()}`;
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


# ── HTTP handler ───────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # silence access log

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/api/connections":
            with _lock:
                payload = {
                    "host":         _host_geo,
                    "connections":  _connections,
                    "last_updated": _last_updated,
                }
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[netmap] Starting background connection poller…")
    t = threading.Thread(target=updater_loop, daemon=True)
    t.start()

    # Brief pause so the first poll can complete before the browser opens
    time.sleep(2)

    url = f"http://localhost:{PORT}"
    print(f"[netmap] Serving on {url}")
    print(f"[netmap] Press Ctrl+C to stop.\n")

    webbrowser.open(url)

    HTTPServer.allow_reuse_address = True
    server = HTTPServer(("localhost", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[netmap] Stopped.")
