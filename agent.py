"""
agent.py — Agent / Hub mode for multi-host monitoring.

Agent mode (--agent):
  Binds server to 0.0.0.0 instead of localhost.
  Optional API-key auth: set --agent-key KEY; clients must send
  "X-Agent-Key: KEY" header.

Hub mode (--hub PATH):
  PATH is a JSON file listing remote tracemap agents:
    [{"url":"http://host:9999","label":"server1","key":"optional-key"}, ...]
  Hub polls each agent's /api/connections every POLL_INTERVAL seconds,
  merges the results, and tags each connection with agent_label/agent_url.
  The merged state is exposed by the local /api/connections endpoint.
"""

import json
import threading
import time
import urllib.request
import urllib.error

POLL_INTERVAL = 5   # seconds between hub polls

_lock         = threading.Lock()
_agent_states: dict[str, dict] = {}   # label → last polled state

_api_key:  str | None = None
_hub_mode: bool       = False
_agents:   list[dict] = []             # [{url, label, key}]


# ── Agent-mode auth ────────────────────────────────────────────────────────────

def set_agent_key(key: str | None):
    global _api_key
    _api_key = key


def get_agent_key() -> str | None:
    return _api_key


def check_auth(provided: str | None) -> bool:
    """Returns True when no key required, or when provided matches."""
    if not _api_key:
        return True
    return provided == _api_key


# ── Hub configuration ──────────────────────────────────────────────────────────

def load_hub_config(path: str):
    global _agents, _hub_mode
    with open(path) as f:
        _agents = json.load(f)
    _hub_mode = True
    labels = ", ".join(a["label"] for a in _agents)
    print(f"[agent] Hub mode — {len(_agents)} agent(s): {labels}")


def is_hub() -> bool:
    return _hub_mode


# ── Per-agent polling ──────────────────────────────────────────────────────────

def _poll_one(cfg: dict):
    url     = cfg["url"].rstrip("/") + "/api/connections"
    label   = cfg.get("label", cfg["url"])
    headers = {}
    if cfg.get("key"):
        headers["X-Agent-Key"] = cfg["key"]
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            state = json.loads(resp.read())
        for c in state.get("connections", []):
            c["agent_label"] = label
            c["agent_url"]   = cfg["url"]
        state["agent_label"]  = label
        state["last_contact"] = time.time()
        state["online"]       = True
    except Exception as e:
        print(f"[agent] Poll failed for {label}: {e}")
        state = {"connections": [], "online": False,
                 "agent_label": label, "last_contact": 0}

    with _lock:
        _agent_states[label] = state


def hub_loop():
    """Background loop: poll every agent in _agents concurrently."""
    while True:
        for cfg in list(_agents):
            threading.Thread(target=_poll_one, args=(cfg,), daemon=True).start()
        time.sleep(POLL_INTERVAL)


# ── Merged state ───────────────────────────────────────────────────────────────

def get_merged_connections() -> list[dict]:
    """Return all remote-agent connections with agent_label set."""
    with _lock:
        merged = []
        for state in _agent_states.values():
            merged.extend(state.get("connections", []))
        return merged


def get_agent_status() -> list[dict]:
    """Return status summary for each known agent."""
    with _lock:
        return [
            {
                "label":        label,
                "online":       state.get("online", False),
                "last_contact": state.get("last_contact", 0),
                "conn_count":   len(state.get("connections", [])),
            }
            for label, state in _agent_states.items()
        ]
