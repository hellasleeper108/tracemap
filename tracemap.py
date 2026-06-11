#!/usr/bin/env python3
"""
tracemap — Live network connection visualizer on a world map.
Usage: python3 tracemap.py [--port PORT] [--alerts-file PATH]
"""

import argparse
import threading
import time
import webbrowser
import db
import collector
import threat
import reputation
import alerts
import server
import agent

_PRUNE_INTERVAL = 86400  # 24 hours


def _prune_loop(days: int):
    """Background thread: prune connection log every 24 hours."""
    while True:
        time.sleep(_PRUNE_INTERVAL)
        db.prune_connection_log(days)


def main():
    parser = argparse.ArgumentParser(
        description="tracemap — Live network connection visualizer"
    )
    parser.add_argument("--port",        type=int, default=server.PORT,
                        help="HTTP server port (default: 9999)")
    parser.add_argument("--db",          metavar="PATH",
                        help="SQLite database path (default: ~/.local/share/tracemap/tracemap.db)")
    parser.add_argument("--alerts-file", metavar="PATH",
                        help="Load alert rules from a JSON file at startup")
    parser.add_argument("--agent",       action="store_true",
                        help="Agent mode: bind to 0.0.0.0 and enable remote access")
    parser.add_argument("--agent-key",   metavar="KEY",
                        help="API key required in X-Agent-Key header (agent mode)")
    parser.add_argument("--hub",         metavar="PATH",
                        help="Hub mode: JSON file listing remote agents to poll")
    parser.add_argument("--history-days", type=int, default=30,
                        help="Delete connection log entries older than N days (0 = keep forever)")
    parser.add_argument("--api-key",     metavar="KEY",
                        help="Require X-Api-Key header on all API requests")
    args = parser.parse_args()

    server.PORT = args.port

    if args.db:
        db.set_db_path(args.db)

    db.init_db()

    if args.history_days > 0:
        db.prune_connection_log(args.history_days)
        threading.Thread(target=_prune_loop, args=(args.history_days,), daemon=True).start()

    if args.alerts_file:
        alerts.load_rules_from_file(args.alerts_file)

    if args.api_key:
        server.API_KEY = args.api_key

    bind_host = "localhost"
    if args.agent or args.hub:
        server.AGENT_MODE = True
        bind_host = "0.0.0.0"
        if args.agent_key:
            agent.set_agent_key(args.agent_key)

    if args.hub:
        server.HUB_MODE = True
        agent.load_hub_config(args.hub)
        threading.Thread(target=agent.hub_loop, daemon=True).start()

    print("[tracemap] Starting…")
    threading.Thread(target=collector.updater_loop,    daemon=True).start()
    threading.Thread(target=threat.checker_loop,       daemon=True).start()
    threading.Thread(target=threat.multi_source_loop,  daemon=True).start()
    threading.Thread(target=reputation.checker_loop,   daemon=True).start()
    time.sleep(2)

    url = f"http://localhost:{server.PORT}"
    print(f"[tracemap] Serving on {url}")
    if args.agent or args.hub:
        print(f"[tracemap] Remote access enabled on 0.0.0.0:{server.PORT}")
    print("[tracemap] Press Ctrl+C to stop.")

    if not (args.agent or args.hub):
        webbrowser.open(url)

    try:
        server.run(bind_host)
    except KeyboardInterrupt:
        print("\n[tracemap] Stopped.")


if __name__ == "__main__":
    main()
