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


def main():
    parser = argparse.ArgumentParser(
        description="tracemap — Live network connection visualizer"
    )
    parser.add_argument("--port",        type=int, default=server.PORT,
                        help="HTTP server port (default: 9999)")
    parser.add_argument("--alerts-file", metavar="PATH",
                        help="Load alert rules from a JSON file at startup")
    args = parser.parse_args()

    server.PORT = args.port

    db.init_db()

    if args.alerts_file:
        alerts.load_rules_from_file(args.alerts_file)

    print("[tracemap] Starting…")
    threading.Thread(target=collector.updater_loop,    daemon=True).start()
    threading.Thread(target=threat.checker_loop,       daemon=True).start()
    threading.Thread(target=threat.multi_source_loop,  daemon=True).start()
    threading.Thread(target=reputation.checker_loop,   daemon=True).start()
    time.sleep(2)

    url = f"http://localhost:{server.PORT}"
    print(f"[tracemap] Serving on {url}")
    print("[tracemap] Press Ctrl+C to stop.")

    webbrowser.open(url)

    try:
        server.run()
    except KeyboardInterrupt:
        print("\n[tracemap] Stopped.")


if __name__ == "__main__":
    main()
