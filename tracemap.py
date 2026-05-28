#!/usr/bin/env python3
"""
tracemap — Live network connection visualizer on a world map.
Usage: python3 tracemap.py
"""

import threading
import time
import webbrowser
import db
import collector
import server


def main():
    db.init_db()

    print("[tracemap] Starting…")
    threading.Thread(target=collector.updater_loop, daemon=True).start()
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
