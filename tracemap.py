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
import report
import geo


def _prune_loop(history_days: int):
    while True:
        time.sleep(3600)
        try:
            db.aggregate_old_connections(cutoff_hours=24)
            db.prune_old_connections(history_days)
        except Exception as e:
            print(f"[tracemap] Prune error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="tracemap — Live network connection visualizer"
    )
    parser.add_argument("--port",        type=int, default=server.PORT,
                        help="HTTP server port (default: 9999)")
    parser.add_argument("--alerts-file", metavar="PATH",
                        help="Load alert rules from a JSON file at startup")
    parser.add_argument("--agent",       action="store_true",
                        help="Agent mode: bind to 0.0.0.0 and enable remote access")
    parser.add_argument("--agent-key",   metavar="KEY",
                        help="API key required in X-Agent-Key header (agent mode)")
    parser.add_argument("--hub",         metavar="PATH",
                        help="Hub mode: JSON file listing remote agents to poll")
    parser.add_argument("--history-days", type=int, default=30, metavar="N",
                        help="Retain connection history for N days (default: 30)")
    parser.add_argument("--no-reports",   action="store_true",
                        help="Disable daily summary reports")
    parser.add_argument("--geoip-db",     metavar="PATH",
                        help="Path to GeoLite2-City.mmdb for offline geolocation")
    parser.add_argument("--geoip-asn",    metavar="PATH",
                        help="Path to GeoLite2-ASN.mmdb for ASN lookup")
    parser.add_argument("--smtp-host",    metavar="HOST", help="SMTP server hostname")
    parser.add_argument("--smtp-port",    type=int, default=587, metavar="PORT")
    parser.add_argument("--smtp-user",    metavar="USER", help="SMTP username")
    parser.add_argument("--smtp-pass",    metavar="PASS", help="SMTP password")
    parser.add_argument("--smtp-from",    metavar="ADDR", help="SMTP from address")
    args = parser.parse_args()

    server.PORT = args.port

    db.init_db()
    db.set_config("history_days", str(args.history_days))
    db.prune_old_connections(args.history_days)

    if args.no_reports:
        report.disable()

    if args.geoip_db:
        geo.configure_geoip_db(args.geoip_db, getattr(args, "geoip_asn", None))

    if args.smtp_host:
        alerts.configure_smtp(
            args.smtp_host, args.smtp_port,
            args.smtp_user or "", args.smtp_pass or "",
            args.smtp_from or "tracemap@localhost",
        )

    if args.alerts_file:
        alerts.load_rules_from_file(args.alerts_file)

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
    threading.Thread(target=report.summary_loop,       daemon=True).start()
    threading.Thread(target=lambda: _prune_loop(args.history_days), daemon=True).start()
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
