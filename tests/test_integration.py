"""
Integration / smoke test for tracemap.
Starts the server as a subprocess, runs HTTP checks, reports results.
Exit code 0 = all pass, 1 = any failure.
"""

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HOST = "localhost"
PORT = 19999
BASE = f"http://{HOST}:{PORT}"
DB   = "/tmp/tracemap_int_test.db"


def _wait_for_server(timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{BASE}/", timeout=1)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def _get(path: str, *, raw: bool = False):
    url = BASE + path
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        body = resp.read()
        ct   = resp.getheader("Content-Type", "")
        code = resp.status
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), b""
    if raw:
        return code, ct, body
    try:
        return code, ct, json.loads(body)
    except Exception:
        return code, ct, body


def _post(path: str, payload: dict, *, expect_201: bool = False):
    url  = BASE + path
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data,
                                  headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        body = resp.read()
        return resp.status, json.loads(body)
    except urllib.error.HTTPError as e:
        return e.code, {}


def run_checks(proc) -> list[tuple[str, bool, str]]:
    results = []

    def check(label: str, passed: bool, detail: str = ""):
        mark = "PASS" if passed else "FAIL"
        print(f"  [{mark}] {label}" + (f": {detail}" if detail else ""))
        results.append((label, passed, detail))

    # a
    code, _, data = _get("/api/connections")
    check("a. GET /api/connections → 200, list",
          code == 200 and isinstance(data, dict) and "connections" in data)

    # b
    code, _, data = _get("/api/stats")
    check("b. GET /api/stats → 200, has required keys",
          code == 200
          and isinstance(data, dict)
          and all(k in data for k in ("total", "unique_ips", "top_countries", "top_orgs")))

    # c
    code, _, data = _get("/api/timeline")
    check("c. GET /api/timeline → 200, list",
          code == 200 and isinstance(data, list))

    # d
    code, _, data = _get("/api/threats")
    check("d. GET /api/threats → 200, list",
          code == 200 and isinstance(data, list))

    # e
    code, _, data = _get("/api/rules")
    check("e. GET /api/rules → 200, list",
          code == 200 and isinstance(data, list))

    # f
    rule_body = {"name": "test", "type": "country", "value": "XX",
                 "action": {"type": "desktop"}}
    code, data = _post("/api/rules", rule_body)
    check("f. POST /api/rules → 201",
          code == 201 and isinstance(data, dict))
    if code == 201:
        code2, _, rules = _get("/api/rules")
        ids = [r.get("id") for r in rules] if isinstance(rules, list) else []
        check("f. POST rule present in GET /api/rules",
              data.get("id") in ids)
    else:
        check("f. POST rule present in GET /api/rules", False, "rule not created")

    # g
    code, _, data = _get("/api/notes/1.2.3.4")
    check("g. GET /api/notes/1.2.3.4 → {ip, note}",
          code == 200
          and isinstance(data, dict)
          and data.get("ip") == "1.2.3.4"
          and data.get("note") == "")

    # h
    code, data = _post("/api/notes/1.2.3.4", {"note": "test note"})
    check("h. POST /api/notes/1.2.3.4 → 200",
          code == 200 and data.get("ok") is True)

    # i
    code, _, data = _get("/api/notes/1.2.3.4")
    check("i. GET /api/notes/1.2.3.4 → note persisted",
          code == 200
          and isinstance(data, dict)
          and data.get("ip") == "1.2.3.4"
          and data.get("note") == "test note")

    # j
    code, _, data = _get("/api/export/connections?format=json")
    check("j. GET /api/export/connections?format=json → 200, list",
          code == 200 and isinstance(data, list))

    # k
    code, ct, body = _get("/api/export/connections?format=csv", raw=True)
    check("k. GET /api/export/connections?format=csv → 200, text/csv",
          code == 200 and "text/csv" in ct)

    # l
    code, _, data = _get("/api/export/threats?format=json")
    check("l. GET /api/export/threats?format=json → 200, list",
          code == 200 and isinstance(data, list))

    # m
    code, _, data = _get("/api/reports")
    check("m. GET /api/reports → 200, list",
          code == 200 and isinstance(data, list))

    # n
    code, _, data = _get("/api/db/stats")
    check("n. GET /api/db/stats → has row_counts, db_size_bytes",
          code == 200
          and isinstance(data, dict)
          and "row_counts" in data
          and "db_size_bytes" in data)

    # o
    code, _, data = _get("/api/geo/status")
    check("o. GET /api/geo/status → has source",
          code == 200 and isinstance(data, dict) and "source" in data)

    # p
    code, _, data = _get("/api/blocked")
    check("p. GET /api/blocked → 200, list",
          code == 200 and isinstance(data, list))

    # q
    code, _, body = _get("/", raw=True)
    check("q. GET / → 200, body contains 'tracemap'",
          code == 200 and b"tracemap" in body.lower())

    return results


def main():
    # Clean up leftover DB
    if os.path.exists(DB):
        os.unlink(DB)

    tracemap = Path(__file__).parent.parent / "tracemap.py"
    proc = subprocess.Popen(
        [sys.executable, str(tracemap), "--port", str(PORT), "--db", DB],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        print(f"[integration] Waiting for server on port {PORT}…")
        if not _wait_for_server(timeout=10):
            print("[integration] ERROR: server did not start within 10 s")
            proc.kill()
            sys.exit(1)
        print("[integration] Server ready. Running checks…\n")

        results = run_checks(proc)

        passed = sum(1 for _, ok, _ in results if ok)
        total  = len(results)
        print(f"\n[integration] {passed}/{total} checks passed")

    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(DB):
            os.unlink(DB)

    failed = [label for label, ok, _ in results if not ok]
    if failed:
        print("[integration] FAILED checks:", ", ".join(failed))
        sys.exit(1)
    print("[integration] ALL CHECKS PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
