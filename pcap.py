"""
pcap.py — tcpdump-based PCAP capture for individual IPs.

Captures are stored in ~/.local/share/tracemap/pcap/ and run in a
background thread. Degrades gracefully when tcpdump is unavailable.
"""

import re
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

PCAP_DIR = Path.home() / ".local" / "share" / "tracemap" / "pcap"
_SAFE_IP  = re.compile(r"^[0-9a-fA-F:.]{2,45}$")   # IPv4 and IPv6

_active: dict[str, subprocess.Popen] = {}
_lock   = threading.Lock()


def is_available() -> bool:
    return shutil.which("tcpdump") is not None


def _safe_ip(ip: str) -> bool:
    return bool(_SAFE_IP.match(ip)) and ".." not in ip


def start_capture(ip: str, duration: int = 10) -> dict:
    """
    Start a tcpdump capture for *ip* lasting *duration* seconds.
    Returns {"file": filename, "status": "started"|"already_running"|"unavailable"|"invalid_ip"}.
    """
    if not _safe_ip(ip):
        return {"file": None, "status": "invalid_ip"}
    if not is_available():
        return {"file": None, "status": "unavailable"}

    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    ts       = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    filename = f"{ip.replace(':', '_')}_{ts}.pcap"
    filepath = PCAP_DIR / filename

    # Use -c 0 (no packet count limit) and terminate via _reap after duration.
    # Avoid -G/-W: those append a rotation counter (.pcap.0) that breaks our glob.
    cmd = ["tcpdump", "-i", "any", "-w", str(filepath), f"host {ip}"]

    with _lock:
        if ip in _active and _active[ip].poll() is None:
            return {"file": None, "status": "already_running"}
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return {"file": None, "status": "unavailable"}
        _active[ip] = proc

    def _reap():
        try:
            proc.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        with _lock:
            _active.pop(ip, None)

    threading.Thread(target=_reap, daemon=True).start()
    return {"file": filename, "status": "started"}


def status(ip: str) -> str:
    """Return 'running', 'idle', or 'unavailable'."""
    if not is_available():
        return "unavailable"
    with _lock:
        proc = _active.get(ip)
    if proc is not None and proc.poll() is None:
        return "running"
    return "idle"


def list_captures(ip: str) -> list[dict]:
    """Return capture files for *ip*, newest first."""
    if not _safe_ip(ip):
        return []
    prefix = ip.replace(":", "_") + "_"
    if not PCAP_DIR.exists():
        return []
    files = sorted(PCAP_DIR.glob(f"{prefix}*.pcap"), reverse=True)
    return [
        {"file": f.name, "size": f.stat().st_size, "mtime": int(f.stat().st_mtime)}
        for f in files
    ]


def get_capture_path(filename: str) -> Path | None:
    """Return the Path for *filename* if it is a safe, existing .pcap file."""
    if not filename.endswith(".pcap") or "/" in filename or "\\" in filename:
        return None
    p = PCAP_DIR / filename
    return p if p.exists() else None
