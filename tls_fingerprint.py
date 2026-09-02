"""
tls_fingerprint.py — Best-effort TLS connection info for a given IP:port.

Does NOT require root or raw-socket access.  Uses:
  1. /proc/net/tcp + /proc/net/tcp6 to confirm an established connection
     to the target IP on port 443.
  2. `ss --info` (iproute2) to extract any TLS/cipher details that the
     kernel exports via tcp_info / tls_rx / tls_tx socket options.

If neither source yields usable data the function degrades gracefully and
returns a minimal dict with a human-readable note.
"""

from __future__ import annotations

import ipaddress
import subprocess
import struct


# ── helpers ──────────────────────────────────────────────────────────────────────────────

def _hex_to_ip4(h: str) -> str:
    """Convert a little-endian hex quad to dotted-decimal (IPv4)."""
    packed = bytes.fromhex(h)  # 4 bytes, little-endian
    return str(ipaddress.IPv4Address(struct.pack(">I", struct.unpack("<I", packed)[0])))


def _hex_to_ip6(h: str) -> str:
    """Convert a /proc/net/tcp6-style 32-hex-char string to compressed IPv6."""
    # Each 4-byte word is stored little-endian in /proc/net/tcp6
    words = [h[i:i+8] for i in range(0, 32, 8)]
    packed = b"".join(struct.pack(">I", struct.unpack("<I", bytes.fromhex(w))[0]) for w in words)
    return str(ipaddress.IPv6Address(packed))


def _hex_port(h: str) -> int:
    return int(h, 16)


def _is_established_proc(target_ip: str, target_port: int) -> bool:
    """
    Check /proc/net/tcp (and /proc/net/tcp6) for an ESTABLISHED connection
    to target_ip:target_port.  State 01 = ESTABLISHED in the kernel enum.
    Returns False silently if the files are unreadable.
    """
    files = ["/proc/net/tcp", "/proc/net/tcp6"]
    for fpath in files:
        try:
            with open(fpath) as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    # parts[2] = remote address (hex IP:hex port), parts[3] = state
                    if parts[3] != "01":        # 01 = ESTABLISHED
                        continue
                    remote_hex = parts[2]
                    colon = remote_hex.index(":")
                    ip_hex   = remote_hex[:colon]
                    port_hex = remote_hex[colon+1:]
                    try:
                        port = _hex_port(port_hex)
                        if port != target_port:
                            continue
                        if len(ip_hex) == 8:    # IPv4
                            ip = _hex_to_ip4(ip_hex)
                        else:                   # IPv6 (32 chars)
                            ip = _hex_to_ip6(ip_hex)
                        if ip == target_ip:
                            return True
                    except Exception:
                        continue
        except OSError:
            continue
    return False


def _ss_tls_info(ip: str, port: int) -> dict:
    """
    Run `ss -tnipH state established dst {ip}:{port}` and parse the output
    for any TLS/cipher/version tokens exported by the kernel.

    Returns a (possibly empty) dict with keys such as:
      cipher, tls_version, rto, wscale, rtt
    """
    result: dict = {}
    try:
        out = subprocess.check_output(
            ["ss", "-tnipH", "state", "established", f"dst {ip}:{port}"],
            stderr=subprocess.DEVNULL,
            timeout=3,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, OSError):
        return result

    for line in out.splitlines():
        low = line.lower()
        # TLS version hint (e.g. from kernel TLS offload: "tls:TLSv1.3")
        if "tls:" in low:
            for token in line.split():
                if token.lower().startswith("tls:"):
                    result["tls_version"] = token.split(":", 1)[1]
        if "tlsv1.3" in low:
            result["tls_version"] = "TLS1.3"
        elif "tlsv1.2" in low:
            result["tls_version"] = "TLS1.2"
        # Cipher suite (rare but some kernels expose it)
        if "cipher:" in low:
            for token in line.split():
                if token.lower().startswith("cipher:"):
                    result["cipher"] = token.split(":", 1)[1]
        # Generic ss fields we surface for informational value
        for field in ("rto", "wscale", "rtt"):
            if f"{field}:" in low:
                for token in line.split():
                    if token.lower().startswith(f"{field}:"):
                        result[field] = token.split(":", 1)[1]
                        break

    return result


# ── public API ──────────────────────────────────────────────────────────────────────────────

def get_tls_info(ip: str, port: str = "443") -> dict:
    """
    Return TLS connection information for *ip*:*port*.

    Guaranteed keys:
      ip   : str
      port : int
      tls  : bool   (always True when port == 443)

    Optional keys (present only when detectable without root):
      tls_version : str   e.g. "TLS1.3"
      cipher      : str
      rto         : str
      wscale      : str
      rtt         : str
      connected   : bool  (whether an ESTABLISHED entry was found in /proc)
      note        : str   (present when detail extraction is not possible)
    """
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        return {"ip": ip, "port": None, "tls": False, "note": "invalid port"}
    info: dict = {"ip": ip, "port": port_int, "tls": port_int == 443}

    # 1. Confirm connection exists via /proc/net/tcp*
    connected = _is_established_proc(ip, port_int)
    info["connected"] = connected

    # 2. Try richer data via ss
    ss_data = _ss_tls_info(ip, port_int)
    info.update(ss_data)

    # 3. Degrade gracefully if nothing useful was found
    if not connected and not ss_data:
        info["note"] = "TLS detail extraction requires root or an active connection"

    return info
