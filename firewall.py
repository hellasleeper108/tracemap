"""
firewall.py — iptables/ip6tables-based IP blocking.

Requires root (os.geteuid()==0) and iptables (or ip6tables for IPv6) on PATH.
All operations degrade gracefully when unavailable.

Safety limits:
  - Private / loopback IPs are refused.
  - Hard rate limit: 10 block operations per 60 seconds.

IPv6 support:
  - _is_ipv6(ip) detects IPv6 addresses.
  - block() / unblock() automatically use ip6tables for IPv6 addresses.
"""

import ipaddress
import os
import subprocess
import threading
import time
import db

_RATE_WINDOW = 60    # seconds
_RATE_LIMIT  = 10    # max block calls per window
_block_times: list[float] = []
_rate_lock = threading.Lock()


def is_available() -> bool:
    """True only when running as root and iptables is on PATH."""
    if os.geteuid() != 0:
        return False
    try:
        r = subprocess.run(
            ["iptables", "--version"],
            capture_output=True, timeout=3
        )
        return r.returncode == 0
    except Exception:
        return False


def _is_ipv6(ip: str) -> bool:
    """Return True if ip is an IPv6 address."""
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False


def _ipt(ip: str) -> str:
    """Return 'ip6tables' for IPv6 addresses, 'iptables' for IPv4."""
    return "ip6tables" if _is_ipv6(ip) else "iptables"


def _is_safe(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback
                    or addr.is_link_local or addr.is_unspecified)
    except ValueError:
        return False


def _rate_ok() -> bool:
    now = time.time()
    _block_times[:] = [t for t in _block_times if now - t < _RATE_WINDOW]
    return len(_block_times) < _RATE_LIMIT


def block(ip: str) -> dict:
    """Add OUTPUT DROP rule for ip. Returns {ok, error?}.

    Uses ip6tables automatically for IPv6 addresses.
    """
    if not is_available():
        return {"ok": False, "error": "firewall unavailable (need root + iptables)"}
    if not _is_safe(ip):
        return {"ok": False, "error": "cannot block private/loopback addresses"}
    with _rate_lock:
        if not _rate_ok():
            return {"ok": False, "error": f"rate limit: max {_RATE_LIMIT} blocks per minute"}
        if db.is_blocked_ip(ip):
            return {"ok": True, "note": "already blocked"}
        try:
            subprocess.run(
                [_ipt(ip), "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, check=True, timeout=5
            )
            db.add_blocked_ip(ip)
            _block_times.append(time.time())
            print(f"[firewall] Blocked {ip}")
            return {"ok": True}
        except subprocess.CalledProcessError as e:
            return {"ok": False, "error": e.stderr.decode().strip()}
        except Exception as e:
            return {"ok": False, "error": str(e)}


def unblock(ip: str) -> dict:
    """Remove OUTPUT DROP rule for ip. Returns {ok, error?}.

    Uses ip6tables automatically for IPv6 addresses.
    """
    if not is_available():
        return {"ok": False, "error": "firewall unavailable"}
    try:
        subprocess.run(
            [_ipt(ip), "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            capture_output=True, check=True, timeout=5
        )
        db.remove_blocked_ip(ip)
        print(f"[firewall] Unblocked {ip}")
        return {"ok": True}
    except subprocess.CalledProcessError as e:
        return {"ok": False, "error": e.stderr.decode().strip()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_blocked() -> list[dict]:
    return db.get_blocked_ips()


def is_blocked(ip: str) -> bool:
    return db.is_blocked_ip(ip)
