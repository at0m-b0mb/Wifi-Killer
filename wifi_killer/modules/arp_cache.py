"""
modules/arp_cache.py -- ARP Cache Reader & Poisoning Detector.

Reads the system ARP table from /proc/net/arp (with a fallback to
``ip neigh show``) and provides a basic ARP-poisoning detection
heuristic by looking for duplicate MAC addresses.

**Educational / authorized-use only.**  This module is part of the
Wifi-Killer educational network-analysis toolkit.  Only use it on
networks you own or have explicit written permission to analyse.
Unauthorized network surveillance may violate local laws.
"""

from __future__ import annotations

import subprocess
import sys
from collections import defaultdict
from typing import Optional


# ------------------------------------------------------------------ #
# Constants                                                            #
# ------------------------------------------------------------------ #

_PROC_ARP_PATH = "/proc/net/arp"

# /proc/net/arp flag values (hex)
_FLAG_COMPLETE = 0x2
_FLAG_INCOMPLETE = 0x0

_INCOMPLETE_MAC = "00:00:00:00:00:00"

# ``ip neigh show`` state tokens we recognise
_NEIGH_STATES = {
    "REACHABLE",
    "STALE",
    "DELAY",
    "PROBE",
    "FAILED",
    "NOARP",
    "NONE",
    "INCOMPLETE",
    "PERMANENT",
}


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _flags_to_state(flags_str: str) -> str:
    """Derive a human-readable NUD state from the ``/proc/net/arp`` Flags field.

    The kernel uses a small bitmask:
      * 0x2 -- entry is complete (REACHABLE / STALE)
      * 0x0 -- entry is incomplete
      * 0x6 -- permanent entry (PERMANENT)
      * 0x4 -- manually published (NOARP)

    We return the closest equivalent NUD state string.
    """
    try:
        val = int(flags_str, 16) if flags_str.startswith("0x") else int(flags_str)
    except (ValueError, TypeError):
        return "UNKNOWN"

    if val == 0x0:
        return "INCOMPLETE"
    if val & 0x4:
        # Published / permanent
        return "PERMANENT" if val & 0x2 else "NOARP"
    if val & 0x2:
        return "REACHABLE"
    return "UNKNOWN"


def _parse_proc_arp() -> list[dict]:
    """Parse ``/proc/net/arp`` and return a list of entry dicts.

    File format (whitespace-separated columns)::

        IP address       HW type  Flags  HW address         Mask  Device
        192.168.1.1      0x1      0x2    aa:bb:cc:dd:ee:ff  *     eth0
    """
    entries: list[dict] = []
    try:
        with open(_PROC_ARP_PATH, "r") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"[WARN] Cannot read {_PROC_ARP_PATH}: {exc}", file=sys.stderr)
        return entries

    # First line is the header -- skip it
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip_addr = parts[0]
        hw_type = parts[1]
        flags = parts[2]
        mac = parts[3].upper()
        # parts[4] is the Mask field (usually "*")
        interface = parts[5]

        entries.append({
            "ip": ip_addr,
            "mac": mac,
            "hw_type": hw_type,
            "flags": flags,
            "state": _flags_to_state(flags),
            "interface": interface,
        })

    return entries


def _parse_ip_neigh() -> list[dict]:
    """Fallback: parse ``ip neigh show`` output.

    Example output lines::

        192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        192.168.1.5 dev wlan0 lladdr 11:22:33:44:55:66 STALE
        192.168.1.99 dev eth0  FAILED
    """
    entries: list[dict] = []
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[WARN] 'ip neigh show' failed: {exc}", file=sys.stderr)
        return entries

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue

        ip_addr = parts[0]
        # Expect "dev <iface>"
        interface = ""
        mac = _INCOMPLETE_MAC
        state = "UNKNOWN"

        idx = 1
        while idx < len(parts):
            token = parts[idx]
            if token == "dev" and idx + 1 < len(parts):
                interface = parts[idx + 1]
                idx += 2
                continue
            if token == "lladdr" and idx + 1 < len(parts):
                mac = parts[idx + 1].upper()
                idx += 2
                continue
            if token.upper() in _NEIGH_STATES:
                state = token.upper()
                idx += 1
                continue
            idx += 1

        entries.append({
            "ip": ip_addr,
            "mac": mac,
            "hw_type": "0x1",
            "flags": "",
            "state": state,
            "interface": interface,
        })

    return entries


# ------------------------------------------------------------------ #
# Public API                                                           #
# ------------------------------------------------------------------ #

def read_arp_cache(
    include_incomplete: bool = False,
) -> list[dict]:
    """Read the system ARP cache and return a list of entry dicts.

    Each dict contains the keys: ``ip``, ``mac``, ``hw_type``, ``flags``,
    ``state``, and ``interface``.

    The function first attempts to read ``/proc/net/arp``.  If that file
    is not available (e.g. on non-Linux systems) it falls back to parsing
    the output of ``ip neigh show``.

    Args:
        include_incomplete: When *False* (the default), entries whose MAC
            address is ``00:00:00:00:00:00`` are silently dropped.

    Returns:
        List of ARP-entry dicts.  Returns an empty list on failure.
    """
    try:
        entries = _parse_proc_arp()
        if not entries:
            entries = _parse_ip_neigh()
    except Exception as exc:
        print(f"[WARN] Failed to read ARP cache: {exc}", file=sys.stderr)
        return []

    if not include_incomplete:
        entries = [e for e in entries if e["mac"] != _INCOMPLETE_MAC]

    return entries


def detect_poisoning(
    entries: Optional[list[dict]] = None,
) -> list[dict]:
    """Check for possible ARP poisoning by detecting duplicate MACs.

    When two or more IP addresses share the same MAC address it *may*
    indicate an ARP spoofing / poisoning attack (though legitimate
    scenarios such as VRRP or load-balancers can also cause duplicates).

    Args:
        entries: Pre-fetched ARP entries.  If *None*, :func:`read_arp_cache`
                 is called automatically.

    Returns:
        A list of warning dicts, each with keys:

        * ``mac``  -- the duplicated MAC address
        * ``ips``  -- list of IP addresses sharing that MAC
        * ``warning`` -- human-readable description
    """
    if entries is None:
        entries = read_arp_cache()

    mac_to_ips: dict[str, list[str]] = defaultdict(list)
    for entry in entries:
        mac = entry["mac"]
        ip = entry["ip"]
        if mac == _INCOMPLETE_MAC:
            continue
        if ip not in mac_to_ips[mac]:
            mac_to_ips[mac].append(ip)

    warnings: list[dict] = []
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            warnings.append({
                "mac": mac,
                "ips": ips,
                "warning": (
                    f"MAC {mac} is shared by {len(ips)} IPs "
                    f"({', '.join(ips)}). Possible ARP poisoning."
                ),
            })

    return warnings


def format_arp_table(entries: list[dict]) -> str:
    """Return a human-readable table string of ARP cache entries.

    Args:
        entries: List of ARP-entry dicts as returned by :func:`read_arp_cache`.

    Returns:
        A formatted multi-line table string ready for printing.
    """
    if not entries:
        return "(ARP cache is empty)"

    # Column headers
    headers = ("IP Address", "MAC Address", "State", "Interface")
    # Determine column widths from the data
    col_ip = max(len(headers[0]), *(len(e["ip"]) for e in entries))
    col_mac = max(len(headers[1]), *(len(e["mac"]) for e in entries))
    col_state = max(len(headers[2]), *(len(e["state"]) for e in entries))
    col_iface = max(len(headers[3]), *(len(e["interface"]) for e in entries))

    fmt = f"  {{:<{col_ip}}}  {{:<{col_mac}}}  {{:<{col_state}}}  {{:<{col_iface}}}"
    sep = "  " + "-" * col_ip + "  " + "-" * col_mac + "  " + "-" * col_state + "  " + "-" * col_iface

    lines: list[str] = [
        fmt.format(*headers),
        sep,
    ]
    for entry in entries:
        lines.append(
            fmt.format(
                entry["ip"],
                entry["mac"],
                entry["state"],
                entry["interface"],
            )
        )

    return "\n".join(lines)
