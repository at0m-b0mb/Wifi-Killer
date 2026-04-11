"""
modules/arp_cache.py -- ARP Cache Reader & Poisoning Detector.

Reads the system ARP table and provides a basic ARP-poisoning detection
heuristic by looking for duplicate MAC addresses.

Platform support:
  Linux   – reads /proc/net/arp, falls back to ``ip neigh show``
  macOS   – uses ``arp -an``
  Windows – uses ``arp -a``

**Educational / authorized-use only.**
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections import defaultdict
from typing import Optional

_IS_LINUX   = sys.platform.startswith("linux")
_IS_MACOS   = sys.platform == "darwin"
_IS_WINDOWS = sys.platform == "win32"

_INCOMPLETE_MAC = "00:00:00:00:00:00"

# ``ip neigh show`` NUD state tokens (Linux)
_NEIGH_STATES = {
    "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED",
    "NOARP", "NONE", "INCOMPLETE", "PERMANENT",
}


# ------------------------------------------------------------------ #
# Linux parsers                                                        #
# ------------------------------------------------------------------ #

def _flags_to_state(flags_str: str) -> str:
    try:
        val = int(flags_str, 16) if flags_str.startswith("0x") else int(flags_str)
    except (ValueError, TypeError):
        return "UNKNOWN"
    if val == 0x0:
        return "INCOMPLETE"
    if val & 0x4:
        return "PERMANENT" if val & 0x2 else "NOARP"
    if val & 0x2:
        return "REACHABLE"
    return "UNKNOWN"


def _parse_proc_arp() -> list[dict]:
    """Parse ``/proc/net/arp`` (Linux only)."""
    entries: list[dict] = []
    try:
        with open("/proc/net/arp") as fh:
            lines = fh.readlines()
    except OSError:
        return entries          # file not present on non-Linux – silent

    for line in lines[1:]:     # skip header
        parts = line.split()
        if len(parts) < 6:
            continue
        entries.append({
            "ip":        parts[0],
            "mac":       parts[3].upper(),
            "hw_type":   parts[1],
            "flags":     parts[2],
            "state":     _flags_to_state(parts[2]),
            "interface": parts[5],
        })
    return entries


def _parse_ip_neigh() -> list[dict]:
    """Parse ``ip neigh show`` (Linux fallback)."""
    entries: list[dict] = []
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return entries          # command not found – silent

    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) < 4:
            continue
        ip_addr, interface, mac, state = parts[0], "", _INCOMPLETE_MAC, "UNKNOWN"
        idx = 1
        while idx < len(parts):
            token = parts[idx]
            if token == "dev" and idx + 1 < len(parts):
                interface = parts[idx + 1]; idx += 2; continue
            if token == "lladdr" and idx + 1 < len(parts):
                mac = parts[idx + 1].upper(); idx += 2; continue
            if token.upper() in _NEIGH_STATES:
                state = token.upper(); idx += 1; continue
            idx += 1
        entries.append({
            "ip": ip_addr, "mac": mac,
            "hw_type": "0x1", "flags": "",
            "state": state, "interface": interface,
        })
    return entries


# ------------------------------------------------------------------ #
# macOS parser                                                         #
# ------------------------------------------------------------------ #

def _parse_arp_an_macos() -> list[dict]:
    """Parse ``arp -an`` output on macOS.

    Example line::

        ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        ? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
    """
    entries: list[dict] = []
    try:
        result = subprocess.run(
            ["arp", "-an"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return entries

    # Match: (IP) at MAC on IFACE  or  (IP) at (incomplete) on IFACE
    pat = re.compile(
        r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17}|\(incomplete\))"
        r"(?:\s+on\s+(\S+))?",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        m = pat.search(line)
        if not m:
            continue
        ip_addr  = m.group(1)
        raw_mac  = m.group(2)
        iface    = m.group(3) or ""
        if raw_mac.lower() == "(incomplete)":
            mac   = _INCOMPLETE_MAC
            state = "INCOMPLETE"
        else:
            mac   = raw_mac.upper()
            state = "REACHABLE"
        # Permanent entries contain the word "permanent"
        if "permanent" in line.lower():
            state = "PERMANENT"
        entries.append({
            "ip": ip_addr, "mac": mac,
            "hw_type": "0x1", "flags": "",
            "state": state, "interface": iface,
        })
    return entries


# ------------------------------------------------------------------ #
# Windows parser                                                       #
# ------------------------------------------------------------------ #

def _parse_arp_a_windows() -> list[dict]:
    """Parse ``arp -a`` output on Windows.

    Example::

        Interface: 192.168.1.100 --- 0x5
          Internet Address      Physical Address      Type
          192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
    """
    entries: list[dict] = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
        )
        output = result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return entries

    current_iface = ""
    # Pattern for an entry line: IP  MAC  type
    entry_pat = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\s+"
        r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}"
        r"[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})\s+"
        r"(\w+)"
    )
    iface_pat = re.compile(r"Interface:\s+(\d+\.\d+\.\d+\.\d+)")

    for line in output.splitlines():
        im = iface_pat.search(line)
        if im:
            current_iface = im.group(1)
            continue
        em = entry_pat.search(line)
        if em:
            ip_addr  = em.group(1)
            raw_mac  = em.group(2).replace("-", ":").upper()
            arp_type = em.group(3).lower()
            state    = "PERMANENT" if arp_type == "static" else "REACHABLE"
            entries.append({
                "ip": ip_addr, "mac": raw_mac,
                "hw_type": "0x1", "flags": "",
                "state": state, "interface": current_iface,
            })
    return entries


# ------------------------------------------------------------------ #
# Public API                                                           #
# ------------------------------------------------------------------ #

def read_arp_cache(include_incomplete: bool = False) -> list[dict]:
    """Read the system ARP cache and return a list of entry dicts.

    Each dict contains: ``ip``, ``mac``, ``hw_type``, ``flags``,
    ``state``, ``interface``.

    Works on Linux, macOS, and Windows.
    """
    try:
        if _IS_LINUX:
            entries = _parse_proc_arp()
            if not entries:
                entries = _parse_ip_neigh()
        elif _IS_MACOS:
            entries = _parse_arp_an_macos()
        elif _IS_WINDOWS:
            entries = _parse_arp_a_windows()
        else:
            entries = []
    except Exception as exc:
        print(f"[WARN] Failed to read ARP cache: {exc}", file=sys.stderr)
        return []

    if not include_incomplete:
        entries = [e for e in entries if e["mac"] != _INCOMPLETE_MAC]
    return entries


def detect_poisoning(entries: Optional[list[dict]] = None) -> list[dict]:
    """Check for possible ARP poisoning by detecting duplicate MACs.

    Returns a list of warning dicts with keys:
    ``mac``, ``ips``, ``warning``.
    """
    if entries is None:
        entries = read_arp_cache()

    mac_to_ips: dict[str, list[str]] = defaultdict(list)
    for entry in entries:
        mac = entry["mac"]
        ip  = entry["ip"]
        if mac == _INCOMPLETE_MAC:
            continue
        if ip not in mac_to_ips[mac]:
            mac_to_ips[mac].append(ip)

    warnings: list[dict] = []
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            warnings.append({
                "mac":     mac,
                "ips":     ips,
                "warning": (
                    f"MAC {mac} is shared by {len(ips)} IPs "
                    f"({', '.join(ips)}). Possible ARP poisoning."
                ),
            })
    return warnings


def format_arp_table(entries: list[dict]) -> str:
    """Return a human-readable table string of ARP cache entries."""
    if not entries:
        return "(ARP cache is empty)"

    headers = ("IP Address", "MAC Address", "State", "Interface")
    col_ip    = max(len(headers[0]), *(len(e["ip"])        for e in entries))
    col_mac   = max(len(headers[1]), *(len(e["mac"])       for e in entries))
    col_state = max(len(headers[2]), *(len(e["state"])     for e in entries))
    col_iface = max(len(headers[3]), *(len(e["interface"]) for e in entries))

    fmt = f"  {{:<{col_ip}}}  {{:<{col_mac}}}  {{:<{col_state}}}  {{:<{col_iface}}}"
    sep = (
        "  " + "-" * col_ip + "  " + "-" * col_mac
        + "  " + "-" * col_state + "  " + "-" * col_iface
    )
    lines: list[str] = [fmt.format(*headers), sep]
    for e in entries:
        lines.append(fmt.format(e["ip"], e["mac"], e["state"], e["interface"]))
    return "\n".join(lines)
