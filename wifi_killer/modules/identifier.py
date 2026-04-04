"""
modules/identifier.py – Module 2: Device Identification.

Provides:
  - OUIDatabase  – looks up vendor from MAC OUI
  - resolve_hostname() – mDNS / NBNS / reverse-DNS
  - guess_device_type() – heuristic type inference
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
from typing import Optional

# ------------------------------------------------------------------ #
# OUI Database                                                         #
# ------------------------------------------------------------------ #

_OUI_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "oui.json")


class OUIDatabase:
    """Lightweight OUI → vendor lookup backed by a local JSON file."""

    def __init__(self, path: str = _OUI_PATH) -> None:
        self._db: dict[str, str] = {}
        try:
            with open(os.path.normpath(path)) as fh:
                self._db = json.load(fh)
        except Exception as exc:
            import sys
            print(f"[WARN] Could not load OUI database from {path}: {exc}", file=sys.stderr)

    def lookup(self, mac: str) -> str:
        """Return vendor string for *mac*, or 'Unknown' if not found.

        Accepts MACs in any common delimiter (colon, dash, dot).
        """
        norm = re.sub(r"[^0-9A-Fa-f]", "", mac)
        if len(norm) < 6:
            return "Unknown"
        oui_bytes = norm[:6].upper()
        # Format as XX:XX:XX
        oui_key = ":".join(oui_bytes[i : i + 2] for i in range(0, 6, 2))
        return self._db.get(oui_key, "Unknown")


# Module-level singleton
oui_db = OUIDatabase()


# ------------------------------------------------------------------ #
# Hostname Resolution                                                  #
# ------------------------------------------------------------------ #

def _try_mdns(ip: str) -> Optional[str]:
    """Attempt a multicast DNS (.local) lookup via avahi-resolve."""
    try:
        out = subprocess.check_output(
            ["avahi-resolve", "--address", ip],
            text=True,
            timeout=3,
            stderr=subprocess.DEVNULL,
        )
        # Output: "192.168.1.5\thostname.local"
        parts = out.strip().split()
        if len(parts) >= 2:
            return parts[-1]
    except Exception:
        pass
    return None


def _try_nbns(ip: str) -> Optional[str]:
    """Attempt a NetBIOS name query using nmblookup."""
    try:
        out = subprocess.check_output(
            ["nmblookup", "-A", ip],
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            # Lines like: "  HOSTNAME          <00> -         B <ACTIVE>"
            m = re.match(r"\s+(\S+)\s+<00>", line)
            if m:
                name = m.group(1).strip()
                if name not in ("<01>", "IS__MSBROWSE__", "__MSBROWSE__"):
                    return name
    except Exception:
        pass
    return None


def _try_rdns(ip: str) -> Optional[str]:
    """Attempt a reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        pass
    return None


def resolve_hostname(ip: str) -> str:
    """Try mDNS → NBNS → rDNS in order; return first successful result or ''."""
    for fn in (_try_mdns, _try_nbns, _try_rdns):
        result = fn(ip)
        if result:
            return result
    return ""


# ------------------------------------------------------------------ #
# Device-type Inference                                                #
# ------------------------------------------------------------------ #

# Vendor prefix patterns mapped to device family hints
_VENDOR_HINTS: list[tuple[str, str]] = [
    ("Apple", "Apple"),
    ("Samsung", "Samsung"),
    ("Google", "Google"),
    ("Amazon", "Amazon"),
    ("Raspberry Pi", "RaspberryPi"),
    ("Cisco", "Cisco"),
    ("TP-Link", "Router"),
    ("NETGEAR", "Router"),
    ("Linksys", "Router"),
    ("Huawei", "Router"),
    ("D-Link", "Router"),
    ("ASUSTeK", "Router"),
    ("Belkin", "Router"),
    ("Ubiquiti", "Router"),
    ("Eero", "Router"),
    ("Peplink", "Router"),
    ("MikroTik", "Router"),
    ("Microsoft", "Windows"),
    ("Intel", "PC"),
    ("Realtek", "PC"),
    ("VMware", "VM"),
    ("Oracle VirtualBox", "VM"),
    ("Parallels", "VM"),
    ("Xiaomi", "Android"),
    ("OnePlus", "Android"),
    ("Oppo", "Android"),
    ("Vivo", "Android"),
    ("Sonos", "Sonos"),
    ("Philips", "SmartHome"),
    ("Nest", "SmartHome"),
    ("Ring", "SmartHome"),
    ("Wyze", "SmartHome"),
    ("Ecobee", "SmartHome"),
    ("Lutron", "SmartHome"),
    ("Shelly", "SmartHome"),
    ("Canon", "Printer"),
    ("Hewlett Packard", "Printer"),
    ("HP Inc", "Printer"),
    ("Epson", "Printer"),
    ("Brother", "Printer"),
    ("Xerox", "Printer"),
    ("Nintendo", "GameConsole"),
    ("Sony Interactive", "GameConsole"),
    ("Microsoft Xbox", "GameConsole"),
    ("LG Electronics", "SmartTV"),
    ("Samsung", "SmartTV"),
    ("TCL", "SmartTV"),
    ("Hisense", "SmartTV"),
    ("Roku", "SmartTV"),
]


def guess_device_type(
    ip: str,
    mac: str,
    vendor: str,
    hostname: str,
    open_ports: list[int],
    gateway_ip: str = "",
) -> str:
    """Return a human-readable device-type guess."""
    vendor_up = vendor.upper()
    hostname_up = hostname.upper()

    # Gateway / router
    if gateway_ip and ip == gateway_ip:
        return "Router / Gateway"

    # Determine vendor family
    family = ""
    for keyword, hint in _VENDOR_HINTS:
        if keyword.upper() in vendor_up:
            family = hint
            break

    # Apple
    if family == "Apple":
        if 548 in open_ports or 5009 in open_ports:
            return "Apple TV"
        if hostname_up.endswith(".LOCAL") and (
            "MACBOOK" in hostname_up or "IMAC" in hostname_up or "MAC" in hostname_up
        ):
            return "Apple Mac"
        return "Apple iPhone / iPad"

    # Samsung / Xiaomi / other Android-likely
    if family in ("Samsung", "Android", "Google") and not open_ports:
        return "Android Device"

    # Amazon
    if family == "Amazon":
        if "ECHO" in hostname_up or "ALEXA" in hostname_up:
            return "Amazon Echo"
        if "FIRE" in hostname_up or "KINDLE" in hostname_up:
            return "Amazon Fire Tablet"
        return "Amazon Device"

    # Windows
    if family == "Windows":
        return "Windows PC"
    if 445 in open_ports or 139 in open_ports:
        return "Windows PC"

    # VM
    if family == "VM":
        return "Virtual Machine"

    # Raspberry Pi
    if family == "RaspberryPi":
        return "Raspberry Pi"

    # Cisco / router
    if family == "Cisco":
        return "Cisco Network Device"

    # Generic router markers
    if family == "Router":
        return "Router / Access Point"

    # Sonos speaker
    if family == "Sonos":
        return "Sonos Speaker"

    # Smart home devices
    if family == "SmartHome":
        return "Smart Home Device"

    # Printers
    if family == "Printer":
        return "Network Printer"

    # Game consoles
    if family == "GameConsole":
        return "Game Console"

    # Smart TV
    if family == "SmartTV":
        return "Smart TV"

    if open_ports and any(p in open_ports for p in [80, 443, 8080, 8443]):
        # Could still be a PC; check for server ports
        if 22 in open_ports or 3389 in open_ports:
            return "Linux/Windows Server"
        return "Network Device / Server"

    # Generic PC
    if family == "PC":
        return "PC / Laptop"

    # IoT catch-all
    if not hostname and vendor == "Unknown":
        return "Unknown IoT Device"

    return "Unknown Device"


# ------------------------------------------------------------------ #
# OS Fingerprinting                                                    #
# ------------------------------------------------------------------ #

def os_fingerprint_from_ttl(ttl: int) -> str:
    """Infer the operating system family from the observed IP TTL value.

    Different OS families initialise the IP time-to-live (TTL) field to
    different values.  By examining the TTL in a received packet and
    working backwards from the hop count, a rough OS guess is possible.

    Typical initial TTL values:
      * Linux / Android / macOS / iOS  →  64
      * Windows                        → 128
      * Cisco / Network devices        → 255

    Args:
        ttl: The TTL value observed in a received IP packet (0–255).

    Returns:
        A human-readable OS family string.
    """
    if ttl <= 0:
        return "Unknown"
    if ttl <= 64:
        return "Linux / macOS / Android"
    if ttl <= 128:
        return "Windows"
    return "Cisco / Network Device"




def identify_host(
    ip: str,
    mac: str,
    open_ports: Optional[list[int]] = None,
    gateway_ip: str = "",
    ttl: Optional[int] = None,
) -> dict:
    """Return a full identification dict for a host.

    Args:
        ip:          IPv4 address string.
        mac:         MAC address string.
        open_ports:  List of open TCP ports (empty list if unknown).
        gateway_ip:  Default gateway IP – used to flag it as a router.
        ttl:         Observed IP TTL value; when provided, an ``os_hint``
                     key is included in the returned dict.

    Returns:
        Dict with keys: ip, mac, vendor, hostname, type, open_ports,
        and optionally os_hint.
    """
    if open_ports is None:
        open_ports = []
    vendor = oui_db.lookup(mac)
    hostname = resolve_hostname(ip)
    device_type = guess_device_type(ip, mac, vendor, hostname, open_ports, gateway_ip)
    result: dict = {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "type": device_type,
        "open_ports": open_ports,
    }
    if ttl is not None:
        result["os_hint"] = os_fingerprint_from_ttl(ttl)
    return result


def format_host(info: dict, status: str = "ONLINE") -> str:
    """Pretty-print a host identification dict."""
    ports_str = (
        ", ".join(str(p) for p in info.get("open_ports", []))
        if info.get("open_ports")
        else "—"
    )
    lines = [
        f"  IP       : {info.get('ip', '?')}",
        f"  MAC      : {info.get('mac', '?')}",
        f"  Vendor   : {info.get('vendor', 'Unknown')}",
        f"  Hostname : {info.get('hostname') or '—'}",
        f"  Type     : {info.get('type', 'Unknown')}",
        f"  Ports    : {ports_str}",
        f"  Status   : {status}",
    ]
    return "\n".join(lines)
