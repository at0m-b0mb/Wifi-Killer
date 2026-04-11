"""
modules/identifier.py – Module 2: Device Identification.

Provides:
  - OUIDatabase  – looks up vendor from MAC OUI
  - resolve_hostname() – pure-Python mDNS / NetBIOS / reverse-DNS (no external tools)
  - guess_device_type() – heuristic type inference
  - identify_host() – full enrichment dict for a discovered host

Platform support: Linux, macOS, Windows (no avahi-resolve or nmblookup required).
"""

from __future__ import annotations

import json
import os
import random
import re
import socket
import struct
import time
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
            with open(os.path.normpath(path), encoding="utf-8") as fh:
                self._db = json.load(fh)
        except Exception as exc:
            import sys
            print(f"[WARN] Could not load OUI database from {path}: {exc}",
                  file=sys.stderr)

    def lookup(self, mac: str) -> str:
        """Return vendor string for *mac*, or 'Unknown' if not found.

        Accepts MACs in any common delimiter (colon, dash, dot).
        """
        norm = re.sub(r"[^0-9A-Fa-f]", "", mac)
        if len(norm) < 6:
            return "Unknown"
        oui_bytes = norm[:6].upper()
        oui_key = ":".join(oui_bytes[i: i + 2] for i in range(0, 6, 2))
        return self._db.get(oui_key, "Unknown")


# Module-level singleton
oui_db = OUIDatabase()


# ------------------------------------------------------------------ #
# DNS wire-format helpers (used by mDNS lookup)                        #
# ------------------------------------------------------------------ #

def _dns_encode_name(name: str) -> bytes:
    """Encode a domain name in DNS wire format (label-length encoding)."""
    encoded = b""
    for label in name.rstrip(".").split("."):
        if label:
            b = label.encode("ascii", errors="replace")
            encoded += bytes([len(b)]) + b
    encoded += b"\x00"
    return encoded


def _dns_skip_name(data: bytes, pos: int) -> int:
    """Skip a DNS-format name and return the position after it."""
    while pos < len(data):
        length = data[pos]
        if length == 0:
            return pos + 1
        if (length & 0xC0) == 0xC0:   # compression pointer
            return pos + 2
        pos += 1 + length
    return pos


def _dns_read_name(data: bytes, pos: int) -> tuple[int, str]:
    """Read a (possibly compressed) DNS name; returns (new_pos, dotted_name)."""
    labels: list[str] = []
    jumps = 0
    original_pos: int = -1
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if (length & 0xC0) == 0xC0:           # compression pointer
            if pos + 1 >= len(data):
                break
            if original_pos == -1:
                original_pos = pos + 2
            offset = ((length & 0x3F) << 8) | data[pos + 1]
            pos = offset
            jumps += 1
            if jumps > 20:
                break
        else:
            pos += 1
            end = pos + length
            if end > len(data):
                break
            labels.append(data[pos:end].decode("ascii", errors="replace"))
            pos = end
    return (original_pos if original_pos != -1 else pos), ".".join(labels)


# ------------------------------------------------------------------ #
# Hostname Resolution – pure-Python, cross-platform                    #
# ------------------------------------------------------------------ #

_MDNS_ADDR = "224.0.0.251"
_MDNS_PORT = 5353


def _try_mdns_direct(ip: str) -> Optional[str]:
    """Pure-Python mDNS reverse-PTR lookup (works on Linux, macOS, Windows).

    Sends a PTR query for ``W.Z.Y.X.in-addr.arpa`` to the mDNS multicast
    group 224.0.0.251:5353 and returns the first PTR hostname in the answer.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    arpa = ".".join(reversed(parts)) + ".in-addr.arpa"

    txid = random.randint(1, 0xFFFF)
    # mDNS query: QR=0, Opcode=0, standard query; QU bit set in QCLASS
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    # QTYPE=PTR (12), QCLASS=IN with QU bit (0x8001)
    question = _dns_encode_name(arpa) + struct.pack(">HH", 12, 0x8001)
    packet = header + question

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        except OSError:
            pass
        sock.sendto(packet, (_MDNS_ADDR, _MDNS_PORT))

        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                break

            if len(data) < 12:
                continue
            resp_flags = struct.unpack(">H", data[2:4])[0]
            if not (resp_flags & 0x8000):   # must be a response (QR=1)
                continue
            ancount = struct.unpack(">H", data[6:8])[0]
            if ancount == 0:
                continue

            # Skip question section
            pos = 12
            qdcount = struct.unpack(">H", data[4:6])[0]
            for _ in range(qdcount):
                pos = _dns_skip_name(data, pos)
                if pos + 4 > len(data):
                    break
                pos += 4  # QTYPE + QCLASS

            # Parse answer records
            for _ in range(ancount):
                if pos >= len(data):
                    break
                pos, _rname = _dns_read_name(data, pos)
                if pos + 10 > len(data):
                    break
                rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
                pos += 10
                rdata_start = pos
                pos += rdlen
                if rtype == 12:  # PTR
                    _, hostname = _dns_read_name(data, rdata_start)
                    hostname = hostname.rstrip(".")
                    if hostname.endswith(".local"):
                        hostname = hostname[:-6]
                    if hostname:
                        return hostname
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return None


def _try_nbns_direct(ip: str) -> Optional[str]:
    """Pure-Python NetBIOS Node Status query (port 137).

    Works on Linux, macOS, and Windows — no ``nmblookup`` required.
    Returns the workstation name of the device at *ip*, or None.
    """
    # Encoded wildcard name: '*' = 0x2A
    # High nibble 2 → 'C' (0x43), low nibble A → 'K' (0x4B) → "CK"
    # Space padding (0x20): high 2 → 'C', low 0 → 'A' → "CA" × 15 = 30 chars
    encoded_star = b"CK" + b"CA" * 15  # 32 bytes total

    txid = random.randint(1, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    name_field = bytes([0x20]) + encoded_star + b"\x00"
    question = struct.pack(">HH", 0x0021, 0x0001)  # QTYPE=NBSTAT, QCLASS=IN
    packet = header + name_field + question

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)

        # rdata starts at:
        #   12 (header) + 34 (question name) + 4 (type+class)
        #   + 2 (answer name ptr) + 2+2+4+2 (type/class/ttl/rdlen) = 62
        # But we try a few offsets for robustness.
        for num_offset in (56, 62, 57):
            if num_offset >= len(data):
                continue
            num_names = data[num_offset]
            if num_names == 0 or num_names > 30:
                continue
            entry_start = num_offset + 1
            for _ in range(num_names):
                if entry_start + 18 > len(data):
                    break
                raw_name = data[entry_start:entry_start + 15]
                name_type = data[entry_start + 15]
                # Type 0x00=workstation, 0x03=messenger, 0x20=file server
                if name_type in (0x00, 0x03, 0x20):
                    decoded = raw_name.decode("ascii", errors="replace")
                    clean = decoded.strip("\x00 ").strip()
                    if (clean and len(clean) > 1
                            and clean not in ("*", "__MSBROWSE__")
                            and all(c.isprintable() for c in clean)):
                        return clean
                entry_start += 18
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return None


def _try_mdns_avahi(ip: str) -> Optional[str]:
    """Avahi mDNS lookup (Linux only, requires avahi-resolve)."""
    import subprocess
    try:
        out = subprocess.check_output(
            ["avahi-resolve", "--address", ip],
            text=True, timeout=3, stderr=subprocess.DEVNULL,
        )
        parts = out.strip().split()
        if len(parts) >= 2:
            return parts[-1]
    except Exception:
        pass
    return None


def _try_nbns_nmblookup(ip: str) -> Optional[str]:
    """NetBIOS lookup via nmblookup (Linux only)."""
    import subprocess
    try:
        out = subprocess.check_output(
            ["nmblookup", "-A", ip],
            text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            m = re.match(r"\s+(\S+)\s+<00>", line)
            if m:
                name = m.group(1).strip()
                if name not in ("<01>", "IS__MSBROWSE__", "__MSBROWSE__"):
                    return name
    except Exception:
        pass
    return None


def _try_rdns(ip: str) -> Optional[str]:
    """Reverse DNS (PTR) lookup via the system resolver."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        # Discard if the resolver returned the IP itself
        if hostname and hostname != ip:
            return hostname
    except Exception:
        pass
    return None


def _clean_hostname(raw: str) -> str:
    """Normalise a raw hostname into a friendly display name.

    - Strips ``.local`` / ``.lan`` / ``.home`` suffixes
    - Strips trailing dots
    - Returns empty string if the result is just an IP or obviously bad
    """
    if not raw:
        return ""
    h = raw.strip().rstrip(".")
    for suffix in (".local", ".lan", ".home", ".internal", ".localdomain"):
        if h.lower().endswith(suffix):
            h = h[: -len(suffix)]
    # Reject if it looks like a raw IP
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
        return ""
    return h


def resolve_hostname(ip: str) -> str:
    """Resolve device hostname using several methods.

    Order (cross-platform):
    1. Pure-Python mDNS multicast PTR query → works everywhere
    2. Pure-Python NetBIOS Node Status → Windows/Linux SMB devices
    3. Reverse DNS via system resolver → works everywhere
    4. avahi-resolve  (Linux only, requires avahi-daemon)
    5. nmblookup     (Linux only, requires samba-common-bin)

    Returns the best hostname found, or '' if nothing resolves.
    """
    import sys
    _IS_LINUX = sys.platform.startswith("linux")

    for fn in (_try_mdns_direct, _try_nbns_direct, _try_rdns):
        result = fn(ip)
        name = _clean_hostname(result or "")
        if name:
            return name

    # Linux-specific fallbacks (require external tools)
    if _IS_LINUX:
        for fn in (_try_mdns_avahi, _try_nbns_nmblookup):
            result = fn(ip)
            name = _clean_hostname(result or "")
            if name:
                return name

    return ""


# ------------------------------------------------------------------ #
# Device-type Inference                                                #
# ------------------------------------------------------------------ #

# Vendor prefix patterns mapped to device family hints.
# Note: list ordering matters – first match wins.
_VENDOR_HINTS: list[tuple[str, str]] = [
    # Apple
    ("Apple",              "Apple"),
    # Network infrastructure
    ("Cisco",              "Cisco"),
    ("TP-Link",            "Router"),
    ("NETGEAR",            "Router"),
    ("Netgear",            "Router"),
    ("Linksys",            "Router"),
    ("Huawei",             "Router"),
    ("D-Link",             "Router"),
    ("ASUSTeK",            "Router"),
    ("Asus",               "Router"),
    ("Belkin",             "Router"),
    ("Ubiquiti",           "Router"),
    ("Eero",               "Router"),
    ("Peplink",            "Router"),
    ("MikroTik",           "Router"),
    ("Arris",              "Router"),
    ("Zyxel",              "Router"),
    ("Actiontec",          "Router"),
    ("2Wire",              "Router"),
    ("Technicolor",        "Router"),
    ("AVM",                "Router"),      # Fritz!Box
    ("EnGenius",           "Router"),
    ("Ruckus",             "Router"),
    ("Meraki",             "Cisco"),
    # Mobile / handsets
    ("Samsung Electronics","Samsung"),
    ("Samsung",            "Samsung"),
    ("Xiaomi",             "Android"),
    ("OnePlus",            "Android"),
    ("Oppo",               "Android"),
    ("Vivo",               "Android"),
    ("Realme",             "Android"),
    ("Motorola",           "Android"),
    ("LGE",                "Android"),
    ("LG Electronics",     "SmartTV"),    # LG also makes TVs – SmartTV wins below
    ("HTC",                "Android"),
    ("ZTE",                "Android"),
    # Printers first (before generic PC so HP is caught as Printer)
    ("Hewlett Packard",    "Printer"),
    ("HP Inc",             "Printer"),
    # PC / Server
    ("Microsoft",          "Windows"),
    ("Intel",              "PC"),
    ("Realtek",            "PC"),
    ("Dell",               "PC"),
    ("Lenovo",             "PC"),
    ("Acer",               "PC"),
    ("ASRock",             "PC"),
    ("Gigabyte",           "PC"),
    # Virtual machines
    ("VMware",             "VM"),
    ("Oracle VirtualBox",  "VM"),
    ("Parallels",          "VM"),
    ("QEMU",               "VM"),
    ("Xen",                "VM"),
    # Special devices
    ("Raspberry Pi",       "RaspberryPi"),
    ("Google",             "Google"),
    ("Amazon",             "Amazon"),
    ("Amazon Tech",        "Amazon"),
    # Audio / speakers
    ("Sonos",              "Sonos"),
    ("Bose",               "Speaker"),
    ("Harman",             "Speaker"),
    # Smart home
    ("Philips",            "SmartHome"),
    ("Nest",               "SmartHome"),
    ("Ring",               "SmartHome"),
    ("Wyze",               "SmartHome"),
    ("Ecobee",             "SmartHome"),
    ("Lutron",             "SmartHome"),
    ("Shelly",             "SmartHome"),
    ("TP-Link Kasa",       "SmartHome"),
    ("Tuya",               "SmartHome"),
    ("Espressif",          "SmartHome"),   # ESP8266/ESP32 IoT modules
    ("Tasmota",            "SmartHome"),
    # More printers
    ("Canon",              "Printer"),
    ("Epson",              "Printer"),
    ("Brother",            "Printer"),
    ("Xerox",              "Printer"),
    ("Lexmark",            "Printer"),
    ("Kyocera",            "Printer"),
    # Entertainment
    ("Nintendo",           "GameConsole"),
    ("Sony Interactive",   "GameConsole"),
    ("Microsoft Xbox",     "GameConsole"),
    ("TCL",                "SmartTV"),
    ("Hisense",            "SmartTV"),
    ("Roku",               "SmartTV"),
    ("Vizio",              "SmartTV"),
    ("Sharp",              "SmartTV"),
    ("Toshiba",            "SmartTV"),
    # NAS / storage
    ("Synology",           "NAS"),
    ("QNAP",               "NAS"),
    ("Western Digital",    "NAS"),
    ("Seagate",            "NAS"),
]


# Device-type emoji icons for visual display in the GUI
DEVICE_ICONS: dict[str, str] = {
    "Router / Gateway":        "🔵",
    "Router / Access Point":   "📶",
    "Cisco Network Device":    "🌐",
    "Apple Mac":               "💻",
    "Apple iPhone / iPad":     "📱",
    "Apple TV":                "📺",
    "Apple Watch":             "⌚",
    "Windows PC":              "🖥️",
    "PC / Laptop":             "💻",
    "Android Device":          "📱",
    "Linux/Windows Server":    "🖧",
    "Network Printer":         "🖨️",
    "Smart TV":                "📺",
    "Game Console":            "🎮",
    "Smart Home Device":       "🏠",
    "Amazon Echo":             "🔊",
    "Amazon Fire Tablet":      "📱",
    "Amazon Device":           "📦",
    "Virtual Machine":         "💾",
    "Raspberry Pi":            "🍓",
    "Sonos Speaker":           "🎵",
    "Bluetooth Speaker":       "🔊",
    "NAS / Storage":           "🗄️",
    "Unknown Device":          "❓",
    "Unknown IoT Device":      "❓",
}


def get_device_icon(device_type: str) -> str:
    """Return an emoji icon for *device_type*, falling back to a generic icon."""
    return DEVICE_ICONS.get(device_type, "🔌")


def guess_device_type(
    ip: str,
    mac: str,
    vendor: str,
    hostname: str,
    open_ports: list[int],
    gateway_ip: str = "",
) -> str:
    """Return a human-readable device-type guess based on available signals."""
    vendor_up   = vendor.upper()
    hostname_up = hostname.upper()

    # Gateway / router (highest priority)
    if gateway_ip and ip == gateway_ip:
        return "Router / Gateway"

    # Determine vendor family (first match wins)
    family = ""
    for keyword, hint in _VENDOR_HINTS:
        if keyword.upper() in vendor_up:
            family = hint
            break

    # ── Apple ────────────────────────────────────────────────────────
    if family == "Apple":
        # Apple TV uses AirPlay / Remote app ports
        if 548 in open_ports or 5009 in open_ports or 7000 in open_ports:
            return "Apple TV"
        # Hostname patterns
        hn = hostname_up
        if any(k in hn for k in ("MACBOOK", "IMAC", "MAC-MINI", "MAC PRO", "MACPRO")):
            return "Apple Mac"
        if any(k in hn for k in ("IPHONE", "IPAD", "IPOD")):
            return "Apple iPhone / iPad"
        if "APPLE-TV" in hn or "APPLETV" in hn:
            return "Apple TV"
        if "WATCH" in hn:
            return "Apple Watch"
        # Ports: SSH/SMB → Mac; no ports → iPhone/iPad
        if 22 in open_ports or 445 in open_ports or 3389 in open_ports:
            return "Apple Mac"
        return "Apple iPhone / iPad"

    # ── Samsung / Android-likely ─────────────────────────────────────
    if family == "Samsung":
        # Samsung also makes TVs – check hostname/ports
        if any(k in hostname_up for k in ("TV", "SMART", "TIZEN")):
            return "Smart TV"
        if 8009 in open_ports or 8443 in open_ports:   # Chromecast / Cast
            return "Smart TV"
        return "Android Device"

    if family in ("Android", "Google"):
        if 8009 in open_ports:   # Google Cast
            return "Smart TV"
        if "CHROMECAST" in hostname_up:
            return "Smart TV"
        return "Android Device"

    # ── Amazon ───────────────────────────────────────────────────────
    if family == "Amazon":
        if any(k in hostname_up for k in ("ECHO", "ALEXA", "DOT", "SHOW")):
            return "Amazon Echo"
        if any(k in hostname_up for k in ("FIRE", "KINDLE")):
            return "Amazon Fire Tablet"
        return "Amazon Device"

    # ── Windows ──────────────────────────────────────────────────────
    if family == "Windows":
        return "Windows PC"
    if 445 in open_ports or 139 in open_ports or 3389 in open_ports:
        return "Windows PC"

    # ── VM ───────────────────────────────────────────────────────────
    if family == "VM":
        return "Virtual Machine"

    # ── Raspberry Pi ─────────────────────────────────────────────────
    if family == "RaspberryPi":
        return "Raspberry Pi"

    # ── Cisco ────────────────────────────────────────────────────────
    if family == "Cisco":
        return "Cisco Network Device"

    # ── Generic routers / APs ────────────────────────────────────────
    if family == "Router":
        return "Router / Access Point"

    # ── Smart TV via ports/hostname ──────────────────────────────────
    if family == "SmartTV":
        return "Smart TV"
    if any(k in hostname_up for k in ("TV", "SMART-TV", "SMARTTV", "ROKU", "FIRE-TV")):
        return "Smart TV"

    # ── Audio ────────────────────────────────────────────────────────
    if family == "Sonos":
        return "Sonos Speaker"
    if family == "Speaker":
        return "Bluetooth Speaker"

    # ── Smart home / IoT ────────────────────────────────────────────
    if family == "SmartHome":
        return "Smart Home Device"

    # ── Printers ────────────────────────────────────────────────────
    if family == "Printer":
        return "Network Printer"
    if 9100 in open_ports or 515 in open_ports or 631 in open_ports:
        return "Network Printer"

    # ── Game consoles ────────────────────────────────────────────────
    if family == "GameConsole":
        return "Game Console"

    # ── NAS ──────────────────────────────────────────────────────────
    if family == "NAS":
        return "NAS / Storage"
    if 5000 in open_ports and 445 in open_ports:   # typical Synology
        return "NAS / Storage"

    # ── Generic PC via ports ─────────────────────────────────────────
    if 22 in open_ports or 3389 in open_ports:
        return "Linux/Windows Server"
    if family == "PC":
        return "PC / Laptop"

    # ── Web-accessible device ────────────────────────────────────────
    if open_ports and any(p in open_ports for p in (80, 443, 8080, 8443)):
        return "Network Device / Server"

    # ── Catch-all ────────────────────────────────────────────────────
    if not hostname and vendor == "Unknown":
        return "Unknown IoT Device"

    return "Unknown Device"


# ------------------------------------------------------------------ #
# OS Fingerprinting                                                    #
# ------------------------------------------------------------------ #

def os_fingerprint_from_ttl(ttl: int) -> str:
    """Infer the operating system family from an observed IP TTL value.

    Typical initial TTL values:
      * Linux / Android / macOS / iOS  →  64
      * Windows                        → 128
      * Cisco / Network devices        → 255
    """
    if ttl <= 0:
        return "Unknown"
    if ttl <= 64:
        return "Linux / macOS / Android"
    if ttl <= 128:
        return "Windows"
    return "Cisco / Network Device"


# ------------------------------------------------------------------ #
# Public API                                                           #
# ------------------------------------------------------------------ #

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
        ttl:         Observed IP TTL value; when provided an ``os_hint``
                     key is included in the returned dict.

    Returns:
        Dict with keys: ip, mac, vendor, hostname, type, open_ports,
        icon, and optionally os_hint.
    """
    if open_ports is None:
        open_ports = []
    vendor      = oui_db.lookup(mac)
    hostname    = resolve_hostname(ip)
    device_type = guess_device_type(ip, mac, vendor, hostname, open_ports, gateway_ip)
    icon        = get_device_icon(device_type)
    result: dict = {
        "ip":         ip,
        "mac":        mac,
        "vendor":     vendor,
        "hostname":   hostname,
        "type":       device_type,
        "icon":       icon,
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
        f"  Type     : {info.get('icon', '')} {info.get('type', 'Unknown')}",
        f"  Ports    : {ports_str}",
        f"  Status   : {status}",
    ]
    return "\n".join(lines)
