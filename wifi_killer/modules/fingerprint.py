"""
fingerprint.py — Active device fingerprinting probes.

Used by the scanner / identifier to decide what kind of device a host is
when the MAC-OUI lookup is inconclusive — typically because the host has
randomised its WiFi MAC (default on modern macOS / iOS / Android).

Two MAC-independent probes are exposed:

* :func:`probe_mdns_services` — unicast mDNS service-discovery query.
  Apple / Google / Spotify / Sonos / printers / Plex all advertise
  themselves via mDNS, so the answer set is a strong device-type signal.
* :func:`probe_telltale_ports` — quick TCP-connect probe of a small
  curated list of device-specific ports (AFP, ARD, lockdownd, Cast …).

Both are designed to complete in well under one second per host and to
return empty cleanly on any error (so callers can use the result as
supplementary signal without having to handle exceptions).
"""

from __future__ import annotations

import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional


# ---------------------------------------------------------------------------
# mDNS service discovery
# ---------------------------------------------------------------------------

_MDNS_PORT = 5353
_DNS_TYPE_PTR = 12
_DNS_CLASS_IN = 1
# QU bit (top bit of class field) requests a unicast reply so non-multicast
# capable senders still receive the answer.
_DNS_CLASS_IN_UNICAST = 0x8001


def _encode_dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if not label:
            continue
        b = label.encode("utf-8")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _build_mdns_query(name: str = "_services._dns-sd._udp.local") -> bytes:
    """Build an mDNS PTR query for *name* with the QU (unicast) bit set."""
    header = struct.pack("!HHHHHH", 0xB33F, 0, 1, 0, 0, 0)
    question = _encode_dns_name(name) + struct.pack(
        "!HH", _DNS_TYPE_PTR, _DNS_CLASS_IN_UNICAST
    )
    return header + question


def _skip_dns_name(data: bytes, offset: int) -> int:
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += length + 1
    return offset


def _read_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a possibly-compressed DNS name, return (name, end-of-name offset)."""
    labels: list[str] = []
    visited: set[int] = set()
    seen_pointer = False
    end_offset = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not seen_pointer:
                end_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            if not seen_pointer:
                end_offset = offset + 2
            seen_pointer = True
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in visited:
                break
            visited.add(ptr)
            offset = ptr
            continue
        offset += 1
        labels.append(
            data[offset:offset + length].decode("utf-8", errors="replace")
        )
        offset += length
    return ".".join(labels), end_offset


def _parse_mdns_services(data: bytes) -> set[str]:
    """Parse an mDNS response packet, return the set of service names found."""
    services: set[str] = set()
    if len(data) < 12:
        return services
    try:
        _, _, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
        offset = 12
        for _ in range(qd):
            offset = _skip_dns_name(data, offset)
            offset += 4
        for _ in range(an):
            offset = _skip_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _, _, rdlength = struct.unpack(
                "!HHIH", data[offset:offset + 10]
            )
            offset += 10
            rdata_end = offset + rdlength
            if rtype == _DNS_TYPE_PTR and rdata_end <= len(data):
                name, _ = _read_dns_name(data, offset)
                name = name.strip(".")
                if name.endswith(".local"):
                    name = name[: -len(".local")]
                if name:
                    services.add(name)
            offset = rdata_end
    except Exception:
        pass
    return services


def probe_mdns_services(ip: str, timeout: float = 0.7) -> set[str]:
    """Send a unicast mDNS service-discovery query to *ip*.

    Returns the set of mDNS service names the host advertises (e.g.
    ``{"_companion-link._tcp", "_airplay._tcp"}``). Apple devices respond
    to unicast queries thanks to the QU bit; non-mDNS hosts return empty.
    Designed to fail silently on every error so callers can use it as
    supplementary signal.
    """
    if not ip:
        return set()
    packet = _build_mdns_query()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (ip, _MDNS_PORT))
        except OSError:
            return set()
        services: set[str] = set()
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break
            services |= _parse_mdns_services(data)
        return services
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Tell-tale TCP port probe
# ---------------------------------------------------------------------------

# Ordered list of (port, hint). The first port that responds wins. Each is
# either uniquely Apple, uniquely Windows, or uniquely a known device class.
_TELLTALE_PORTS: list[tuple[int, str]] = [
    (62078, "iOS Device"),         # lockdownd — iPhone / iPad
    (3283,  "Apple Mac"),          # Apple Remote Desktop / Net Assistant
    (548,   "Apple Mac"),          # AFP (Apple Filing Protocol)
    (7000,  "Apple AirPlay"),      # AirPlay receiver (Apple TV / HomePod)
    (5009,  "Apple AirPort"),      # AirPort utility admin
    (32400, "Plex Media Server"),  # Plex
    (8009,  "Chromecast / Cast"),  # Google Cast
    (9100,  "Network Printer"),    # RAW printing
    (631,   "Network Printer"),    # IPP / CUPS
    (3389,  "Windows PC"),         # RDP
    (445,   "Windows / Mac (SMB)"),
]


def probe_telltale_ports(
    ip: str,
    ports: Optional[list[int]] = None,
    timeout: float = 0.35,
    max_workers: int = 6,
) -> dict[int, str]:
    """Quick TCP-connect probe of revealing ports. Returns ``{port: hint}``.

    Designed for the fast path: 11 ports × ~350 ms timeout = ~4 s worst
    case if all closed, but a parallel pool of 6 workers means the wall
    clock is ~700 ms when probing the default port set. Closed/filtered
    ports never block long because TCP returns ECONNREFUSED quickly on
    a LAN.
    """
    if not ip:
        return {}
    candidates = ports or [p for p, _ in _TELLTALE_PORTS]
    hint_for = dict(_TELLTALE_PORTS)
    open_with_hint: dict[int, str] = {}

    def _probe(port: int) -> tuple[int, bool]:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return port, True
        except Exception:
            return port, False

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for port, is_open in pool.map(_probe, candidates):
            if is_open:
                open_with_hint[port] = hint_for.get(port, "")
    return open_with_hint


# ---------------------------------------------------------------------------
# Signal-to-device-type classification
# ---------------------------------------------------------------------------

# (icon, label) — kept in sync with DEVICE_ICONS in identifier.py so the
# scan-results table uses consistent emoji.
_TYPE_ICON = {
    "Apple iPhone / iPad":      "📱",
    "Apple Mac":                "💻",
    "Apple TV":                 "📺",
    "Apple Watch":              "⌚",
    "Apple HomePod":            "🔊",
    "Apple Device":             "🍎",
    "Network Printer":          "🖨️",
    "Smart TV":                 "📺",
    "Plex Media Server":        "🎬",
    "Windows PC":               "🖥️",
    "Linux Server":             "🖧",
    "Sonos Speaker":            "🎵",
}


def classify_from_fingerprint(
    services: set[str],
    open_ports: dict[int, str],
) -> Optional[tuple[str, str]]:
    """Combine mDNS + port signals into a (device_type, icon) decision.

    Returns ``None`` if neither signal yields a confident classification.

    Service-name heuristics (all mDNS service-type prefixes):

    * ``_apple-mobdev2``    → iOS (iPhone / iPad)
    * ``_appletv-v2`` etc.  → Apple TV
    * ``_hap``              → HomeKit Accessory (HomePod, smart bulb)
    * ``_asquic``           → macOS-only QUIC service → Mac
    * ``_companion-link`` + (AFP/SMB/SSH) → Mac
    * ``_companion-link`` + ``_airplay``  → at least an Apple device
    """

    svc_prefixes = {s.split(".")[0].lower() for s in services}

    def has(*names: str) -> bool:
        return any(n.lower() in svc_prefixes for n in names)

    # ── Printers — strongest signal first ────────────────────────────
    if has("_ipp", "_pdl-datastream", "_printer", "_ipps"):
        return "Network Printer", _TYPE_ICON["Network Printer"]
    if 9100 in open_ports or 631 in open_ports:
        return "Network Printer", _TYPE_ICON["Network Printer"]

    # ── Sonos / Spotify ──────────────────────────────────────────────
    if has("_sonos", "_spotify-connect"):
        return "Sonos Speaker", _TYPE_ICON["Sonos Speaker"]

    # ── Plex ─────────────────────────────────────────────────────────
    if 32400 in open_ports:
        return "Plex Media Server", _TYPE_ICON["Plex Media Server"]

    # ── Google / Chromecast ──────────────────────────────────────────
    if has("_googlecast", "_googlezone"):
        return "Smart TV", _TYPE_ICON["Smart TV"]
    if 8009 in open_ports:
        return "Smart TV", _TYPE_ICON["Smart TV"]

    # ── Apple family — distinguish iPhone / Mac / Apple TV / HomePod ─
    apple_signals = {
        "_apple-mobdev", "_apple-mobdev2",
        "_companion-link", "_airplay", "_raop",
        "_homekit", "_airdrop", "_airport",
        "_rdlink", "_touch-able", "_asquic",
        "_appletv-v2", "_mediaremotetv", "_apple-pairable",
    }
    has_apple_mdns = any(p in svc_prefixes for p in apple_signals)

    is_ios = has("_apple-mobdev2", "_apple-mobdev")
    is_apple_tv = has("_appletv-v2", "_mediaremotetv", "_touch-able")
    is_homepod = has("_hap")  # HomeKit Accessory Protocol (HomePod / sensors)
    # ``_asquic`` is only emitted by macOS, never iOS / tvOS / HomePod.
    is_mac_only_service = has("_asquic")
    is_mac_share = has(
        "_afpovertcp", "_smb", "_workstation",
        "_adisk", "_device-info", "_rfb", "_ssh",
    )
    is_airplay_receiver = has("_airplay") and has("_raop")
    apple_port_hits = any(
        p in open_ports for p in (548, 3283, 5009, 7000, 62078)
    )

    if is_ios or 62078 in open_ports:
        return "Apple iPhone / iPad", _TYPE_ICON["Apple iPhone / iPad"]
    # Apple TV before Mac because TV advertises specific service types.
    if is_apple_tv:
        return "Apple TV", _TYPE_ICON["Apple TV"]
    if is_homepod and is_airplay_receiver and not is_mac_only_service:
        return "Apple HomePod", _TYPE_ICON["Apple HomePod"]
    # Mac signals: macOS-only mDNS service, classic share protocols, or
    # the Apple Remote Desktop / AFP ports.
    if is_mac_only_service or is_mac_share \
            or 548 in open_ports or 3283 in open_ports:
        return "Apple Mac", _TYPE_ICON["Apple Mac"]
    # Generic Apple — companion-link / AirPlay receiver without finer signal.
    if has_apple_mdns or apple_port_hits:
        return "Apple Device", _TYPE_ICON["Apple Device"]

    # ── Windows ──────────────────────────────────────────────────────
    if 3389 in open_ports:
        return "Windows PC", _TYPE_ICON["Windows PC"]
    # NOTE: SMB (445) alone is too generic — Macs and NAS units use it too.

    return None
