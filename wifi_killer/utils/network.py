"""
utils/network.py – Shared network helpers.

Provides:
  - get_default_gateway()         -> Optional[str]
  - get_interface_ip(iface)       -> Optional[str]
  - get_interface_mac(iface)      -> Optional[str]
  - get_interface_subnet(iface)   -> Optional[str]
  - list_interfaces()             -> list[str]
  - list_all_subnets()            -> list[str]   (from all interfaces)
  - get_all_routes()              -> list[str]   (from routing table)
  - split_large_subnet(cidr, max_prefix) -> list[str]
  - get_candidate_subnets()       -> list[str]   (merged, deduplicated)
  - ip_to_int / int_to_ip         helpers
  - ping_once(host, timeout)      -> Optional[float]  RTT in ms
"""

from __future__ import annotations

import ipaddress
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Optional


def get_default_gateway() -> Optional[str]:
    """Return the default gateway IP address by reading /proc/net/route."""
    try:
        with open("/proc/net/route") as fh:
            for line in fh:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    gateway_hex = parts[2]
                    gateway_ip = socket.inet_ntoa(
                        struct.pack("<L", int(gateway_hex, 16))
                    )
                    return gateway_ip
    except Exception:
        pass
    # Fallback: parse `ip route`
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, timeout=5
        )
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def get_interface_mac(iface: str) -> Optional[str]:
    """Return the MAC address of a network interface."""
    try:
        path = f"/sys/class/net/{iface}/address"
        with open(path) as f:
            return f.read().strip().upper()
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "link", "show", iface], text=True, timeout=5
        )
        m = re.search(r"link/ether\s+([0-9a-f:]{17})", out, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    except Exception:
        pass
    return None


def get_interface_ip(iface: str) -> Optional[str]:
    """Return the IPv4 address assigned to a network interface."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], text=True, timeout=5
        )
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def get_interface_subnet(iface: str) -> Optional[str]:
    """Return the /24 subnet for a given interface IP (e.g. '192.168.1.0/24')."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], text=True, timeout=5
        )
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if m:
            ip = m.group(1)
            prefix = int(m.group(2))
            # Build network address
            ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            network_int = ip_int & mask
            network_ip = socket.inet_ntoa(struct.pack("!I", network_int))
            return f"{network_ip}/{prefix}"
    except Exception:
        pass
    return None


def list_interfaces() -> list[str]:
    """Return a list of up network interface names (excluding loopback)."""
    ifaces: list[str] = []
    try:
        out = subprocess.check_output(
            ["ip", "-o", "link", "show", "up"], text=True, timeout=5
        )
        for line in out.splitlines():
            m = re.match(r"\d+:\s+(\S+):", line)
            if m:
                name = m.group(1)
                if name != "lo":
                    ifaces.append(name)
    except Exception:
        pass
    return ifaces


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", n))


# ------------------------------------------------------------------ #
# ICMP ping helper                                                     #
# ------------------------------------------------------------------ #

def _icmp_checksum(data: bytes) -> int:
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += data[i] + (data[i + 1] << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ping_once(host: str, timeout: float = 1.0) -> Optional[float]:
    """Send one ICMP echo request and return RTT in milliseconds, or None.

    Requires a raw socket (root / CAP_NET_RAW).  Falls back to a TCP
    connect probe to port 80 when raw sockets are not available.

    Args:
        host:    IPv4 address or hostname string.
        timeout: How long to wait for a reply (seconds).

    Returns:
        RTT in milliseconds as a float, or None on timeout / error.
    """
    # Resolve hostname → IP first (catches 'not-a-valid-host.invalid' early)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None

    sock = None
    try:
        icmp_proto = socket.getprotobyname("icmp")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
        sock.settimeout(timeout)
        pid = threading.get_ident() & 0xFFFF
        header = struct.pack("!BBHHH", 8, 0, 0, pid, 1)
        payload = b"wifi-killer-ping"
        chk = _icmp_checksum(header + payload)
        header = struct.pack("!BBHHH", 8, 0, chk, pid, 1)
        packet = header + payload
        t0 = time.perf_counter()
        sock.sendto(packet, (ip, 0))
        while True:
            ready = select.select([sock], [], [], timeout)
            if not ready[0]:
                return None
            data, _ = sock.recvfrom(1024)
            elapsed = (time.perf_counter() - t0) * 1000
            if len(data) >= 28 and data[20] == 0:  # ICMP echo reply
                return elapsed
    except PermissionError:
        pass   # no raw socket: try TCP fallback
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    # TCP connect fallback (no raw socket)
    try:
        t0 = time.perf_counter()
        with socket.create_connection((ip, 80), timeout=timeout):
            pass
        return (time.perf_counter() - t0) * 1000
    except Exception:
        return None


# ------------------------------------------------------------------ #
# Multi-subnet / route-discovery helpers                               #
# ------------------------------------------------------------------ #

# RFC-1918 private address space
_PRIVATE_NETS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


def _is_private(net: ipaddress.IPv4Network) -> bool:
    """Return True if *net* is inside any RFC-1918 private range."""
    return any(net.overlaps(priv) for priv in _PRIVATE_NETS)


def list_all_subnets() -> list[str]:
    """Return the subnets of every active non-loopback interface.

    Unlike :func:`get_interface_subnet` (which takes a single interface),
    this iterates all interfaces and collects their subnets.
    """
    subnets: list[str] = []
    for iface in list_interfaces():
        subnet = get_interface_subnet(iface)
        if subnet and subnet not in subnets:
            subnets.append(subnet)
    return subnets


def get_all_routes() -> list[str]:
    """Return all non-default, non-loopback network routes as CIDR strings.

    Parses ``/proc/net/route`` first; falls back to ``ip route``.
    Results are filtered to RFC-1918 private space only.
    """
    routes: list[str] = []
    seen: set[str] = set()

    def _add(cidr: str) -> None:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            if net.prefixlen == 0 or net.is_loopback or net.is_multicast:
                return
            if not _is_private(net):
                return
            key = str(net)
            if key not in seen:
                seen.add(key)
                routes.append(key)
        except ValueError:
            pass

    # /proc/net/route: each non-default entry has Destination != 00000000
    try:
        with open("/proc/net/route") as fh:
            for line in fh:
                parts = line.strip().split()
                if len(parts) < 8:
                    continue
                dest_hex, mask_hex = parts[1], parts[7]
                if dest_hex == "00000000":
                    continue  # skip default route
                try:
                    dest_int = int(dest_hex, 16)
                    mask_int = int(mask_hex, 16)
                    dest_ip = socket.inet_ntoa(struct.pack("<I", dest_int))
                    mask_ip = socket.inet_ntoa(struct.pack("<I", mask_int))
                    net = ipaddress.IPv4Network(f"{dest_ip}/{mask_ip}", strict=False)
                    _add(str(net))
                except Exception:
                    pass
    except Exception:
        pass

    # Fallback / supplement: ``ip route``
    try:
        out = subprocess.check_output(["ip", "route"], text=True, timeout=5)
        for line in out.splitlines():
            # Lines like: "192.168.2.0/24 dev eth0 ..."
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m:
                _add(m.group(1))
    except Exception:
        pass

    return routes


def split_large_subnet(cidr: str, max_prefix: int = 24) -> list[str]:
    """Split *cidr* into subnets no larger than ``/max_prefix``.

    Example: '10.0.0.0/8' with max_prefix=24 → ['10.0.0.0/24', '10.0.1.0/24', …]
    Caps at 1024 subnets to stay practical.

    Args:
        cidr:       A CIDR string, e.g. '192.168.0.0/16'.
        max_prefix: Target prefix length (default 24).

    Returns:
        List of CIDR strings.
    """
    MAX_RESULTS = 1024
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return [cidr]

    if net.prefixlen >= max_prefix:
        return [str(net)]

    subnets = list(net.subnets(new_prefix=max_prefix))
    return [str(s) for s in subnets[:MAX_RESULTS]]


def _default_iface() -> str:
    """Return the first non-loopback interface or 'eth0' as fallback."""
    ifaces = list_interfaces()
    return ifaces[0] if ifaces else "eth0"


def get_candidate_subnets(max_prefix: int = 24) -> list[str]:
    """Build a merged, deduplicated list of subnets worth scanning.

    Combines:
    1. All subnets from active interfaces (direct).
    2. All subnets found in the routing table.

    Large networks (prefix < max_prefix) are split into /max_prefix chunks.

    Args:
        max_prefix: The largest subnet size to return (default /24 ≙ 256 hosts).

    Returns:
        Sorted list of unique CIDR strings.
    """
    raw: list[str] = list_all_subnets() + get_all_routes()
    seen: set[str] = set()
    result: list[str] = []

    for cidr in raw:
        chunks = split_large_subnet(cidr, max_prefix=max_prefix)
        for chunk in chunks:
            if chunk not in seen:
                seen.add(chunk)
                result.append(chunk)

    return sorted(result)

