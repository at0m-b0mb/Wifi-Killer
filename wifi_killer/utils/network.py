"""
utils/network.py – Shared network helpers (Linux, macOS, Windows).

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

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

_IS_LINUX = sys.platform.startswith("linux")
_IS_MACOS = sys.platform == "darwin"
_IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Scapy cross-platform utilities (optional but preferred)
# ---------------------------------------------------------------------------

try:
    from scapy.all import (  # type: ignore
        conf as _scapy_conf,
        get_if_addr as _scapy_get_if_addr,
        get_if_hwaddr as _scapy_get_if_hwaddr,
        get_if_list as _scapy_get_if_list,
    )
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------

def get_default_gateway() -> Optional[str]:
    """Return the default gateway IP address."""

    # 1. Scapy routing table (cross-platform)
    if _SCAPY_AVAILABLE:
        try:
            _, gw, _ = _scapy_conf.route.route("0.0.0.0")
            if gw and gw != "0.0.0.0":
                return gw
        except Exception:
            pass

    # 2. Linux: /proc/net/route then ip route
    if _IS_LINUX:
        try:
            with open("/proc/net/route") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        gateway_ip = socket.inet_ntoa(
                            struct.pack("<L", int(parts[2], 16))
                        )
                        return gateway_ip
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"], text=True, timeout=5
            )
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass

    # 3. macOS: route -n get default
    elif _IS_MACOS:
        try:
            out = subprocess.check_output(
                ["route", "-n", "get", "default"], text=True, timeout=5
            )
            m = re.search(r"gateway:\s+(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["netstat", "-rn", "-f", "inet"], text=True, timeout=5
            )
            for line in out.splitlines():
                parts = line.split()
                if parts and parts[0] == "default" and len(parts) >= 2:
                    gw = parts[1]
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
                        return gw
        except Exception:
            pass

    # 4. Windows: route print 0.0.0.0 then ipconfig
    elif _IS_WINDOWS:
        try:
            out = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
            )
            for line in out.splitlines():
                parts = line.split()
                if (len(parts) >= 3 and parts[0] == "0.0.0.0"
                        and parts[1] == "0.0.0.0"):
                    gw = parts[2]
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
                        return gw
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["ipconfig"],
                text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
            )
            m = re.search(r"Default Gateway[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# Interface MAC
# ---------------------------------------------------------------------------

def get_interface_mac(iface: str) -> Optional[str]:
    """Return the MAC address of a network interface."""

    # 1. Scapy (cross-platform)
    if _SCAPY_AVAILABLE:
        try:
            mac = _scapy_get_if_hwaddr(iface)
            if mac and mac not in ("00:00:00:00:00:00", ""):
                return mac.upper()
        except Exception:
            pass

    # 2. Linux: /sys/class/net then ip link show
    if _IS_LINUX:
        try:
            with open(f"/sys/class/net/{iface}/address") as f:
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

    # 3. macOS/BSD: ifconfig
    elif _IS_MACOS:
        try:
            out = subprocess.check_output(
                ["ifconfig", iface], text=True, timeout=5
            )
            m = re.search(r"ether\s+([0-9a-f:]{17})", out, re.IGNORECASE)
            if m:
                return m.group(1).upper()
        except Exception:
            pass

    # 4. Windows: getmac /fo csv /v
    elif _IS_WINDOWS:
        try:
            out = subprocess.check_output(
                ["getmac", "/fo", "csv", "/v"],
                text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
            )
            for line in out.splitlines():
                if iface.lower() in line.lower():
                    m = re.search(
                        r"([0-9A-F]{2}[-:][0-9A-F]{2}[-:][0-9A-F]{2}"
                        r"[-:][0-9A-F]{2}[-:][0-9A-F]{2}[-:][0-9A-F]{2})",
                        line, re.IGNORECASE,
                    )
                    if m:
                        return m.group(1).replace("-", ":").upper()
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# Interface IP
# ---------------------------------------------------------------------------

def get_interface_ip(iface: str) -> Optional[str]:
    """Return the IPv4 address assigned to a network interface."""

    # 1. Scapy (cross-platform)
    if _SCAPY_AVAILABLE:
        try:
            ip = _scapy_get_if_addr(iface)
            if ip and ip != "0.0.0.0":
                return ip
        except Exception:
            pass

    # 2. Linux: ip -4 addr show
    if _IS_LINUX:
        try:
            out = subprocess.check_output(
                ["ip", "-4", "addr", "show", iface], text=True, timeout=5
            )
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", out)
            if m:
                return m.group(1)
        except Exception:
            pass

    # 3. macOS/BSD: ifconfig
    elif _IS_MACOS:
        try:
            out = subprocess.check_output(
                ["ifconfig", iface], text=True, timeout=5
            )
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask", out)
            if m:
                return m.group(1)
        except Exception:
            pass

    # 4. Windows: ipconfig /all
    elif _IS_WINDOWS:
        try:
            out = subprocess.check_output(
                ["ipconfig", "/all"],
                text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
            )
            sections = re.split(r"\r?\n\r?\n", out)
            for section in sections:
                if iface.lower() in section.lower():
                    m = re.search(
                        r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", section
                    )
                    if m:
                        return m.group(1)
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# Interface subnet
# ---------------------------------------------------------------------------

def get_interface_subnet(iface: str) -> Optional[str]:
    """Return the subnet CIDR for a given interface (e.g. '192.168.1.0/24')."""

    # 1. Linux: ip -4 addr show
    if _IS_LINUX:
        try:
            out = subprocess.check_output(
                ["ip", "-4", "addr", "show", iface], text=True, timeout=5
            )
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
            if m:
                ip = m.group(1)
                prefix = int(m.group(2))
                ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
                mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                network_ip = socket.inet_ntoa(struct.pack("!I", ip_int & mask))
                return f"{network_ip}/{prefix}"
        except Exception:
            pass

    # 2. macOS/BSD: ifconfig (netmask is hex on macOS, e.g. 0xffffff00)
    elif _IS_MACOS:
        try:
            out = subprocess.check_output(
                ["ifconfig", iface], text=True, timeout=5
            )
            m = re.search(
                r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+"
                r"(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)",
                out, re.IGNORECASE,
            )
            if m:
                ip = m.group(1)
                raw_mask = m.group(2)
                if raw_mask.startswith("0x") or raw_mask.startswith("0X"):
                    mask_int = int(raw_mask, 16)
                else:
                    mask_int = struct.unpack("!I", socket.inet_aton(raw_mask))[0]
                prefix = bin(mask_int & 0xFFFFFFFF).count("1")
                ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
                network_ip = socket.inet_ntoa(struct.pack("!I", ip_int & mask_int))
                return f"{network_ip}/{prefix}"
        except Exception:
            pass

    # 3. Windows: ipconfig /all
    elif _IS_WINDOWS:
        try:
            ip = get_interface_ip(iface)
            if ip:
                out = subprocess.check_output(
                    ["ipconfig", "/all"],
                    text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
                )
                sections = re.split(r"\r?\n\r?\n", out)
                for section in sections:
                    if iface.lower() in section.lower():
                        m = re.search(
                            r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", section
                        )
                        if m:
                            netmask = m.group(1)
                            mask_int = struct.unpack(
                                "!I", socket.inet_aton(netmask)
                            )[0]
                            ip_int = struct.unpack(
                                "!I", socket.inet_aton(ip)
                            )[0]
                            network_ip = socket.inet_ntoa(
                                struct.pack("!I", ip_int & mask_int)
                            )
                            prefix = bin(mask_int).count("1")
                            return f"{network_ip}/{prefix}"
        except Exception:
            pass

    # 4. Fallback: derive subnet from Scapy routing table
    if _SCAPY_AVAILABLE:
        try:
            ip = get_interface_ip(iface)
            if ip:
                for net, mask_int, gw, dev, addr, *_ in _scapy_conf.route.routes:
                    if dev == iface and gw == "0.0.0.0" and mask_int != 0:
                        prefix = bin(mask_int & 0xFFFFFFFF).count("1")
                        network_ip = socket.inet_ntoa(
                            struct.pack("!I", net & mask_int)
                        )
                        return f"{network_ip}/{prefix}"
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# Interface list
# ---------------------------------------------------------------------------

def list_interfaces() -> list[str]:
    """Return a list of up network interface names (excluding loopback)."""

    # 1. Scapy (cross-platform)
    if _SCAPY_AVAILABLE:
        try:
            ifaces = _scapy_get_if_list()
            result = [
                i for i in ifaces
                if i and not i.lower().startswith("lo")
                and i.lower() not in ("loopback", "lo0")
            ]
            if result:
                return result
        except Exception:
            pass

    # 2. Linux: ip -o link show up
    if _IS_LINUX:
        try:
            out = subprocess.check_output(
                ["ip", "-o", "link", "show", "up"], text=True, timeout=5
            )
            ifaces: list[str] = []
            for line in out.splitlines():
                m = re.match(r"\d+:\s+(\S+):", line)
                if m:
                    name = m.group(1)
                    if name != "lo":
                        ifaces.append(name)
            return ifaces
        except Exception:
            pass

    # 3. macOS: ifconfig -l then filter out loopback
    elif _IS_MACOS:
        try:
            out = subprocess.check_output(
                ["ifconfig", "-l"], text=True, timeout=5
            )
            ifaces = [
                i for i in out.split()
                if i and not i.startswith("lo")
            ]
            # Filter to only interfaces that have an IPv4 address
            active = []
            for iface in ifaces:
                try:
                    ip_out = subprocess.check_output(
                        ["ifconfig", iface], text=True, timeout=3
                    )
                    if "inet " in ip_out and "status: active" in ip_out.lower():
                        active.append(iface)
                    elif "inet " in ip_out:
                        active.append(iface)
                except Exception:
                    pass
            return active if active else ifaces
        except Exception:
            pass

    # 4. Windows: ipconfig adapter names
    elif _IS_WINDOWS:
        try:
            out = subprocess.check_output(
                ["ipconfig"],
                text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
            )
            ifaces = []
            for line in out.splitlines():
                m = re.match(r"^(\S.+?)\s+adapter\s+(.+?)\s*:", line)
                if m:
                    ifaces.append(m.group(2).strip())
            return ifaces
        except Exception:
            pass

    return []


# ---------------------------------------------------------------------------
# Integer ↔ IP helpers
# ---------------------------------------------------------------------------

def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", n))


# ---------------------------------------------------------------------------
# ICMP ping helper
# ---------------------------------------------------------------------------

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

    Falls back to a TCP connect probe to port 80 when raw sockets are
    not available.
    """
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
            if len(data) >= 28 and data[20] == 0:
                return elapsed
    except PermissionError:
        pass
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    # TCP connect fallback
    try:
        t0 = time.perf_counter()
        with socket.create_connection((ip, 80), timeout=timeout):
            pass
        return (time.perf_counter() - t0) * 1000
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Multi-subnet / route-discovery helpers
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


def _is_private(net: ipaddress.IPv4Network) -> bool:
    return any(net.overlaps(priv) for priv in _PRIVATE_NETS)


def list_all_subnets() -> list[str]:
    """Return the subnets of every active non-loopback interface."""
    subnets: list[str] = []
    for iface in list_interfaces():
        subnet = get_interface_subnet(iface)
        if subnet and subnet not in subnets:
            subnets.append(subnet)
    return subnets


def get_all_routes() -> list[str]:
    """Return all non-default, non-loopback RFC-1918 routes as CIDR strings."""
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

    # Linux
    if _IS_LINUX:
        try:
            with open("/proc/net/route") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) < 8:
                        continue
                    dest_hex, mask_hex = parts[1], parts[7]
                    if dest_hex == "00000000":
                        continue
                    try:
                        dest_ip = socket.inet_ntoa(
                            struct.pack("<I", int(dest_hex, 16))
                        )
                        mask_ip = socket.inet_ntoa(
                            struct.pack("<I", int(mask_hex, 16))
                        )
                        net = ipaddress.IPv4Network(
                            f"{dest_ip}/{mask_ip}", strict=False
                        )
                        _add(str(net))
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["ip", "route"], text=True, timeout=5
            )
            for line in out.splitlines():
                m = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)", line)
                if m:
                    _add(m.group(1))
        except Exception:
            pass

    # macOS
    elif _IS_MACOS:
        try:
            out = subprocess.check_output(
                ["netstat", "-rn", "-f", "inet"], text=True, timeout=5
            )
            for line in out.splitlines():
                parts = line.split()
                if not parts or parts[0] in (
                    "Destination", "default", "127.0.0.1/8", "127",
                ):
                    continue
                dest = parts[0]
                if "/" in dest:
                    _add(dest)
        except Exception:
            pass

    # Windows
    elif _IS_WINDOWS:
        try:
            out = subprocess.check_output(
                ["route", "print"],
                text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                    dest = parts[0]
                    mask = parts[1]
                    if dest == "0.0.0.0":
                        continue
                    try:
                        net = ipaddress.IPv4Network(
                            f"{dest}/{mask}", strict=False
                        )
                        _add(str(net))
                    except Exception:
                        pass
        except Exception:
            pass

    # Scapy routing table supplement (cross-platform)
    if _SCAPY_AVAILABLE:
        try:
            for net_int, mask_int, gw, dev, addr, *_ in _scapy_conf.route.routes:
                if net_int == 0 or mask_int == 0:
                    continue
                try:
                    net_ip = socket.inet_ntoa(struct.pack("!I", net_int))
                    mask_ip = socket.inet_ntoa(struct.pack("!I", mask_int))
                    cidr = str(
                        ipaddress.IPv4Network(f"{net_ip}/{mask_ip}", strict=False)
                    )
                    _add(cidr)
                except Exception:
                    pass
        except Exception:
            pass

    return routes


def split_large_subnet(cidr: str, max_prefix: int = 24) -> list[str]:
    """Split *cidr* into subnets no larger than ``/max_prefix`` (cap: 1024)."""
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
    """Return the best available non-loopback interface name."""
    # Prefer Scapy's chosen default interface
    if _SCAPY_AVAILABLE:
        try:
            iface = str(_scapy_conf.iface)
            if iface and iface not in ("lo", "lo0", "loopback"):
                return iface
        except Exception:
            pass
    ifaces = list_interfaces()
    if ifaces:
        return ifaces[0]
    # Hard-coded fallbacks per platform
    if _IS_MACOS:
        return "en0"
    if _IS_WINDOWS:
        return "Ethernet"
    return "eth0"


def get_candidate_subnets(max_prefix: int = 24) -> list[str]:
    """Merged, deduplicated list of subnets worth scanning."""
    raw: list[str] = list_all_subnets() + get_all_routes()
    seen: set[str] = set()
    result: list[str] = []
    for cidr in raw:
        for chunk in split_large_subnet(cidr, max_prefix=max_prefix):
            if chunk not in seen:
                seen.add(chunk)
                result.append(chunk)
    return sorted(result)
