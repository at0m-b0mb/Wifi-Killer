"""
modules/scanner.py – Module 1: Host Discovery.

Scan types:
  1. fast_scan()        – ARP-only broadcast sweep
  2. balanced_scan()    – ARP + ICMP ping, merged & deduplicated
  3. stealth_scan()     – TCP SYN probe to selected ports
  4. monitor_mode()     – Continuous ARP sweep with join/leave alerts

All scan functions return a list of dicts:
  {ip, mac, vendor, ping, open_ports, ...}
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

try:
    from scapy.all import (  # type: ignore
        ARP,
        IP,
        ICMP,
        TCP,
        Ether,
        sr,
        srp,
        sr1,
    )

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from wifi_killer.modules.identifier import oui_db
from wifi_killer.utils.network import get_interface_subnet, _default_iface


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _check_scapy() -> None:
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "Scapy is not installed. Install it with: pip install scapy"
        )


def _arp_sweep(
    target: str,
    iface: Optional[str] = None,
    timeout: float = 2.0,
) -> list[dict]:
    """Send ARP 'who-has' broadcasts and collect replies.

    Args:
        target:  Scapy target string (e.g. '192.168.1.0/24' or single IP).
        iface:   Network interface; None lets Scapy choose.
        timeout: Seconds to wait for replies.

    Returns:
        List of {ip, mac, vendor} dicts.
    """
    _check_scapy()
    kwargs: dict = {"timeout": timeout, "verbose": 0}
    if iface:
        kwargs["iface"] = iface

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    answered, _ = srp(pkt, **kwargs)

    results: list[dict] = []
    seen_ips: set[str] = set()
    for sent, rcv in answered:
        ip = rcv[ARP].psrc
        mac = rcv[Ether].src.upper()
        if ip not in seen_ips:
            seen_ips.add(ip)
            results.append(
                {"ip": ip, "mac": mac, "vendor": oui_db.lookup(mac), "ping": False}
            )
    return results


def _icmp_sweep(
    subnet: str,
    iface: Optional[str] = None,
    timeout: float = 2.0,
) -> list[dict]:
    """Send ICMP echo requests to each host in *subnet*.

    Returns list of {ip, ping} dicts for hosts that replied.
    """
    _check_scapy()
    import ipaddress

    net = ipaddress.IPv4Network(subnet, strict=False)
    hosts = [str(h) for h in net.hosts()]

    kwargs: dict = {"timeout": timeout, "verbose": 0, "inter": 0.005}
    if iface:
        kwargs["iface"] = iface

    pkts = [IP(dst=h) / ICMP() for h in hosts]
    answered, _ = sr(pkts, **kwargs)

    pinged: set[str] = set()
    for sent, rcv in answered:
        if rcv.haslayer(ICMP) and rcv[ICMP].type == 0:
            pinged.add(rcv[IP].src)
    return [{"ip": ip, "ping": True} for ip in pinged]


def _tcp_syn_probe(
    ip: str,
    ports: list[int],
    iface: Optional[str] = None,
    timeout: float = 1.5,
    delay: float = 0.0,
) -> list[int]:
    """Send TCP SYN packets and return list of open ports (SYN-ACK received)."""
    _check_scapy()
    open_ports: list[int] = []
    for port in ports:
        if delay:
            time.sleep(delay)
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        kwargs: dict = {"timeout": timeout, "verbose": 0}
        if iface:
            kwargs["iface"] = iface
        resp = sr1(pkt, **kwargs)
        if resp and resp.haslayer(TCP):
            flags = resp[TCP].flags
            # SYN-ACK = 0x12
            if flags & 0x12 == 0x12:
                open_ports.append(port)
    return open_ports


# ------------------------------------------------------------------ #
# Public scan API                                                      #
# ------------------------------------------------------------------ #

def fast_scan(
    subnet: Optional[str] = None,
    iface: Optional[str] = None,
    timeout: float = 2.0,
) -> list[dict]:
    """ARP broadcast sweep of the local subnet.

    Args:
        subnet: CIDR string (e.g. '192.168.1.0/24').  Auto-detected if None.
        iface:  Network interface.
        timeout: Seconds to wait.

    Returns:
        List of {ip, mac, vendor, ping} dicts.
    """
    _check_scapy()
    if subnet is None:
        detected = get_interface_subnet(iface or _default_iface())
        if detected is None:
            import sys
            print("[WARN] Could not auto-detect subnet; falling back to 192.168.1.0/24", file=sys.stderr)
        subnet = detected or "192.168.1.0/24"
    return _arp_sweep(subnet, iface=iface, timeout=timeout)


def balanced_scan(
    subnet: Optional[str] = None,
    iface: Optional[str] = None,
    timeout: float = 2.0,
) -> list[dict]:
    """ARP scan + ICMP ping sweep run in parallel threads.

    Returns merged, deduplicated list with ping=True where ICMP replied.
    """
    _check_scapy()
    if subnet is None:
        detected = get_interface_subnet(iface or _default_iface())
        if detected is None:
            import sys
            print("[WARN] Could not auto-detect subnet; falling back to 192.168.1.0/24", file=sys.stderr)
        subnet = detected or "192.168.1.0/24"

    arp_results: list[dict] = []
    icmp_results: list[dict] = []

    def _arp_worker():
        arp_results.extend(_arp_sweep(subnet, iface=iface, timeout=timeout))

    def _icmp_worker():
        icmp_results.extend(_icmp_sweep(subnet, iface=iface, timeout=timeout))

    t1 = threading.Thread(target=_arp_worker, daemon=True)
    t2 = threading.Thread(target=_icmp_worker, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Build a map from IP → entry
    merged: dict[str, dict] = {}
    for entry in arp_results:
        merged[entry["ip"]] = entry.copy()

    pinged_ips = {e["ip"] for e in icmp_results}

    # Hosts found by ICMP but not ARP (uncommon – add minimal entry)
    for e in icmp_results:
        if e["ip"] not in merged:
            merged[e["ip"]] = {
                "ip": e["ip"],
                "mac": "??:??:??:??:??:??",
                "vendor": "Unknown",
                "ping": True,
            }

    # Mark ping flag
    for ip in merged:
        merged[ip]["ping"] = ip in pinged_ips

    return list(merged.values())


def stealth_scan(
    subnet: Optional[str] = None,
    iface: Optional[str] = None,
    ports: Optional[list[int]] = None,
    delay: float = 0.5,
    timeout: float = 1.5,
) -> list[dict]:
    """TCP SYN probe to common ports with configurable inter-probe delay.

    Performs a light ARP sweep first to enumerate live hosts, then probes
    each host with TCP SYN packets.

    Args:
        subnet:  CIDR subnet string.
        iface:   Network interface.
        ports:   Ports to probe (default: [22, 80, 443, 8080]).
        delay:   Seconds between individual SYN probes (stealth rate).
        timeout: Seconds to wait for each reply.

    Returns:
        List of {ip, mac, vendor, open_ports} dicts.
    """
    _check_scapy()
    if ports is None:
        ports = [22, 80, 443, 8080]
    if subnet is None:
        detected = get_interface_subnet(iface or _default_iface())
        if detected is None:
            import sys
            print("[WARN] Could not auto-detect subnet; falling back to 192.168.1.0/24", file=sys.stderr)
        subnet = detected or "192.168.1.0/24"

    # Discover live hosts via ARP first (quiet, 1 s timeout)
    live_hosts = _arp_sweep(subnet, iface=iface, timeout=1.0)

    results: list[dict] = []
    for host in live_hosts:
        open_ports = _tcp_syn_probe(
            host["ip"], ports, iface=iface, timeout=timeout, delay=delay
        )
        entry = host.copy()
        entry["open_ports"] = open_ports
        results.append(entry)
    return results


# ------------------------------------------------------------------ #
# Continuous Monitor Mode                                              #
# ------------------------------------------------------------------ #

class NetworkMonitor:
    """Continuously ARP-sweeps the subnet and fires callbacks on join/leave."""

    def __init__(
        self,
        subnet: Optional[str] = None,
        iface: Optional[str] = None,
        interval: float = 30.0,
        on_new: Optional[Callable[[dict], None]] = None,
        on_left: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self.subnet = subnet
        self.iface = iface
        self.interval = interval
        self.on_new = on_new or (lambda d: None)
        self.on_left = on_left or (lambda d: None)

        self._known: dict[str, dict] = {}   # ip -> host dict
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ---------------------------------------------------------------- #

    def start(self) -> None:
        """Start the background monitor thread."""
        _check_scapy()
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the monitor thread to stop and wait for it."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.interval + 5)

    @property
    def known_devices(self) -> dict[str, dict]:
        """Read-only view of the current known-device map."""
        return dict(self._known)

    # ---------------------------------------------------------------- #

    def _run(self) -> None:
        # Seed initial state without firing callbacks
        try:
            initial = fast_scan(self.subnet, iface=self.iface, timeout=2.0)
            for host in initial:
                self._known[host["ip"]] = host
        except Exception:
            pass

        while not self._stop_event.is_set():
            self._stop_event.wait(self.interval)
            if self._stop_event.is_set():
                break
            try:
                current = fast_scan(self.subnet, iface=self.iface, timeout=2.0)
            except Exception:
                continue

            current_ips = {h["ip"] for h in current}
            known_ips = set(self._known.keys())

            # New devices
            for host in current:
                if host["ip"] not in known_ips:
                    self._known[host["ip"]] = host
                    self.on_new(host)

            # Left devices
            for ip in known_ips - current_ips:
                self.on_left(self._known.pop(ip))


# ------------------------------------------------------------------ #
# Multi-subnet parallel scanner                                        #
# ------------------------------------------------------------------ #

def multi_subnet_scan(
    subnets: list[str],
    iface: Optional[str] = None,
    scan_type: str = "fast",
    max_workers: int = 8,
    timeout: float = 2.0,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
) -> list[dict]:
    """Scan multiple CIDR subnets in parallel and return merged results.

    Args:
        subnets:     List of CIDR strings to scan (e.g. ['192.168.1.0/24', '10.0.0.0/24']).
        iface:       Network interface to use (or None for default).
        scan_type:   ``'fast'`` (ARP), ``'balanced'`` (ARP+ICMP), or ``'stealth'`` (TCP SYN).
        max_workers: Maximum concurrent scan threads.
        timeout:     Per-subnet ARP/ICMP timeout in seconds.
        progress_cb: Optional callback ``(subnet, found_so_far, total_subnets)`` fired
                     each time a subnet finishes scanning.

    Returns:
        Deduplicated list of host dicts merged across all subnets.
    """
    _check_scapy()

    scan_type = scan_type.lower()
    total = len(subnets)
    completed = [0]  # mutable counter shared across threads
    lock = threading.Lock()
    merged: dict[str, dict] = {}  # ip → host dict

    def _scan_one(subnet: str) -> None:
        try:
            if scan_type == "balanced":
                hosts = balanced_scan(subnet=subnet, iface=iface, timeout=timeout)
            elif scan_type == "stealth":
                hosts = stealth_scan(subnet=subnet, iface=iface, delay=0.3, timeout=timeout)
            else:
                hosts = fast_scan(subnet=subnet, iface=iface, timeout=timeout)
        except Exception:
            hosts = []

        with lock:
            for h in hosts:
                ip = h["ip"]
                if ip not in merged:
                    merged[ip] = h.copy()
                    merged[ip].setdefault("subnet", subnet)
            completed[0] += 1
            done = completed[0]

        if progress_cb:
            try:
                progress_cb(subnet, done, total)
            except Exception:
                pass

    # Use a semaphore-bounded thread pool
    sem = threading.Semaphore(max_workers)
    threads: list[threading.Thread] = []

    def _worker(subnet: str) -> None:
        with sem:
            _scan_one(subnet)

    for subnet in subnets:
        t = threading.Thread(target=_worker, args=(subnet,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return list(merged.values())
