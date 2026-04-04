"""
modules/dns_sniffer.py -- DNS query sniffer for network analysis.

Captures DNS queries on the local network by sniffing UDP port 53 traffic.
Queries are stored with timestamps, source IPs, queried domains, and record
types.  Results can be exported to CSV for offline analysis.

**This module is intended for educational and authorized-use purposes only.**
Sniffing network traffic without explicit permission from the network owner
is illegal in most jurisdictions.  Always obtain proper authorization before
running any network analysis tools.

Usage
-----
    from wifi_killer.modules.dns_sniffer import DnsSniffer

    sniffer = DnsSniffer(iface="eth0", target_ip="192.168.1.42")
    sniffer.start(callback=lambda q: print(q["domain"]))
    # ... some time later ...
    sniffer.stop()

    for q in sniffer.queries:
        print(f"{q['timestamp']}  {q['src_ip']}  {q['domain']}  {q['query_type']}")

    sniffer.export_csv("/tmp/dns_queries.csv")
"""

from __future__ import annotations

import csv
import logging
import os
import threading
import time
from typing import Callable, Optional

try:
    from scapy.all import sniff, DNS, DNSQR, IP  # type: ignore

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)

# DNS record-type codes used by DNSQR.qtype
_QTYPE_MAP: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    43: "DS",
    46: "RRSIG",
    48: "DNSKEY",
    255: "ANY",
    257: "CAA",
}


def _qtype_name(code: int) -> str:
    """Return the human-readable name for a DNS query-type code."""
    return _QTYPE_MAP.get(code, f"TYPE{code}")


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _check_scapy() -> None:
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "Scapy is not installed. Install it with: pip install scapy"
        )


# ------------------------------------------------------------------ #
# Standalone packet parser                                             #
# ------------------------------------------------------------------ #

def parse_dns_packet(packet) -> Optional[dict]:
    """Parse a single DNS packet and return query information.

    This helper is useful for testing or for processing pre-captured
    packets without needing a live network.

    Args:
        packet: A scapy packet object that may contain DNS query layers.

    Returns:
        A dict with keys ``timestamp``, ``src_ip``, ``domain``, and
        ``query_type`` if the packet contains a valid DNS query, or
        ``None`` otherwise.
    """
    _check_scapy()
    try:
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None

        dns_layer = packet[DNS]
        # Only process queries (qr == 0), not responses
        if dns_layer.qr != 0:
            return None

        qname_raw = packet[DNSQR].qname
        if isinstance(qname_raw, bytes):
            domain = qname_raw.decode("utf-8", errors="replace").rstrip(".")
        else:
            domain = str(qname_raw).rstrip(".")

        if not domain:
            return None

        qtype_code = packet[DNSQR].qtype
        query_type = _qtype_name(qtype_code)

        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

        timestamp = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(float(packet.time))
        )

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "domain": domain,
            "query_type": query_type,
        }
    except Exception:
        logger.debug("Failed to parse DNS packet", exc_info=True)
        return None


# ------------------------------------------------------------------ #
# DnsSniffer class                                                     #
# ------------------------------------------------------------------ #

class DnsSniffer:
    """Background DNS query sniffer.

    Captures DNS queries on a network interface (optionally filtered to a
    single source IP) and stores them for later inspection or CSV export.

    Parameters
    ----------
    iface :
        Network interface to sniff on (e.g. ``'eth0'``).  When *None*,
        scapy selects the default interface.
    target_ip :
        If provided, only capture DNS queries originating from this IP
        address.  Useful for monitoring a specific device.
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        target_ip: Optional[str] = None,
    ) -> None:
        self._iface: Optional[str] = iface
        self._target_ip: Optional[str] = target_ip

        self._queries: list[dict] = []
        self._lock: threading.Lock = threading.Lock()
        self._stop_event: threading.Event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable[[dict], None]] = None

    # ---------------------------------------------------------------- #
    # Public API                                                        #
    # ---------------------------------------------------------------- #

    def start(self, callback: Optional[Callable[[dict], None]] = None) -> None:
        """Start sniffing DNS queries in a background thread.

        Args:
            callback: Optional callable invoked with each captured query
                      dict.  The callback is called from the sniffer
                      thread, so it must be thread-safe.

        Raises:
            RuntimeError: If scapy is not installed or the sniffer is
                          already running.
        """
        _check_scapy()
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("DNS sniffer is already running.")

        self._callback = callback
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="dns-sniffer"
        )
        self._thread.start()
        logger.info(
            "DNS sniffer started on %s%s",
            self._iface or "default interface",
            f" (filtering {self._target_ip})" if self._target_ip else "",
        )

    def stop(self) -> None:
        """Signal the sniffer thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._callback = None
        logger.info("DNS sniffer stopped.")

    @property
    def queries(self) -> list[dict]:
        """Return a shallow copy of the captured queries list."""
        with self._lock:
            return list(self._queries)

    @property
    def is_running(self) -> bool:
        """Return ``True`` if the background sniffer thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def clear(self) -> None:
        """Discard all captured queries."""
        with self._lock:
            self._queries.clear()

    def export_csv(self, path: str) -> None:
        """Export captured queries to a CSV file.

        The CSV file contains one row per query with columns:
        ``timestamp``, ``src_ip``, ``domain``, ``query_type``.

        Args:
            path: Filesystem path for the output CSV file.  Parent
                  directories are created automatically if they do not
                  exist.

        Raises:
            OSError: If the file cannot be written.
        """
        with self._lock:
            snapshot = list(self._queries)

        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)

        fieldnames = ["timestamp", "src_ip", "domain", "query_type"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for query in snapshot:
                writer.writerow(
                    {k: query.get(k, "") for k in fieldnames}
                )

        logger.info("Exported %d queries to %s", len(snapshot), path)

    # ---------------------------------------------------------------- #
    # Internal methods                                                  #
    # ---------------------------------------------------------------- #

    def _sniff_loop(self) -> None:
        """Main loop executed in the background thread.

        Uses scapy's ``sniff()`` with a BPF filter for UDP port 53 and
        a ``stop_filter`` that honours the stop event.
        """
        bpf = "udp port 53"
        if self._target_ip:
            bpf = f"udp port 53 and src host {self._target_ip}"

        kwargs: dict = {
            "filter": bpf,
            "prn": self._process_packet,
            "store": 0,
            "stop_filter": lambda _pkt: self._stop_event.is_set(),
        }
        if self._iface:
            kwargs["iface"] = self._iface

        try:
            sniff(**kwargs)
        except Exception:
            logger.error("DNS sniffer encountered an error", exc_info=True)

    def _process_packet(self, packet) -> None:
        """Extract DNS query information from *packet* and store it.

        Called by scapy's ``sniff()`` for each captured packet that
        matches the BPF filter.
        """
        parsed = parse_dns_packet(packet)
        if parsed is None:
            return

        with self._lock:
            self._queries.append(parsed)

        cb = self._callback
        if cb is not None:
            try:
                cb(parsed)
            except Exception:
                logger.debug("DNS sniffer callback raised an exception", exc_info=True)
