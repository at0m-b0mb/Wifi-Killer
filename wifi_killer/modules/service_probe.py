"""
service_probe.py — Active service / banner reconnaissance.

Given a list of target IPs, probes a curated set of well-known service
ports in parallel, reads the first few bytes returned (the *banner*),
and infers the running service. The result is a per-host table of
``(port, service, banner)`` triples — exactly the kind of recon a red
team wants before deciding which targets are worth attacking.

This is an **active** probe — every checked port involves a TCP SYN/ACK
exchange from this machine to the target. Some hosts and IDSes will
log/alert on these connections. The module is intentionally rate-
limited (small port set, parallel pool capped, short timeouts) so a
typical 5-host sweep finishes in well under a second.

Banner-grab strategy per protocol family:

* Plaintext servers that greet on connect (FTP / SSH / SMTP / IMAP /
  POP3 / Telnet / Redis / MySQL / VNC) — read whatever they send.
* HTTP-style servers (HTTP/HTTPS/HTTP-alt) — send ``HEAD / HTTP/1.0``
  then read the response, extract ``Server:`` header.
* SMB / RDP / MongoDB — connect-only (open/closed signal; reading raw
  bytes from these isn't useful without a real protocol handshake).

Designed to fail soft: every error returns ``None`` for that port,
never throws.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Port → (service-name, probe-strategy) catalogue
# ---------------------------------------------------------------------------

_GREET_ON_CONNECT = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    110:   "POP3",
    143:   "IMAP",
    587:   "SMTP-submission",
    993:   "IMAPS",
    995:   "POP3S",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
}
_HTTP_PORTS = {
    80:    "HTTP",
    443:   "HTTPS",
    8000:  "HTTP-alt",
    8008:  "HTTP-alt",
    8080:  "HTTP-alt",
    8443:  "HTTPS-alt",
    8888:  "HTTP-alt",
}
_CONNECT_ONLY = {
    135:   "DCE/RPC endpoint mapper",
    137:   "NetBIOS",
    139:   "NetBIOS-SSN",
    445:   "SMB",
    3389:  "RDP",
    5985:  "WinRM-HTTP",
    5986:  "WinRM-HTTPS",
    27017: "MongoDB",
    32400: "Plex",
}

# Default port set probed for each host. The selection is short on purpose
# so a 5-host sweep finishes inside ~1 second even with conservative
# per-port timeouts.
DEFAULT_PORTS: list[int] = (
    sorted(_GREET_ON_CONNECT.keys())
    + sorted(_HTTP_PORTS.keys())
    + sorted(_CONNECT_ONLY.keys())
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ServiceFinding:
    """One open port on one host."""
    ip: str
    port: int
    service: str
    banner: str = ""
    version: str = ""


@dataclass
class HostResult:
    ip: str
    findings: list[ServiceFinding] = field(default_factory=list)
    error: Optional[str] = None
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Banner parsing helpers
# ---------------------------------------------------------------------------

_HTTP_SERVER_RE = re.compile(rb"\r\nServer:\s*([^\r\n]+)", re.IGNORECASE)
_SSH_VERSION_RE = re.compile(rb"^(SSH-\d\.\d+[^\r\n]*)", re.IGNORECASE)
_FTP_VERSION_RE = re.compile(rb"^220[- ]?([^\r\n]+)", re.IGNORECASE)
_SMTP_VERSION_RE = re.compile(rb"^220[- ]?([^\r\n]+)", re.IGNORECASE)
_REDIS_VERSION_RE = re.compile(rb"redis_version:([^\r\n]+)", re.IGNORECASE)


def _decode(b: bytes, limit: int = 120) -> str:
    """ASCII-printable best-effort decode for banner display."""
    try:
        s = b.decode("utf-8", errors="replace")
    except Exception:
        return ""
    # Strip non-printables except space.
    s = "".join(c for c in s if c.isprintable() or c in " \t")
    return s[:limit].strip()


def _extract_version(service: str, raw: bytes) -> str:
    if not raw:
        return ""
    if service == "SSH":
        m = _SSH_VERSION_RE.match(raw)
        if m:
            return _decode(m.group(1), 60)
    if service in ("FTP",):
        m = _FTP_VERSION_RE.match(raw)
        if m:
            return _decode(m.group(1), 60)
    if service.startswith("SMTP"):
        m = _SMTP_VERSION_RE.match(raw)
        if m:
            return _decode(m.group(1), 60)
    if service.startswith("HTTP"):
        m = _HTTP_SERVER_RE.search(raw)
        if m:
            return _decode(m.group(1), 60)
    if service == "Redis":
        m = _REDIS_VERSION_RE.search(raw)
        if m:
            return _decode(m.group(1), 40)
    # Fallback — first line of the banner.
    first_line = raw.split(b"\n", 1)[0]
    return _decode(first_line, 60)


# ---------------------------------------------------------------------------
# Per-port probe
# ---------------------------------------------------------------------------

def _probe_port(
    ip: str, port: int, timeout: float,
) -> Optional[ServiceFinding]:
    """Connect to (*ip*, *port*) and return a ``ServiceFinding`` or ``None``."""
    service = (
        _GREET_ON_CONNECT.get(port)
        or _HTTP_PORTS.get(port)
        or _CONNECT_ONLY.get(port)
    )
    if not service:
        return None
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        raw = b""
        if port in _GREET_ON_CONNECT:
            try:
                raw = sock.recv(512)
            except socket.timeout:
                raw = b""
        elif port in _HTTP_PORTS:
            # HEAD is preferred so we don't fetch a body. Use HTTP/1.0
            # because some servers close 1.0 connections after the response.
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n")
                raw = sock.recv(1024)
            except (socket.timeout, OSError):
                raw = b""
        # else: connect-only — leave raw empty.
        banner = _decode(raw, 120)
        version = _extract_version(service, raw)
        return ServiceFinding(
            ip=ip, port=port, service=service,
            banner=banner, version=version,
        )
    except (socket.timeout, OSError, ConnectionRefusedError):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# ServiceProber
# ---------------------------------------------------------------------------

class ServiceProber:
    """Run a banner-grab sweep against a list of hosts in parallel."""

    def __init__(
        self,
        ips: list[str],
        ports: Optional[list[int]] = None,
        timeout: float = 0.6,
        host_workers: int = 4,
        port_workers: int = 8,
        on_host_done: Optional[Callable[[HostResult], None]] = None,
    ) -> None:
        self.ips = [i for i in ips if i]
        self.ports = list(ports) if ports else list(DEFAULT_PORTS)
        self.timeout = float(timeout)
        self.host_workers = max(1, int(host_workers))
        self.port_workers = max(1, int(port_workers))
        self._on_host_done = on_host_done
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._results: list[HostResult] = []
        self._lock = threading.Lock()
        self.started_at: float = 0.0
        self.finished_at: float = 0.0

    # ------------------------------------------------------------------ #

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running:
            return
        self._stop.clear()
        self.started_at = time.time()
        self.finished_at = 0.0
        self._results = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None

    def results(self) -> list[HostResult]:
        with self._lock:
            return list(self._results)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "running": self.is_running,
                "started": self.started_at,
                "finished": self.finished_at,
                "host_count": len(self.ips),
                "results": list(self._results),
            }

    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        try:
            with ThreadPoolExecutor(max_workers=self.host_workers) as pool:
                futures = {
                    pool.submit(self._probe_host, ip): ip for ip in self.ips
                }
                for fut in futures:
                    if self._stop.is_set():
                        break
                    try:
                        host_result = fut.result()
                    except Exception as exc:
                        host_result = HostResult(
                            ip=futures[fut], error=str(exc),
                        )
                    with self._lock:
                        self._results.append(host_result)
                    if self._on_host_done is not None:
                        try:
                            self._on_host_done(host_result)
                        except Exception:
                            pass
        finally:
            self.finished_at = time.time()

    def _probe_host(self, ip: str) -> HostResult:
        t0 = time.time()
        findings: list[ServiceFinding] = []
        with ThreadPoolExecutor(max_workers=self.port_workers) as pool:
            futures = [
                pool.submit(_probe_port, ip, port, self.timeout)
                for port in self.ports
            ]
            for fut in futures:
                if self._stop.is_set():
                    break
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if res is not None:
                    findings.append(res)
        # Sort by port for stable display.
        findings.sort(key=lambda f: f.port)
        return HostResult(
            ip=ip, findings=findings,
            duration_ms=(time.time() - t0) * 1000.0,
        )
