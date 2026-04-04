"""
modules/reporter.py – Scan report generation.

Generates scan reports from a list of host dicts in three formats:

  * **JSON**  – machine-readable, suitable for further processing.
  * **text**  – human-readable ASCII table, suitable for terminals / logs.
  * **HTML**  – self-contained dark-themed HTML page.

Usage
-----
    from wifi_killer.modules.reporter import ScanReport

    report = ScanReport(hosts, gateway="192.168.1.1", iface="eth0")

    json_str  = report.to_json()
    text_str  = report.to_text()
    html_str  = report.to_html()

    report.save("/tmp/scan.html", fmt="html")
    report.save("/tmp/scan.json", fmt="json")
    report.save("/tmp/scan.txt",  fmt="text")
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional


class ScanReport:
    """Immutable scan report wrapping a list of host dicts.

    Parameters
    ----------
    hosts :
        List of host dicts as returned by the scanner / identifier
        modules (keys: ip, mac, vendor, hostname, type, open_ports, …).
    gateway :
        Default gateway IP (informational only).
    iface :
        Network interface used for the scan (informational only).
    scan_type :
        Human-readable scan method label, e.g. ``'fast'``, ``'balanced'``.
    generated_at :
        ISO-like timestamp string; auto-set to the current local time when
        *None*.
    """

    def __init__(
        self,
        hosts: list[dict],
        gateway: str = "",
        iface: str = "",
        scan_type: str = "fast",
        generated_at: Optional[str] = None,
    ) -> None:
        self.hosts = list(hosts)
        self.gateway = gateway
        self.iface = iface
        self.scan_type = scan_type
        self.generated_at = generated_at or time.strftime("%Y-%m-%d %H:%M:%S")

    # ------------------------------------------------------------------ #
    # Serialisation                                                        #
    # ------------------------------------------------------------------ #

    def to_json(self, indent: int = 2) -> str:
        """Return a JSON string representation of the report.

        The top-level object contains report metadata followed by the
        ``hosts`` array.
        """
        data = {
            "generated_at": self.generated_at,
            "interface": self.iface,
            "gateway": self.gateway,
            "scan_type": self.scan_type,
            "host_count": len(self.hosts),
            "hosts": self.hosts,
        }
        return json.dumps(data, indent=indent, default=str)

    def to_text(self) -> str:
        """Return a plain-text report suitable for terminal output or logs."""
        sep = "=" * 62
        lines = [
            sep,
            "  Wifi-Killer – Scan Report",
            f"  Generated : {self.generated_at}",
            f"  Interface : {self.iface or '—'}",
            f"  Gateway   : {self.gateway or '—'}",
            f"  Scan type : {self.scan_type}",
            f"  Hosts     : {len(self.hosts)}",
            sep,
        ]
        for i, host in enumerate(self.hosts, 1):
            ports = host.get("open_ports", [])
            ports_str = ", ".join(str(p) for p in ports) if ports else "—"
            os_hint = host.get("os_hint", "")
            lines += [
                f"\n[{i}]  {host.get('ip', '?')}",
                f"     MAC      : {host.get('mac', '?')}",
                f"     Vendor   : {host.get('vendor', 'Unknown')}",
                f"     Hostname : {host.get('hostname') or '—'}",
                f"     Type     : {host.get('type', 'Unknown')}",
                f"     Ports    : {ports_str}",
            ]
            if os_hint:
                lines.append(f"     OS Hint  : {os_hint}")
        lines.append("")
        return "\n".join(lines)

    def to_html(self) -> str:
        """Return a self-contained dark-themed HTML report."""
        rows = ""
        for host in self.hosts:
            ports = host.get("open_ports", [])
            ports_str = ", ".join(str(p) for p in ports) if ports else "—"
            os_hint = host.get("os_hint", "—")
            # Escape basic HTML characters to avoid injection
            def _esc(s: str) -> str:
                return (
                    str(s)
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace('"', "&quot;")
                )

            rows += (
                "<tr>"
                f"<td>{_esc(host.get('ip', '?'))}</td>"
                f"<td>{_esc(host.get('mac', '?'))}</td>"
                f"<td>{_esc(host.get('vendor', 'Unknown'))}</td>"
                f"<td>{_esc(host.get('hostname') or '—')}</td>"
                f"<td>{_esc(host.get('type', 'Unknown'))}</td>"
                f"<td>{_esc(ports_str)}</td>"
                f"<td>{_esc(os_hint)}</td>"
                "</tr>\n"
            )

        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n'
            "<head>"
            '<meta charset="utf-8">'
            f"<title>Wifi-Killer Report – {self.generated_at}</title>"
            "<style>"
            "body{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#eaeaea;margin:32px}"
            "h1{color:#e94560}"
            "table{border-collapse:collapse;width:100%;margin-top:20px}"
            "th{background:#0f3460;color:#64ffda;padding:10px 14px;text-align:left}"
            "td{padding:8px 14px;border-bottom:1px solid #252545}"
            "tr:nth-child(even){background:#1e1e3a}"
            ".meta{color:#8892b0;margin-bottom:24px}"
            "</style>"
            "</head>"
            "<body>"
            "<h1>&#x1F4E1; Wifi-Killer Scan Report</h1>"
            '<p class="meta">'
            f"Generated: {self.generated_at} &nbsp;|&nbsp; "
            f"Interface: {self.iface or '—'} &nbsp;|&nbsp; "
            f"Gateway: {self.gateway or '—'} &nbsp;|&nbsp; "
            f"Scan type: {self.scan_type} &nbsp;|&nbsp; "
            f"<strong>{len(self.hosts)}</strong> host(s)"
            "</p>"
            "<table><thead>"
            "<tr>"
            "<th>IP Address</th><th>MAC</th><th>Vendor</th>"
            "<th>Hostname</th><th>Type</th><th>Open Ports</th><th>OS Hint</th>"
            "</tr>"
            "</thead><tbody>\n"
            f"{rows}"
            "</tbody></table>"
            "</body></html>"
        )

    # ------------------------------------------------------------------ #
    # Persistence                                                          #
    # ------------------------------------------------------------------ #

    def save(self, path: str, fmt: str = "json") -> None:
        """Write the report to *path* in the requested format.

        Args:
            path: Filesystem path to write to.  Parent directories are
                  created automatically if they do not exist.
            fmt:  Output format – one of ``'json'``, ``'text'``/``'txt'``,
                  or ``'html'``.

        Raises:
            ValueError: if *fmt* is not one of the supported values.
            OSError:    if the file cannot be written.
        """
        fmt = fmt.lower().strip()
        if fmt == "json":
            content = self.to_json()
        elif fmt in ("text", "txt"):
            content = self.to_text()
        elif fmt == "html":
            content = self.to_html()
        else:
            raise ValueError(
                f"Unknown format '{fmt}'. Choose: json, text, html"
            )

        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
