"""
wifi_killer/gui.py – Modern CustomTkinter GUI for Wifi-Killer.

Run with:  sudo python3 gui.py

Requires: customtkinter >= 5.2
"""

from __future__ import annotations

import csv
import json
import math
import os
import platform
import re
import socket
import statistics
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Optional

# ---------------------------------------------------------------------------
# Guard: customtkinter
# ---------------------------------------------------------------------------
try:
    import customtkinter as ctk  # type: ignore

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    CTK_AVAILABLE = True
except ImportError:
    CTK_AVAILABLE = False

# ---------------------------------------------------------------------------
# Internal imports
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_killer.modules.config import attack_config
from wifi_killer.modules.identifier import identify_host
from wifi_killer.utils.network import (
    get_default_gateway,
    get_interface_mac,
    get_interface_subnet,
    list_interfaces,
    ping_once as _ping_once,
)
import ipaddress

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
_VERSION = "4.1.0"

# ---------------------------------------------------------------------------
# Platform-aware fonts
# ---------------------------------------------------------------------------
_PLT = platform.system()
if _PLT == "Darwin":           # macOS
    _SF  = "Helvetica Neue"
    _MF  = "Menlo"
elif _PLT == "Windows":
    _SF  = "Segoe UI"
    _MF  = "Consolas"
else:                           # Linux and other
    _SF  = "Ubuntu"
    _MF  = "DejaVu Sans Mono"

# Colours / theme constants — modern dark palette
# ---------------------------------------------------------------------------
_CLR_BG       = "#0b0b12"   # app background – true near-black
_CLR_SIDEBAR  = "#11111c"   # sidebar / top-bar surface (elevation 1)
_CLR_PANEL    = "#181826"   # cards & section surfaces       (elevation 2)
_CLR_HOVER    = "#222234"   # hover state for nav / buttons
_CLR_BORDER   = "#2a2a3a"   # subtle separators & dividers
_CLR_ACCENT   = "#ff3b5c"   # primary accent – refined crimson
_CLR_ACCENT2  = "#8b5cf6"   # secondary accent – violet
_CLR_TEXT     = "#ececf1"   # primary text                 (off-white)
_CLR_MUTED    = "#8a8a9c"   # secondary / label text
_CLR_SUCCESS  = "#10b981"   # green (online, ok)
_CLR_WARNING  = "#f59e0b"   # amber (warnings)
_CLR_DANGER   = "#ef4444"   # red (errors, attack active)
_CLR_ROW_ODD  = "#16161f"   # alternating table rows
_CLR_ROW_EVEN = "#1c1c28"

# Typography — refined scale, slightly larger for readability
_FONT_TITLE   = (_SF, 24, "bold")
_FONT_HEAD    = (_SF, 15, "bold")
_FONT_LABEL   = (_SF, 12)
_FONT_MONO    = (_MF, 11)
_FONT_SMALL   = (_SF, 10)
_FONT_NAME    = (_SF, 12, "bold")   # device name (hostname) – prominent


# ===========================================================================
# Utility helpers
# ===========================================================================

def _thread(fn, *args, **kwargs) -> threading.Thread:
    t = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
    t.start()
    return t


def _fmt_ports(ports: list[int]) -> str:
    return ", ".join(str(p) for p in ports) if ports else "—"


def _validate_ip(ip: str) -> bool:
    """Return True if *ip* looks like a valid IPv4 address."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _validate_mac(mac: str) -> bool:
    """Return True if *mac* matches XX:XX:XX:XX:XX:XX format."""
    return bool(re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac))


def _ip_sort_key(ip: str) -> tuple[int, int, int, int]:
    """Numeric sort key for IPv4 strings so 10.0.0.9 < 10.0.0.10."""
    try:
        return tuple(int(p) for p in ip.split("."))  # type: ignore[return-value]
    except (ValueError, AttributeError):
        return (0, 0, 0, 0)


# ===========================================================================
# Tooltip helper
# ===========================================================================

class _ToolTip:
    """Lightweight hover tooltip shown below any tkinter/ctk widget."""

    def __init__(self, widget, text: str, delay_ms: int = 500) -> None:
        self._widget = widget
        self._text   = text
        self._job: Optional[str] = None
        self._tip: Optional[tk.Toplevel] = None
        widget.bind("<Enter>",       self._schedule, add="+")
        widget.bind("<Leave>",       self._cancel,   add="+")
        widget.bind("<ButtonPress>", self._cancel,   add="+")

    def _schedule(self, _event=None) -> None:
        self._cancel()
        self._job = self._widget.after(500, self._show)

    def _cancel(self, _event=None) -> None:
        if self._job:
            self._widget.after_cancel(self._job)
            self._job = None
        if self._tip:
            self._tip.destroy()
            self._tip = None

    def _show(self) -> None:
        x = self._widget.winfo_rootx() + self._widget.winfo_width() // 2
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 6
        self._tip = tk.Toplevel(self._widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        tk.Label(
            self._tip, text=self._text,
            bg=_CLR_PANEL, fg=_CLR_TEXT,
            font=(_SF, 10), padx=10, pady=5,
            relief="flat", bd=0,
            highlightbackground=_CLR_BORDER, highlightthickness=1,
        ).pack()


# ===========================================================================
# Reusable styled widget helpers
# ===========================================================================

def _shade(hex_color: str, factor: float) -> str:
    """Return *hex_color* lightened (factor>1) or darkened (factor<1)."""
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    r = max(0, min(255, int(r * factor)))
    g = max(0, min(255, int(g * factor)))
    b = max(0, min(255, int(b * factor)))
    return f"#{r:02x}{g:02x}{b:02x}"


def _primary_button(parent, text: str, command=None, **kwargs):
    """Bold accent-filled call-to-action button."""
    defaults = dict(
        text=text,
        command=command,
        fg_color=_CLR_ACCENT,
        hover_color=_shade(_CLR_ACCENT, 0.85),
        text_color="#ffffff",
        font=(_SF, 12, "bold"),
        corner_radius=10,
        height=40,
        border_width=0,
    )
    defaults.update(kwargs)
    return ctk.CTkButton(parent, **defaults)


def _secondary_button(parent, text: str, command=None, **kwargs):
    """Neutral panel-filled button — for secondary actions."""
    defaults = dict(
        text=text,
        command=command,
        fg_color=_CLR_PANEL,
        hover_color=_CLR_HOVER,
        text_color=_CLR_TEXT,
        font=_FONT_LABEL,
        corner_radius=10,
        height=38,
        border_width=1,
        border_color=_CLR_BORDER,
    )
    defaults.update(kwargs)
    return ctk.CTkButton(parent, **defaults)


def _danger_button(parent, text: str, command=None, **kwargs):
    """Destructive red action button."""
    defaults = dict(
        text=text,
        command=command,
        fg_color=_CLR_DANGER,
        hover_color=_shade(_CLR_DANGER, 0.85),
        text_color="#ffffff",
        font=(_SF, 12, "bold"),
        corner_radius=10,
        height=40,
        border_width=0,
    )
    defaults.update(kwargs)
    return ctk.CTkButton(parent, **defaults)


def _ghost_button(parent, text: str, command=None, **kwargs):
    """Transparent bordered button — quiet/tertiary action."""
    defaults = dict(
        text=text,
        command=command,
        fg_color="transparent",
        hover_color=_CLR_HOVER,
        text_color=_CLR_TEXT,
        font=_FONT_LABEL,
        corner_radius=10,
        height=36,
        border_width=1,
        border_color=_CLR_BORDER,
    )
    defaults.update(kwargs)
    return ctk.CTkButton(parent, **defaults)


def _page_header(
    parent,
    icon: str,
    title: str,
    subtitle: str = "",
) -> "ctk.CTkFrame":
    """Standard page header: large icon + title + optional subtitle.

    Returns a container frame so callers can add right-aligned widgets
    via ``frame.right_slot`` (a sub-frame on the right side).
    """
    header = ctk.CTkFrame(parent, fg_color="transparent")
    header.grid_columnconfigure(1, weight=1)

    # Icon badge — accent-tinted square
    icon_badge = ctk.CTkFrame(
        header,
        fg_color=_CLR_PANEL,
        corner_radius=12,
        width=44, height=44,
        border_width=1,
        border_color=_CLR_BORDER,
    )
    icon_badge.grid(row=0, column=0, rowspan=2, padx=(0, 14), sticky="w")
    icon_badge.grid_propagate(False)
    ctk.CTkLabel(
        icon_badge, text=icon, font=(_SF, 22),
        text_color=_CLR_ACCENT,
    ).place(relx=0.5, rely=0.5, anchor="center")

    ctk.CTkLabel(
        header, text=title,
        font=_FONT_TITLE, text_color=_CLR_TEXT,
        anchor="w",
    ).grid(row=0, column=1, sticky="sw")

    if subtitle:
        ctk.CTkLabel(
            header, text=subtitle,
            font=_FONT_SMALL, text_color=_CLR_MUTED,
            anchor="w",
        ).grid(row=1, column=1, sticky="nw", pady=(1, 0))

    # Right slot for action widgets
    right_slot = ctk.CTkFrame(header, fg_color="transparent")
    right_slot.grid(row=0, column=2, rowspan=2, sticky="e")
    header.right_slot = right_slot  # type: ignore[attr-defined]

    return header


def _stat_card(
    parent,
    icon: str,
    title: str,
    value: str,
    column: int,
    accent: str = _CLR_TEXT,
) -> "ctk.CTkLabel":
    """Polished stat card with icon column + value emphasis.

    Returns the value label so the caller can update it via ``.configure``.
    """
    card = ctk.CTkFrame(
        parent,
        fg_color=_CLR_PANEL,
        corner_radius=14,
        border_width=1,
        border_color=_CLR_BORDER,
    )
    card.grid(row=0, column=column, sticky="nsew", padx=6, pady=4)
    card.grid_columnconfigure(1, weight=1)

    # Icon column
    icon_lbl = ctk.CTkLabel(
        card, text=icon, font=(_SF, 22),
        text_color=accent,
    )
    icon_lbl.grid(row=0, column=0, rowspan=2,
                  padx=(14, 10), pady=10, sticky="w")

    ctk.CTkLabel(
        card, text=title.upper(),
        font=(_SF, 9, "bold"),
        text_color=_CLR_MUTED,
        anchor="w",
    ).grid(row=0, column=1, padx=(0, 14), pady=(12, 0), sticky="sw")

    value_lbl = ctk.CTkLabel(
        card, text=value,
        font=(_SF, 20, "bold"),
        text_color=accent,
        anchor="w",
    )
    value_lbl.grid(row=1, column=1, padx=(0, 14), pady=(0, 12), sticky="nw")
    return value_lbl


# ===========================================================================
# Root application window
# ===========================================================================

class WifiKillerApp(ctk.CTk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()

        self.title("Wifi-Killer  ·  Educational Network Tool")
        self.geometry("1280x800")
        self.minsize(1000, 650)

        # App-level state
        self._iface: str = ""
        self._gateway: str = ""
        self._hosts: list[dict] = []
        # Persistent device registry keyed by IP – survives across scans
        self._host_registry: dict[str, dict] = {}
        self._monitor: Optional[object] = None  # NetworkMonitor instance
        self._active_attack: Optional[object] = None
        self._original_mac: str = ""
        # Scan history: list of (timestamp_str, host_count)
        self._scan_history: list[tuple[str, int]] = []

        self._build_layout()
        self._show_frame("dashboard")

        # Populate interface after UI is ready
        self.after(100, self._auto_detect_interface)

        # ── Keyboard shortcuts ───────────────────────────────────────
        self.bind_all("<F5>",        lambda _e: self._kb_scan())
        self.bind_all("<Control-a>", lambda _e: self._kb_select_all())
        self.bind_all("<Escape>",    lambda _e: self._kb_escape())
        self.bind_all("<Control-q>", lambda _e: self._confirm_quit())
        self.bind_all("<Control-e>", lambda _e: self._kb_export())
        self.protocol("WM_DELETE_WINDOW", self._confirm_quit)

    # ------------------------------------------------------------------ #
    # Layout                                                               #
    # ------------------------------------------------------------------ #

    def _build_layout(self) -> None:
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Sidebar
        self._sidebar = _Sidebar(self, self._show_frame)
        self._sidebar.grid(row=0, column=0, sticky="nsew")

        # Main area container
        self._main = ctk.CTkFrame(self, fg_color=_CLR_BG, corner_radius=0)
        self._main.grid(row=0, column=1, sticky="nsew")
        self._main.grid_rowconfigure(1, weight=1)
        self._main.grid_columnconfigure(0, weight=1)

        # Top bar (interface selector + status)
        self._topbar = _TopBar(self._main, self._on_interface_changed)
        self._topbar.grid(row=0, column=0, sticky="ew", padx=0, pady=0)

        # Frame container
        self._frame_host = ctk.CTkFrame(self._main, fg_color=_CLR_BG, corner_radius=0)
        self._frame_host.grid(row=1, column=0, sticky="nsew")
        self._frame_host.grid_rowconfigure(0, weight=1)
        self._frame_host.grid_columnconfigure(0, weight=1)

        # Build all frames
        self._frames: dict[str, ctk.CTkFrame] = {}

        self._frames["dashboard"]    = DashboardFrame(self._frame_host, self)
        self._frames["scan"]         = ScanFrame(self._frame_host, self)
        self._frames["network_map"]  = NetworkMapFrame(self._frame_host, self)
        self._frames["multi_subnet"] = MultiSubnetFrame(self._frame_host, self)
        self._frames["dns_sniffer"]  = DnsSnifferFrame(self._frame_host, self)
        self._frames["arp_cache"]    = ArpCacheFrame(self._frame_host, self)
        self._frames["throttle"]     = ThrottleFrame(self._frame_host, self)
        self._frames["ping_monitor"] = PingMonitorFrame(self._frame_host, self)
        self._frames["attack"]       = AttackFrame(self._frame_host, self)
        self._frames["mitm_inspect"] = MITMInspectorFrame(self._frame_host, self)
        self._frames["anonymize"]    = AnonymizeFrame(self._frame_host, self)
        self._frames["wol"]          = WolFrame(self._frame_host, self)
        self._frames["settings"]     = SettingsFrame(self._frame_host, self)
        self._frames["about"]        = AboutFrame(self._frame_host, self)

        for frame in self._frames.values():
            frame.grid(row=0, column=0, sticky="nsew")

    def _show_frame(self, name: str) -> None:
        frame = self._frames.get(name)
        if frame:
            frame.tkraise()
            # Let the frame refresh itself when it becomes visible.
            on_show = getattr(frame, "_on_show", None)
            if callable(on_show):
                try:
                    on_show()
                except Exception:
                    pass
        self._sidebar.set_active(name)

    # ------------------------------------------------------------------ #
    # Interface / gateway helpers                                          #
    # ------------------------------------------------------------------ #

    def _auto_detect_interface(self) -> None:
        ifaces = list_interfaces()
        if ifaces:
            self._iface = ifaces[0]
        self._gateway = get_default_gateway() or ""
        self._topbar.populate_interfaces(ifaces, self._iface)
        self._topbar.set_gateway(self._gateway)
        if self._iface:
            self._original_mac = get_interface_mac(self._iface) or ""
        self._topbar.set_own_ip(self._get_own_ip())

    def _on_interface_changed(self, iface: str) -> None:
        self._iface = iface
        self._gateway = get_default_gateway() or ""
        self._topbar.set_gateway(self._gateway)
        self._original_mac = get_interface_mac(iface) or ""
        self._hosts = []
        self._host_registry = {}
        self._own_ip_cache = ""  # invalidate cached IP since iface changed
        self._topbar.set_own_ip(self._get_own_ip())
        self.log(f"Interface changed to {iface}  |  Gateway: {self._gateway or '(unknown)'}")

    _own_ip_cache: str = ""

    def _get_own_ip(self) -> str:
        """Cached best-effort detection of the local outbound IP.

        Called from hot paths (dashboard refresh, map redraw); the actual
        UDP-route lookup is cheap but we still cache it because it was
        being called dozens of times per second during active scans.
        """
        if self._own_ip_cache:
            return self._own_ip_cache
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = "?"
        self._own_ip_cache = ip
        return ip

    # ------------------------------------------------------------------ #
    # Shared log                                                           #
    # ------------------------------------------------------------------ #

    def log(self, msg: str, level: str = "info") -> None:
        """Write a timestamped message to the log console on the Scan frame."""
        ts = time.strftime("%H:%M:%S")
        prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[✕]"}.get(level, "[*]")
        line = f"{ts}  {prefix}  {msg}\n"
        scan_frame: ScanFrame = self._frames.get("scan")  # type: ignore
        if scan_frame:
            scan_frame.append_log(line, level)

    def refresh_dashboard(self) -> None:
        """Ask the dashboard to redraw its stat cards."""
        dash: DashboardFrame = self._frames.get("dashboard")  # type: ignore
        if dash:
            self.after(0, dash.refresh)
        # The network map is intentionally NOT redrawn from this hook —
        # the dashboard fires it every 5 s on a timer, and the map's
        # topology resolution does subprocess + ARP-cache reads that
        # block the main thread under load. The map self-refreshes on
        # ``_on_show`` (tab change) and ``mark_hosts_changed`` (scan
        # completion), which is enough.

    def mark_hosts_changed(self) -> None:
        """Notify dependent frames that the host registry has changed.

        Called once at the end of a scan — not on every host added —
        so we don't spam the main thread with redraws during an active
        scan with hundreds of intermediate updates.
        """
        nmap: NetworkMapFrame = self._frames.get("network_map")  # type: ignore
        if nmap:
            nmap.request_topology_refresh()

    def mark_attack_changed(self) -> None:
        """Notify the network map that attack state changed (start / stop)."""
        nmap: NetworkMapFrame = self._frames.get("network_map")  # type: ignore
        if nmap:
            nmap.request_topology_refresh()

    def get_attack_info(self) -> Optional[dict]:
        """Return a snapshot of the active ARP attack, or ``None`` if idle.

        Returned dict::

            {
                "active":       True,
                "method":       "A" | "B" | "C",
                "gateway":      "10.0.0.1",
                "attacked_ips": {"10.0.0.55", "10.0.0.72"},
            }
        """
        af = self._frames.get("attack")
        if not af or not getattr(af, "_running", False):
            return None
        obj = getattr(af, "_attack_obj", None)
        if obj is None:
            return None
        # Discover the per-target IPs whether it's a single ArpAttack or a
        # MultiTargetAttack (whose ``attacks`` is the actual list).
        attacked: set[str] = set()
        method = ""
        gateway = ""
        single_attacks = getattr(obj, "attacks", None)
        if single_attacks is not None:
            for sub in single_attacks:
                if getattr(sub, "target_ip", ""):
                    attacked.add(sub.target_ip)
                method = method or getattr(sub, "method", "")
                gateway = gateway or getattr(sub, "gateway_ip", "")
        else:
            if getattr(obj, "target_ip", ""):
                attacked.add(obj.target_ip)
            method = getattr(obj, "method", "")
            gateway = getattr(obj, "gateway_ip", "")
        if not attacked:
            return None
        return {
            "active": True,
            "method": method,
            "gateway": gateway,
            "attacked_ips": attacked,
        }

    def record_scan(self, host_count: int) -> None:
        """Record a completed scan in the history (kept to last 5)."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self._scan_history.append((ts, host_count))
        self._scan_history = self._scan_history[-5:]  # keep last 5

    def merge_hosts(self, new_hosts: list[dict]) -> None:
        """Merge new scan results into the persistent registry.

        Existing hosts NOT found in the new scan are marked ``online=False``
        (they remain in the list so the user can see them).  Hosts that ARE
        found are updated with fresh data and marked ``online=True``.  Brand-
        new hosts are added with ``online=True``.

        After merging, ``self._hosts`` is resynchronised from the registry.
        """
        # Mark every known host offline; new scan will re-flag survivors.
        for entry in self._host_registry.values():
            entry["online"] = False

        for h in new_hosts:
            ip = h.get("ip", "")
            if not ip:
                continue
            if ip in self._host_registry:
                self._host_registry[ip].update(h)
            else:
                self._host_registry[ip] = dict(h)
            self._host_registry[ip]["online"] = True

        self._hosts = list(self._host_registry.values())

    def add_host(self, host: dict) -> None:
        """Add or update a single host in the registry (e.g. from monitor)."""
        ip = host.get("ip", "")
        if not ip:
            return
        if ip in self._host_registry:
            self._host_registry[ip].update(host)
        else:
            self._host_registry[ip] = dict(host)
        self._host_registry[ip]["online"] = True
        self._hosts = list(self._host_registry.values())

    # ------------------------------------------------------------------ #
    # Keyboard shortcut handlers                                           #
    # ------------------------------------------------------------------ #

    def _kb_scan(self) -> None:
        """F5 → go to Scan tab and start a scan if not already running."""
        self._show_frame("scan")
        sf: ScanFrame = self._frames.get("scan")  # type: ignore
        if sf and not getattr(sf, "_scanning", False):
            sf._start_scan()

    def _kb_select_all(self) -> None:
        """Ctrl+A → select all hosts in the Scan frame."""
        sf: ScanFrame = self._frames.get("scan")  # type: ignore
        if sf:
            sf._select_all()

    def _kb_escape(self) -> None:
        """Escape → stop active scan or attack."""
        sf: ScanFrame = self._frames.get("scan")  # type: ignore
        if sf and getattr(sf, "_scanning", False):
            sf._scanning = False
            return
        af: AttackFrame = self._frames.get("attack")  # type: ignore
        if af and getattr(af, "_running", False):
            af._stop_attack()

    def _kb_export(self) -> None:
        """Ctrl+E → export scan results from Scan frame."""
        sf: ScanFrame = self._frames.get("scan")  # type: ignore
        if sf:
            sf._export_results()

    def _confirm_quit(self) -> None:
        """Ask before quitting if an attack or scan is active."""
        af: AttackFrame = self._frames.get("attack")  # type: ignore
        sf: ScanFrame   = self._frames.get("scan")    # type: ignore
        active = (af and getattr(af, "_running", False)) or \
                 (sf and getattr(sf, "_scanning", False))
        if active:
            if not messagebox.askyesno(
                "Quit?",
                "A scan or attack is currently running.\n"
                "Quitting now will NOT restore ARP caches.\n\n"
                "Are you sure you want to quit?",
            ):
                return
        self.destroy()


# ===========================================================================
# Sidebar
# ===========================================================================

class _Sidebar(ctk.CTkFrame):
    # Grouped navigation: (section_label_or_None, [(key, label), ...])
    _NAV_SECTIONS: list[tuple[Optional[str], list[tuple[str, str]]]] = [
        (None, [
            ("dashboard",    "📊   Dashboard"),
        ]),
        ("DISCOVERY", [
            ("scan",         "🔍   Scan Network"),
            ("network_map",  "🗺️    Network Map"),
            ("multi_subnet", "🌐   Multi-Subnet"),
            ("dns_sniffer",  "🔎   DNS Sniffer"),
            ("arp_cache",    "📋   ARP Cache"),
            ("ping_monitor", "🏓   Ping Monitor"),
        ]),
        ("CONTROL", [
            ("throttle",     "🚦   Speed Control"),
            ("attack",       "⚡   ARP Attack"),
            ("mitm_inspect", "🔭   MITM Inspector"),
            ("anonymize",    "🎭   MAC Anonymize"),
            ("wol",          "🔆   Wake-on-LAN"),
        ]),
        ("SYSTEM", [
            ("settings",     "⚙️    Settings"),
            ("about",        "ℹ️    About"),
        ]),
    ]

    def __init__(self, parent: ctk.CTk, on_select) -> None:
        super().__init__(parent, fg_color=_CLR_SIDEBAR, corner_radius=0, width=244)
        self._on_select = on_select
        # For each nav entry we track (stripe_frame, button) so we can recolour
        # the left-edge accent on selection without rebuilding the widget tree.
        self._items: dict[str, tuple[ctk.CTkFrame, ctk.CTkButton]] = {}
        self._active: str = ""
        self._build()

    def _build(self) -> None:
        self.grid_propagate(False)

        # ── Brand / logo ─────────────────────────────────────────────
        logo_frame = ctk.CTkFrame(self, fg_color="transparent")
        logo_frame.pack(pady=(24, 4), padx=18, fill="x")

        ctk.CTkLabel(
            logo_frame,
            text="📡",
            font=(_SF, 28),
            text_color=_CLR_ACCENT,
        ).pack(side="left", padx=(0, 10))

        title_col = ctk.CTkFrame(logo_frame, fg_color="transparent")
        title_col.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(
            title_col,
            text="Wifi-Killer",
            font=(_SF, 17, "bold"),
            text_color=_CLR_TEXT,
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_col,
            text=f"v{_VERSION}  ·  Network Lab",
            font=(_SF, 10),
            text_color=_CLR_MUTED,
            anchor="w",
        ).pack(anchor="w")

        ctk.CTkFrame(self, height=1, fg_color=_CLR_BORDER).pack(
            fill="x", padx=18, pady=(16, 6))

        # ── Grouped nav ──────────────────────────────────────────────
        for section_idx, (section, entries) in enumerate(self._NAV_SECTIONS):
            if section is not None:
                ctk.CTkLabel(
                    self,
                    text=section,
                    font=(_SF, 9, "bold"),
                    text_color=_CLR_MUTED,
                    anchor="w",
                ).pack(fill="x", padx=22, pady=(12 if section_idx > 0 else 8, 4))

            for key, label in entries:
                self._add_nav_item(key, label)

        # ── Footer ───────────────────────────────────────────────────
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(side="bottom", fill="x", pady=(10, 14))

        ctk.CTkFrame(footer, height=1, fg_color=_CLR_BORDER).pack(
            fill="x", padx=18, pady=(0, 10))
        ctk.CTkLabel(
            footer,
            text="⚠  Authorised use only",
            font=(_SF, 9),
            text_color=_CLR_MUTED,
        ).pack(padx=18, anchor="w")

    def _add_nav_item(self, key: str, label: str) -> None:
        """Build a single nav row: left accent stripe + button."""
        row = ctk.CTkFrame(self, fg_color="transparent", height=38)
        row.pack(fill="x", padx=(0, 10), pady=1)
        row.pack_propagate(False)

        stripe = ctk.CTkFrame(
            row, fg_color="transparent", width=3, corner_radius=0)
        stripe.pack(side="left", fill="y", padx=(0, 7))
        stripe.pack_propagate(False)

        btn = ctk.CTkButton(
            row,
            text=label,
            anchor="w",
            fg_color="transparent",
            hover_color=_CLR_HOVER,
            text_color=_CLR_TEXT,
            font=_FONT_LABEL,
            corner_radius=8,
            height=38,
            command=lambda k=key: self._on_select(k),
        )
        btn.pack(side="left", fill="both", expand=True)
        self._items[key] = (stripe, btn)

    def set_active(self, key: str) -> None:
        for k, (stripe, btn) in self._items.items():
            if k == key:
                stripe.configure(fg_color=_CLR_ACCENT)
                btn.configure(
                    fg_color=_CLR_PANEL,
                    text_color=_CLR_TEXT,
                    font=(_SF, 12, "bold"),
                )
            else:
                stripe.configure(fg_color="transparent")
                btn.configure(
                    fg_color="transparent",
                    text_color=_CLR_TEXT,
                    font=_FONT_LABEL,
                )
        self._active = key


# ===========================================================================
# Top bar
# ===========================================================================

class _TopBar(ctk.CTkFrame):
    def __init__(self, parent, on_iface_change) -> None:
        super().__init__(parent, fg_color=_CLR_SIDEBAR, corner_radius=0, height=62)
        self._on_iface_change = on_iface_change
        self._iface_var = tk.StringVar()
        self._build()

    def _build(self) -> None:
        self.pack_propagate(False)
        # Bottom hairline for visual separation from content
        ctk.CTkFrame(self, height=1, fg_color=_CLR_BORDER).pack(
            side="bottom", fill="x")

        # ── Left side: interface picker ──────────────────────────────
        left = ctk.CTkFrame(self, fg_color="transparent")
        left.pack(side="left", fill="y", padx=(20, 0))

        ctk.CTkLabel(
            left, text="INTERFACE",
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED,
        ).pack(side="left", padx=(0, 10), pady=14)

        self._combo = ctk.CTkComboBox(
            left,
            variable=self._iface_var,
            values=[],
            width=170,
            height=34,
            command=self._on_iface_change,
            font=_FONT_LABEL,
            fg_color=_CLR_PANEL,
            border_color=_CLR_BORDER,
            border_width=1,
            button_color=_CLR_PANEL,
            button_hover_color=_CLR_HOVER,
            dropdown_fg_color=_CLR_PANEL,
            dropdown_hover_color=_CLR_HOVER,
        )
        self._combo.pack(side="left", pady=14)
        _ToolTip(self._combo, "Select the network interface to use for all operations")

        # ── Right side: keyboard hint pill ───────────────────────────
        hint = ctk.CTkLabel(
            self,
            text="F5  Scan    Ctrl+A  Select all    Esc  Stop    Ctrl+E  Export",
            font=(_SF, 9), text_color=_CLR_MUTED,
        )
        hint.pack(side="right", padx=(0, 20), pady=14)

        # ── Center: status pills (gateway, my IP) ────────────────────
        center = ctk.CTkFrame(self, fg_color="transparent")
        center.pack(side="left", padx=(24, 0), pady=14)

        self._gw_dot, self._gw_label = self._make_pill(
            center, "Gateway", "—", _CLR_MUTED)
        self._gw_pill_container = self._gw_label.master
        self._gw_pill_container.pack(side="left", padx=(0, 10))

        self._ip_dot, self._ip_label = self._make_pill(
            center, "My IP", "—", _CLR_MUTED)
        self._ip_label.master.pack(side="left", padx=(0, 10))

    def _make_pill(
        self,
        parent,
        caption: str,
        value: str,
        dot_color: str,
    ) -> tuple[ctk.CTkLabel, ctk.CTkLabel]:
        """Return (status_dot_label, value_label) for a pill-style chip."""
        pill = ctk.CTkFrame(
            parent,
            fg_color=_CLR_PANEL,
            corner_radius=999,
            border_width=1,
            border_color=_CLR_BORDER,
            height=32,
        )
        pill.pack_propagate(False)

        dot = ctk.CTkLabel(
            pill, text="●", font=(_SF, 11), text_color=dot_color)
        dot.pack(side="left", padx=(12, 4), pady=2)

        ctk.CTkLabel(
            pill, text=caption,
            font=(_SF, 9, "bold"),
            text_color=_CLR_MUTED,
        ).pack(side="left", padx=(0, 6), pady=2)

        value_lbl = ctk.CTkLabel(
            pill, text=value, font=_FONT_LABEL, text_color=_CLR_TEXT)
        value_lbl.pack(side="left", padx=(0, 14), pady=2)
        return dot, value_lbl

    def populate_interfaces(self, ifaces: list[str], selected: str) -> None:
        self._combo.configure(values=ifaces)
        if selected:
            self._iface_var.set(selected)

    def set_gateway(self, gw: str) -> None:
        if gw:
            self._gw_label.configure(text=gw)
            self._gw_dot.configure(text_color=_CLR_SUCCESS)
        else:
            self._gw_label.configure(text="unknown")
            self._gw_dot.configure(text_color=_CLR_WARNING)

    def set_own_ip(self, ip: str) -> None:
        if ip and ip != "—" and ip != "?":
            self._ip_label.configure(text=ip)
            self._ip_dot.configure(text_color=_CLR_ACCENT2)
        else:
            self._ip_label.configure(text=ip or "—")
            self._ip_dot.configure(text_color=_CLR_MUTED)


# ===========================================================================
# Scan Frame
# ===========================================================================

class ScanFrame(ctk.CTkFrame):
    """Host discovery panel."""

    _COLS = ("Device / Hostname", "IP Address", "MAC Address", "Vendor", "Type", "Ports", "●")

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._scanning = False
        self._monitor_running = False
        self._monitor_obj = None
        self._build()

    def _build(self) -> None:
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ── Page header ───────────────────────────────────────────────
        header = _page_header(
            self,
            icon="🔍",
            title="Scan Network",
            subtitle="Discover live hosts on your network and inspect their details",
        )
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(22, 14))

        # host count badge in the right slot
        self._count_label = ctk.CTkLabel(
            header.right_slot, text="No hosts yet",
            font=(_SF, 10, "bold"), text_color=_CLR_MUTED,
        )
        self._count_label.pack(side="right", padx=(0, 2))

        # ── Top controls card ─────────────────────────────────────────
        ctrl = ctk.CTkFrame(
            self, fg_color=_CLR_PANEL, corner_radius=14,
            border_width=1, border_color=_CLR_BORDER,
        )
        ctrl.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 12))
        ctrl.grid_columnconfigure(6, weight=1)

        ctk.CTkLabel(
            ctrl, text="SCAN TYPE",
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED,
        ).grid(row=0, column=0, padx=(18, 8), pady=(16, 14))

        self._scan_type = ctk.CTkComboBox(
            ctrl,
            values=["Fast (ARP)", "Balanced (ARP+ICMP)", "Stealth (TCP SYN)"],
            width=200, height=36,
            font=_FONT_LABEL,
            fg_color=_CLR_SIDEBAR,
            border_color=_CLR_BORDER,
            border_width=1,
            button_color=_CLR_SIDEBAR,
            button_hover_color=_CLR_HOVER,
            dropdown_fg_color=_CLR_PANEL,
            dropdown_hover_color=_CLR_HOVER,
            command=self._on_scan_type_changed,
        )
        self._scan_type.set("Fast (ARP)")
        self._scan_type.grid(row=0, column=1, padx=(0, 12), pady=(16, 14))
        _ToolTip(self._scan_type,
                 "Fast=ARP only  |  Balanced=ARP+ICMP  |  Stealth=TCP SYN (slow, needs root)")

        self._scan_btn = _primary_button(
            ctrl, text="▶   Start Scan",
            command=self._start_scan, width=140, height=36,
        )
        self._scan_btn.grid(row=0, column=2, padx=(0, 8), pady=(16, 14))
        _ToolTip(self._scan_btn, "Start scanning the local network for devices  (F5)")

        self._monitor_btn = _secondary_button(
            ctrl, text="📡   Monitor",
            command=self._toggle_monitor, width=120, height=36,
        )
        self._monitor_btn.configure(border_color=_CLR_ACCENT2)
        self._monitor_btn.grid(row=0, column=3, padx=(0, 8), pady=(16, 14))
        _ToolTip(self._monitor_btn, "Continuously monitor for devices joining or leaving the network")

        self._export_btn = _ghost_button(
            ctrl, text="💾   Export",
            command=self._export_results, width=110, height=36,
        )
        self._export_btn.grid(row=0, column=4, padx=(0, 8), pady=(16, 14))
        _ToolTip(self._export_btn, "Save scan results to CSV or JSON  (Ctrl+E)")

        self._import_btn = _ghost_button(
            ctrl, text="📂   Import",
            command=self._import_hosts, width=110, height=36,
        )
        self._import_btn.grid(row=0, column=5, padx=(0, 8), pady=(16, 14))
        _ToolTip(self._import_btn, "Load hosts from a CSV, JSON, or plain-text file (one IP per line)")

        self._attack_sel_btn = _danger_button(
            ctrl, text="⚡   Attack Selected",
            command=self._go_attack_selected, width=170, height=36,
        )
        self._attack_sel_btn.grid(row=0, column=6, padx=(0, 18), pady=(16, 14), sticky="e")
        _ToolTip(self._attack_sel_btn, "Send selected hosts to the ARP Attack frame")

        # ── Second row: select-all / copy-IPs + optional stealth ports ──
        row2 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row2.grid(row=1, column=0, columnspan=7, sticky="ew", padx=14, pady=(0, 10))

        _ghost_button(
            row2, text="☑   Select All",
            command=self._select_all, width=110, height=30,
            font=_FONT_SMALL,
        ).pack(side="left", padx=(0, 6))

        _ghost_button(
            row2, text="☐   Deselect All",
            command=self._deselect_all, width=120, height=30,
            font=_FONT_SMALL,
        ).pack(side="left", padx=(0, 12))

        _ghost_button(
            row2, text="📋   Copy All IPs",
            command=self._copy_all_ips, width=130, height=30,
            font=_FONT_SMALL,
        ).pack(side="left", padx=(0, 16))

        # Custom ports for Stealth scan
        self._ports_label = ctk.CTkLabel(
            row2, text="Stealth ports:", font=_FONT_SMALL, text_color=_CLR_MUTED)
        self._ports_label.pack(side="left", padx=(0, 4))
        self._ports_entry = ctk.CTkEntry(
            row2, width=200, height=28, font=_FONT_MONO,
            placeholder_text="22,80,443,8080  (comma-separated)")
        self._ports_entry.pack(side="left")
        # Only visible for Stealth mode
        self._ports_label.pack_forget()
        self._ports_entry.pack_forget()

        # ── Search / filter bar ────────────────────────────────────────
        flt = ctk.CTkFrame(ctrl, fg_color="transparent")
        flt.grid(row=2, column=0, columnspan=7, sticky="ew", padx=14, pady=(0, 14))
        flt.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            flt, text="🔎   Filter",
            font=(_SF, 10, "bold"), text_color=_CLR_MUTED,
        ).grid(row=0, column=0, padx=(0, 10))
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())
        self._filter_entry = ctk.CTkEntry(
            flt, textvariable=self._filter_var,
            placeholder_text="Type IP, vendor, hostname, or device type…",
            font=_FONT_LABEL, height=32,
            fg_color=_CLR_SIDEBAR,
            border_color=_CLR_BORDER,
            border_width=1,
        )
        self._filter_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))
        _ghost_button(
            flt, text="✕", width=32, height=32,
            command=lambda: self._filter_var.set(""),
            font=_FONT_LABEL,
        ).grid(row=0, column=2)

        # ── Host table card ───────────────────────────────────────────
        tbl_frame = ctk.CTkFrame(
            self, fg_color=_CLR_PANEL, corner_radius=14,
            border_width=1, border_color=_CLR_BORDER,
        )
        tbl_frame.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 10))
        tbl_frame.grid_rowconfigure(1, weight=1)
        tbl_frame.grid_columnconfigure(0, weight=1)

        # Header row
        hdr = ctk.CTkFrame(tbl_frame, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=2, pady=(2, 0))
        for ci, col in enumerate(self._COLS):
            ctk.CTkLabel(
                hdr, text=col.upper(),
                font=(_SF, 9, "bold"),
                text_color=_CLR_MUTED, anchor="w",
            ).grid(row=0, column=ci, padx=(14 if ci == 0 else 6, 4), pady=10, sticky="w")
        hdr.grid_columnconfigure(len(self._COLS) - 1, weight=1)

        ctk.CTkFrame(tbl_frame, height=1, fg_color=_CLR_BORDER).grid(
            row=0, column=0, sticky="sew", padx=10)

        # Scrollable body
        self._table_body = ctk.CTkScrollableFrame(
            tbl_frame, fg_color="transparent", corner_radius=0)
        self._table_body.grid(row=1, column=0, sticky="nsew", padx=4, pady=(2, 4))
        self._table_body.grid_columnconfigure(0, weight=1)

        self._row_frames: list[_HostRow] = []

        # ── Log console card ──────────────────────────────────────────
        log_frame = ctk.CTkFrame(
            self, fg_color=_CLR_PANEL, corner_radius=14,
            border_width=1, border_color=_CLR_BORDER,
        )
        log_frame.grid(row=3, column=0, sticky="ew", padx=24, pady=(0, 22))
        log_frame.grid_columnconfigure(0, weight=1)

        log_hdr = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_hdr.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        log_hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            log_hdr, text="Activity Log",
            font=_FONT_HEAD, text_color=_CLR_TEXT,
        ).grid(row=0, column=0, sticky="w")

        _ghost_button(
            log_hdr, text="💾   Export Log",
            command=self._export_log, width=120, height=28,
            font=_FONT_SMALL,
        ).grid(row=0, column=1, padx=(0, 6))

        _ghost_button(
            log_hdr, text="🗑   Clear",
            command=self._clear_log, width=80, height=28,
            font=_FONT_SMALL,
        ).grid(row=0, column=2)

        self._log_text = ctk.CTkTextbox(
            log_frame, height=140, font=_FONT_MONO,
            fg_color=_CLR_BG, text_color=_CLR_SUCCESS,
            scrollbar_button_color=_CLR_PANEL,
            border_width=1, border_color=_CLR_BORDER,
            corner_radius=10,
        )
        self._log_text.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 14))
        self._log_text.configure(state="disabled")

        # Progress bar (hidden by default)
        self._progress = ctk.CTkProgressBar(
            self, mode="indeterminate",
            fg_color=_CLR_PANEL,
            progress_color=_CLR_ACCENT,
            corner_radius=999,
            height=4,
        )

    # ── Scan ──────────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        if self._scanning:
            return
        if not self._app._iface:
            messagebox.showerror("No Interface", "Please select a network interface first.")
            return
        self._scanning = True
        self._scan_btn.configure(state="disabled", text="Scanning…")
        self._progress.grid(row=4, column=0, sticky="ew", padx=24, pady=(0, 6))
        self._progress.start()
        self._clear_table()
        self._app.log(f"Starting {self._scan_type.get()} on {self._app._iface} …")
        _thread(self._run_scan)

    def _run_scan(self) -> None:
        try:
            from wifi_killer.modules import scanner

            subnet = get_interface_subnet(self._app._iface)
            if not subnet:
                self.after(0, lambda: self._app.log("Could not detect subnet.", "warn"))
                return

            scan_choice = self._scan_type.get()
            if "Balanced" in scan_choice:
                hosts = scanner.balanced_scan(subnet=subnet, iface=self._app._iface, timeout=2.0)
            elif "Stealth" in scan_choice:
                # Parse and validate custom ports
                raw_ports = self._ports_entry.get().strip()
                custom_ports = None
                if raw_ports:
                    try:
                        custom_ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip()]
                    except ValueError as exc:
                        self.after(0, lambda e=exc: messagebox.showerror(
                            "Invalid Ports", f"Port values must be integers.\n\n{e}"))
                        return
                    invalid = [p for p in custom_ports if not (1 <= p <= 65535)]
                    if invalid:
                        self.after(0, lambda iv=invalid: messagebox.showerror(
                            "Invalid Ports",
                            f"Ports must be between 1 and 65535.\nInvalid: {iv}",
                        ))
                        return
                hosts = scanner.stealth_scan(
                    subnet=subnet, iface=self._app._iface, delay=0.3,
                    ports=custom_ports,
                )
            else:
                hosts = scanner.fast_scan(subnet=subnet, iface=self._app._iface, timeout=2.0)

            # Enrich
            enriched = []
            gw = self._app._gateway
            for h in hosts:
                info = identify_host(h["ip"], h["mac"],
                                     open_ports=h.get("open_ports", []),
                                     gateway_ip=gw)
                info["ping"] = h.get("ping", False)
                enriched.append(info)

            self._app.merge_hosts(enriched)
            all_known = list(self._app._host_registry.values())
            online_count = sum(1 for h in all_known if h.get("online", True))
            self._app.record_scan(online_count)
            self.after(0, lambda ah=all_known: self._populate_table(ah))
            self.after(0, lambda: self._app.log(
                f"Scan complete – {online_count} online, "
                f"{len(all_known) - online_count} offline (total {len(all_known)} known).", "ok"))
            self.after(0, self._app.refresh_dashboard)
            self.after(0, self._app.mark_hosts_changed)

        except Exception as exc:
            self.after(0, lambda exc=exc: self._app.log(f"Scan error: {exc}", "err"))
        finally:
            self.after(0, self._scan_done)

    def _scan_done(self) -> None:
        self._scanning = False
        self._scan_btn.configure(state="normal", text="▶  Start Scan")
        self._progress.stop()
        self._progress.grid_remove()

    # ── Scan-type helper ──────────────────────────────────────────────

    def _on_scan_type_changed(self, choice: str) -> None:
        """Show/hide the custom ports entry based on scan type."""
        if "Stealth" in choice:
            self._ports_label.pack(side="left", padx=(0, 4))
            self._ports_entry.pack(side="left")
        else:
            self._ports_label.pack_forget()
            self._ports_entry.pack_forget()

    # ── Select / deselect helpers ────────────────────────────────────

    def _select_all(self) -> None:
        for row in self._row_frames:
            row.selected.set(True)

    def _deselect_all(self) -> None:
        for row in self._row_frames:
            row.selected.set(False)

    def _copy_all_ips(self) -> None:
        hosts = getattr(self, "_all_hosts", self._app._hosts)
        if not hosts:
            messagebox.showinfo("Copy IPs", "No hosts found. Run a scan first.")
            return
        ips = "\n".join(h.get("ip", "") for h in hosts if h.get("ip"))
        self.clipboard_clear()
        self.clipboard_append(ips)
        self._app.log(f"Copied {len(hosts)} IP address(es) to clipboard.", "ok")

    # ── Log helpers ───────────────────────────────────────────────────

    def _clear_log(self) -> None:
        if not messagebox.askyesno("Clear Log", "Delete all activity log entries?"):
            return
        widget = self._log_text._textbox
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.configure(state="disabled")

    def _export_log(self) -> None:
        widget = self._log_text._textbox
        content = widget.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showinfo("Export Log", "The activity log is empty.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Export Activity Log",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self._app.log(f"Activity log exported to {path}", "ok")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    # ── Monitor ───────────────────────────────────────────────────────

    def _toggle_monitor(self) -> None:
        if self._monitor_running:
            self._stop_monitor()
        else:
            self._start_monitor()

    def _start_monitor(self) -> None:
        if not self._app._iface:
            messagebox.showerror("No Interface", "Please select a network interface first.")
            return
        from wifi_killer.modules.scanner import NetworkMonitor

        subnet = get_interface_subnet(self._app._iface)
        gw = self._app._gateway

        def on_new(h: dict) -> None:
            info = identify_host(h["ip"], h["mac"], gateway_ip=gw)
            info["ping"] = False
            self._app.add_host(info)
            # Append a new row for this host at the end of the table
            self.after(0, lambda i=info: self._add_row(i, len(self._row_frames)))
            self.after(0, lambda: self._app.log(
                f"New device: {h['ip']} ({info.get('vendor','?')})", "ok"))

        def on_left(h: dict) -> None:
            ip = h.get("ip", "")
            # Mark device offline in registry (don't remove it)
            if ip in self._app._host_registry:
                self._app._host_registry[ip]["online"] = False
                self._app._hosts = list(self._app._host_registry.values())
            self.after(0, lambda: self._app.log(
                f"Device left (offline): {ip}", "warn"))

        self._monitor_obj = NetworkMonitor(
            subnet=subnet, iface=self._app._iface,
            interval=15, on_new=on_new, on_left=on_left,
        )
        self._monitor_obj.start()
        self._monitor_running = True
        self._monitor_btn.configure(text="⏹  Stop Monitor", fg_color=_CLR_DANGER)
        self._app.log("Continuous monitor started (15 s interval).", "ok")

    def _stop_monitor(self) -> None:
        if self._monitor_obj:
            self._monitor_obj.stop()
            self._monitor_obj = None
        self._monitor_running = False
        self._monitor_btn.configure(text="📡  Monitor", fg_color=_CLR_ACCENT2)
        self._app.log("Monitor stopped.", "warn")

    # ── Table helpers ─────────────────────────────────────────────────

    def _clear_table(self) -> None:
        for r in self._row_frames:
            r.destroy()
        self._row_frames.clear()
        self._count_label.configure(text="Scanning…")

    def _populate_table(self, hosts: list[dict]) -> None:
        self._all_hosts = hosts  # keep unfiltered copy for search
        self._clear_table()
        self._apply_filter()

    def _apply_filter(self) -> None:
        """Filter the displayed rows based on the search entry (no re-scan)."""
        query = self._filter_var.get().strip().lower()
        hosts = getattr(self, "_all_hosts", self._app._hosts)
        if query:
            def _match(h: dict) -> bool:
                return any(
                    query in str(h.get(k, "")).lower()
                    for k in ("ip", "mac", "vendor", "hostname", "type")
                )
            filtered = [h for h in hosts if _match(h)]
        else:
            filtered = hosts

        for r in self._row_frames:
            r.destroy()
        self._row_frames.clear()
        for i, h in enumerate(filtered):
            self._add_row(h, i)
        total = len(hosts)
        shown = len(filtered)
        if query:
            self._count_label.configure(
                text=f"{shown}/{total} host(s) shown")
        else:
            self._count_label.configure(
                text=f"{total} host(s) found" if total else "No hosts yet")

    def _add_row(self, info: dict, idx: int) -> None:
        row = _HostRow(self._table_body, info, idx, self._app)
        row.grid(row=idx, column=0, sticky="ew", padx=4, pady=1)
        self._table_body.grid_columnconfigure(0, weight=1)
        self._row_frames.append(row)

    # ── Export ────────────────────────────────────────────────────────

    def _export_results(self) -> None:
        if not self._app._hosts:
            messagebox.showinfo("Export", "No hosts to export. Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv"), ("JSON file", "*.json"), ("All files", "*.*")],
            title="Export scan results",
        )
        if not path:
            return
        try:
            if path.endswith(".json"):
                with open(path, "w") as f:
                    json.dump(self._app._hosts, f, indent=2)
            else:
                keys = ["ip", "mac", "vendor", "hostname", "type", "open_ports", "ping"]
                with open(path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(self._app._hosts)
            self._app.log(f"Results exported to {path}", "ok")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    # ── Import hosts ──────────────────────────────────────────────────

    def _import_hosts(self) -> None:
        """Load hosts from a CSV, JSON, or plain-text file (one IP per line)."""
        path = filedialog.askopenfilename(
            filetypes=[
                ("All supported", "*.csv *.json *.txt"),
                ("CSV file", "*.csv"),
                ("JSON file", "*.json"),
                ("Text file", "*.txt"),
                ("All files", "*.*"),
            ],
            title="Import hosts",
        )
        if not path:
            return
        try:
            hosts: list[dict] = []
            if path.endswith(".json"):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    hosts = data
                else:
                    messagebox.showerror("Import Error", "JSON file must contain a list of host objects.")
                    return
            elif path.endswith(".csv"):
                with open(path, "r", encoding="utf-8", newline="") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        hosts.append(dict(row))
            else:
                # Plain text – one IP per line
                with open(path, "r", encoding="utf-8") as f:
                    for raw_line in f:
                        ip = raw_line.strip()
                        if ip and _validate_ip(ip):
                            hosts.append({"ip": ip, "mac": "—", "vendor": "—",
                                          "hostname": "—", "type": "unknown",
                                          "open_ports": [], "ping": False})

            if not hosts:
                messagebox.showinfo("Import", "No valid hosts found in the file.")
                return

            # Normalise keys – ensure every record has the expected fields
            normalised: list[dict] = []
            for h in hosts:
                normalised.append({
                    "ip":         h.get("ip", "?.?.?.?"),
                    "mac":        h.get("mac", "—"),
                    "vendor":     h.get("vendor", "—"),
                    "hostname":   h.get("hostname", "—"),
                    "type":       h.get("type", "unknown"),
                    "open_ports": h.get("open_ports", []),
                    "ping":       h.get("ping", False),
                })

            self._app._hosts = normalised
            self._populate_table(normalised)
            self._app.log(f"Imported {len(normalised)} host(s) from {os.path.basename(path)}", "ok")

        except json.JSONDecodeError as exc:
            messagebox.showerror("Import Error", f"Invalid JSON:\n{exc}")
        except Exception as exc:
            messagebox.showerror("Import Error", str(exc))

    # ── Attack shortcut ───────────────────────────────────────────────

    def _go_attack_selected(self) -> None:
        selected = [r.info for r in self._row_frames if r.selected.get()]
        if not selected:
            messagebox.showinfo("Attack", "Please select at least one host via the checkbox.")
            return
        atk_frame: AttackFrame = self._app._frames.get("attack")  # type: ignore
        if atk_frame:
            atk_frame.set_targets(selected)
        self._app._show_frame("attack")

    # ── Log helper (called by WifiKillerApp.log) ───────────────────────

    def append_log(self, line: str, level: str = "info") -> None:
        color_map = {
            "ok":   _CLR_SUCCESS,
            "warn": _CLR_WARNING,
            "err":  _CLR_DANGER,
            "info": _CLR_TEXT,
        }
        color = color_map.get(level, _CLR_TEXT)
        widget = self._log_text._textbox  # underlying tk.Text widget
        widget.configure(state="normal")
        start = widget.index("end-1c")
        widget.insert("end", line)
        end = widget.index("end-1c")
        tag = f"lvl_{level}"
        widget.tag_configure(tag, foreground=color)
        widget.tag_add(tag, start, end)
        widget.see("end")
        widget.configure(state="disabled")


# ===========================================================================
# Host table row widget
# ===========================================================================

class _HostRow(ctk.CTkFrame):
    # Column widths: [icon+name block, IP, MAC, Vendor, Type, Ports, Ping]
    _WIDTHS = (200, 120, 150, 155, 155, 110, 42)

    def __init__(self, parent, info: dict, idx: int, app: WifiKillerApp) -> None:
        online = info.get("online", True)
        if not online:
            bg = "#111120"   # noticeably dimmer for offline hosts
        else:
            bg = _CLR_ROW_ODD if idx % 2 == 0 else _CLR_ROW_EVEN
        super().__init__(parent, fg_color=bg, corner_radius=7)
        self.info = info
        self._app = app
        self.selected = tk.BooleanVar(value=False)
        self._build()

    def _build(self) -> None:
        self.grid_columnconfigure(8, weight=1)

        # ── Checkbox ────────────────────────────────────────────────
        chk = ctk.CTkCheckBox(
            self, text="", variable=self.selected,
            width=24, checkbox_width=18, checkbox_height=18,
        )
        chk.grid(row=0, column=0, padx=(8, 2), pady=8)

        # ── Column 1: device icon + name/hostname (prominent) ───────
        icon       = self.info.get("icon", "🔌")
        hostname   = self.info.get("hostname") or ""
        device_type = self.info.get("type", "Unknown")
        # Display name = hostname if known, else device type
        display_name = hostname if hostname else device_type

        name_cell = ctk.CTkFrame(self, fg_color="transparent", width=self._WIDTHS[0])
        name_cell.grid(row=0, column=1, padx=(6, 4), pady=4, sticky="w")
        name_cell.grid_propagate(False)
        name_cell.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            name_cell, text=icon, font=(_SF, 16), anchor="w",
        ).grid(row=0, column=0, padx=(4, 4), pady=0, sticky="w")

        _name_color = (_CLR_TEXT if hostname else _CLR_MUTED) if self.info.get("online", True) else "#444460"
        ctk.CTkLabel(
            name_cell, text=display_name,
            font=_FONT_NAME,
            text_color=_name_color,
            anchor="w",
        ).grid(row=0, column=1, padx=(0, 4), pady=0, sticky="w")

        name_cell.bind("<Button-3>", self._show_context_menu)

        # ── Columns 2-7: IP, MAC, Vendor, Type, Ports, Ping ─────────
        ip_str = self.info.get("ip", "")
        mac_str = self.info.get("mac", "")
        vendor_str = self.info.get("vendor", "Unknown")
        # Shorten vendor if too long
        if len(vendor_str) > 18:
            vendor_str = vendor_str[:16] + "…"
        # Type: just the text (icon already in column 1)
        type_str  = device_type
        if len(type_str) > 20:
            type_str = type_str[:18] + "…"
        ports_str  = _fmt_ports(self.info.get("open_ports", []))
        online     = self.info.get("online", True)
        status_str = "●" if online else "○"

        # Dim text for offline rows so they look visually distinct
        _txt  = _CLR_TEXT  if online else "#555577"
        _mute = _CLR_MUTED if online else "#3a3a55"

        col_vals = [ip_str, mac_str, vendor_str, type_str, ports_str, status_str]
        col_colors = [
            _CLR_SUCCESS if online else "#3a7a55",  # IP – green online, dim offline
            _mute,                                   # MAC
            _txt,                                    # Vendor
            (_CLR_WARNING if "Unknown" in type_str else _txt) if online else _mute,
            _txt,                                    # Ports
            _CLR_SUCCESS if online else "#555577",   # Status dot
        ]

        for ci, (val, w, color) in enumerate(zip(col_vals, self._WIDTHS[1:], col_colors)):
            lbl = ctk.CTkLabel(
                self, text=val,
                font=_FONT_MONO if ci in (0, 1) else _FONT_LABEL,
                text_color=color,
                anchor="w", width=w,
            )
            lbl.grid(row=0, column=ci + 2, padx=(2, 2), pady=8, sticky="w")
            lbl.bind("<Button-3>", self._show_context_menu)

        # ── Action buttons ───────────────────────────────────────────
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=0, column=9, padx=(4, 10), pady=4, sticky="e")

        info_btn = ctk.CTkButton(
            btn_frame, text="ℹ️", width=32, height=28,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=(_SF, 11), command=self._show_detail,
        )
        info_btn.pack(side="left", padx=2)
        _ToolTip(info_btn, "View full details for this host")

        copy_btn = ctk.CTkButton(
            btn_frame, text="📋", width=32, height=28,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=(_SF, 11), command=self._copy_info,
        )
        copy_btn.pack(side="left", padx=2)
        _ToolTip(copy_btn, "Copy host info to clipboard")

        atk_btn = ctk.CTkButton(
            btn_frame, text="⚡", width=32, height=28,
            fg_color="#5a2d00", hover_color="#a05000",
            font=(_SF, 11), command=self._quick_attack,
        )
        atk_btn.pack(side="left", padx=2)
        _ToolTip(atk_btn, "Launch ARP attack on this host")

        # Right-click on the row frame itself
        self.bind("<Button-3>", self._show_context_menu)

    # ── Context menu ─────────────────────────────────────────────────

    def _show_context_menu(self, event: tk.Event) -> None:
        ip  = self.info.get("ip", "")
        mac = self.info.get("mac", "")
        menu = tk.Menu(
            self, tearoff=0,
            bg=_CLR_PANEL, fg=_CLR_TEXT,
            activebackground=_CLR_ACCENT, activeforeground="white",
            font=(_SF, 10),
        )
        menu.add_command(label=f"  {ip}",       state="disabled")
        menu.add_separator()
        menu.add_command(label="ℹ️   View Details",        command=self._show_detail)
        menu.add_command(label="📋  Copy Info",             command=self._copy_info)
        menu.add_command(label="📌  Copy IP Only",          command=lambda: self._copy_ip(ip))
        menu.add_separator()
        menu.add_command(label="⚡  ARP Attack",            command=self._quick_attack)
        menu.add_command(label="🚦  Set Speed Limit",       command=self._go_throttle)
        menu.add_command(label="🏓  Add to Ping Monitor",   command=self._add_to_ping)
        menu.add_command(label="🗺️   Show on Map",           command=self._show_on_map)
        menu.add_separator()
        if mac and mac not in ("??:??:??:??:??:??", ""):
            menu.add_command(label="💡  Wake on LAN",       command=self._wake_on_lan)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # ── Actions ──────────────────────────────────────────────────────

    def _show_detail(self) -> None:
        _HostDetailDialog(self, self.info, self._app)

    def _copy_info(self) -> None:
        text = (
            f"IP: {self.info.get('ip','')}\n"
            f"MAC: {self.info.get('mac','')}\n"
            f"Vendor: {self.info.get('vendor','')}\n"
            f"Hostname: {self.info.get('hostname') or '—'}\n"
            f"Type: {self.info.get('type','')}\n"
            f"Ports: {_fmt_ports(self.info.get('open_ports',[]))}"
        )
        self.clipboard_clear()
        self.clipboard_append(text)
        self._app.log(f"Copied info for {self.info.get('ip','')}", "ok")

    def _copy_ip(self, ip: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(ip)
        self._app.log(f"Copied {ip} to clipboard", "ok")

    def _quick_attack(self) -> None:
        atk_frame: AttackFrame = self._app._frames.get("attack")  # type: ignore
        if atk_frame:
            atk_frame.set_targets([self.info])
        self._app._show_frame("attack")

    def _go_throttle(self) -> None:
        tf: ThrottleFrame = self._app._frames.get("throttle")  # type: ignore
        if tf:
            tf.prefill_target(self.info.get("ip", ""))
        self._app._show_frame("throttle")

    def _add_to_ping(self) -> None:
        pm: PingMonitorFrame = self._app._frames.get("ping_monitor")  # type: ignore
        if pm:
            pm.add_host(self.info.get("ip", ""))
        self._app._show_frame("ping_monitor")

    def _show_on_map(self) -> None:
        nm: NetworkMapFrame = self._app._frames.get("network_map")  # type: ignore
        if nm:
            nm.redraw()
        self._app._show_frame("network_map")

    def _wake_on_lan(self) -> None:
        mac = self.info.get("mac", "")
        if not mac or mac == "??:??:??:??:??:??":
            messagebox.showwarning("No MAC", "MAC address not available for this host.")
            return
        try:
            from wifi_killer.modules.wol import send_wol
            send_wol(mac)
            self._app.log(f"Wake-on-LAN packet sent to {mac}", "ok")
            messagebox.showinfo("Wake on LAN", f"Magic packet sent to {mac}.\n\nThe device will power on if it has WoL enabled.")
        except Exception as exc:
            messagebox.showerror("WoL Error", str(exc))


# ===========================================================================
# Host Detail Dialog
# ===========================================================================

class _HostDetailDialog(ctk.CTkToplevel):
    """Modal popup showing full details for a scanned host, with action buttons."""

    def __init__(self, parent, info: dict, app: WifiKillerApp) -> None:
        super().__init__(parent)
        self._info = info
        self._app = app
        self._ping_samples: list[float] = []
        self._ping_running = False

        ip = info.get("ip", "?")
        self.title(f"Host Details – {ip}")
        self.geometry("540x560")
        self.resizable(False, False)
        self.configure(fg_color=_CLR_BG)
        self.grab_set()
        self._build()
        self._start_live_ping()

    def _build(self) -> None:
        info = self._info
        icon     = info.get("icon", "🔌")
        hostname = info.get("hostname") or ""
        ip_str   = info.get("ip", "?")

        # ── Title bar ────────────────────────────────────────────────
        title_row = ctk.CTkFrame(self, fg_color="transparent")
        title_row.pack(padx=24, pady=(20, 2), anchor="w")

        ctk.CTkLabel(
            title_row, text=icon, font=(_SF, 32),
        ).pack(side="left", padx=(0, 12))

        title_col = ctk.CTkFrame(title_row, fg_color="transparent")
        title_col.pack(side="left")

        # Show hostname prominently if known, else show IP
        display_name = hostname if hostname else ip_str
        ctk.CTkLabel(
            title_col, text=display_name,
            font=_FONT_TITLE, text_color=_CLR_TEXT,
            anchor="w",
        ).pack(anchor="w")
        if hostname:
            ctk.CTkLabel(
                title_col, text=ip_str,
                font=_FONT_MONO, text_color=_CLR_SUCCESS,
                anchor="w",
            ).pack(anchor="w")

        ctk.CTkLabel(
            self, text=info.get("vendor", "Unknown Vendor"),
            font=_FONT_HEAD, text_color=_CLR_MUTED,
        ).pack(padx=24, pady=(0, 12), anchor="w")

        # Detail rows card
        card = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        card.pack(fill="x", padx=20, pady=(0, 12))
        card.grid_columnconfigure(1, weight=1)

        fields = [
            ("IP Address",  info.get("ip", "?")),
            ("MAC Address", info.get("mac", "?")),
            ("Vendor",      info.get("vendor", "Unknown")),
            ("Hostname",    info.get("hostname") or "—"),
            ("Device Type", f"{info.get('icon','🔌')}  {info.get('type', 'Unknown')}"),
            ("OS Hint",     info.get("os_hint", "—")),
            ("Open Ports",  _fmt_ports(info.get("open_ports", []))),
            ("Ping",        "● Alive" if info.get("ping") else "○ No response"),
            ("Subnet",      info.get("subnet", "—")),
        ]
        for ri, (label, val) in enumerate(fields):
            bg = _CLR_ROW_ODD if ri % 2 == 0 else _CLR_ROW_EVEN
            row = ctk.CTkFrame(card, fg_color=bg, corner_radius=0)
            row.pack(fill="x")
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(
                row, text=label, font=_FONT_LABEL,
                text_color=_CLR_MUTED, width=110, anchor="w",
            ).grid(row=0, column=0, padx=(14, 6), pady=7, sticky="w")
            ctk.CTkLabel(
                row, text=val, font=_FONT_MONO,
                text_color=_CLR_TEXT, anchor="w",
            ).grid(row=0, column=1, padx=(0, 14), pady=7, sticky="w")

        # Live ping panel
        ping_card = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        ping_card.pack(fill="x", padx=20, pady=(0, 12))
        ping_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(ping_card, text="Live Ping  (RTT)",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).grid(
            row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self._ping_label = ctk.CTkLabel(
            ping_card, text="Measuring…", font=_FONT_MONO,
            text_color=_CLR_SUCCESS)
        self._ping_label.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")

        # Action buttons
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(padx=20, pady=(0, 16), anchor="w")

        ctk.CTkButton(
            btn_row, text="⚡  Attack",
            fg_color=_CLR_ACCENT, hover_color="#c73652",
            font=_FONT_LABEL, width=120,
            command=self._go_attack,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row, text="🚦  Throttle",
            fg_color=_CLR_ACCENT2, hover_color="#6b44a8",
            font=_FONT_LABEL, width=120,
            command=self._go_throttle,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row, text="🏓  Add to Ping",
            fg_color=_CLR_PANEL, hover_color="#1a4a80",
            font=_FONT_LABEL, width=140,
            command=self._go_ping_monitor,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row, text="🗺️  Show on Map",
            fg_color=_CLR_PANEL, hover_color="#1a4a80",
            font=_FONT_LABEL, width=140,
            command=self._go_map,
        ).pack(side="left", padx=(0, 8))

        mac = info.get("mac", "")
        if mac and mac not in ("??:??:??:??:??:??", ""):
            wol_btn = ctk.CTkButton(
                btn_row, text="💡  Wake Up",
                fg_color="#1a4a20", hover_color="#256b30",
                font=_FONT_LABEL, width=110,
                command=self._wake_on_lan,
            )
            wol_btn.pack(side="left", padx=(0, 8))
            _ToolTip(wol_btn, "Send a Wake-on-LAN magic packet to power on this device")

        ctk.CTkButton(
            btn_row, text="📋  Copy",
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=_FONT_LABEL, width=100,
            command=self._copy,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row, text="✕ Close",
            fg_color=_CLR_PANEL, hover_color=_CLR_DANGER,
            font=_FONT_LABEL, width=90,
            command=self.destroy,
        ).pack(side="left")

    # ── Live ping thread ──────────────────────────────────────────────

    def _start_live_ping(self) -> None:
        self._ping_running = True
        _thread(self._ping_loop)

    def _ping_loop(self) -> None:
        ip = self._info.get("ip", "")
        for _ in range(6):   # 6 probes then stop to avoid hanging forever
            if not self._ping_running:
                break
            rtt = _ping_once(ip, timeout=1.5)
            if rtt is not None:
                self._ping_samples.append(rtt)
            self.after(0, self._update_ping_label)
            time.sleep(1.5)

    def _update_ping_label(self) -> None:
        if not self._ping_samples:
            self._ping_label.configure(text="No response (host may be down)")
            return
        last = self._ping_samples[-1]
        mn = min(self._ping_samples)
        av = statistics.mean(self._ping_samples)
        mx = max(self._ping_samples)
        self._ping_label.configure(
            text=f"Last: {last:.1f} ms    min {mn:.1f}  avg {av:.1f}  max {mx:.1f} ms")

    def destroy(self) -> None:
        self._ping_running = False
        super().destroy()

    # ── Action shortcuts ──────────────────────────────────────────────

    def _go_attack(self) -> None:
        atk_frame: AttackFrame = self._app._frames.get("attack")  # type: ignore
        if atk_frame:
            atk_frame.set_targets([self._info])
        self._app._show_frame("attack")
        self.destroy()

    def _go_throttle(self) -> None:
        thr: ThrottleFrame = self._app._frames.get("throttle")  # type: ignore
        if thr:
            ip = self._info.get("ip", "")
            thr._manual_entry.delete(0, "end")
            thr._manual_entry.insert(0, ip)
        self._app._show_frame("throttle")
        self.destroy()

    def _go_ping_monitor(self) -> None:
        pm: PingMonitorFrame = self._app._frames.get("ping_monitor")  # type: ignore
        if pm:
            pm.add_host(self._info.get("ip", ""), self._info.get("hostname"))
        self._app._show_frame("ping_monitor")
        self.destroy()

    def _go_map(self) -> None:
        nm: NetworkMapFrame = self._app._frames.get("network_map")  # type: ignore
        if nm:
            nm.redraw()
        self._app._show_frame("network_map")
        self.destroy()

    def _wake_on_lan(self) -> None:
        mac = self._info.get("mac", "")
        if not mac or mac == "??:??:??:??:??:??":
            messagebox.showwarning("No MAC", "MAC address not available for this host.")
            return
        try:
            from wifi_killer.modules.wol import send_wol
            send_wol(mac)
            self._app.log(f"Wake-on-LAN packet sent to {mac}", "ok")
            messagebox.showinfo(
                "Wake on LAN",
                f"Magic packet sent to {mac}.\n\n"
                "The device will power on if Wake-on-LAN is enabled in its firmware/OS.",
            )
        except Exception as exc:
            messagebox.showerror("WoL Error", str(exc))

    def _copy(self) -> None:
        info = self._info
        text = (
            f"IP: {info.get('ip','')}\n"
            f"MAC: {info.get('mac','')}\n"
            f"Vendor: {info.get('vendor','')}\n"
            f"Hostname: {info.get('hostname') or '—'}\n"
            f"Type: {info.get('type','')}\n"
            f"Ports: {_fmt_ports(info.get('open_ports',[]))}"
        )
        self.clipboard_clear()
        self.clipboard_append(text)


# ===========================================================================
# Attack Frame
# ===========================================================================

class AttackFrame(ctk.CTkFrame):
    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._attack_obj = None
        self._running = False
        # Selection model: IP → BooleanVar driving the checkbox.
        self._selection: dict[str, tk.BooleanVar] = {}
        # Row widgets keyed by IP so we can recolour / hide on filter.
        self._rows: dict[str, ctk.CTkFrame] = {}
        self._filter_var = tk.StringVar()
        # MITM-companion modules — start with attack, stop with attack.
        self._mitm_inspector = None
        self._dns_spoofer = None
        self._conn_killer = None
        self._llmnr_poisoner = None
        self._mdns_spoofer = None
        self._ntp_spoofer = None
        self._pcap_recorder = None
        # Live activity badges on each target row (keyed by victim IP).
        # Populated only while the MITM Inspector is running.
        self._row_activity_labels: dict[str, ctk.CTkLabel] = {}
        # User-defined DNS spoof rules: list of (StringVar pattern, StringVar ip).
        self._dns_rules: list[tuple[tk.StringVar, tk.StringVar]] = []
        # User-defined TCP-kill rules: list of (StringVar pattern, StringVar port).
        self._kill_rules: list[tuple[tk.StringVar, tk.StringVar]] = []
        # Toggle whether each companion auto-starts with the attack.
        self._opt_inspect = tk.BooleanVar(value=True)
        self._opt_dns_spoof = tk.BooleanVar(value=False)
        self._opt_conn_kill = tk.BooleanVar(value=False)
        self._opt_llmnr = tk.BooleanVar(value=False)
        self._opt_mdns = tk.BooleanVar(value=False)
        self._opt_ntp_spoof = tk.BooleanVar(value=False)
        self._opt_pcap = tk.BooleanVar(value=False)
        # Inputs for the new modules.
        self._mdns_pattern_var = tk.StringVar(value="*")  # all .local by default
        self._ntp_offset_var = tk.StringVar(value="3600")  # +1h default
        self._pcap_path_var = tk.StringVar(
            value=os.path.join(
                os.path.expanduser("~"), "wifi-killer-session.pcap",
            )
        )
        self._build()

    # ------------------------------------------------------------------ #
    # Target selection                                                     #
    # ------------------------------------------------------------------ #

    @property
    def _selected_targets(self) -> list[dict]:
        """Return the currently-checked hosts as a list of host dicts."""
        out: list[dict] = []
        registry = self._app._host_registry
        for ip, var in self._selection.items():
            if var.get() and ip in registry:
                out.append(registry[ip])
        return out

    def set_targets(self, targets: list[dict]) -> None:
        """Programmatic API used from the Scan tab's 'Attack Selected'.

        Ensures the target picker reflects the passed-in hosts (others
        get deselected so the user sees exactly what's about to run).
        """
        wanted = {t.get("ip", "") for t in targets if t.get("ip")}
        # Make sure every wanted host is in the registry / picker.
        self._refresh_target_list()
        for ip, var in self._selection.items():
            var.set(ip in wanted)
        self._update_target_summary()

    def _on_show(self) -> None:
        """Re-sync the target list each time the tab is opened."""
        self._refresh_target_list()

    def _build(self) -> None:
        """Tabbed layout: Targets / Companions / Status, with a fixed top
        bar holding the page header, the hazard banner, and the always-
        visible Method + Gateway + Launch row.
        """
        # Rows: 0 header  ·  1 banner  ·  2 quick-config bar  ·  3 tabview (grows)
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ── Page header ───────────────────────────────────────────────
        header = _page_header(
            self, icon="⚡", title="ARP Attack",
            subtitle="ARP-spoofing attacks — authorised network testing only",
        )
        header.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 8))

        # Selection-count badge in the header's right slot — always visible.
        self._target_summary = ctk.CTkLabel(
            header.right_slot, text="0 of 0 targets selected",
            font=(_SF, 11, "bold"), text_color=_CLR_MUTED,
        )
        self._target_summary.pack(side="right", padx=(0, 2))

        # ── Hazard banner ─────────────────────────────────────────────
        banner = ctk.CTkFrame(
            self, fg_color=_shade(_CLR_DANGER, 0.25),
            corner_radius=12, border_width=1, border_color=_CLR_DANGER,
        )
        banner.grid(row=1, column=0, sticky="ew", padx=28, pady=(0, 10))
        ctk.CTkLabel(
            banner,
            text="⚠   Destructive: this will impersonate the gateway on your LAN. "
                 "Only run on networks you own or have explicit permission to test.",
            font=(_SF, 11, "bold"),
            text_color="#ffd6dc",
            anchor="w",
        ).pack(fill="x", padx=14, pady=10)

        # ── Quick-config bar: method + gateway + launch/stop (sticky) ─
        cfg = ctk.CTkFrame(
            self, fg_color=_CLR_PANEL, corner_radius=14,
            border_width=1, border_color=_CLR_BORDER,
        )
        cfg.grid(row=2, column=0, padx=28, pady=(0, 10), sticky="ew")
        cfg.grid_columnconfigure(1, weight=0)
        cfg.grid_columnconfigure(3, weight=0)
        cfg.grid_columnconfigure(5, weight=1)

        ctk.CTkLabel(
            cfg, text="METHOD",
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED,
        ).grid(row=0, column=0, padx=(18, 10), pady=14, sticky="w")
        self._method = ctk.CTkComboBox(
            cfg, width=280, height=36, font=_FONT_LABEL,
            values=[
                "A – Full MITM (bi-directional)",
                "B – Cut Client Only",
                "C – Cut Gateway Only",
            ],
            fg_color=_CLR_SIDEBAR,
            border_color=_CLR_BORDER, border_width=1,
            button_color=_CLR_SIDEBAR, button_hover_color=_CLR_HOVER,
            dropdown_fg_color=_CLR_PANEL, dropdown_hover_color=_CLR_HOVER,
        )
        self._method.set("A – Full MITM (bi-directional)")
        self._method.grid(row=0, column=1, padx=(0, 18), pady=14, sticky="w")

        ctk.CTkLabel(
            cfg, text="GATEWAY IP",
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED,
        ).grid(row=0, column=2, padx=(0, 10), pady=14, sticky="w")
        self._gw_entry = ctk.CTkEntry(
            cfg, width=160, height=36, font=_FONT_LABEL,
            placeholder_text="auto-detected",
            fg_color=_CLR_SIDEBAR,
            border_color=_CLR_BORDER, border_width=1,
        )
        self._gw_entry.grid(row=0, column=3, padx=(0, 18), pady=14, sticky="w")

        self._start_btn = _danger_button(
            cfg, text="⚡   Launch Attack",
            command=self._start_attack, width=180,
        )
        self._start_btn.grid(row=0, column=4, padx=(0, 10), pady=14, sticky="e")

        self._stop_btn = _secondary_button(
            cfg, text="⏹   Stop & Restore",
            command=self._stop_attack, width=170, height=40,
            state="disabled",
        )
        self._stop_btn.grid(row=0, column=5, padx=(0, 18), pady=14, sticky="e")

        # ── Tabview body (the bulk of the page) ───────────────────────
        self._tabview = ctk.CTkTabview(
            self,
            fg_color=_CLR_PANEL,
            segmented_button_fg_color=_CLR_SIDEBAR,
            segmented_button_selected_color=_CLR_ACCENT,
            segmented_button_selected_hover_color=_shade(_CLR_ACCENT, 0.85),
            segmented_button_unselected_color=_CLR_SIDEBAR,
            segmented_button_unselected_hover_color=_CLR_HOVER,
            text_color=_CLR_TEXT,
            border_color=_CLR_BORDER, border_width=1,
            corner_radius=14,
        )
        self._tabview.grid(row=3, column=0, padx=28, pady=(0, 22),
                           sticky="nsew")
        self._tabview.add("🎯  Targets")
        self._tabview.add("🧰  Companion Modules")
        self._tabview.add("📊  Live Status")

        self._build_targets_tab(self._tabview.tab("🎯  Targets"))
        self._build_companions_tab(self._tabview.tab("🧰  Companion Modules"))
        self._build_status_tab(self._tabview.tab("📊  Live Status"))

        self._timer_id = None

        # Initial population (after construction is complete)
        self.after(50, self._refresh_target_list)

    # ------------------------------------------------------------------ #
    # Tab builders                                                         #
    # ------------------------------------------------------------------ #

    def _build_targets_tab(self, parent) -> None:
        parent.grid_rowconfigure(2, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        # Title + count
        title_row = ctk.CTkFrame(parent, fg_color="transparent")
        title_row.grid(row=0, column=0, sticky="ew", padx=8, pady=(10, 4))
        title_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            title_row, text="Choose victims",
            font=_FONT_HEAD, text_color=_CLR_TEXT, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        self._picker_count = ctk.CTkLabel(
            title_row, text="",
            font=(_SF, 10, "bold"), text_color=_CLR_MUTED, anchor="e",
        )
        self._picker_count.grid(row=0, column=1, sticky="e")

        # Filter row
        ctrl_row = ctk.CTkFrame(parent, fg_color="transparent")
        ctrl_row.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 4))
        ctrl_row.grid_columnconfigure(0, weight=1)

        self._filter_entry = ctk.CTkEntry(
            ctrl_row, textvariable=self._filter_var, height=32,
            placeholder_text="Filter by IP, hostname, vendor, or type…",
            font=_FONT_LABEL,
            fg_color=_CLR_SIDEBAR, border_color=_CLR_BORDER, border_width=1,
        )
        self._filter_entry.grid(row=0, column=0, sticky="ew", padx=(4, 8))
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())
        _ghost_button(
            ctrl_row, text="✕", width=32, height=32,
            command=lambda: self._filter_var.set(""),
            font=_FONT_LABEL,
        ).grid(row=0, column=1, padx=(0, 8))
        _ghost_button(
            ctrl_row, text="🔄  Refresh", width=110, height=32,
            command=self._refresh_target_list, font=_FONT_SMALL,
        ).grid(row=0, column=2, padx=(0, 4))

        # Quick-select chip row (wraps onto its own line so it stays readable)
        chip_row = ctk.CTkFrame(parent, fg_color="transparent")
        chip_row.grid(row=2, column=0, sticky="new", padx=4, pady=(2, 6))
        chip_row.grid_propagate(True)
        for label, fn in [
            ("☑   All",          self._select_all_visible),
            ("☐   None",         self._select_none),
            ("🟢   Online",      self._select_online),
            ("💻   Macs / PCs",  self._select_computers),
            ("📱   Phones",      self._select_phones),
            ("📺   TVs / Cast",  self._select_media),
            ("🖨   Printers",    self._select_printers),
            ("❓   Unknown",     self._select_unknown),
        ]:
            _ghost_button(
                chip_row, text=label, command=fn,
                width=0, height=28, font=_FONT_SMALL,
            ).pack(side="left", padx=(0, 6))

        # Scrollable list of hosts — given a dedicated grid row that grows.
        # Move the chip row up to row=1.5 by inserting another grid row.
        parent.grid_rowconfigure(3, weight=1)
        self._target_list = ctk.CTkScrollableFrame(
            parent, fg_color=_CLR_BG, corner_radius=10,
        )
        self._target_list.grid(row=3, column=0, sticky="nsew",
                               padx=4, pady=(0, 6))
        self._target_list.grid_columnconfigure(0, weight=1)

    def _build_companions_tab(self, parent) -> None:
        """All 7 companion-module toggles in a single scrollable column."""
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        scroll = ctk.CTkScrollableFrame(
            parent, fg_color="transparent", corner_radius=0,
        )
        scroll.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        scroll.grid_columnconfigure(0, weight=1)

        # Helper to build one toggle card with a consistent look.
        def card(icon: str, title: str, desc: str, var: tk.BooleanVar,
                 row: int) -> ctk.CTkFrame:
            card = ctk.CTkFrame(
                scroll, fg_color=_CLR_SIDEBAR, corner_radius=12,
                border_width=1, border_color=_CLR_BORDER,
            )
            card.grid(row=row, column=0, sticky="ew", padx=6, pady=6)
            card.grid_columnconfigure(2, weight=1)
            ctk.CTkCheckBox(
                card, text="", variable=var,
                checkbox_width=20, checkbox_height=20,
                fg_color=_CLR_ACCENT,
                hover_color=_shade(_CLR_ACCENT, 0.85),
                border_color=_CLR_BORDER, width=28,
            ).grid(row=0, column=0, padx=(14, 8), pady=(12, 0), sticky="nw")
            ctk.CTkLabel(
                card, text=icon, font=(_SF, 18),
            ).grid(row=0, column=1, padx=(0, 10), pady=(10, 0), sticky="nw")
            ctk.CTkLabel(
                card, text=title,
                font=_FONT_NAME, text_color=_CLR_TEXT, anchor="w",
            ).grid(row=0, column=2, sticky="w", padx=(0, 14), pady=(12, 0))
            ctk.CTkLabel(
                card, text=desc,
                font=_FONT_SMALL, text_color=_CLR_MUTED, anchor="w",
                justify="left", wraplength=520,
            ).grid(row=1, column=2, sticky="w", padx=(0, 14), pady=(0, 12))
            return card

        # 1) MITM Inspector
        card(
            "🔭", "MITM Inspector",
            "Passive sniffer that captures DNS queries, TLS SNI hostnames, "
            "HTTP request URLs and plaintext credentials from each victim.",
            self._opt_inspect, row=0,
        )

        # 2) DNS Spoofer (with rule table inline)
        dns_card = card(
            "🎯", "DNS Spoofer",
            "Returns forged DNS replies for matching domain patterns "
            "(e.g. ad-domain → 0.0.0.0 to null-route ads).",
            self._opt_dns_spoof, row=1,
        )
        self._build_rule_subcard(
            dns_card,
            title="DOMAIN  →  REDIRECT TO",
            add_cb=self._add_dns_rule_row,
            holder_attr="_dns_rules_body",
        )
        self._add_dns_rule_row(pattern="*.example.com", ip="10.0.0.1")
        self._add_dns_rule_row(pattern="", ip="")

        # 3) TCP Connection Killer (with rule table inline)
        kill_card = card(
            "🔪", "TCP Connection Killer",
            "Sends RST packets to terminate specific connections by "
            "destination host or port (e.g. cut *.twitter.com only).",
            self._opt_conn_kill, row=2,
        )
        self._build_rule_subcard(
            kill_card,
            title="TARGET HOST / IP / CIDR   ·   PORT  (0 = any)",
            add_cb=self._add_kill_rule_row,
            holder_attr="_kill_rules_body",
        )
        self._add_kill_rule_row(pattern="*.example.com", port="443")
        self._add_kill_rule_row(pattern="", port="0")

        # 4) LLMNR / NBT-NS Responder
        card(
            "🕷", "LLMNR / NBT-NS Responder",
            "Answers Windows multicast (LLMNR, UDP 5355) and broadcast "
            "(NBT-NS, UDP 137) name queries with our IP — RFC 4795 / 1002.",
            self._opt_llmnr, row=3,
        )

        # 5) mDNS Spoofer (with pattern input inline)
        mdns_card = card(
            "🍏", "mDNS Spoofer",
            "Apple/Linux equivalent of LLMNR — answers .local queries on "
            "UDP 5353 / multicast 224.0.0.251 (RFC 6762). Useful against "
            "macOS / iOS / IoT devices.",
            self._opt_mdns, row=4,
        )
        self._build_input_subcard(
            mdns_card,
            label="NAME PATTERN",
            var=self._mdns_pattern_var,
            placeholder="* (all .local) or e.g. printer.local",
        )

        # 6) NTP Spoofer (with offset input inline)
        ntp_card = card(
            "🕓", "NTP Spoofer",
            "Skews the victim's clock by the offset below. Demonstrates "
            "time-based attacks against TLS / Kerberos / token expiry.",
            self._opt_ntp_spoof, row=5,
        )
        self._build_input_subcard(
            ntp_card,
            label="OFFSET (seconds)",
            var=self._ntp_offset_var,
            placeholder="e.g. 3600 = +1h, -86400 = -1 day",
        )

        # 7) PCAP Recorder (with file path + browse button inline)
        pcap_card = card(
            "💾", "PCAP Recorder",
            "Save MITM traffic to a Wireshark-readable .pcap file. "
            "Filtered to the attacked target IPs; capped at 200 MB.",
            self._opt_pcap, row=6,
        )
        self._build_pcap_subcard(pcap_card)

    def _build_rule_subcard(
        self, parent, title: str, add_cb, holder_attr: str,
    ) -> None:
        """Add a rule-list sub-panel under a companion card."""
        wrap = ctk.CTkFrame(
            parent, fg_color=_CLR_BG, corner_radius=10,
            border_width=1, border_color=_CLR_BORDER,
        )
        wrap.grid(row=2, column=0, columnspan=3, sticky="ew",
                  padx=14, pady=(0, 14))
        wrap.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(wrap, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text=title,
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        _ghost_button(
            hdr, text="➕   Add rule", width=110, height=28,
            command=add_cb, font=_FONT_SMALL,
        ).grid(row=0, column=1, sticky="e")

        body = ctk.CTkFrame(wrap, fg_color="transparent")
        body.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        body.grid_columnconfigure(0, weight=1)
        setattr(self, holder_attr, body)

    def _build_input_subcard(
        self, parent, label: str, var: tk.StringVar, placeholder: str,
    ) -> None:
        wrap = ctk.CTkFrame(
            parent, fg_color=_CLR_BG, corner_radius=10,
            border_width=1, border_color=_CLR_BORDER,
        )
        wrap.grid(row=2, column=0, columnspan=3, sticky="ew",
                  padx=14, pady=(0, 14))
        wrap.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            wrap, text=label,
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED,
        ).grid(row=0, column=0, padx=(14, 10), pady=10)
        ctk.CTkEntry(
            wrap, textvariable=var, height=30,
            placeholder_text=placeholder,
            font=_FONT_MONO,
            fg_color=_CLR_SIDEBAR, border_color=_CLR_BORDER, border_width=1,
        ).grid(row=0, column=1, sticky="ew", padx=(0, 14), pady=10)

    def _build_pcap_subcard(self, parent) -> None:
        wrap = ctk.CTkFrame(
            parent, fg_color=_CLR_BG, corner_radius=10,
            border_width=1, border_color=_CLR_BORDER,
        )
        wrap.grid(row=2, column=0, columnspan=3, sticky="ew",
                  padx=14, pady=(0, 14))
        wrap.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            wrap, text="OUTPUT FILE",
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED,
        ).grid(row=0, column=0, padx=(14, 10), pady=10)
        ctk.CTkEntry(
            wrap, textvariable=self._pcap_path_var, height=30,
            placeholder_text="~/wifi-killer-session.pcap",
            font=_FONT_MONO,
            fg_color=_CLR_SIDEBAR, border_color=_CLR_BORDER, border_width=1,
        ).grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=10)
        _ghost_button(
            wrap, text="📁   Browse…", width=110, height=30,
            command=self._pick_pcap_path, font=_FONT_SMALL,
        ).grid(row=0, column=2, padx=(0, 14), pady=10)

    def _build_status_tab(self, parent) -> None:
        parent.grid_columnconfigure(0, weight=1)

        # Big stat-cards strip — 4 cards for uptime / packets / pps / companions.
        cards = ctk.CTkFrame(parent, fg_color="transparent")
        cards.grid(row=0, column=0, sticky="ew", padx=4, pady=(8, 4))
        for i in range(4):
            cards.grid_columnconfigure(i, weight=1, uniform="status")
        self._stat_uptime = _stat_card(cards, "⏱", "Uptime",  "—", 0, _CLR_TEXT)
        self._stat_pkt    = _stat_card(cards, "📦", "Packets", "0", 1, _CLR_SUCCESS)
        self._stat_rate   = _stat_card(cards, "⚡", "Rate",    "0 pkt/s", 2, _CLR_ACCENT)
        self._stat_comp   = _stat_card(cards, "🧰", "Active",  "0", 3, _CLR_ACCENT2)

        # Main status text — same widget the rest of the code already targets.
        text_card = ctk.CTkFrame(
            parent, fg_color=_CLR_SIDEBAR, corner_radius=12,
            border_width=1, border_color=_CLR_BORDER,
        )
        text_card.grid(row=1, column=0, sticky="ew", padx=8, pady=(8, 4))
        text_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            text_card, text="STATUS",
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED, anchor="w",
        ).grid(row=0, column=0, padx=18, pady=(12, 0), sticky="w")
        self._status_label = ctk.CTkLabel(
            text_card, text="Idle",
            font=(_SF, 17, "bold"), text_color=_CLR_MUTED, anchor="w",
        )
        self._status_label.grid(row=1, column=0, padx=18, pady=(2, 4),
                                 sticky="w")
        self._pkt_label = ctk.CTkLabel(
            text_card, text="",
            font=_FONT_MONO, text_color=_CLR_SUCCESS, anchor="w",
        )
        self._pkt_label.grid(row=2, column=0, padx=18, pady=(0, 2),
                              sticky="w")
        self._companion_label = ctk.CTkLabel(
            text_card, text="",
            font=_FONT_SMALL, text_color=_CLR_MUTED, anchor="w",
            justify="left", wraplength=900,
        )
        self._companion_label.grid(row=3, column=0, padx=18, pady=(0, 12),
                                    sticky="w")

    # ------------------------------------------------------------------ #
    # DNS spoof rules                                                      #
    # ------------------------------------------------------------------ #

    def _add_dns_rule_row(self, pattern: str = "", ip: str = "") -> None:
        idx = len(self._dns_rules)
        row = ctk.CTkFrame(self._dns_rules_body, fg_color="transparent")
        row.grid(row=idx, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(0, weight=2)
        row.grid_columnconfigure(2, weight=1)

        pattern_var = tk.StringVar(value=pattern)
        ip_var = tk.StringVar(value=ip)

        ctk.CTkEntry(
            row, textvariable=pattern_var, height=30,
            placeholder_text="Pattern (e.g. *.example.com)",
            font=_FONT_MONO,
            fg_color=_CLR_BG, border_color=_CLR_BORDER, border_width=1,
        ).grid(row=0, column=0, sticky="ew", padx=(2, 6))
        ctk.CTkLabel(row, text="→", text_color=_CLR_MUTED,
                     font=_FONT_LABEL).grid(row=0, column=1, padx=2)
        ctk.CTkEntry(
            row, textvariable=ip_var, height=30,
            placeholder_text="IPv4 (e.g. 10.0.0.1 or 0.0.0.0)",
            font=_FONT_MONO,
            fg_color=_CLR_BG, border_color=_CLR_BORDER, border_width=1,
        ).grid(row=0, column=2, sticky="ew", padx=(0, 6))
        _ghost_button(
            row, text="✕", width=30, height=30, font=_FONT_LABEL,
            command=lambda r=row, p=pattern_var, i=ip_var:
                self._remove_dns_rule_row(r, p, i),
        ).grid(row=0, column=3)

        self._dns_rules.append((pattern_var, ip_var))

    def _remove_dns_rule_row(
        self, row: ctk.CTkFrame,
        pattern_var: tk.StringVar, ip_var: tk.StringVar,
    ) -> None:
        self._dns_rules = [
            (p, i) for p, i in self._dns_rules
            if not (p is pattern_var and i is ip_var)
        ]
        row.destroy()

    def _collect_dns_rules(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for p_var, i_var in self._dns_rules:
            p = p_var.get().strip()
            i = i_var.get().strip()
            if p and _validate_ip(i):
                out.append((p, i))
        return out

    # ------------------------------------------------------------------ #
    # TCP-kill rules                                                       #
    # ------------------------------------------------------------------ #

    def _add_kill_rule_row(self, pattern: str = "", port: str = "0") -> None:
        idx = len(self._kill_rules)
        row = ctk.CTkFrame(self._kill_rules_body, fg_color="transparent")
        row.grid(row=idx, column=0, sticky="ew", pady=2)
        row.grid_columnconfigure(0, weight=3)
        row.grid_columnconfigure(2, weight=1)

        pattern_var = tk.StringVar(value=pattern)
        port_var = tk.StringVar(value=port)

        ctk.CTkEntry(
            row, textvariable=pattern_var, height=30,
            placeholder_text="Hostname pattern, IP, or CIDR",
            font=_FONT_MONO,
            fg_color=_CLR_BG, border_color=_CLR_BORDER, border_width=1,
        ).grid(row=0, column=0, sticky="ew", padx=(2, 6))
        ctk.CTkLabel(row, text=":", text_color=_CLR_MUTED,
                     font=_FONT_LABEL).grid(row=0, column=1, padx=2)
        ctk.CTkEntry(
            row, textvariable=port_var, height=30,
            placeholder_text="0",
            font=_FONT_MONO,
            fg_color=_CLR_BG, border_color=_CLR_BORDER, border_width=1,
            width=80,
        ).grid(row=0, column=2, sticky="ew", padx=(0, 6))
        _ghost_button(
            row, text="✕", width=30, height=30, font=_FONT_LABEL,
            command=lambda r=row, p=pattern_var, q=port_var:
                self._remove_kill_rule_row(r, p, q),
        ).grid(row=0, column=3)

        self._kill_rules.append((pattern_var, port_var))

    def _remove_kill_rule_row(
        self, row: ctk.CTkFrame,
        pattern_var: tk.StringVar, port_var: tk.StringVar,
    ) -> None:
        self._kill_rules = [
            (p, q) for p, q in self._kill_rules
            if not (p is pattern_var and q is port_var)
        ]
        row.destroy()

    def _collect_kill_rules(self) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        for p_var, q_var in self._kill_rules:
            p = p_var.get().strip()
            try:
                q = int(q_var.get().strip() or "0")
            except ValueError:
                continue
            if not p or not (0 <= q <= 65535):
                continue
            out.append((p, q))
        return out

    def _pick_pcap_path(self) -> None:
        """Open a save-as dialog and store the chosen path in the entry."""
        path = filedialog.asksaveasfilename(
            title="Save PCAP capture to…",
            defaultextension=".pcap",
            initialfile=os.path.basename(self._pcap_path_var.get())
                        or "wifi-killer-session.pcap",
            initialdir=os.path.dirname(self._pcap_path_var.get())
                        or os.path.expanduser("~"),
            filetypes=[("PCAP capture", "*.pcap"),
                       ("All files", "*.*")],
        )
        if path:
            self._pcap_path_var.set(path)

    # ------------------------------------------------------------------ #
    # Target list population & filtering                                   #
    # ------------------------------------------------------------------ #

    def _refresh_target_list(self) -> None:
        """Rebuild the host list from the app's host registry.

        Preserves the current selection — checkboxes for hosts that
        remain in the registry stay ticked; new hosts default to
        unchecked. Excludes the gateway and the local machine.
        """
        # Capture current selection state.
        prior = {ip: var.get() for ip, var in self._selection.items()}

        # Clear widgets and the row map.
        for w in self._target_list.winfo_children():
            w.destroy()
        self._rows.clear()
        self._row_activity_labels.clear()
        new_selection: dict[str, tk.BooleanVar] = {}

        gw = (self._app._gateway or self._gw_entry.get() or "").strip()
        own = self._app._get_own_ip()

        hosts = sorted(
            (h for h in self._app._hosts
             if h.get("ip") and h["ip"] != gw and h["ip"] != own),
            key=lambda h: _ip_sort_key(h.get("ip", "")),
        )

        if not hosts:
            ctk.CTkLabel(
                self._target_list,
                text="No hosts discovered yet — run a scan first.",
                font=_FONT_LABEL, text_color=_CLR_MUTED,
            ).pack(padx=16, pady=20, anchor="w")
            self._picker_count.configure(text="0 hosts")
            self._update_target_summary()
            return

        for idx, host in enumerate(hosts):
            ip = host["ip"]
            var = tk.BooleanVar(value=prior.get(ip, False))
            var.trace_add("write", lambda *_: self._update_target_summary())
            new_selection[ip] = var
            self._add_target_row(host, var, idx)

        self._selection = new_selection
        self._picker_count.configure(text=f"{len(hosts)} hosts")
        self._update_target_summary()
        self._apply_filter()

    def _add_target_row(
        self, host: dict, var: tk.BooleanVar, idx: int,
    ) -> None:
        bg = _CLR_ROW_ODD if idx % 2 == 0 else _CLR_ROW_EVEN
        row = ctk.CTkFrame(self._target_list, fg_color=bg, corner_radius=8)
        row.pack(fill="x", padx=4, pady=1)
        row.grid_columnconfigure(2, weight=1)

        # Checkbox
        ctk.CTkCheckBox(
            row, text="", variable=var,
            checkbox_width=18, checkbox_height=18,
            corner_radius=4,
            fg_color=_CLR_ACCENT,
            hover_color=_shade(_CLR_ACCENT, 0.85),
            border_color=_CLR_BORDER, border_width=1,
            width=22,
        ).grid(row=0, column=0, padx=(12, 8), pady=8, sticky="w")

        # Icon + IP + hostname stack
        icon = host.get("icon", "🔌")
        ctk.CTkLabel(
            row, text=icon, font=(_SF, 16),
        ).grid(row=0, column=1, padx=(0, 8), pady=8, sticky="w")

        text_col = ctk.CTkFrame(row, fg_color="transparent")
        text_col.grid(row=0, column=2, padx=(0, 8), pady=6, sticky="ew")
        text_col.grid_columnconfigure(0, weight=1)

        hn = host.get("hostname") or ""
        primary = hn if hn and hn not in ("Unknown",) else host["ip"]
        ctk.CTkLabel(
            text_col, text=primary,
            font=_FONT_NAME, text_color=_CLR_TEXT, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        # Secondary line: IP (if hostname shown) + vendor + type
        bits = []
        if primary != host["ip"]:
            bits.append(host["ip"])
        vendor = host.get("vendor") or ""
        if vendor and vendor != "Unknown":
            bits.append(vendor)
        dtype = host.get("type") or ""
        if dtype and dtype != "Unknown Device":
            bits.append(dtype)
        if bits:
            ctk.CTkLabel(
                text_col, text="  ·  ".join(bits),
                font=_FONT_SMALL, text_color=_CLR_MUTED, anchor="w",
            ).grid(row=1, column=0, sticky="w")

        # Right-side info column: type pill (idle) or live activity (attack).
        activity_lbl = ctk.CTkLabel(
            row, text=host.get("type", "—"),
            font=_FONT_SMALL, text_color=_CLR_MUTED,
            anchor="e", width=200,
        )
        activity_lbl.grid(row=0, column=3, padx=(0, 8), pady=8, sticky="e")
        self._row_activity_labels[host["ip"]] = activity_lbl

        online = host.get("online", True)
        ctk.CTkLabel(
            row, text="●",
            font=(_SF, 13),
            text_color=_CLR_SUCCESS if online else _CLR_MUTED,
        ).grid(row=0, column=4, padx=(0, 14), pady=8, sticky="e")

        self._rows[host["ip"]] = row

    def _apply_filter(self) -> None:
        needle = self._filter_var.get().strip().lower()
        registry = self._app._host_registry
        for ip, row in self._rows.items():
            host = registry.get(ip, {"ip": ip})
            haystack = " ".join(str(host.get(k, "")) for k in
                                ("ip", "hostname", "vendor", "type",
                                 "mac", "icon")).lower()
            visible = (not needle) or (needle in haystack)
            if visible:
                row.pack(fill="x", padx=4, pady=1)
            else:
                row.pack_forget()

    def _update_target_summary(self) -> None:
        total = len(self._selection)
        selected = sum(1 for v in self._selection.values() if v.get())
        self._target_summary.configure(
            text=f"{selected} of {total} targets selected",
            text_color=_CLR_ACCENT if selected else _CLR_MUTED,
        )

    # ── Quick-select shortcuts ────────────────────────────────────────

    def _matching_visible(self) -> list[str]:
        """IPs of rows currently visible under the active filter."""
        return [ip for ip, row in self._rows.items()
                if row.winfo_manager()]  # 'pack' if visible, '' if hidden

    def _select_all_visible(self) -> None:
        for ip in self._matching_visible():
            self._selection[ip].set(True)

    def _select_none(self) -> None:
        for var in self._selection.values():
            var.set(False)

    def _select_online(self) -> None:
        reg = self._app._host_registry
        for ip, var in self._selection.items():
            var.set(bool(reg.get(ip, {}).get("online", True)))

    def _select_by_type(self, predicate) -> None:
        reg = self._app._host_registry
        for ip, var in self._selection.items():
            t = (reg.get(ip, {}).get("type") or "").lower()
            var.set(predicate(t))

    def _select_computers(self) -> None:
        self._select_by_type(lambda t: any(k in t for k in (
            "mac", "windows", "pc", "laptop", "linux", "server",
        )))

    def _select_phones(self) -> None:
        self._select_by_type(lambda t: any(k in t for k in (
            "iphone", "ipad", "ipod", "android", "mobile", "phone",
        )))

    def _select_media(self) -> None:
        self._select_by_type(lambda t: any(k in t for k in (
            "tv", "cast", "chromecast", "roku", "console", "plex",
            "homepod", "sonos", "speaker",
        )))

    def _select_printers(self) -> None:
        self._select_by_type(lambda t: "printer" in t)

    def _select_unknown(self) -> None:
        self._select_by_type(
            lambda t: t in ("", "unknown device", "unknown iot device")
        )

    def _start_attack(self) -> None:
        if self._running:
            return

        targets = self._selected_targets
        if not targets:
            messagebox.showwarning(
                "No Targets",
                "Tick at least one host in the target list before launching.",
            )
            return
        gw = self._gw_entry.get().strip() or self._app._gateway
        if not gw:
            messagebox.showerror("No Gateway", "Could not determine gateway IP.")
            return

        # Validate gateway IP format
        if not _validate_ip(gw):
            messagebox.showerror("Invalid Gateway IP",
                                 f"'{gw}' is not a valid IPv4 address.")
            return

        method_str = self._method.get()[0]  # 'A', 'B', or 'C'
        target_ips = ", ".join(t["ip"] for t in targets[:5])
        if len(targets) > 5:
            target_ips += f" + {len(targets) - 5} more"

        # Safety confirmation
        method_desc = {
            "A": "Full MITM – intercepts traffic between targets and gateway",
            "B": "Client-only cut – targets lose internet access",
            "C": "Gateway-only – gateway loses visibility of targets",
        }.get(method_str, method_str)
        confirmed = messagebox.askyesno(
            "⚠  Confirm ARP Attack",
            f"You are about to launch an ARP-spoofing attack.\n\n"
            f"Method : {method_str} – {method_desc}\n"
            f"Targets: {target_ips}\n"
            f"Gateway: {gw}\n\n"
            "Only proceed if you have explicit authorisation to test this network.\n\n"
            "Launch attack?",
        )
        if not confirmed:
            return

        # ── Prepare & start in a background thread ────────────────────
        # MAC resolution can take several seconds even in parallel; doing
        # it on the main thread froze the GUI before. The worker reports
        # back via after(0, ...) for all UI updates.
        self._start_btn.configure(state="disabled", text="Preparing…")
        self._stop_btn.configure(state="disabled")
        self._status_label.configure(
            text=f"⏳  Resolving MACs for {len(targets)} target(s)…",
            text_color=_CLR_WARNING,
        )
        self._pkt_label.configure(text="")

        _thread(self._launch_worker, method_str, targets, gw)

    def _launch_worker(self, method_str: str, targets: list[dict], gw: str) -> None:
        """Background-thread half of _start_attack — does the slow MAC work."""
        from wifi_killer.modules.attacker import ArpAttack, MultiTargetAttack
        try:
            if len(targets) == 1:
                atk = ArpAttack(method_str, targets[0]["ip"], gw, self._app._iface)
                # Use prepare() so we can resolve in this worker thread.
                atk.prepare(
                    target_mac=(targets[0].get("mac") or "").upper() or None,
                )
                atk.start()
                self._attack_obj = atk
                failed: list[tuple[str, str]] = []
            else:
                multi = MultiTargetAttack(
                    method_str, targets, gw, self._app._iface,
                )
                multi.start()
                self._attack_obj = multi
                failed = list(multi.failed_targets)
            actual_count = (
                1 if isinstance(self._attack_obj, ArpAttack)
                else len(self._attack_obj.attacks)
            )
        except Exception as exc:
            self.after(0, lambda e=exc: self._launch_failed(str(e)))
            return

        self.after(0, lambda: self._launch_succeeded(
            method_str, actual_count, gw, failed,
        ))

    def _launch_failed(self, message: str) -> None:
        """Main-thread handler: worker raised; reset UI and show the error."""
        self._attack_obj = None
        self._start_btn.configure(state="normal", text="⚡   Launch Attack")
        self._stop_btn.configure(state="disabled")
        self._status_label.configure(text="Idle", text_color=_CLR_MUTED)
        self._pkt_label.configure(text="")
        messagebox.showerror("Attack Error", message)
        self._app.log(f"Attack failed: {message}", "err")

    def _launch_succeeded(
        self, method_str: str, count: int, gw: str,
        failed: list[tuple[str, str]],
    ) -> None:
        """Main-thread handler: attack is running; flip the UI to live state."""
        self._running = True
        self._start_btn.configure(state="disabled", text="⚡   Launch Attack")
        self._stop_btn.configure(state="normal")
        self._status_label.configure(
            text=f"🔴  ATTACKING  {count} target(s)  |  Method {method_str}",
            text_color=_CLR_DANGER,
        )
        self._start_counter()
        self._app.log(
            f"Attack started – Method {method_str}  |  {count} target(s)  |  GW {gw}",
            "warn",
        )
        # Surface targets that couldn't be resolved (offline / blocked ARP).
        for ip, reason in failed:
            self._app.log(f"  · Skipped {ip}: {reason}", "warn")
        # ── Auto-start companion modules ──────────────────────────────
        attacked_ips = self._attacked_ips()
        if self._opt_inspect.get() and attacked_ips:
            self._start_inspector(attacked_ips)
        if self._opt_dns_spoof.get():
            rules = self._collect_dns_rules()
            if rules:
                self._start_dns_spoofer(rules, attacked_ips)
            else:
                self._app.log(
                    "DNS Spoofer enabled but no valid rules — skipping.",
                    "warn",
                )
        if self._opt_conn_kill.get():
            kill_rules = self._collect_kill_rules()
            if kill_rules:
                self._start_conn_killer(kill_rules, attacked_ips)
            else:
                self._app.log(
                    "Connection Killer enabled but no valid rules — skipping.",
                    "warn",
                )
        if self._opt_llmnr.get():
            own_ip = self._app._get_own_ip()
            if own_ip and own_ip not in ("?", ""):
                self._start_llmnr_poisoner(own_ip)
            else:
                self._app.log(
                    "LLMNR/NBT-NS Responder skipped — local IP unknown.",
                    "warn",
                )
        if self._opt_mdns.get():
            own_ip = self._app._get_own_ip()
            pattern = self._mdns_pattern_var.get().strip() or "*"
            if own_ip and own_ip not in ("?", ""):
                self._start_mdns_spoofer(own_ip, [pattern])
            else:
                self._app.log(
                    "mDNS Spoofer skipped — local IP unknown.",
                    "warn",
                )
        if self._opt_ntp_spoof.get():
            try:
                offset = float(self._ntp_offset_var.get().strip() or "0")
            except ValueError:
                offset = None
            if offset is None:
                self._app.log(
                    "NTP Spoofer skipped — offset must be a number.", "warn",
                )
            elif attacked_ips:
                self._start_ntp_spoofer(offset, attacked_ips)
        if self._opt_pcap.get():
            path = self._pcap_path_var.get().strip()
            if path and attacked_ips:
                self._start_pcap_recorder(path, attacked_ips)
            elif not path:
                self._app.log(
                    "PCAP Recorder skipped — no output path set.", "warn",
                )
        # Tell the network map to repaint with attack styling now that
        # ``app.get_attack_info()`` will return a live snapshot.
        self._app.mark_attack_changed()

    def _attacked_ips(self) -> list[str]:
        if self._attack_obj is None:
            return []
        sub = getattr(self._attack_obj, "attacks", None)
        if sub is not None:
            return [a.target_ip for a in sub if getattr(a, "target_ip", "")]
        ip = getattr(self._attack_obj, "target_ip", "")
        return [ip] if ip else []

    def _start_inspector(self, attacked_ips: list[str]) -> None:
        try:
            from wifi_killer.modules.mitm_inspector import MITMInspector
            self._mitm_inspector = MITMInspector(self._app._iface, attacked_ips)
            self._mitm_inspector.start()
            self._app.log(
                f"MITM Inspector running — observing {len(attacked_ips)} target(s)",
                "ok",
            )
        except Exception as exc:
            self._mitm_inspector = None
            self._app.log(f"MITM Inspector failed: {exc}", "err")

    def _start_dns_spoofer(
        self, rules: list[tuple[str, str]], attacked_ips: list[str],
    ) -> None:
        try:
            from wifi_killer.modules.dns_spoofer import DNSSpoofer
            self._dns_spoofer = DNSSpoofer(
                self._app._iface, rules, attacked_ips,
            )
            self._dns_spoofer.start()
            rules_desc = ", ".join(f"{p}→{i}" for p, i in rules[:3])
            if len(rules) > 3:
                rules_desc += f" + {len(rules) - 3} more"
            self._app.log(
                f"DNS Spoofer running — {len(rules)} rule(s): {rules_desc}",
                "warn",
            )
        except Exception as exc:
            self._dns_spoofer = None
            self._app.log(f"DNS Spoofer failed: {exc}", "err")

    def _start_conn_killer(
        self, rules: list[tuple[str, int]], attacked_ips: list[str],
    ) -> None:
        try:
            from wifi_killer.modules.connection_killer import ConnectionKiller
            self._conn_killer = ConnectionKiller(
                self._app._iface, rules, attacked_ips,
            )
            self._conn_killer.start()
            desc = ", ".join(
                f"{p}:{q if q else 'any'}" for p, q in rules[:3]
            )
            if len(rules) > 3:
                desc += f" + {len(rules) - 3} more"
            self._app.log(
                f"Connection Killer running — {len(rules)} rule(s): {desc}",
                "warn",
            )
        except Exception as exc:
            self._conn_killer = None
            self._app.log(f"Connection Killer failed: {exc}", "err")

    def _start_llmnr_poisoner(self, answer_ip: str) -> None:
        try:
            from wifi_killer.modules.llmnr_poisoner import LLMNRNBNSPoisoner
            # Avoid hijacking queries for our own hostname.
            own_name = socket.gethostname().split(".")[0]
            self._llmnr_poisoner = LLMNRNBNSPoisoner(
                self._app._iface, answer_ip, exclude_names={own_name},
            )
            self._llmnr_poisoner.start()
            self._app.log(
                f"LLMNR / NBT-NS Responder running → answering as {answer_ip}",
                "warn",
            )
        except Exception as exc:
            self._llmnr_poisoner = None
            self._app.log(f"LLMNR Responder failed: {exc}", "err")

    def _start_mdns_spoofer(
        self, answer_ip: str, patterns: list[str],
    ) -> None:
        try:
            from wifi_killer.modules.mdns_spoofer import MDNSSpoofer
            own_name = socket.gethostname().split(".")[0]
            exclude = {own_name, f"{own_name}.local"}
            self._mdns_spoofer = MDNSSpoofer(
                self._app._iface, answer_ip,
                patterns=patterns, exclude_names=exclude,
            )
            self._mdns_spoofer.start()
            self._app.log(
                f"mDNS Spoofer running → answering {patterns} as {answer_ip}",
                "warn",
            )
        except Exception as exc:
            self._mdns_spoofer = None
            self._app.log(f"mDNS Spoofer failed: {exc}", "err")

    def _start_ntp_spoofer(
        self, offset: float, attacked_ips: list[str],
    ) -> None:
        try:
            from wifi_killer.modules.ntp_spoofer import NTPSpoofer
            self._ntp_spoofer = NTPSpoofer(
                self._app._iface, offset, attacked_ips,
            )
            self._ntp_spoofer.start()
            sign = "+" if offset >= 0 else ""
            self._app.log(
                f"NTP Spoofer running — offset {sign}{offset:.0f}s on "
                f"{len(attacked_ips)} target(s)",
                "warn",
            )
        except Exception as exc:
            self._ntp_spoofer = None
            self._app.log(f"NTP Spoofer failed: {exc}", "err")

    def _start_pcap_recorder(
        self, path: str, attacked_ips: list[str],
    ) -> None:
        try:
            from wifi_killer.modules.pcap_recorder import PCAPRecorder
            self._pcap_recorder = PCAPRecorder(
                self._app._iface, attacked_ips, path,
            )
            self._pcap_recorder.start()
            self._app.log(f"PCAP Recorder writing to {path}", "ok")
        except Exception as exc:
            self._pcap_recorder = None
            self._app.log(f"PCAP Recorder failed: {exc}", "err")

    def _stop_attack(self) -> None:
        if not self._running:
            return
        if self._attack_obj:
            _thread(self._attack_obj.stop)
        # Tear down companion modules.
        if self._mitm_inspector is not None:
            try:
                self._mitm_inspector.stop()
            except Exception:
                pass
            self._app.log("MITM Inspector stopped.", "ok")
            self._mitm_inspector = None
        if self._dns_spoofer is not None:
            try:
                hits = self._dns_spoofer.hits
                self._dns_spoofer.stop()
                self._app.log(
                    f"DNS Spoofer stopped — {hits} forged response(s) sent.",
                    "ok",
                )
            except Exception:
                pass
            self._dns_spoofer = None
        if self._conn_killer is not None:
            try:
                kills = self._conn_killer.kills
                self._conn_killer.stop()
                self._app.log(
                    f"Connection Killer stopped — {kills} connection(s) reset.",
                    "ok",
                )
            except Exception:
                pass
            self._conn_killer = None
        if self._llmnr_poisoner is not None:
            try:
                hits = self._llmnr_poisoner.hits
                self._llmnr_poisoner.stop()
                self._app.log(
                    f"LLMNR Responder stopped — {hits} name query/queries poisoned.",
                    "ok",
                )
            except Exception:
                pass
            self._llmnr_poisoner = None
        if self._mdns_spoofer is not None:
            try:
                hits = self._mdns_spoofer.hits
                self._mdns_spoofer.stop()
                self._app.log(
                    f"mDNS Spoofer stopped — {hits} .local query/queries poisoned.",
                    "ok",
                )
            except Exception:
                pass
            self._mdns_spoofer = None
        if self._ntp_spoofer is not None:
            try:
                hits = self._ntp_spoofer.hits
                self._ntp_spoofer.stop()
                self._app.log(
                    f"NTP Spoofer stopped — {hits} forged reply/replies sent.",
                    "ok",
                )
            except Exception:
                pass
            self._ntp_spoofer = None
        if self._pcap_recorder is not None:
            try:
                snap = self._pcap_recorder.snapshot()
                self._pcap_recorder.stop()
                self._app.log(
                    f"PCAP Recorder stopped — wrote "
                    f"{snap['packets_written']:,} packet(s) "
                    f"({snap['bytes_written']/1024:.1f} KB) to "
                    f"{snap['output']}",
                    "ok",
                )
            except Exception:
                pass
            self._pcap_recorder = None
        self._running = False
        self._start_btn.configure(state="normal", text="⚡   Launch Attack")
        self._stop_btn.configure(state="disabled")
        self._status_label.configure(text="Stopped – ARP tables restoring…", text_color=_CLR_WARNING)
        self._pkt_label.configure(text="")
        self._companion_label.configure(text="")
        # Restore the type-pill text on each picker row.
        registry = self._app._host_registry
        for ip, lbl in self._row_activity_labels.items():
            host = registry.get(ip, {})
            lbl.configure(
                text=host.get("type", "—"),
                text_color=_CLR_MUTED,
            )
        if self._timer_id:
            self.after_cancel(self._timer_id)
            self._timer_id = None
        self._app.log("Attack stopped, restoring ARP caches.", "ok")
        # Clear attack styling from the network map.
        self._app.mark_attack_changed()

    def _start_counter(self) -> None:
        self._counter_start = time.time()
        self._tick()

    def _tick(self) -> None:
        if not self._running:
            return

        # ── Aggregate live stats from the attack object ───────────────
        elapsed = int(time.time() - self._counter_start)
        mm, ss = divmod(elapsed, 60)
        hh, mm = divmod(mm, 60)
        if hh:
            uptime = f"{hh:d}h {mm:02d}m {ss:02d}s"
        elif mm:
            uptime = f"{mm:d}m {ss:02d}s"
        else:
            uptime = f"{ss:d}s"

        packets = 0
        rate = 0.0
        sub = getattr(self._attack_obj, "attacks", None)
        if sub is not None:
            for atk in sub:
                packets += getattr(atk, "packets_sent", 0)
                rate += getattr(atk, "packet_rate", 0.0)
        else:
            packets = getattr(self._attack_obj, "packets_sent", 0)
            rate = getattr(self._attack_obj, "packet_rate", 0.0)

        self._pkt_label.configure(
            text=(
                f"Uptime {uptime}   ·   {packets:,} pkt sent"
                f"   ·   {rate:5.1f} pkt/s"
                f"   ·   interval {attack_config.interval}s   "
                f"·   burst {attack_config.burst}"
            )
        )

        # Mirror into the dedicated Status-tab stat cards if present.
        if getattr(self, "_stat_uptime", None) is not None:
            self._stat_uptime.configure(text=uptime, text_color=_CLR_TEXT)
            self._stat_pkt.configure(text=f"{packets:,}",
                                    text_color=_CLR_SUCCESS)
            self._stat_rate.configure(text=f"{rate:.1f} pkt/s",
                                     text_color=_CLR_ACCENT)
            active_companions = sum(1 for x in [
                self._mitm_inspector, self._dns_spoofer,
                self._conn_killer, self._llmnr_poisoner,
                self._mdns_spoofer, self._ntp_spoofer, self._pcap_recorder,
            ] if x is not None)
            self._stat_comp.configure(text=str(active_companions),
                                       text_color=_CLR_ACCENT2)

        # ── Companion summary line ────────────────────────────────────
        bits: list[str] = []
        if self._mitm_inspector is not None:
            snap = self._mitm_inspector.snapshot()
            per_target = snap["per_target"]
            total_dns = sum(s.get("dns", 0) for s in per_target.values())
            total_sni = sum(s.get("sni", 0) for s in per_target.values())
            total_http = sum(s.get("http", 0) for s in per_target.values())
            total_cred = sum(s.get("cred", 0) for s in per_target.values())
            inspector_bits = [
                f"🔭 Inspector: {total_dns} DNS · {total_sni} SNI "
                f"· {total_http} HTTP"
            ]
            if total_cred:
                inspector_bits.append(f"🔑 {total_cred} CREDS")
            bits.append("  ·  ".join(inspector_bits))

            # ── Per-target activity badges in the picker rows ─────────
            # Each row's right-hand label switches from the type pill
            # to a live counter so the user can see at a glance which
            # victims are generating the most traffic.
            for ip, lbl in self._row_activity_labels.items():
                stats = per_target.get(ip)
                if not stats:
                    continue
                creds = stats.get("cred", 0)
                txt = (
                    f"{stats.get('dns', 0)} DNS  ·  "
                    f"{stats.get('sni', 0)} SNI  ·  "
                    f"{stats.get('http', 0)} HTTP"
                )
                if creds:
                    txt += f"  ·  🔑 {creds}"
                lbl.configure(
                    text=txt,
                    text_color=_CLR_DANGER if creds else _CLR_ACCENT,
                )
        if self._dns_spoofer is not None:
            snap = self._dns_spoofer.snapshot()
            bits.append(
                f"🎯 DNS Spoofer: {snap['hits']} forged "
                f"({len(snap['rules'])} rule(s))"
            )
        if self._conn_killer is not None:
            snap = self._conn_killer.snapshot()
            bits.append(
                f"🔪 Conn Killer: {snap['kills']} reset "
                f"({len(snap['rules'])} rule(s))"
            )
        if self._llmnr_poisoner is not None:
            snap = self._llmnr_poisoner.snapshot()
            bits.append(f"🕷 LLMNR/NBNS: {snap['hits']} poisoned")
        if self._mdns_spoofer is not None:
            snap = self._mdns_spoofer.snapshot()
            bits.append(f"🍏 mDNS: {snap['hits']} poisoned")
        if self._ntp_spoofer is not None:
            snap = self._ntp_spoofer.snapshot()
            sign = "+" if snap["offset"] >= 0 else ""
            bits.append(
                f"🕓 NTP: {snap['hits']} forged "
                f"(offset {sign}{snap['offset']:.0f}s)"
            )
        if self._pcap_recorder is not None:
            snap = self._pcap_recorder.snapshot()
            kb = snap["bytes_written"] / 1024
            bits.append(
                f"💾 PCAP: {snap['packets_written']:,} pkt · {kb:.0f} KB"
            )
        self._companion_label.configure(text="    ·    ".join(bits))

        self._timer_id = self.after(1000, self._tick)


# ===========================================================================
# Anonymize Frame
# ===========================================================================

class AnonymizeFrame(ctk.CTkFrame):
    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._build()

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self, text="🎭  MAC Address Anonymization",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, padx=28, pady=(24, 4), sticky="w")

        ctk.CTkLabel(
            self,
            text="Change your interface MAC address to avoid identification on the local network.",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).grid(row=1, column=0, padx=28, pady=(0, 16), sticky="w")

        panel = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        panel.grid(row=2, column=0, padx=28, pady=0, sticky="ew")
        panel.grid_columnconfigure(1, weight=1)

        # Current MAC
        ctk.CTkLabel(panel, text="Current MAC:", font=_FONT_LABEL,
                     text_color=_CLR_MUTED).grid(row=0, column=0, padx=16, pady=(16, 8), sticky="w")
        self._cur_mac = ctk.CTkLabel(panel, text="—", font=_FONT_MONO, text_color=_CLR_SUCCESS)
        self._cur_mac.grid(row=0, column=1, padx=8, pady=(16, 8), sticky="w")

        ctk.CTkButton(
            panel, text="🔄 Refresh", width=100,
            fg_color=_CLR_PANEL, font=_FONT_SMALL,
            command=self._refresh_mac,
        ).grid(row=0, column=2, padx=16, pady=(16, 8))

        # Custom MAC entry
        ctk.CTkLabel(panel, text="Custom MAC:", font=_FONT_LABEL,
                     text_color=_CLR_MUTED).grid(row=1, column=0, padx=16, pady=8, sticky="w")
        self._mac_entry = ctk.CTkEntry(
            panel, width=220, font=_FONT_MONO,
            placeholder_text="XX:XX:XX:XX:XX:XX")
        self._mac_entry.grid(row=1, column=1, padx=8, pady=8, sticky="w")

        # Preserve OUI toggle
        self._preserve_oui = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            panel, text="Preserve vendor OUI (first 3 octets)",
            variable=self._preserve_oui,
            font=_FONT_LABEL,
        ).grid(row=2, column=0, columnspan=2, padx=16, pady=8, sticky="w")

        # Action buttons
        btn_row = ctk.CTkFrame(panel, fg_color="transparent")
        btn_row.grid(row=3, column=0, columnspan=3, padx=16, pady=(12, 16), sticky="w")

        ctk.CTkButton(
            btn_row, text="🎲  Random MAC",
            fg_color=_CLR_ACCENT, hover_color="#c73652",
            font=_FONT_LABEL, width=140, command=self._randomize,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row, text="✏️  Set Custom MAC",
            fg_color=_CLR_ACCENT2, hover_color="#6b44a8",
            font=_FONT_LABEL, width=140, command=self._set_custom,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row, text="↩  Restore Original",
            fg_color=_CLR_PANEL, hover_color="#1a4a80",
            font=_FONT_LABEL, width=150, command=self._restore,
        ).pack(side="left")

        # Status
        self._mac_status = ctk.CTkLabel(
            self, text="", font=_FONT_LABEL, text_color=_CLR_SUCCESS)
        self._mac_status.grid(row=3, column=0, padx=28, pady=(16, 0), sticky="w")

        self.after(200, self._refresh_mac)

    def _refresh_mac(self) -> None:
        if self._app._iface:
            mac = get_interface_mac(self._app._iface) or "—"
            self._cur_mac.configure(text=mac)

    def _randomize(self) -> None:
        if not self._app._iface:
            messagebox.showerror("No Interface", "Select a network interface first.")
            return
        if not messagebox.askyesno(
            "Confirm MAC Change",
            f"This will change the MAC address of '{self._app._iface}'.\n\n"
            "The interface will briefly go down and come back up.\n"
            "Proceed?",
        ):
            return
        try:
            from wifi_killer.modules.anonymizer import randomize_mac
            new_mac = randomize_mac(self._app._iface,
                                    preserve_oui=self._preserve_oui.get())
            self._cur_mac.configure(text=new_mac)
            self._mac_status.configure(text=f"✓  MAC changed to {new_mac}", text_color=_CLR_SUCCESS)
            self._app.log(f"MAC randomized: {new_mac}", "ok")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _set_custom(self) -> None:
        mac = self._mac_entry.get().strip()
        if not mac:
            messagebox.showwarning("Input Required", "Enter a MAC address first.")
            return
        # Validate format before touching the interface
        if not _validate_mac(mac):
            messagebox.showerror(
                "Invalid MAC Address",
                f"'{mac}' is not a valid MAC address.\n\n"
                "Expected format: XX:XX:XX:XX:XX:XX  (hex octets separated by colons).",
            )
            return
        if not self._app._iface:
            messagebox.showerror("No Interface", "Select a network interface first.")
            return
        try:
            from wifi_killer.modules.anonymizer import randomize_mac
            new_mac = randomize_mac(self._app._iface, new_mac=mac)
            self._cur_mac.configure(text=new_mac)
            self._mac_status.configure(text=f"✓  MAC set to {new_mac}", text_color=_CLR_SUCCESS)
            self._app.log(f"MAC set to custom: {new_mac}", "ok")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _restore(self) -> None:
        original = self._app._original_mac
        if not original:
            messagebox.showwarning("Restore", "Original MAC address not recorded.")
            return
        try:
            from wifi_killer.modules.anonymizer import restore_mac
            restore_mac(self._app._iface, original)
            self._cur_mac.configure(text=original)
            self._mac_status.configure(text=f"✓  MAC restored to {original}", text_color=_CLR_SUCCESS)
            self._app.log(f"MAC restored to original: {original}", "ok")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))


# ===========================================================================
# Settings Frame
# ===========================================================================

class SettingsFrame(ctk.CTkFrame):
    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._build()

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self, text="⚙️  Attack Speed / Intensity",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, padx=28, pady=(24, 4), sticky="w")

        ctk.CTkLabel(
            self,
            text="Control how frequently and aggressively ARP spoof packets are sent.",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).grid(row=1, column=0, padx=28, pady=(0, 16), sticky="w")

        # Preset buttons
        preset_frame = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        preset_frame.grid(row=2, column=0, padx=28, pady=(0, 12), sticky="ew")

        ctk.CTkLabel(preset_frame, text="Quick Presets",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).grid(
            row=0, column=0, padx=16, pady=(14, 8), sticky="w")

        pb = ctk.CTkFrame(preset_frame, fg_color="transparent")
        pb.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="w")

        for label, name, color in [
            ("🟢 Normal",     "normal",     _CLR_PANEL),
            ("🔴 Aggressive", "aggressive", _CLR_ACCENT),
            ("🟡 Stealth",    "stealth",    _CLR_ACCENT2),
        ]:
            ctk.CTkButton(
                pb, text=label, fg_color=color,
                hover_color=_CLR_ACCENT2, font=_FONT_LABEL, width=140,
                command=lambda n=name: self._apply_preset(n),
            ).pack(side="left", padx=(0, 10))

        # Manual config
        cfg_frame = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        cfg_frame.grid(row=3, column=0, padx=28, pady=(0, 12), sticky="ew")
        cfg_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(cfg_frame, text="Manual Configuration",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).grid(
            row=0, column=0, columnspan=2, padx=16, pady=(14, 8), sticky="w")

        fields = [
            ("Interval (s):",    "interval",    str(attack_config.interval)),
            ("Burst size:",      "burst",       str(attack_config.burst)),
            ("Deauth count:",    "deauth_count",str(attack_config.deauth_count)),
            ("Deauth delay (s):","deauth_delay",str(attack_config.deauth_delay)),
        ]
        self._entries: dict[str, ctk.CTkEntry] = {}
        for ri, (label, key, val) in enumerate(fields, 1):
            ctk.CTkLabel(cfg_frame, text=label, font=_FONT_LABEL,
                         text_color=_CLR_MUTED).grid(
                row=ri, column=0, padx=16, pady=6, sticky="w")
            entry = ctk.CTkEntry(cfg_frame, width=160, font=_FONT_LABEL)
            entry.insert(0, val)
            entry.grid(row=ri, column=1, padx=8, pady=6, sticky="w")
            self._entries[key] = entry

        ctk.CTkButton(
            cfg_frame, text="✓  Apply Manual Config",
            fg_color=_CLR_SUCCESS, hover_color="#40c090",
            text_color="#000", font=_FONT_LABEL, width=180,
            command=self._apply_manual,
        ).grid(row=len(fields) + 1, column=0, columnspan=2, padx=16, pady=(12, 16), sticky="w")

        # Current values display
        self._disp = ctk.CTkLabel(
            self, text=attack_config.display(), font=_FONT_MONO, text_color=_CLR_SUCCESS)
        self._disp.grid(row=4, column=0, padx=28, pady=(8, 0), sticky="w")

        # ── Appearance / Theme card ────────────────────────────────────
        theme_frame = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        theme_frame.grid(row=5, column=0, padx=28, pady=(16, 0), sticky="ew")
        theme_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(theme_frame, text="Appearance",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).grid(
            row=0, column=0, columnspan=2, padx=16, pady=(14, 8), sticky="w")

        ctk.CTkLabel(theme_frame, text="Theme mode:",
                     font=_FONT_LABEL, text_color=_CLR_MUTED).grid(
            row=1, column=0, padx=16, pady=(0, 14), sticky="w")

        theme_btn_row = ctk.CTkFrame(theme_frame, fg_color="transparent")
        theme_btn_row.grid(row=1, column=1, padx=8, pady=(0, 14), sticky="w")

        for mode_label, mode_val in [("🌙 Dark", "dark"), ("☀️  Light", "light"), ("💻 System", "system")]:
            ctk.CTkButton(
                theme_btn_row, text=mode_label, width=110, height=30,
                fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
                font=_FONT_LABEL,
                command=lambda m=mode_val: self._set_theme(m),
            ).pack(side="left", padx=(0, 8))

    def _apply_preset(self, name: str) -> None:
        try:
            attack_config.apply_preset(name)
            self._disp.configure(text=attack_config.display())
            # Sync entries
            self._entries["interval"].delete(0, "end")
            self._entries["interval"].insert(0, str(attack_config.interval))
            self._entries["burst"].delete(0, "end")
            self._entries["burst"].insert(0, str(attack_config.burst))
            self._entries["deauth_count"].delete(0, "end")
            self._entries["deauth_count"].insert(0, str(attack_config.deauth_count))
            self._entries["deauth_delay"].delete(0, "end")
            self._entries["deauth_delay"].insert(0, str(attack_config.deauth_delay))
            self._app.log(f"Applied preset: {name}", "ok")
        except ValueError as exc:
            messagebox.showerror("Preset Error", str(exc))

    def _apply_manual(self) -> None:
        try:
            attack_config.interval = float(self._entries["interval"].get())
            attack_config.burst = int(self._entries["burst"].get())
            attack_config.deauth_count = int(self._entries["deauth_count"].get())
            attack_config.deauth_delay = float(self._entries["deauth_delay"].get())
            attack_config.preset = "custom"
            self._disp.configure(text=attack_config.display())
            self._app.log("Manual attack config applied.", "ok")
        except ValueError as exc:
            messagebox.showerror("Input Error", f"Invalid value: {exc}")

    def _set_theme(self, mode: str) -> None:
        ctk.set_appearance_mode(mode)
        self._app.log(f"Theme changed to: {mode}", "ok")


# ===========================================================================
# Dashboard Frame
# ===========================================================================

class DashboardFrame(ctk.CTkFrame):
    """Live overview: stat cards, recent devices, and quick-action shortcuts."""

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._build()
        # Refresh stats every 5 s automatically
        self._schedule_refresh()

    def _build(self) -> None:
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ── Page header ───────────────────────────────────────────────
        header = _page_header(
            self,
            icon="📊",
            title="Dashboard",
            subtitle="Live overview of your network and active operations",
        )
        header.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 4))

        self._last_refresh_label = ctk.CTkLabel(
            header.right_slot, text="",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        )
        self._last_refresh_label.pack(side="right", padx=(0, 2))

        # ── Stat cards ────────────────────────────────────────────────
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.grid(row=1, column=0, sticky="ew", padx=22, pady=(18, 14))
        for i in range(5):
            cards_frame.grid_columnconfigure(i, weight=1, uniform="cards")

        self._card_hosts   = _stat_card(cards_frame, "🖥️", "Hosts Found",   "0",    0, _CLR_SUCCESS)
        self._card_iface   = _stat_card(cards_frame, "📡", "Interface",     "—",    1, _CLR_TEXT)
        self._card_gw      = _stat_card(cards_frame, "🌐", "Gateway",       "—",    2, _CLR_ACCENT2)
        self._card_monitor = _stat_card(cards_frame, "👁",  "Monitor",       "Idle", 3, _CLR_MUTED)
        self._card_attack  = _stat_card(cards_frame, "⚡", "Active Attack", "None", 4, _CLR_MUTED)

        # ── Recent devices + Quick actions ────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=22, pady=(0, 22))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=1)

        # ── Recent devices card ───────────────────────────────────────
        recent = ctk.CTkFrame(
            body, fg_color=_CLR_PANEL, corner_radius=14,
            border_width=1, border_color=_CLR_BORDER,
        )
        recent.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        recent.grid_rowconfigure(2, weight=1)
        recent.grid_columnconfigure(0, weight=1)

        rec_title = ctk.CTkFrame(recent, fg_color="transparent")
        rec_title.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 4))
        rec_title.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            rec_title, text="Recent Devices",
            font=_FONT_HEAD, text_color=_CLR_TEXT, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            rec_title, text="Latest 8",
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED, anchor="e",
        ).grid(row=0, column=1, sticky="e")

        ctk.CTkFrame(recent, height=1, fg_color=_CLR_BORDER).grid(
            row=1, column=0, sticky="ew", padx=14, pady=(8, 0))

        self._recent_body = ctk.CTkScrollableFrame(
            recent, fg_color="transparent", corner_radius=0)
        self._recent_body.grid(row=2, column=0, sticky="nsew",
                               padx=10, pady=(8, 12))
        self._recent_body.grid_columnconfigure(0, weight=1)

        # ── Quick actions card ────────────────────────────────────────
        qa = ctk.CTkFrame(
            body, fg_color=_CLR_PANEL, corner_radius=14,
            border_width=1, border_color=_CLR_BORDER,
        )
        qa.grid(row=0, column=1, sticky="nsew")
        qa.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            qa, text="Quick Actions",
            font=_FONT_HEAD, text_color=_CLR_TEXT,
        ).pack(padx=20, pady=(16, 4), anchor="w")
        ctk.CTkLabel(
            qa, text="Jump straight to any tool",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).pack(padx=20, pady=(0, 12), anchor="w")

        ctk.CTkFrame(qa, height=1, fg_color=_CLR_BORDER).pack(
            fill="x", padx=14, pady=(0, 10))

        # Featured primary action
        _primary_button(
            qa, text="▶   Start Scan Now",
            command=self._quick_scan,
            height=44,
        ).pack(fill="x", padx=14, pady=(0, 12))

        # Secondary actions
        for label, key in [
            ("🌐   Multi-Subnet Scan",  "multi_subnet"),
            ("🏓   Ping Monitor",       "ping_monitor"),
            ("🎭   MAC Anonymize",      "anonymize"),
            ("🚦   Speed Control",      "throttle"),
        ]:
            _secondary_button(
                qa, text=label,
                command=lambda k=key: self._app._show_frame(k),
                anchor="w",
            ).pack(fill="x", padx=14, pady=3)

        # Destructive action
        _danger_button(
            qa, text="⚡   ARP Attack",
            command=lambda: self._app._show_frame("attack"),
            height=38,
        ).pack(fill="x", padx=14, pady=(8, 12))

        # ── Scan history block ────────────────────────────────────────
        ctk.CTkFrame(qa, height=1, fg_color=_CLR_BORDER).pack(
            fill="x", padx=14, pady=(2, 10))
        ctk.CTkLabel(
            qa, text="Scan History",
            font=_FONT_HEAD, text_color=_CLR_TEXT,
        ).pack(padx=20, pady=(0, 6), anchor="w")
        self._history_body = ctk.CTkFrame(qa, fg_color="transparent")
        self._history_body.pack(fill="x", padx=14, pady=(0, 14))

    # ── Refresh ───────────────────────────────────────────────────────

    def refresh(self) -> None:
        hosts = self._app._hosts
        self._card_hosts.configure(text=str(len(hosts)))
        self._card_iface.configure(text=self._app._iface or "—")
        self._card_gw.configure(text=self._app._gateway or "—")

        # Monitor status
        scan_frame: ScanFrame = self._app._frames.get("scan")  # type: ignore
        if scan_frame and getattr(scan_frame, "_monitor_running", False):
            self._card_monitor.configure(text="Running 🟢", text_color=_CLR_SUCCESS)
        else:
            self._card_monitor.configure(text="Idle", text_color=_CLR_MUTED)

        # Attack status
        atk_frame: AttackFrame = self._app._frames.get("attack")  # type: ignore
        if atk_frame and getattr(atk_frame, "_running", False):
            self._card_attack.configure(text="Active 🔴", text_color=_CLR_DANGER)
        else:
            self._card_attack.configure(text="None", text_color=_CLR_MUTED)

        # Recent devices (last 8)
        for w in self._recent_body.winfo_children():
            w.destroy()
        recent = hosts[-8:][::-1]
        if not recent:
            ctk.CTkLabel(
                self._recent_body,
                text="No hosts yet — run a scan first.",
                font=_FONT_LABEL, text_color=_CLR_MUTED,
            ).pack(padx=16, pady=12, anchor="w")
        else:
            for i, h in enumerate(recent):
                bg = _CLR_ROW_ODD if i % 2 == 0 else _CLR_ROW_EVEN
                row = ctk.CTkFrame(self._recent_body, fg_color=bg, corner_radius=6)
                row.pack(fill="x", padx=4, pady=1)
                row.grid_columnconfigure(3, weight=1)
                icon     = h.get("icon", "🔌")
                hostname = h.get("hostname") or ""
                dev_type = h.get("type", "Unknown")
                display  = f"{icon}  {hostname}" if hostname else f"{icon}  {dev_type}"
                vendor   = h.get("vendor", "Unknown")
                if len(vendor) > 18:
                    vendor = vendor[:16] + "…"
                for ci, (val, w, color, font) in enumerate([
                    (display,              180, _CLR_TEXT,    _FONT_NAME),
                    (h.get("ip", ""),      110, _CLR_SUCCESS, _FONT_MONO),
                    (vendor,               140, _CLR_MUTED,   _FONT_LABEL),
                    (dev_type,             0,   _CLR_TEXT,    _FONT_LABEL),
                ]):
                    ctk.CTkLabel(
                        row, text=val, font=font,
                        text_color=color, anchor="w",
                        **({"width": w} if w else {}),
                    ).grid(row=0, column=ci,
                           padx=(10 if ci == 0 else 8, 4), pady=6, sticky="w")

        self._last_refresh_label.configure(
            text=f"Last updated {time.strftime('%H:%M:%S')}")

        # Scan history
        for w in self._history_body.winfo_children():
            w.destroy()
        history = self._app._scan_history
        if not history:
            ctk.CTkLabel(
                self._history_body, text="No scans yet.",
                font=_FONT_SMALL, text_color=_CLR_MUTED,
            ).pack(anchor="w")
        else:
            for ts, count in reversed(history):
                ctk.CTkLabel(
                    self._history_body,
                    text=f"  {ts}  →  {count} host(s)",
                    font=_FONT_SMALL, text_color=_CLR_TEXT,
                ).pack(anchor="w", pady=1)

    def _schedule_refresh(self) -> None:
        self.refresh()
        self.after(5000, self._schedule_refresh)

    def _quick_scan(self) -> None:
        self._app._show_frame("scan")
        scan_frame: ScanFrame = self._app._frames.get("scan")  # type: ignore
        if scan_frame and not getattr(scan_frame, "_scanning", False):
            scan_frame._start_scan()


# ===========================================================================
# Ping Monitor Frame
# ===========================================================================

class PingMonitorFrame(ctk.CTkFrame):
    """Continuously ping a list of hosts and show live RTT statistics."""

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        # host_ip → {"label": label_widget, "samples": [], "running": bool}
        self._entries: dict[str, dict] = {}
        self._build()

    def _build(self) -> None:
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self, text="🏓  Ping Monitor",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, padx=28, pady=(22, 2), sticky="w")

        ctk.CTkLabel(
            self,
            text="Continuously probe hosts with ICMP echo and display round-trip latency.",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).grid(row=1, column=0, padx=28, pady=(0, 10), sticky="w")

        # Controls
        ctrl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        ctrl.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 10))
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="Add Host:",
                     font=_FONT_LABEL, text_color=_CLR_MUTED).grid(
            row=0, column=0, padx=(16, 6), pady=12)

        self._add_entry = ctk.CTkEntry(
            ctrl, font=_FONT_MONO,
            placeholder_text="IP or hostname…")
        self._add_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=12)
        self._add_entry.bind("<Return>", lambda _: self._add_from_entry())

        ctk.CTkButton(
            ctrl, text="➕  Add", width=100, height=32,
            fg_color=_CLR_ACCENT, hover_color="#c73652",
            font=_FONT_LABEL, command=self._add_from_entry,
        ).grid(row=0, column=2, padx=(0, 8), pady=12)

        ctk.CTkButton(
            ctrl, text="📋  From Scan", width=130, height=32,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=_FONT_LABEL, command=self._add_all_scanned,
        ).grid(row=0, column=3, padx=(0, 8), pady=12)

        ctk.CTkButton(
            ctrl, text="🗑️  Clear All", width=110, height=32,
            fg_color="#4a1010", hover_color=_CLR_DANGER,
            font=_FONT_LABEL, command=self._clear_all,
        ).grid(row=0, column=4, padx=(0, 16), pady=12)

        # Ping table
        tbl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        tbl.grid(row=3, column=0, sticky="nsew", padx=24, pady=(0, 20))
        tbl.grid_rowconfigure(1, weight=1)
        tbl.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(tbl, fg_color=_CLR_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        for ci, col in enumerate(("Host / IP", "Last RTT", "Min", "Avg", "Max", "Sent", "Status")):
            ctk.CTkLabel(hdr, text=col,
                         font=(_SF, 10, "bold"),
                         text_color=_CLR_ACCENT, anchor="w").grid(
                row=0, column=ci,
                padx=(14 if ci == 0 else 16, 4), pady=8, sticky="w")
        hdr.grid_columnconfigure(0, weight=1)

        self._tbl_body = ctk.CTkScrollableFrame(
            tbl, fg_color=_CLR_BG, corner_radius=0)
        self._tbl_body.grid(row=1, column=0, sticky="nsew")
        self._tbl_body.grid_columnconfigure(0, weight=1)

        self._grid_rowconfigure(3, weight=1)

    def _grid_rowconfigure(self, row: int, weight: int) -> None:
        """Proxy so we can call from _build without confusion."""
        self.grid_rowconfigure(row, weight=weight)

    # ── Host management ───────────────────────────────────────────────

    def add_host(self, ip: str, label: Optional[str] = None) -> None:
        """Add a host to the monitor (called programmatically too)."""
        ip = ip.strip()
        if not ip or ip in self._entries:
            return
        display = f"{label} ({ip})" if label and label != ip else ip
        self._entries[ip] = {
            "display":  display,
            "samples":  [],
            "sent":     0,
            "running":  True,
            "row":      None,  # will be set in _add_row_widget
        }
        self._add_row_widget(ip)
        _thread(self._ping_loop, ip)

    def _add_from_entry(self) -> None:
        val = self._add_entry.get().strip()
        if not val:
            return
        self._add_entry.delete(0, "end")
        # Resolve hostname → IP
        resolved = True
        try:
            ip = socket.gethostbyname(val)
        except socket.gaierror:
            ip = val
            resolved = False
        if not resolved:
            self._app.log(f"Could not resolve hostname '{val}' – using as-is.", "warn")
        if ip in self._entries:
            messagebox.showinfo("Duplicate", f"{ip} is already being monitored.")
            return
        self.add_host(ip, val if val != ip else None)

    def _add_all_scanned(self) -> None:
        hosts = self._app._hosts
        if not hosts:
            messagebox.showinfo("No Hosts", "Run a scan first to discover hosts.")
            return
        added = 0
        for h in hosts:
            if h.get("ip") and h["ip"] not in self._entries:
                self.add_host(h["ip"], h.get("hostname"))
                added += 1
        if added == 0:
            messagebox.showinfo("Already added", "All scanned hosts are already in the monitor.")
        else:
            self._app.log(f"Ping monitor: added {added} host(s).", "ok")

    def _clear_all(self) -> None:
        for entry in self._entries.values():
            entry["running"] = False
        self._entries.clear()
        for w in self._tbl_body.winfo_children():
            w.destroy()

    # ── Row widget ────────────────────────────────────────────────────

    def _add_row_widget(self, ip: str) -> None:
        i = len(self._entries) - 1
        bg = _CLR_ROW_ODD if i % 2 == 0 else _CLR_ROW_EVEN
        row = ctk.CTkFrame(self._tbl_body, fg_color=bg, corner_radius=6)
        row.pack(fill="x", padx=4, pady=1)
        row.grid_columnconfigure(0, weight=1)

        entry = self._entries[ip]
        display = entry["display"]

        ctk.CTkLabel(row, text=display, font=_FONT_LABEL,
                     text_color=_CLR_SUCCESS, anchor="w", width=180).grid(
            row=0, column=0, padx=(14, 8), pady=8, sticky="w")

        rtt_lbl   = ctk.CTkLabel(row, text="—", font=_FONT_MONO, text_color=_CLR_TEXT, width=80)
        rtt_lbl.grid(row=0, column=1, padx=8, pady=8, sticky="w")
        min_lbl   = ctk.CTkLabel(row, text="—", font=_FONT_MONO, text_color=_CLR_MUTED, width=70)
        min_lbl.grid(row=0, column=2, padx=8, pady=8, sticky="w")
        avg_lbl   = ctk.CTkLabel(row, text="—", font=_FONT_MONO, text_color=_CLR_MUTED, width=70)
        avg_lbl.grid(row=0, column=3, padx=8, pady=8, sticky="w")
        max_lbl   = ctk.CTkLabel(row, text="—", font=_FONT_MONO, text_color=_CLR_MUTED, width=70)
        max_lbl.grid(row=0, column=4, padx=8, pady=8, sticky="w")
        sent_lbl  = ctk.CTkLabel(row, text="0", font=_FONT_MONO, text_color=_CLR_MUTED, width=50)
        sent_lbl.grid(row=0, column=5, padx=8, pady=8, sticky="w")
        stat_lbl  = ctk.CTkLabel(row, text="Probing…", font=_FONT_LABEL,
                                  text_color=_CLR_WARNING, width=90)
        stat_lbl.grid(row=0, column=6, padx=8, pady=8, sticky="w")

        ctk.CTkButton(
            row, text="✕", width=28, height=24,
            fg_color="transparent", hover_color=_CLR_DANGER,
            font=_FONT_SMALL,
            command=lambda i=ip: self._remove_host(i),
        ).grid(row=0, column=7, padx=(4, 10), pady=6, sticky="e")

        entry["row"] = row
        entry["labels"] = {
            "rtt": rtt_lbl, "min": min_lbl, "avg": avg_lbl,
            "max": max_lbl, "sent": sent_lbl, "stat": stat_lbl,
        }

    def _remove_host(self, ip: str) -> None:
        entry = self._entries.pop(ip, None)
        if entry:
            entry["running"] = False
            row = entry.get("row")
            if row:
                row.destroy()

    # ── Ping loop ─────────────────────────────────────────────────────

    def _ping_loop(self, ip: str) -> None:
        while True:
            # Atomically check existence and running flag to avoid race
            entry = self._entries.get(ip)
            if not entry or not entry.get("running"):
                break
            rtt = _ping_once(ip, timeout=2.0)
            entry["sent"] = entry.get("sent", 0) + 1
            if rtt is not None:
                entry["samples"].append(rtt)
            self.after(0, lambda i=ip: self._update_row(i))
            time.sleep(2.0)

    def _update_row(self, ip: str) -> None:
        entry = self._entries.get(ip)
        if not entry:
            return
        lbls = entry.get("labels")
        if not lbls:
            return
        samples = entry["samples"]
        sent = entry.get("sent", 0)
        lbls["sent"].configure(text=str(sent))
        if samples:
            last = samples[-1]
            mn   = min(samples)
            av   = statistics.mean(samples)
            mx   = max(samples)
            color = (
                _CLR_SUCCESS if last < 30 else
                _CLR_WARNING if last < 100 else
                _CLR_DANGER
            )
            lbls["rtt"].configure(text=f"{last:.1f} ms", text_color=color)
            lbls["min"].configure(text=f"{mn:.1f}")
            lbls["avg"].configure(text=f"{av:.1f}")
            lbls["max"].configure(text=f"{mx:.1f}")
            lbls["stat"].configure(text="🟢 Online", text_color=_CLR_SUCCESS)
        else:
            if sent > 0:
                lbls["rtt"].configure(text="Timeout", text_color=_CLR_DANGER)
                lbls["stat"].configure(text="🔴 Offline", text_color=_CLR_DANGER)


# ===========================================================================
# Multi-Subnet Frame
# ===========================================================================

class MultiSubnetFrame(ctk.CTkFrame):
    """Discover and scan multiple subnets across different network segments."""

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._scanning = False
        self._subnet_vars: list[tuple[tk.BooleanVar, str]] = []   # (checked, cidr)
        self._build()

    def _build(self) -> None:
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Title
        ctk.CTkLabel(
            self, text="🌐  Multi-Subnet Discovery",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, padx=28, pady=(22, 2), sticky="w")

        ctk.CTkLabel(
            self,
            text="Automatically detect and scan multiple network segments to find "
                 "devices across different subnets.",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).grid(row=1, column=0, padx=28, pady=(0, 10), sticky="w")

        # ── Body split: left (subnet list) + right (controls + results) ──
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 18))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=0)
        body.grid_columnconfigure(1, weight=1)

        # ── Left: subnet list ──────────────────────────────────────────
        left = ctk.CTkFrame(body, fg_color=_CLR_SIDEBAR, corner_radius=12, width=260)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.grid_propagate(False)
        left.grid_rowconfigure(2, weight=1)
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="Subnet List", font=_FONT_HEAD,
                     text_color=_CLR_TEXT).grid(row=0, column=0, padx=14, pady=(14, 6), sticky="w")

        # Detect button
        detect_btn = ctk.CTkButton(
            left, text="🔎  Auto-detect", fg_color=_CLR_ACCENT,
            hover_color="#c73652", font=_FONT_LABEL, height=32,
            command=self._detect_subnets,
        )
        detect_btn.grid(row=1, column=0, padx=10, pady=(0, 8), sticky="ew")

        self._subnet_scroll = ctk.CTkScrollableFrame(
            left, fg_color=_CLR_BG, corner_radius=0)
        self._subnet_scroll.grid(row=2, column=0, sticky="nsew", padx=4, pady=(0, 6))
        self._subnet_scroll.grid_columnconfigure(0, weight=1)

        # Manual add row
        add_row = ctk.CTkFrame(left, fg_color="transparent")
        add_row.grid(row=3, column=0, padx=8, pady=(0, 12), sticky="ew")
        add_row.grid_columnconfigure(0, weight=1)

        self._add_entry = ctk.CTkEntry(
            add_row, font=_FONT_MONO, placeholder_text="x.x.x.x/24")
        self._add_entry.grid(row=0, column=0, padx=(0, 4), sticky="ew")

        ctk.CTkButton(
            add_row, text="+", width=34, height=32,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT,
            font=_FONT_LABEL, command=self._add_manual,
        ).grid(row=0, column=1)

        # ── Right: scan controls + results ────────────────────────────
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(2, weight=1)
        right.grid_columnconfigure(0, weight=1)

        # Controls card
        ctrl = ctk.CTkFrame(right, fg_color=_CLR_SIDEBAR, corner_radius=12)
        ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ctrl.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(ctrl, text="Scan type:", font=_FONT_LABEL,
                     text_color=_CLR_MUTED).grid(row=0, column=0, padx=(14, 4), pady=12)

        self._scan_type = ctk.CTkComboBox(
            ctrl, values=["Fast (ARP)", "Balanced (ARP+ICMP)", "Stealth (TCP SYN)"],
            width=190, font=_FONT_LABEL)
        self._scan_type.set("Fast (ARP)")
        self._scan_type.grid(row=0, column=1, padx=(0, 12), pady=12)

        ctk.CTkLabel(ctrl, text="Threads:", font=_FONT_LABEL,
                     text_color=_CLR_MUTED).grid(row=0, column=2, padx=(0, 4), pady=12)

        self._threads_entry = ctk.CTkEntry(ctrl, width=60, font=_FONT_LABEL)
        self._threads_entry.insert(0, "8")
        self._threads_entry.grid(row=0, column=3, padx=(0, 12), pady=12, sticky="w")

        self._scan_btn = ctk.CTkButton(
            ctrl, text="▶  Scan All", fg_color=_CLR_ACCENT,
            hover_color="#c73652", font=_FONT_LABEL, width=120,
            command=self._start_scan,
        )
        self._scan_btn.grid(row=0, column=4, padx=(0, 8), pady=12)

        self._export_btn = ctk.CTkButton(
            ctrl, text="💾  Export", fg_color=_CLR_PANEL,
            hover_color="#1a4a80", font=_FONT_LABEL, width=100,
            command=self._export,
        )
        self._export_btn.grid(row=0, column=5, padx=(0, 14), pady=12)

        # Progress bar
        self._progress = ctk.CTkProgressBar(
            right, mode="determinate", fg_color=_CLR_SIDEBAR,
            progress_color=_CLR_ACCENT)
        self._progress.set(0)

        self._prog_label = ctk.CTkLabel(
            right, text="", font=_FONT_SMALL, text_color=_CLR_MUTED)
        self._prog_label.grid(row=1, column=0, padx=0, pady=(0, 4), sticky="w")

        # Results table
        tbl = ctk.CTkFrame(right, fg_color=_CLR_SIDEBAR, corner_radius=12)
        tbl.grid(row=2, column=0, sticky="nsew")
        tbl.grid_rowconfigure(1, weight=1)
        tbl.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(tbl, fg_color=_CLR_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        for ci, col in enumerate(("Subnet", "IP Address", "MAC", "Vendor", "Type")):
            ctk.CTkLabel(
                hdr, text=col, font=(_SF, 10, "bold"),
                text_color=_CLR_ACCENT, anchor="w",
            ).grid(row=0, column=ci, padx=(12 if ci == 0 else 4, 4), pady=8, sticky="w")
        hdr.grid_columnconfigure(4, weight=1)

        self._result_body = ctk.CTkScrollableFrame(tbl, fg_color=_CLR_BG, corner_radius=0)
        self._result_body.grid(row=1, column=0, sticky="nsew")
        self._result_body.grid_columnconfigure(0, weight=1)

        self._result_rows: list[ctk.CTkFrame] = []
        self._result_count = ctk.CTkLabel(
            right, text="", font=_FONT_SMALL, text_color=_CLR_MUTED)
        self._result_count.grid(row=3, column=0, padx=0, pady=(4, 0), sticky="w")

    # ── Subnet management ─────────────────────────────────────────────

    def _detect_subnets(self) -> None:
        from wifi_killer.utils.network import get_candidate_subnets
        try:
            subnets = get_candidate_subnets()
        except Exception as exc:
            self._app.log(f"Subnet detection error: {exc}", "err")
            return
        # Clear and repopulate
        self._subnet_vars.clear()
        for widget in self._subnet_scroll.winfo_children():
            widget.destroy()
        for cidr in subnets:
            self._add_subnet_row(cidr)
        self._app.log(f"Detected {len(subnets)} subnet(s).", "ok")

    def _add_manual(self) -> None:
        cidr = self._add_entry.get().strip()
        if not cidr:
            return
        self._add_entry.delete(0, "end")
        # Validate
        try:
            import ipaddress
            ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            messagebox.showerror("Invalid CIDR", f"'{cidr}' is not a valid CIDR range.")
            return
        if any(c == cidr for _, c in self._subnet_vars):
            return
        self._add_subnet_row(cidr)

    def _add_subnet_row(self, cidr: str) -> None:
        var = tk.BooleanVar(value=True)
        row = ctk.CTkFrame(self._subnet_scroll, fg_color="transparent")
        row.pack(fill="x", pady=1)
        ctk.CTkCheckBox(
            row, text=cidr, variable=var,
            font=_FONT_MONO, checkbox_width=16, checkbox_height=16,
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            row, text="✕", width=24, height=22,
            fg_color="transparent", hover_color=_CLR_DANGER,
            font=_FONT_SMALL,
            command=lambda r=row, v=var, c=cidr: self._remove_subnet_row(r, v, c),
        ).pack(side="right", padx=4)
        self._subnet_vars.append((var, cidr))

    def _remove_subnet_row(self, row: ctk.CTkFrame,
                            var: tk.BooleanVar, cidr: str) -> None:
        self._subnet_vars = [(v, c) for v, c in self._subnet_vars if c != cidr]
        row.destroy()

    # ── Scan ──────────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        if self._scanning:
            return
        checked = [c for v, c in self._subnet_vars if v.get()]
        if not checked:
            messagebox.showinfo("No Subnets",
                                "Add or detect subnets first, then tick the ones to scan.")
            return
        if not self._app._iface:
            messagebox.showerror("No Interface", "Select a network interface in the top bar.")
            return

        self._scanning = True
        self._scan_btn.configure(state="disabled", text="Scanning…")
        self._progress.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        self._progress.set(0)
        self._clear_results()
        self._app.log(f"Multi-subnet scan: {len(checked)} subnet(s) …")
        _thread(self._run_scan, checked)

    def _run_scan(self, subnets: list[str]) -> None:
        total = len(subnets)

        def progress_cb(subnet: str, done: int, total: int) -> None:
            frac = done / total if total else 0
            self.after(0, lambda f=frac, d=done, t=total, s=subnet: (
                self._progress.set(f),
                self._prog_label.configure(
                    text=f"  Completed {d}/{t}  ·  last: {s}"),
            ))

        try:
            from wifi_killer.modules.scanner import multi_subnet_scan
            scan_map = {"Balanced (ARP+ICMP)": "balanced",
                        "Stealth (TCP SYN)": "stealth"}
            stype = scan_map.get(self._scan_type.get(), "fast")
            try:
                workers = max(1, min(32, int(self._threads_entry.get())))
            except ValueError:
                workers = 8

            raw = multi_subnet_scan(
                subnets=subnets,
                iface=self._app._iface,
                scan_type=stype,
                max_workers=workers,
                progress_cb=progress_cb,
            )

            gw = self._app._gateway
            from wifi_killer.modules.identifier import identify_host
            enriched = []
            for h in raw:
                info = identify_host(h["ip"], h["mac"],
                                     open_ports=h.get("open_ports", []),
                                     gateway_ip=gw)
                info["ping"] = h.get("ping", False)
                info["subnet"] = h.get("subnet", "")
                enriched.append(info)

            # Merge into persistent registry (preserves offline hosts from prev scans)
            self._app.merge_hosts(enriched)

            self.after(0, lambda: self._populate_results(enriched))
            self.after(0, lambda: self._app.log(
                f"Multi-subnet complete – {len(enriched)} host(s) across {total} subnet(s). "
                f"Total known: {len(self._app._host_registry)}.", "ok"))
            self.after(0, self._app.mark_hosts_changed)

        except Exception as exc:
            self.after(0, lambda exc=exc: self._app.log(f"Multi-subnet error: {exc}", "err"))
        finally:
            self.after(0, self._scan_done)

    def _scan_done(self) -> None:
        self._scanning = False
        self._scan_btn.configure(state="normal", text="▶  Scan All")
        self._progress.grid_remove()

    # ── Results ───────────────────────────────────────────────────────

    def _clear_results(self) -> None:
        for r in self._result_rows:
            r.destroy()
        self._result_rows.clear()

    def _populate_results(self, hosts: list[dict]) -> None:
        self._clear_results()
        for i, h in enumerate(hosts):
            bg = _CLR_ROW_ODD if i % 2 == 0 else _CLR_ROW_EVEN
            row = ctk.CTkFrame(self._result_body, fg_color=bg, corner_radius=6)
            row.grid(row=i, column=0, sticky="ew", padx=4, pady=1)
            row.grid_columnconfigure(4, weight=1)
            vals = [
                h.get("subnet", ""),
                h.get("ip", ""),
                h.get("mac", ""),
                h.get("vendor", "Unknown"),
                h.get("type", "Unknown"),
            ]
            widths = (110, 120, 145, 150, 0)
            for ci, (val, w) in enumerate(zip(vals, widths)):
                ctk.CTkLabel(
                    row, text=val, font=_FONT_LABEL,
                    text_color=_CLR_SUCCESS if ci == 1 else _CLR_TEXT,
                    anchor="w", **({"width": w} if w else {}),
                ).grid(row=0, column=ci, padx=(10 if ci == 0 else 4, 4), pady=6, sticky="w")
            self._result_rows.append(row)
        self._result_count.configure(
            text=f"  {len(hosts)} host(s) found across all subnets")

    def _export(self) -> None:
        import csv
        import json
        if not self._app._hosts:
            messagebox.showinfo("Export", "No hosts to export. Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json"), ("All", "*.*")],
            title="Export multi-subnet results",
        )
        if not path:
            return
        try:
            if path.endswith(".json"):
                with open(path, "w") as f:
                    json.dump(self._app._hosts, f, indent=2)
            else:
                keys = ["subnet", "ip", "mac", "vendor", "hostname", "type", "open_ports"]
                with open(path, "w", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(self._app._hosts)
            self._app.log(f"Exported to {path}", "ok")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))


# ===========================================================================
# Network Map Frame
# ===========================================================================

class NetworkMapFrame(ctk.CTkFrame):
    """Visual hub-and-spoke topology: gateway in the centre, hosts around it."""

    _NODE_R = 28   # host node radius (px)
    _GW_R   = 36   # gateway node radius (px)
    _MAP_BG = "#0d0d1a"

    # Topology cache TTL — how long a resolved snapshot stays fresh.
    _TOPO_TTL_SEC = 8.0
    # Minimum gap between two on_show-triggered refreshes (prevents thrash).
    _REDRAW_MIN_GAP_SEC = 0.5

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        # Async topology cache: heavy resolution runs in a background
        # thread; the renderer reads this dict and never blocks.
        self._topo_cache: Optional[dict] = None
        self._topo_cache_ts: float = 0.0
        self._topo_lock = threading.Lock()
        self._topo_resolving = False
        # If a refresh is requested while a worker is in-flight, the
        # worker will re-run automatically when it finishes — otherwise
        # the second request would be a no-op and the stale snapshot
        # captured by the first worker (e.g. before hosts arrived) wins.
        self._topo_refresh_pending = False
        self._last_redraw_ts = 0.0
        # Cache of hostname lookups (DNS can block) — IP → hostname.
        self._hostname_cache: dict[str, str] = {}
        self._build()

    def _build(self) -> None:
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ── Header ────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 8))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr, text="🗺️  Network Map",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, sticky="w")

        self._lbl_count = ctk.CTkLabel(
            hdr, text="No hosts loaded – run a scan first.",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        )
        self._lbl_count.grid(row=0, column=1, sticky="e")

        ctk.CTkButton(
            hdr, text="🔄  Refresh", width=110, height=30,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=_FONT_LABEL, command=self.request_topology_refresh,
        ).grid(row=0, column=2, padx=(12, 0), sticky="e")

        # ── Canvas ────────────────────────────────────────────────────
        self._canvas = tk.Canvas(
            self, bg=self._MAP_BG, highlightthickness=0, bd=0,
        )
        self._canvas.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self._canvas.bind("<Configure>", lambda _e: self.redraw())

    def _on_show(self) -> None:
        """Refresh the topology whenever the tab is raised.

        The canvas only re-renders on resize events; without this hook the
        map stays blank if hosts were scanned in another tab and then the
        user navigates here without resizing the window.
        """
        # Always request a topology refresh on tab show — the host list
        # almost certainly changed since the previous resolution. The
        # refresh is cheap (a flag flip) and queues a single bg worker.
        self.request_topology_refresh()
        self.after(20, self.redraw)

    def request_topology_refresh(self) -> None:
        """Mark the topology cache stale and kick off a background refresh.

        Called from the WifiKillerApp scan-completion hook and from
        the user's "Refresh" button. Safe to call from any thread.
        """
        with self._topo_lock:
            self._topo_cache_ts = 0.0
        self._ensure_topology_fresh()

    # ------------------------------------------------------------------ #
    # Topology resolution (async — never blocks the Tk main thread)        #
    # ------------------------------------------------------------------ #

    def _ensure_topology_fresh(self) -> None:
        """Spawn the resolver in a worker thread if the cache is stale.

        The renderer reads ``self._topo_cache`` directly — this method
        only ever schedules background work, never blocks. If a worker
        is already in-flight, the request is queued via
        ``_topo_refresh_pending`` so the worker re-runs once it finishes.
        """
        with self._topo_lock:
            if self._topo_resolving:
                self._topo_refresh_pending = True
                return
            if (self._topo_cache is not None
                    and time.time() - self._topo_cache_ts < self._TOPO_TTL_SEC):
                return
            self._topo_resolving = True
            self._topo_refresh_pending = False
        _thread(self._resolve_topology_worker)

    def _resolve_topology_worker(self) -> None:
        """Heavy lifting: runs in a background thread, then schedules redraw."""
        try:
            result = self._compute_topology()
        except Exception:
            result = {"gateway": None, "self_node": None,
                      "clients": [], "subnet": None}
        with self._topo_lock:
            self._topo_cache = result
            self._topo_resolving = False
            rerun = self._topo_refresh_pending
            self._topo_refresh_pending = False
            # If a refresh was requested mid-run, leave the cache_ts as
            # stale (0) so the next _ensure_topology_fresh() proceeds.
            # Otherwise stamp it fresh so subsequent reads use this result.
            self._topo_cache_ts = 0.0 if rerun else time.time()
        try:
            self.after(0, self._render_from_cache)
        except Exception:
            return
        if rerun:
            self._ensure_topology_fresh()

    def _compute_topology(self) -> dict:
        """Build the topology model. **Runs in a background thread.**

        Returns a dict with::

            gateway:   {ip, mac, vendor, hostname, online}  or None
            self_node: {ip, mac, vendor, hostname}          or None
            clients:   [host_dict, ...]                     (peers on LAN)
            subnet:    ipaddress.IPv4Network                or None
        """
        from wifi_killer.modules.arp_cache import read_arp_cache
        from wifi_killer.modules.identifier import oui_db

        # 1. Gateway IP — re-detect live, falling back to the cached value.
        gw_ip = (get_default_gateway() or self._app._gateway or "").strip()
        if gw_ip and gw_ip != self._app._gateway:
            self._app._gateway = gw_ip

        own_ip = self._app._get_own_ip()
        iface = self._app._iface or ""

        # 2. Determine the LAN subnet from the active interface.
        subnet: Optional[ipaddress.IPv4Network] = None
        if iface:
            try:
                cidr = get_interface_subnet(iface)
                if cidr:
                    subnet = ipaddress.IPv4Network(cidr, strict=False)
            except Exception:
                subnet = None
        if subnet is None and gw_ip:
            try:
                subnet = ipaddress.IPv4Network(f"{gw_ip}/24", strict=False)
            except Exception:
                subnet = None

        def _in_subnet(ip_str: str) -> bool:
            if subnet is None or not ip_str:
                return True
            try:
                return ipaddress.IPv4Address(ip_str) in subnet
            except Exception:
                return False

        # 3. Pull host registry; partition into gateway / self / clients.
        gateway: Optional[dict] = None
        self_node: Optional[dict] = None
        clients: list[dict] = []
        # Snapshot the registry once — it may be mutated by scan threads.
        hosts_snapshot = list(self._app._hosts)
        for host in hosts_snapshot:
            ip = (host.get("ip") or "").strip()
            if not ip or not _in_subnet(ip):
                continue
            if gw_ip and ip == gw_ip:
                gateway = dict(host)
            elif own_ip and ip == own_ip:
                self_node = dict(host)
            else:
                clients.append(host)

        # 4. Enrich gateway from the system ARP cache when needed.
        if gw_ip:
            if gateway is None:
                gateway = {"ip": gw_ip, "online": True}
            if not gateway.get("mac") or not gateway.get("vendor"):
                try:
                    for entry in read_arp_cache():
                        if entry.get("ip") == gw_ip and entry.get("mac"):
                            gateway.setdefault("mac", entry["mac"])
                            break
                except Exception:
                    pass
            mac = gateway.get("mac", "")
            if mac and not gateway.get("vendor"):
                try:
                    gateway["vendor"] = oui_db.lookup(mac)
                except Exception:
                    pass
            # Hostname resolution can block on DNS; use the cache and only
            # attempt one lookup per IP per session.
            if not gateway.get("hostname"):
                gateway["hostname"] = self._cached_hostname(gw_ip)
            gateway.setdefault("type", "Router")
            gateway.setdefault("icon", "📶")
            gateway.setdefault("online", True)

        # 5. Build the self-node entry even when the scan didn't include it.
        if own_ip and own_ip not in ("", "?"):
            if self_node is None:
                self_node = {"ip": own_ip, "online": True}
            if not self_node.get("mac") and iface:
                try:
                    self_node["mac"] = get_interface_mac(iface) or ""
                except Exception:
                    pass
            mac = self_node.get("mac", "")
            if mac and not self_node.get("vendor"):
                try:
                    self_node["vendor"] = oui_db.lookup(mac)
                except Exception:
                    pass
            self_node.setdefault("hostname", "This device")
            self_node.setdefault("icon", "💻")

        return {
            "gateway": gateway,
            "self_node": self_node,
            "clients": clients,
            "subnet": subnet,
            # Snapshot of any active ARP attack so the renderer can mark
            # the affected nodes/spokes with danger styling.
            "attack": self._app.get_attack_info(),
        }

    def _cached_hostname(self, ip: str) -> str:
        """Reverse-DNS lookup with per-frame caching and a hard timeout."""
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        result = ""
        prev = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(1.0)
            host, _, _ = socket.gethostbyaddr(ip)
            if host and host != ip:
                result = host
        except Exception:
            result = ""
        finally:
            socket.setdefaulttimeout(prev)
        self._hostname_cache[ip] = result
        return result

    # ------------------------------------------------------------------ #
    # Drawing                                                              #
    # ------------------------------------------------------------------ #

    def redraw(self) -> None:
        """Repaint the network map using the cached topology snapshot.

        This is called by Tk on resize, by the on_show hook, and after
        the background resolver finishes. It is **never** allowed to
        do subprocess / DNS work itself — that all happens in the
        worker thread. Calling redraw on a cold cache draws a "loading"
        placeholder and triggers the background resolver.
        """
        self._last_redraw_ts = time.time()
        self._render_from_cache()
        # Always make sure the cache stays warm; the worker no-ops if
        # the cache is fresh or another worker is already running.
        self._ensure_topology_fresh()

    def _render_from_cache(self) -> None:
        canvas = self._canvas
        canvas.delete("all")

        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 10 or h < 10:
            return

        with self._topo_lock:
            topo = self._topo_cache

        if topo is None:
            cx, cy = w // 2, h // 2
            canvas.create_text(
                cx, cy,
                text="Resolving network topology…",
                fill=_CLR_MUTED, font=(_SF, 13),
            )
            self._lbl_count.configure(text="Resolving…")
            return

        gateway   = topo["gateway"]
        self_node = topo["self_node"]
        clients   = topo["clients"]
        subnet    = topo["subnet"]
        attack    = topo.get("attack") or None
        attacked_ips: set[str] = (
            set(attack.get("attacked_ips", set())) if attack else set()
        )
        cx, cy = w // 2, h // 2

        # ── Empty state ───────────────────────────────────────────────
        if gateway is None and not clients:
            canvas.create_text(
                cx, cy,
                text="No gateway detected and no hosts scanned yet.\n\n"
                     "1. Pick an interface in the top bar.\n"
                     "2. Run a scan from the Scan Network tab.",
                fill=_CLR_MUTED, font=(_SF, 13), justify="center",
            )
            self._lbl_count.configure(text="No network detected.")
            return

        # ── Status banner text ────────────────────────────────────────
        online_count  = sum(1 for c in clients if c.get("online", True))
        offline_count = len(clients) - online_count
        bits: list[str] = []
        if subnet is not None:
            bits.append(f"LAN {subnet.with_prefixlen}")
        if gateway:
            bits.append(f"GW {gateway['ip']}")
        bits.append(f"{online_count} online")
        if offline_count:
            bits.append(f"{offline_count} offline")
        if attack:
            method = attack.get("method") or "?"
            bits.append(f"⚡ ATTACK {method} · {len(attacked_ips)} target(s)")
        self._lbl_count.configure(
            text="  ·  ".join(bits),
            text_color=_CLR_DANGER if attack else _CLR_MUTED,
        )

        # ── Attack banner across the top of the canvas ────────────────
        if attack:
            self._draw_attack_banner(canvas, w, attack)

        # ── Legend (top-right corner) ─────────────────────────────────
        self._draw_legend(canvas, w, has_attack=bool(attack))

        # ── Geometry ──────────────────────────────────────────────────
        n = len(clients)
        # Slot 0 is reserved for the self-node so it gets a stable position.
        slot_count = max(n + (1 if self_node else 0), 1)
        radius = min(w, h) * 0.36

        # ── Edges (spokes from gateway) ───────────────────────────────
        if gateway:
            for slot in range(slot_count):
                angle = 2 * math.pi * slot / slot_count - math.pi / 2
                hx = cx + radius * math.cos(angle)
                hy = cy + radius * math.sin(angle)
                line_dash: Optional[tuple] = None
                line_width = 2
                if slot == 0 and self_node:
                    # Solid spoke for "this device" — turn red if attacking.
                    line_color = _CLR_DANGER if attack else _CLR_ACCENT2
                    if attack:
                        line_width = 3
                else:
                    idx = slot - (1 if self_node else 0)
                    if idx < 0 or idx >= n:
                        continue
                    client = clients[idx]
                    online = client.get("online", True)
                    if client.get("ip") in attacked_ips:
                        line_color = _CLR_DANGER
                        line_dash  = (8, 4)
                        line_width = 3
                    else:
                        line_color = _CLR_PANEL if online else "#2a2a3a"
                        line_dash  = (4, 4) if online else (2, 6)
                kwargs = dict(fill=line_color, width=line_width)
                if line_dash is not None:
                    kwargs["dash"] = line_dash
                canvas.create_line(cx, cy, hx, hy, **kwargs)

        # ── Gateway node (centre) ─────────────────────────────────────
        if gateway:
            # In method A (MITM) and C (gateway-cut) the gateway's ARP
            # cache is also being poisoned — flag it on the centre node.
            gw_is_poisoned = (
                attack is not None
                and attack.get("method") in ("A", "C")
            )
            self._draw_gateway(canvas, cx, cy, gateway, poisoned=gw_is_poisoned)

        # ── Self node (slot 0) ────────────────────────────────────────
        if self_node and slot_count > 0:
            angle = -math.pi / 2  # straight up
            sx = cx + radius * math.cos(angle)
            sy = cy + radius * math.sin(angle)
            self._draw_self(canvas, sx, sy, self_node, attacking=bool(attack))

        # ── Client nodes (rest of the ring) ───────────────────────────
        for i, host in enumerate(clients):
            slot = i + (1 if self_node else 0)
            angle = 2 * math.pi * slot / slot_count - math.pi / 2
            hx = cx + radius * math.cos(angle)
            hy = cy + radius * math.sin(angle)
            is_attacked = host.get("ip") in attacked_ips
            self._draw_client(canvas, hx, hy, host, attacked=is_attacked)

    # ------------------------------------------------------------------ #
    # Per-node draw helpers                                                #
    # ------------------------------------------------------------------ #

    def _draw_attack_banner(
        self, canvas: tk.Canvas, w: int, attack: dict,
    ) -> None:
        """Bright red banner across the top of the canvas while attacking."""
        method = attack.get("method") or "?"
        n = len(attack.get("attacked_ips") or set())
        method_label = {
            "A": "FULL MITM (bi-directional)",
            "B": "CLIENT CUT-OFF",
            "C": "GATEWAY CUT-OFF",
        }.get(method, method)
        canvas.create_rectangle(
            12, 12, w - 12, 44,
            fill=_shade(_CLR_DANGER, 0.3),
            outline=_CLR_DANGER, width=1,
        )
        canvas.create_text(
            24, 28, anchor="w",
            text="⚡  ARP ATTACK ACTIVE",
            fill=_CLR_DANGER, font=(_SF, 11, "bold"),
        )
        canvas.create_text(
            w // 2, 28,
            text=f"Method {method} · {method_label} · {n} target(s)",
            fill="#ffd6dc", font=(_SF, 10, "bold"),
        )

    def _draw_legend(
        self, canvas: tk.Canvas, w: int, has_attack: bool = False,
    ) -> None:
        # Push legend down when the attack banner is visible.
        ly = 56 if has_attack else 14
        lx = w - 168
        rows = [
            (_CLR_ACCENT,  "Gateway / router"),
            (_CLR_ACCENT2, "This device"),
            ("#5bc0de",    "Client (online)"),
            ("#3a3a4a",    "Client (offline)"),
        ]
        if has_attack:
            rows.append((_CLR_DANGER, "Under attack"))
        height = 6 + len(rows) * 18 + 4
        canvas.create_rectangle(
            lx - 10, ly - 4, w - 4, ly + height,
            fill=_CLR_PANEL, outline=_CLR_BORDER, width=1,
        )
        for i, (color, label) in enumerate(rows):
            row_y = ly + 6 + i * 18
            canvas.create_oval(lx, row_y, lx + 12, row_y + 12,
                               fill=color, outline="")
            canvas.create_text(lx + 20, row_y + 6, text=label,
                               fill=_CLR_MUTED, font=(_SF, 9), anchor="w")

    def _draw_gateway(
        self, canvas: tk.Canvas, cx: int, cy: int, gw: dict,
        poisoned: bool = False,
    ) -> None:
        gr = self._GW_R
        halo_color = _CLR_DANGER if poisoned else _CLR_ACCENT
        # Outer halo — wider + red when the gateway's ARP cache is being poisoned.
        canvas.create_oval(
            cx - gr - 8, cy - gr - 8, cx + gr + 8, cy + gr + 8,
            fill="", outline=halo_color, width=2 if poisoned else 1,
        )
        # Filled gateway node
        canvas.create_oval(
            cx - gr, cy - gr, cx + gr, cy + gr,
            fill=_CLR_ACCENT, outline="#ffffff", width=2,
        )
        # Router icon
        canvas.create_text(
            cx, cy - 2, text=gw.get("icon") or "📶",
            font=(_SF, 18),
        )
        # Caption above the IP
        caption = "GATEWAY ⚡ SPOOFED" if poisoned else "GATEWAY"
        canvas.create_text(
            cx, cy - gr - 30,
            text=caption,
            fill=_CLR_DANGER if poisoned else _CLR_ACCENT,
            font=(_SF, 8, "bold"),
        )
        canvas.create_text(
            cx, cy - gr - 16,
            text=gw.get("ip", ""), fill=_CLR_TEXT, font=(_SF, 11, "bold"),
        )
        # Hostname / vendor / MAC below the gateway
        meta_lines = []
        hn = gw.get("hostname") or ""
        if hn and hn not in ("Unknown", ""):
            meta_lines.append(hn[:28])
        vd = gw.get("vendor") or ""
        if vd and vd not in ("Unknown", "") and vd not in meta_lines:
            meta_lines.append(vd[:28])
        mac = gw.get("mac") or ""
        if mac:
            meta_lines.append(mac.upper())
        for i, line in enumerate(meta_lines):
            canvas.create_text(
                cx, cy + gr + 14 + i * 13,
                text=line, fill=_CLR_MUTED, font=(_SF, 8),
            )

    def _draw_self(
        self, canvas: tk.Canvas, sx: float, sy: float, node: dict,
        attacking: bool = False,
    ) -> None:
        r = self._NODE_R
        # When attacking, our own node gets a red ring + filled red core
        # so it's obvious *this machine* is the source of the spoofing.
        if attacking:
            canvas.create_oval(
                sx - r - 6, sy - r - 6, sx + r + 6, sy + r + 6,
                fill="", outline=_CLR_DANGER, width=2,
            )
            inner_fill = _CLR_DANGER
        else:
            canvas.create_oval(
                sx - r - 4, sy - r - 4, sx + r + 4, sy + r + 4,
                fill="", outline=_CLR_ACCENT2, width=1,
            )
            inner_fill = _CLR_ACCENT2
        canvas.create_oval(
            sx - r, sy - r, sx + r, sy + r,
            fill=inner_fill, outline="#ffffff", width=2,
        )
        canvas.create_text(sx, sy, text=node.get("icon") or "💻",
                           font=(_SF, 14))
        caption = "ATTACKER ⚡" if attacking else "THIS DEVICE"
        caption_color = _CLR_DANGER if attacking else _CLR_ACCENT2
        canvas.create_text(
            sx, sy - r - 14,
            text=caption, fill=caption_color, font=(_SF, 8, "bold"),
        )
        canvas.create_text(
            sx, sy + r + 13,
            text=node.get("ip", ""), fill=_CLR_TEXT, font=(_SF, 8, "bold"),
        )
        hn = node.get("hostname") or ""
        if hn and hn not in ("Unknown", ""):
            canvas.create_text(
                sx, sy + r + 26,
                text=hn[:22], fill=_CLR_MUTED, font=(_SF, 7),
            )

    def _draw_client(
        self, canvas: tk.Canvas, hx: float, hy: float, host: dict,
        attacked: bool = False,
    ) -> None:
        r = self._NODE_R
        htype  = (host.get("type") or "").lower()
        online = host.get("online", True)
        icon   = host.get("icon") or ""

        if attacked:
            # Override the type-based palette with a danger fill + red halo.
            fill, outline = _CLR_DANGER, "#ffffff"
        elif not online:
            fill, outline = "#2a2a44", "#444466"
        elif "mobile" in htype or "phone" in htype or "ipad" in htype:
            fill, outline = "#5bc0de", _CLR_TEXT
        elif "printer" in htype:
            fill, outline = _CLR_WARNING, _CLR_TEXT
        elif "mac" in htype or "apple" in htype:
            fill, outline = "#7c3aed", _CLR_TEXT
        elif "tv" in htype or "console" in htype:
            fill, outline = "#0ea5e9", _CLR_TEXT
        else:
            fill, outline = _CLR_ACCENT2, _CLR_TEXT

        # Halo ring for attacked clients.
        if attacked:
            canvas.create_oval(
                hx - r - 5, hy - r - 5, hx + r + 5, hy + r + 5,
                fill="", outline=_CLR_DANGER, width=2,
            )

        canvas.create_oval(
            hx - r, hy - r, hx + r, hy + r,
            fill=fill, outline=outline, width=1,
        )
        if icon:
            canvas.create_text(hx, hy, text=icon, font=(_SF, 12))
        if not online and not attacked:
            canvas.create_text(
                hx, hy + 1, text="off",
                fill="#888899", font=(_SF, 7, "bold"),
            )

        # Caption above attacked nodes so the user sees status without hover.
        if attacked:
            canvas.create_text(
                hx, hy - r - 12,
                text="⚡ UNDER ATTACK",
                fill=_CLR_DANGER, font=(_SF, 8, "bold"),
            )

        # Labels below the node
        ip_color = (_CLR_DANGER if attacked
                    else _CLR_TEXT if online else "#555577")
        canvas.create_text(
            hx, hy + r + 13,
            text=host.get("ip", "?"),
            fill=ip_color, font=(_SF, 8, "bold"),
        )
        sub = host.get("hostname") or ""
        if not sub:
            vd = host.get("vendor") or ""
            if vd and vd not in ("Unknown", ""):
                sub = vd[:18] + ("…" if len(vd) > 18 else "")
        if sub:
            canvas.create_text(
                hx, hy + r + 26,
                text=sub[:20],
                fill="#555577" if not online and not attacked else _CLR_MUTED,
                font=(_SF, 7),
            )


# ===========================================================================
# Speed Control (Throttle) Frame
# ===========================================================================

_THROTTLE_MAX_MBPS: float = 100.0   # slider ceiling in Mbps

class ThrottleFrame(ctk.CTkFrame):
    """Per-client bandwidth throttling via Linux tc (traffic control)."""

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._throttler = None   # BandwidthThrottler instance
        self._active_rules: dict[str, tuple[float, float]] = {}  # ip→(dl_mbps, ul_mbps)
        self._build()

    # ── UI construction ───────────────────────────────────────────────

    def _build(self) -> None:
        self.grid_rowconfigure(4, weight=1)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self, text="🚦  Client Speed Control",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, padx=28, pady=(22, 2), sticky="w")

        ctk.CTkLabel(
            self,
            text="Rate-limit a client's download and upload speed using Linux tc HTB.\n"
                 "Requires an active ARP MITM session so traffic flows through this machine.",
            font=_FONT_SMALL, text_color=_CLR_MUTED, justify="left",
        ).grid(row=1, column=0, padx=28, pady=(0, 12), sticky="w")

        # ── Target selector card ──────────────────────────────────────
        sel_card = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        sel_card.grid(row=2, column=0, sticky="ew", padx=28, pady=(0, 12))
        sel_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(sel_card, text="Target IP:", font=_FONT_LABEL,
                     text_color=_CLR_MUTED).grid(row=0, column=0, padx=16, pady=(14, 10), sticky="w")

        self._target_var = tk.StringVar()
        self._target_combo = ctk.CTkComboBox(
            sel_card, variable=self._target_var, values=[],
            width=200, font=_FONT_MONO,
            command=lambda _: None,
        )
        self._target_combo.grid(row=0, column=1, padx=(0, 8), pady=(14, 10), sticky="w")

        ctk.CTkButton(
            sel_card, text="🔄 Refresh", width=100, height=30,
            fg_color=_CLR_PANEL, font=_FONT_SMALL,
            command=self._refresh_targets,
        ).grid(row=0, column=2, padx=(0, 8), pady=(14, 10))

        self._manual_entry = ctk.CTkEntry(
            sel_card, width=160, font=_FONT_MONO,
            placeholder_text="or type IP manually")
        self._manual_entry.grid(row=0, column=3, padx=(0, 16), pady=(14, 10))

        # ── Slider card ───────────────────────────────────────────────
        sliders_card = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        sliders_card.grid(row=3, column=0, sticky="ew", padx=28, pady=(0, 12))
        sliders_card.grid_columnconfigure(1, weight=1)

        # Download slider
        ctk.CTkLabel(sliders_card, text="⬇  Download:",
                     font=_FONT_LABEL, text_color=_CLR_MUTED).grid(
            row=0, column=0, padx=(16, 8), pady=(16, 8), sticky="w")

        self._dl_var = tk.DoubleVar(value=10.0)
        self._dl_slider = ctk.CTkSlider(
            sliders_card, from_=0, to=_THROTTLE_MAX_MBPS,
            variable=self._dl_var, width=400,
            button_color=_CLR_ACCENT, button_hover_color="#c73652",
            progress_color=_CLR_ACCENT,
            command=lambda v: self._on_slider(v, "dl"),
        )
        self._dl_slider.grid(row=0, column=1, padx=(0, 12), pady=(16, 8), sticky="ew")

        self._dl_label = ctk.CTkLabel(
            sliders_card, text="10.0 Mbps", font=_FONT_MONO,
            text_color=_CLR_SUCCESS, width=100)
        self._dl_label.grid(row=0, column=2, padx=(0, 16), pady=(16, 8))

        # Upload slider
        ctk.CTkLabel(sliders_card, text="⬆  Upload:",
                     font=_FONT_LABEL, text_color=_CLR_MUTED).grid(
            row=1, column=0, padx=(16, 8), pady=(0, 8), sticky="w")

        self._ul_var = tk.DoubleVar(value=5.0)
        self._ul_slider = ctk.CTkSlider(
            sliders_card, from_=0, to=_THROTTLE_MAX_MBPS,
            variable=self._ul_var, width=400,
            button_color=_CLR_ACCENT2, button_hover_color="#6b44a8",
            progress_color=_CLR_ACCENT2,
            command=lambda v: self._on_slider(v, "ul"),
        )
        self._ul_slider.grid(row=1, column=1, padx=(0, 12), pady=(0, 8), sticky="ew")

        self._ul_label = ctk.CTkLabel(
            sliders_card, text="5.0 Mbps", font=_FONT_MONO,
            text_color=_CLR_SUCCESS, width=100)
        self._ul_label.grid(row=1, column=2, padx=(0, 16), pady=(0, 8))

        # ── Preset speed buttons ──────────────────────────────────────
        preset_row = ctk.CTkFrame(sliders_card, fg_color="transparent")
        preset_row.grid(row=2, column=0, columnspan=3, padx=16, pady=(0, 14), sticky="w")

        ctk.CTkLabel(preset_row, text="Presets:",
                     font=_FONT_LABEL, text_color=_CLR_MUTED).pack(side="left", padx=(0, 10))

        for label, dl, ul in [
            ("🔴 Block",    0.0,  0.0),
            ("🐢 Dial-Up",  0.056, 0.028),
            ("🟡 1 Mbps",   1.0,  0.5),
            ("🔵 5 Mbps",   5.0,  2.0),
            ("🟢 25 Mbps",  25.0, 10.0),
            ("⚡ Full",     100.0, 100.0),
        ]:
            ctk.CTkButton(
                preset_row, text=label, width=90, height=28,
                fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
                font=_FONT_SMALL,
                command=lambda d=dl, u=ul: self._set_preset(d, u),
            ).pack(side="left", padx=(0, 6))

        # ── Action buttons ────────────────────────────────────────────
        act_row = ctk.CTkFrame(sliders_card, fg_color="transparent")
        act_row.grid(row=3, column=0, columnspan=3, padx=16, pady=(0, 16), sticky="w")

        self._apply_btn = ctk.CTkButton(
            act_row, text="✓  Apply Throttle",
            fg_color=_CLR_ACCENT, hover_color="#c73652",
            font=_FONT_LABEL, width=160,
            command=self._apply,
        )
        self._apply_btn.pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            act_row, text="↩  Remove Throttle",
            fg_color=_CLR_PANEL, hover_color="#1a4a80",
            font=_FONT_LABEL, width=160,
            command=self._remove_one,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            act_row, text="🧹  Clear All",
            fg_color="#4a1010", hover_color=_CLR_DANGER,
            font=_FONT_LABEL, width=120,
            command=self._clear_all,
        ).pack(side="left")

        # ── Active rules table ────────────────────────────────────────
        rules_card = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        rules_card.grid(row=4, column=0, sticky="nsew", padx=28, pady=(0, 20))
        rules_card.grid_rowconfigure(1, weight=1)
        rules_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(rules_card, text="Active Throttle Rules",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).grid(
            row=0, column=0, padx=16, pady=(12, 6), sticky="w")

        hdr = ctk.CTkFrame(rules_card, fg_color=_CLR_PANEL, corner_radius=0)
        hdr.grid(row=1, column=0, sticky="ew")
        for ci, col in enumerate(("Target IP", "Download", "Upload", "Status")):
            ctk.CTkLabel(
                hdr, text=col, font=(_SF, 10, "bold"),
                text_color=_CLR_ACCENT, anchor="w",
            ).grid(row=0, column=ci, padx=(12 if ci == 0 else 20, 4), pady=8, sticky="w")
        hdr.grid_columnconfigure(3, weight=1)

        self._rules_body = ctk.CTkScrollableFrame(
            rules_card, fg_color=_CLR_BG, corner_radius=0, height=160)
        self._rules_body.grid(row=2, column=0, sticky="nsew")
        self._rules_body.grid_columnconfigure(0, weight=1)
        self._rule_rows: dict[str, ctk.CTkFrame] = {}

        # Status bar
        self._status = ctk.CTkLabel(
            self, text="", font=_FONT_LABEL, text_color=_CLR_MUTED)
        self._status.grid(row=5, column=0, padx=28, pady=(0, 8), sticky="w")

    # ── Helpers ───────────────────────────────────────────────────────

    def _on_slider(self, value: float, which: str) -> None:
        from wifi_killer.modules.throttler import kbps_to_label, mbps_to_kbps
        label_text = ("Blocked" if value == 0.0
                      else kbps_to_label(mbps_to_kbps(value)))
        if which == "dl":
            self._dl_label.configure(text=label_text)
        else:
            self._ul_label.configure(text=label_text)

    def _set_preset(self, dl_mbps: float, ul_mbps: float) -> None:
        self._dl_var.set(dl_mbps)
        self._ul_var.set(ul_mbps)
        self._on_slider(dl_mbps, "dl")
        self._on_slider(ul_mbps, "ul")

    def _refresh_targets(self) -> None:
        ips = [h["ip"] for h in self._app._hosts]
        self._target_combo.configure(values=ips)
        if ips and not self._target_var.get():
            self._target_var.set(ips[0])

    def prefill_target(self, ip: str) -> None:
        """Pre-fill the manual target entry with *ip* (called from host row)."""
        self._manual_entry.delete(0, "end")
        self._manual_entry.insert(0, ip)

    def _resolve_target(self) -> Optional[str]:
        manual = self._manual_entry.get().strip()
        if manual:
            return manual
        return self._target_var.get().strip() or None

    def _ensure_throttler(self) -> bool:
        """Lazily create and set up the BandwidthThrottler.  Returns True on success."""
        if self._throttler and self._throttler.is_setup:
            return True
        try:
            from wifi_killer.modules.throttler import BandwidthThrottler
            self._throttler = BandwidthThrottler(self._app._iface)
            self._throttler.setup()
            return True
        except Exception as exc:
            messagebox.showerror("tc Error",
                                 f"Could not initialize traffic control:\n{exc}\n\n"
                                 "Make sure you are running as root and iproute2 is installed.")
            return False

    def _apply(self) -> None:
        target = self._resolve_target()
        if not target:
            messagebox.showwarning("No Target", "Select or type a target IP address.")
            return
        if not self._app._iface:
            messagebox.showerror("No Interface", "Select a network interface first.")
            return

        from wifi_killer.modules.throttler import mbps_to_kbps, kbps_to_label
        dl_mbps = self._dl_var.get()
        ul_mbps = self._ul_var.get()
        dl_kbps = mbps_to_kbps(dl_mbps)
        ul_kbps = mbps_to_kbps(ul_mbps)

        if not self._ensure_throttler():
            return

        try:
            self._throttler.set_speed(target, download_kbps=dl_kbps, upload_kbps=ul_kbps)
        except Exception as exc:
            messagebox.showerror("Throttle Error", str(exc))
            return

        self._active_rules[target] = (dl_mbps, ul_mbps)
        self._update_rules_table()

        dl_str = kbps_to_label(dl_kbps)
        ul_str = kbps_to_label(ul_kbps)
        self._status.configure(
            text=f"✓  {target}  →  ⬇ {dl_str}  ⬆ {ul_str}", text_color=_CLR_SUCCESS)
        self._app.log(f"Speed throttle applied: {target}  ⬇{dl_str}  ⬆{ul_str}", "ok")

    def _remove_one(self) -> None:
        target = self._resolve_target()
        if not target:
            messagebox.showwarning("No Target", "Select or type a target IP address.")
            return
        if self._throttler:
            try:
                self._throttler.remove(target)
            except Exception as exc:
                messagebox.showerror("Remove Error", str(exc))
                return
        self._active_rules.pop(target, None)
        self._update_rules_table()
        self._status.configure(text=f"↩  Throttle removed for {target}",
                               text_color=_CLR_WARNING)
        self._app.log(f"Throttle removed: {target}", "warn")

    def _clear_all(self) -> None:
        if self._throttler:
            try:
                self._throttler.cleanup()
            except Exception as exc:
                messagebox.showerror("Cleanup Error", str(exc))
                return
            self._throttler = None
        self._active_rules.clear()
        self._update_rules_table()
        self._status.configure(text="All throttle rules cleared.", text_color=_CLR_MUTED)
        self._app.log("All throttle rules cleared and tc qdisc removed.", "ok")

    def _update_rules_table(self) -> None:
        from wifi_killer.modules.throttler import kbps_to_label, mbps_to_kbps
        # Destroy old rows
        for widget in self._rules_body.winfo_children():
            widget.destroy()
        self._rule_rows.clear()

        if not self._active_rules:
            ctk.CTkLabel(
                self._rules_body, text="No active throttle rules.",
                font=_FONT_LABEL, text_color=_CLR_MUTED,
            ).grid(row=0, column=0, padx=16, pady=12, sticky="w")
            return

        for i, (ip, (dl_mbps, ul_mbps)) in enumerate(self._active_rules.items()):
            bg = _CLR_ROW_ODD if i % 2 == 0 else _CLR_ROW_EVEN
            row = ctk.CTkFrame(self._rules_body, fg_color=bg, corner_radius=6)
            row.grid(row=i, column=0, sticky="ew", padx=4, pady=1)
            row.grid_columnconfigure(3, weight=1)

            dl_str = kbps_to_label(mbps_to_kbps(dl_mbps))
            ul_str = kbps_to_label(mbps_to_kbps(ul_mbps))
            is_blocked = (dl_mbps == 0 and ul_mbps == 0)
            status_text = "🔴 BLOCKED" if is_blocked else "🟡 THROTTLED"
            status_color = _CLR_DANGER if is_blocked else _CLR_WARNING

            for ci, (text, color, w) in enumerate([
                (ip,           _CLR_SUCCESS, 140),
                (f"⬇ {dl_str}", _CLR_TEXT,  130),
                (f"⬆ {ul_str}", _CLR_TEXT,  130),
                (status_text,  status_color,   0),
            ]):
                ctk.CTkLabel(
                    row, text=text, font=_FONT_LABEL,
                    text_color=color, anchor="w",
                    **({"width": w} if w else {}),
                ).grid(row=0, column=ci, padx=(12 if ci == 0 else 20, 4), pady=8, sticky="w")

            # Remove button on right
            ctk.CTkButton(
                row, text="✕", width=28, height=24,
                fg_color="transparent", hover_color=_CLR_DANGER,
                font=_FONT_SMALL,
                command=lambda t=ip: self._remove_specific(t),
            ).grid(row=0, column=4, padx=8, pady=6, sticky="e")

            self._rule_rows[ip] = row

    def _remove_specific(self, ip: str) -> None:
        if self._throttler:
            try:
                self._throttler.remove(ip)
            except Exception:
                pass
        self._active_rules.pop(ip, None)
        self._update_rules_table()
        self._status.configure(text=f"↩  Throttle removed for {ip}",
                               text_color=_CLR_WARNING)
        self._app.log(f"Throttle removed: {ip}", "warn")


# ===========================================================================
# Wake-on-LAN Frame
# ===========================================================================

class WolFrame(ctk.CTkFrame):
    """Send Wake-on-LAN magic packets to power on devices remotely."""

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._history: list[str] = []   # list of "timestamp  MAC  status"
        self._build()

    # ------------------------------------------------------------------ #
    # Layout                                                               #
    # ------------------------------------------------------------------ #

    def _build(self) -> None:
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ── Header ────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 8))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr, text="🔆  Wake-on-LAN",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            hdr,
            text="Power on devices remotely by sending a magic packet.",
            font=_FONT_LABEL, text_color=_CLR_MUTED,
        ).grid(row=1, column=0, sticky="w")

        # ── Body ──────────────────────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=28, pady=(0, 18))
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(1, weight=1)

        # ── Form card ─────────────────────────────────────────────────
        form = ctk.CTkFrame(body, fg_color=_CLR_SIDEBAR, corner_radius=14)
        form.grid(row=0, column=0, sticky="new", padx=(0, 12), pady=(8, 0))
        form.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form, text="Target MAC", font=_FONT_LABEL,
                     text_color=_CLR_TEXT).grid(
            row=0, column=0, padx=(18, 8), pady=(18, 4), sticky="w")
        self._mac_entry = ctk.CTkEntry(
            form, placeholder_text="AA:BB:CC:DD:EE:FF",
            width=200, font=_FONT_MONO,
        )
        self._mac_entry.grid(row=0, column=1, padx=(0, 18), pady=(18, 4), sticky="ew")

        ctk.CTkLabel(form, text="Broadcast", font=_FONT_LABEL,
                     text_color=_CLR_TEXT).grid(
            row=1, column=0, padx=(18, 8), pady=4, sticky="w")
        self._bcast_entry = ctk.CTkEntry(
            form, placeholder_text="255.255.255.255",
            width=200, font=_FONT_MONO,
        )
        self._bcast_entry.grid(row=1, column=1, padx=(0, 18), pady=4, sticky="ew")
        self._bcast_entry.insert(0, "255.255.255.255")

        ctk.CTkLabel(form, text="UDP Port", font=_FONT_LABEL,
                     text_color=_CLR_TEXT).grid(
            row=2, column=0, padx=(18, 8), pady=4, sticky="w")
        self._port_entry = ctk.CTkEntry(
            form, placeholder_text="9 (or 7)",
            width=80, font=_FONT_MONO,
        )
        self._port_entry.grid(row=2, column=1, padx=(0, 18), pady=4, sticky="w")
        self._port_entry.insert(0, "9")

        ctk.CTkLabel(form, text="SecureOn\n(optional)", font=_FONT_LABEL,
                     text_color=_CLR_TEXT).grid(
            row=3, column=0, padx=(18, 8), pady=4, sticky="w")
        self._secureon_entry = ctk.CTkEntry(
            form, placeholder_text="AA:BB:CC:DD:EE:FF or leave blank",
            width=200, font=_FONT_MONO,
        )
        self._secureon_entry.grid(row=3, column=1, padx=(0, 18), pady=4, sticky="ew")

        ctk.CTkLabel(
            form,
            text=(
                "SecureOn is a 6-byte password used by some managed NICs.\n"
                "Leave blank for a standard magic packet."
            ),
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).grid(row=4, column=0, columnspan=2, padx=18, pady=(0, 4), sticky="w")

        self._send_btn = ctk.CTkButton(
            form, text="🚀  Send Magic Packet",
            fg_color=_CLR_ACCENT, hover_color="#c73652",
            font=_FONT_HEAD, height=44,
            command=self._send_wol,
        )
        self._send_btn.grid(row=5, column=0, columnspan=2,
                            padx=18, pady=(12, 18), sticky="ew")

        # ── Pick from scanned hosts ────────────────────────────────────
        tip = ctk.CTkFrame(body, fg_color=_CLR_SIDEBAR, corner_radius=14)
        tip.grid(row=0, column=1, sticky="nsew", padx=(0, 0), pady=(8, 0))
        tip.grid_columnconfigure(0, weight=1)
        tip.grid_rowconfigure(2, weight=1)

        pick_hdr = ctk.CTkFrame(tip, fg_color="transparent")
        pick_hdr.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 4))
        pick_hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(pick_hdr, text="Pick from Scan",
                     font=_FONT_HEAD, text_color=_CLR_TEXT,
                     anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkButton(
            pick_hdr, text="🔄  Refresh", width=92, height=26,
            fg_color=_CLR_PANEL, hover_color=_CLR_HOVER,
            border_width=1, border_color=_CLR_BORDER,
            text_color=_CLR_TEXT, font=_FONT_SMALL,
            command=self._refresh_pick_list,
        ).grid(row=0, column=1, sticky="e")

        ctk.CTkLabel(
            tip,
            text="Click a host to prefill its MAC address.",
            font=_FONT_SMALL, text_color=_CLR_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=14, pady=(0, 4))

        self._pick_scroll = ctk.CTkScrollableFrame(
            tip, fg_color="transparent", corner_radius=0,
        )
        self._pick_scroll.grid(row=2, column=0, sticky="nsew",
                                padx=8, pady=(0, 12))
        self._pick_scroll.grid_columnconfigure(0, weight=1)
        # Populate after construction so app._hosts may have been filled.
        self.after(50, self._refresh_pick_list)

        # ── History log ───────────────────────────────────────────────
        log_frame = ctk.CTkFrame(body, fg_color=_CLR_SIDEBAR, corner_radius=14)
        log_frame.grid(row=1, column=0, columnspan=2,
                       sticky="nsew", pady=(14, 0))
        log_frame.grid_rowconfigure(1, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        top_bar = ctk.CTkFrame(log_frame, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))
        top_bar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(top_bar, text="Packet History",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).grid(
            row=0, column=0, sticky="w")
        ctk.CTkButton(
            top_bar, text="Clear", width=70, height=26,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=_FONT_SMALL, command=self._clear_log,
        ).grid(row=0, column=1, sticky="e")

        self._log_box = ctk.CTkTextbox(
            log_frame, fg_color=_CLR_BG,
            font=_FONT_MONO, state="disabled",
        )
        self._log_box.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    # ------------------------------------------------------------------ #
    # Actions                                                              #
    # ------------------------------------------------------------------ #

    def prefill_mac(self, mac: str) -> None:
        """Pre-fill the MAC entry from an external caller (e.g. host detail dialog)."""
        self._mac_entry.delete(0, "end")
        self._mac_entry.insert(0, mac)

    def _on_show(self) -> None:
        """Re-populate the host picker each time the tab is opened."""
        self._refresh_pick_list()

    def _refresh_pick_list(self) -> None:
        """Rebuild the pick-from-scan list from the app's host registry."""
        for w in self._pick_scroll.winfo_children():
            w.destroy()

        hosts = sorted(
            (h for h in self._app._hosts if h.get("mac")),
            key=lambda h: _ip_sort_key(h.get("ip", "")),
        )
        if not hosts:
            ctk.CTkLabel(
                self._pick_scroll,
                text="No hosts with MACs yet — run a scan first.",
                font=_FONT_SMALL, text_color=_CLR_MUTED, anchor="w",
            ).pack(padx=12, pady=10, anchor="w", fill="x")
            return

        for idx, host in enumerate(hosts):
            bg = _CLR_ROW_ODD if idx % 2 == 0 else _CLR_ROW_EVEN
            row = ctk.CTkFrame(self._pick_scroll, fg_color=bg,
                               corner_radius=8)
            row.pack(fill="x", padx=4, pady=1)

            inner = ctk.CTkButton(
                row, text="", fg_color="transparent",
                hover_color=_CLR_HOVER, anchor="w",
                command=lambda h=host: self._apply_picked_host(h),
                corner_radius=8, height=44,
            )
            inner.pack(fill="x", padx=4, pady=2)

            label_col = ctk.CTkFrame(inner, fg_color="transparent")
            label_col.place(relx=0.0, rely=0.5, anchor="w", x=10)

            ctk.CTkLabel(
                label_col,
                text=f"{host.get('icon', '🔌')}  "
                     f"{host.get('hostname') or host.get('ip', '?')}",
                font=_FONT_NAME, text_color=_CLR_TEXT, anchor="w",
            ).pack(anchor="w")
            ctk.CTkLabel(
                label_col,
                text=f"{host.get('ip', '')}  ·  {host.get('mac', '')}",
                font=_FONT_MONO, text_color=_CLR_MUTED, anchor="w",
            ).pack(anchor="w")

    def _apply_picked_host(self, host: dict) -> None:
        """Prefill MAC + broadcast from a clicked scanned host."""
        mac = host.get("mac") or ""
        if mac:
            self.prefill_mac(mac.upper())
        # Use the host's /24 broadcast if possible — more reliable than
        # 255.255.255.255 since some routers don't forward limited bcasts.
        ip = host.get("ip") or ""
        if ip and ip.count(".") == 3:
            parts = ip.split(".")
            if parts[-1] != "255":
                bcast = ".".join(parts[:3] + ["255"])
                self._bcast_entry.delete(0, "end")
                self._bcast_entry.insert(0, bcast)

    def _send_wol(self) -> None:
        from wifi_killer.modules.wol import send_wol

        mac = self._mac_entry.get().strip()
        bcast = self._bcast_entry.get().strip() or "255.255.255.255"
        secure_on = self._secureon_entry.get().strip()

        try:
            port = int(self._port_entry.get().strip() or "9")
        except ValueError:
            self._log("Invalid port number.", ok=False)
            return

        if not _validate_mac(mac):
            self._log(f"Invalid MAC address: '{mac}'", ok=False)
            return

        if secure_on and not _validate_mac(secure_on):
            self._log(f"Invalid SecureOn password: '{secure_on}'", ok=False)
            return

        def _worker() -> None:
            try:
                send_wol(mac, broadcast=bcast, port=port,
                         secure_on=secure_on)
                size = 108 if secure_on else 102
                msg = (
                    f"Sent {size}-byte magic packet → {mac} "
                    f"(broadcast {bcast}:{port}"
                    + (f", SecureOn={secure_on}" if secure_on else "")
                    + ")"
                )
                self.after(0, lambda: self._log(msg, ok=True))
                self._app.log(f"WoL: {msg}", "ok")
            except Exception as exc:
                err = str(exc)
                self.after(0, lambda exc=exc: self._log(f"Error: {exc}", ok=False))
                self._app.log(f"WoL error: {err}", "err")

        _thread(_worker)

    def _log(self, msg: str, ok: bool = True) -> None:
        ts = time.strftime("%H:%M:%S")
        icon = "✔" if ok else "✕"
        line = f"{ts}  [{icon}]  {msg}\n"
        self._log_box.configure(state="normal")
        self._log_box.insert("end", line)
        self._log_box.configure(state="disabled")
        self._log_box.see("end")

    def _clear_log(self) -> None:
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.configure(state="disabled")


# ===========================================================================
# About Frame
# ===========================================================================

# ===========================================================================
# DNS Sniffer Frame
# ===========================================================================

class DnsSnifferFrame(ctk.CTkFrame):
    """GUI panel for capturing and displaying DNS queries in real time."""

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._sniffer = None
        self._running = False
        self._refresh_id = None
        self._build()

    def _build(self) -> None:
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self, text="🔎  DNS Sniffer",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, padx=28, pady=(24, 4), sticky="w")

        ctk.CTkLabel(
            self,
            text="Capture DNS queries flowing through the network (requires active MITM or monitor mode).",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).grid(row=1, column=0, padx=28, pady=(0, 12), sticky="w")

        # Controls
        ctrl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        ctrl.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 10))

        self._start_btn = ctk.CTkButton(
            ctrl, text="▶  Start Capture", width=150,
            fg_color=_CLR_ACCENT, hover_color="#c73652",
            font=_FONT_LABEL, command=self._toggle,
        )
        self._start_btn.grid(row=0, column=0, padx=(16, 8), pady=12)

        ctk.CTkButton(
            ctrl, text="🗑  Clear", width=90,
            fg_color=_CLR_PANEL, hover_color=_CLR_DANGER,
            font=_FONT_LABEL, command=self._clear,
        ).grid(row=0, column=1, padx=(0, 8), pady=12)

        ctk.CTkButton(
            ctrl, text="💾  Export CSV", width=120,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=_FONT_LABEL, command=self._export,
        ).grid(row=0, column=2, padx=(0, 16), pady=12)

        self._count_label = ctk.CTkLabel(
            ctrl, text="0 queries captured", font=_FONT_SMALL, text_color=_CLR_MUTED)
        self._count_label.grid(row=0, column=3, padx=16, pady=12, sticky="e")
        ctrl.grid_columnconfigure(3, weight=1)

        # DNS query table
        tbl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        tbl.grid(row=3, column=0, sticky="nsew", padx=24, pady=(0, 20))
        tbl.grid_rowconfigure(1, weight=1)
        tbl.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(tbl, fg_color=_CLR_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        for ci, col in enumerate(("Timestamp", "Source IP", "Domain", "Type")):
            ctk.CTkLabel(hdr, text=col, font=(_SF, 10, "bold"),
                         text_color=_CLR_ACCENT, anchor="w").grid(
                row=0, column=ci, padx=(14 if ci == 0 else 8, 4), pady=8, sticky="w")
        hdr.grid_columnconfigure(2, weight=1)

        self._tbl_body = ctk.CTkScrollableFrame(tbl, fg_color=_CLR_BG, corner_radius=0)
        self._tbl_body.grid(row=1, column=0, sticky="nsew")
        self._tbl_body.grid_columnconfigure(0, weight=1)

        self._row_count = 0
        self.grid_rowconfigure(3, weight=1)

    def _toggle(self) -> None:
        if self._running:
            self._stop()
        else:
            self._start()

    def _start(self) -> None:
        try:
            from wifi_killer.modules.dns_sniffer import DnsSniffer
        except ImportError:
            messagebox.showerror("Missing Module", "DNS Sniffer module not available.")
            return

        iface = self._app._iface or None
        self._sniffer = DnsSniffer(iface=iface)
        try:
            self._sniffer.start()
        except Exception as exc:
            messagebox.showerror("Sniffer Error", str(exc))
            return

        self._running = True
        self._start_btn.configure(text="⏹  Stop Capture", fg_color=_CLR_DANGER)
        self._app.log("DNS sniffer started.", "ok")
        self._schedule_refresh()

    def _stop(self) -> None:
        if self._sniffer:
            self._sniffer.stop()
        self._running = False
        self._start_btn.configure(text="▶  Start Capture", fg_color=_CLR_ACCENT)
        if self._refresh_id:
            self.after_cancel(self._refresh_id)
            self._refresh_id = None
        self._app.log("DNS sniffer stopped.", "warn")

    def _schedule_refresh(self) -> None:
        if not self._running:
            return
        self._refresh_table()
        self._refresh_id = self.after(2000, self._schedule_refresh)

    def _refresh_table(self) -> None:
        if not self._sniffer:
            return
        queries = self._sniffer.queries
        new_count = len(queries)
        if new_count <= self._row_count:
            self._count_label.configure(text=f"{new_count} queries captured")
            return

        for q in queries[self._row_count:]:
            idx = self._row_count
            bg = _CLR_ROW_ODD if idx % 2 == 0 else _CLR_ROW_EVEN
            row = ctk.CTkFrame(self._tbl_body, fg_color=bg, corner_radius=6)
            row.grid(row=idx, column=0, sticky="ew", padx=4, pady=1)
            row.grid_columnconfigure(2, weight=1)

            ts = q.get("timestamp", "")
            if "T" in ts:
                ts = ts.split("T")[1][:8]

            for ci, (val, w) in enumerate([
                (ts, 90),
                (q.get("src_ip", ""), 130),
                (q.get("domain", ""), 0),
                (q.get("query_type", ""), 60),
            ]):
                ctk.CTkLabel(
                    row, text=val, font=_FONT_MONO,
                    text_color=_CLR_SUCCESS if ci == 2 else _CLR_TEXT,
                    anchor="w", **({"width": w} if w else {}),
                ).grid(row=0, column=ci, padx=(14 if ci == 0 else 4, 4), pady=6, sticky="w")
            self._row_count += 1

        self._count_label.configure(text=f"{new_count} queries captured")

    def _clear(self) -> None:
        if self._sniffer:
            self._sniffer.clear()
        for w in self._tbl_body.winfo_children():
            w.destroy()
        self._row_count = 0
        self._count_label.configure(text="0 queries captured")

    def _export(self) -> None:
        if not self._sniffer or not self._sniffer.queries:
            messagebox.showinfo("Export", "No DNS queries to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv"), ("All files", "*.*")],
            title="Export DNS queries",
        )
        if not path:
            return
        try:
            self._sniffer.export_csv(path)
            self._app.log(f"DNS queries exported to {path}", "ok")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))


# ===========================================================================
# ARP Cache Frame
# ===========================================================================

class ArpCacheFrame(ctk.CTkFrame):
    """GUI panel for viewing the system ARP cache and detecting poisoning."""

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._auto_refresh_id = None
        self._build()
        self.after(500, self._refresh)

    def _build(self) -> None:
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self, text="📋  ARP Cache Viewer",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, padx=28, pady=(24, 4), sticky="w")

        ctk.CTkLabel(
            self,
            text="View the system ARP table and detect potential ARP cache poisoning.",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).grid(row=1, column=0, padx=28, pady=(0, 12), sticky="w")

        # Controls
        ctrl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        ctrl.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 10))

        ctk.CTkButton(
            ctrl, text="🔄  Refresh", width=110,
            fg_color=_CLR_ACCENT, hover_color="#c73652",
            font=_FONT_LABEL, command=self._refresh,
        ).grid(row=0, column=0, padx=(16, 8), pady=12)

        self._auto_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            ctrl, text="Auto-refresh (5s)", variable=self._auto_var,
            font=_FONT_LABEL, command=self._toggle_auto,
        ).grid(row=0, column=1, padx=(0, 16), pady=12)

        self._count_label = ctk.CTkLabel(
            ctrl, text="", font=_FONT_SMALL, text_color=_CLR_MUTED)
        self._count_label.grid(row=0, column=2, padx=16, pady=12, sticky="e")
        ctrl.grid_columnconfigure(2, weight=1)

        self._warn_label = ctk.CTkLabel(
            ctrl, text="", font=_FONT_LABEL, text_color=_CLR_DANGER)
        self._warn_label.grid(row=0, column=3, padx=(0, 16), pady=12)

        # ARP table
        tbl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        tbl.grid(row=3, column=0, sticky="nsew", padx=24, pady=(0, 20))
        tbl.grid_rowconfigure(1, weight=1)
        tbl.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(tbl, fg_color=_CLR_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        for ci, col in enumerate(("IP Address", "MAC Address", "State", "Interface")):
            ctk.CTkLabel(hdr, text=col, font=(_SF, 10, "bold"),
                         text_color=_CLR_ACCENT, anchor="w").grid(
                row=0, column=ci, padx=(14 if ci == 0 else 8, 4), pady=8, sticky="w")
        hdr.grid_columnconfigure(3, weight=1)

        self._tbl_body = ctk.CTkScrollableFrame(tbl, fg_color=_CLR_BG, corner_radius=0)
        self._tbl_body.grid(row=1, column=0, sticky="nsew")
        self._tbl_body.grid_columnconfigure(0, weight=1)

        self._toggle_auto()

    def _toggle_auto(self) -> None:
        if self._auto_refresh_id:
            self.after_cancel(self._auto_refresh_id)
            self._auto_refresh_id = None
        if self._auto_var.get():
            self._auto_loop()

    def _auto_loop(self) -> None:
        self._refresh()
        if self._auto_var.get():
            self._auto_refresh_id = self.after(5000, self._auto_loop)

    def _refresh(self) -> None:
        try:
            from wifi_killer.modules.arp_cache import read_arp_cache, detect_poisoning
        except ImportError:
            self._count_label.configure(text="ARP cache module not available")
            return

        entries = read_arp_cache()
        poisoned = detect_poisoning(entries)

        # Build set of IPs involved in poisoning
        poisoned_ips: set[str] = set()
        for p in poisoned:
            poisoned_ips.update(p.get("ips", []))

        # Clear and rebuild table
        for w in self._tbl_body.winfo_children():
            w.destroy()

        for i, entry in enumerate(entries):
            is_poisoned = entry.get("ip") in poisoned_ips
            bg = _CLR_DANGER if is_poisoned else (_CLR_ROW_ODD if i % 2 == 0 else _CLR_ROW_EVEN)
            row = ctk.CTkFrame(self._tbl_body, fg_color=bg, corner_radius=6)
            row.grid(row=i, column=0, sticky="ew", padx=4, pady=1)
            row.grid_columnconfigure(3, weight=1)

            for ci, (val, w) in enumerate([
                (entry.get("ip", ""), 140),
                (entry.get("mac", ""), 160),
                (entry.get("state", ""), 110),
                (entry.get("interface", ""), 0),
            ]):
                text_color = _CLR_TEXT
                if is_poisoned and ci == 1:
                    text_color = _CLR_WARNING
                elif ci == 0:
                    text_color = _CLR_SUCCESS

                ctk.CTkLabel(
                    row, text=val, font=_FONT_MONO,
                    text_color=text_color, anchor="w",
                    **({"width": w} if w else {}),
                ).grid(row=0, column=ci, padx=(14 if ci == 0 else 4, 4), pady=6, sticky="w")

        self._count_label.configure(text=f"{len(entries)} entries")

        if poisoned:
            macs = ", ".join(p.get("mac", "?") for p in poisoned)
            self._warn_label.configure(
                text=f"⚠  Possible ARP poisoning detected! Duplicate MACs: {macs}")
        else:
            self._warn_label.configure(text="")


# ===========================================================================
# MITM Inspector Frame
# ===========================================================================

class MITMInspectorFrame(ctk.CTkFrame):
    """Live view of DNS / SNI / HTTP traffic captured during an ARP attack.

    Reads from the ``MITMInspector`` instance owned by ``AttackFrame``.
    No state of its own — pure read-only visualisation. Auto-refreshes
    every second while the attack is active; quiet when idle.
    """

    _KINDS = (
        ("all",  "All"),
        ("dns",  "DNS"),
        ("sni",  "TLS SNI"),
        ("http", "HTTP"),
        ("cred", "Credentials"),
    )

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._kind_var = tk.StringVar(value="all")
        self._target_filter = tk.StringVar(value="all")
        self._refresh_job: Optional[str] = None
        self._build()

    # ------------------------------------------------------------------ #

    def _build(self) -> None:
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Page header
        header = _page_header(
            self,
            icon="🔭",
            title="MITM Inspector",
            subtitle="Real-time DNS, TLS SNI, and HTTP captures from "
                     "victims during an active ARP attack",
        )
        header.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 12))

        self._badge = ctk.CTkLabel(
            header.right_slot, text="Idle",
            font=(_SF, 10, "bold"), text_color=_CLR_MUTED,
        )
        self._badge.pack(side="right", padx=(0, 2))

        # Stat cards row
        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", padx=22, pady=(0, 12))
        for i in range(5):
            cards.grid_columnconfigure(i, weight=1, uniform="mitm_cards")

        self._card_targets = _stat_card(
            cards, "🎯", "Targets", "0", 0, _CLR_DANGER,
        )
        self._card_dns = _stat_card(
            cards, "🔍", "DNS Queries", "0", 1, _CLR_SUCCESS,
        )
        self._card_sni = _stat_card(
            cards, "🔒", "TLS SNI", "0", 2, _CLR_ACCENT2,
        )
        self._card_http = _stat_card(
            cards, "🌐", "HTTP Requests", "0", 3, _CLR_WARNING,
        )
        self._card_cred = _stat_card(
            cards, "🔑", "Credentials", "0", 4, _CLR_DANGER,
        )

        # Filter row
        ctrl = ctk.CTkFrame(
            self, fg_color=_CLR_PANEL, corner_radius=14,
            border_width=1, border_color=_CLR_BORDER,
        )
        ctrl.grid(row=2, column=0, sticky="ew", padx=28, pady=(0, 10))
        ctrl.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(
            ctrl, text="EVENT TYPE",
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED,
        ).grid(row=0, column=0, padx=(18, 10), pady=12)
        self._kind_combo = ctk.CTkComboBox(
            ctrl, variable=self._kind_var,
            values=[label for _k, label in self._KINDS],
            width=120, height=32, font=_FONT_LABEL,
            fg_color=_CLR_SIDEBAR, border_color=_CLR_BORDER, border_width=1,
            button_color=_CLR_SIDEBAR, button_hover_color=_CLR_HOVER,
            dropdown_fg_color=_CLR_PANEL, dropdown_hover_color=_CLR_HOVER,
        )
        self._kind_combo.set("All")
        self._kind_combo.grid(row=0, column=1, padx=(0, 14), pady=12)

        ctk.CTkLabel(
            ctrl, text="TARGET",
            font=(_SF, 9, "bold"), text_color=_CLR_MUTED,
        ).grid(row=0, column=2, padx=(0, 10), pady=12)
        self._target_combo = ctk.CTkComboBox(
            ctrl, variable=self._target_filter,
            values=["all"],
            width=160, height=32, font=_FONT_LABEL,
            fg_color=_CLR_SIDEBAR, border_color=_CLR_BORDER, border_width=1,
            button_color=_CLR_SIDEBAR, button_hover_color=_CLR_HOVER,
            dropdown_fg_color=_CLR_PANEL, dropdown_hover_color=_CLR_HOVER,
        )
        self._target_combo.set("all")
        self._target_combo.grid(row=0, column=3, padx=(0, 14), pady=12,
                                sticky="w")

        _ghost_button(
            ctrl, text="🔄   Refresh", width=110, height=30,
            command=self._do_refresh, font=_FONT_SMALL,
        ).grid(row=0, column=4, padx=(0, 18), pady=12, sticky="e")

        # Events table card
        table_card = ctk.CTkFrame(
            self, fg_color=_CLR_PANEL, corner_radius=14,
            border_width=1, border_color=_CLR_BORDER,
        )
        table_card.grid(row=3, column=0, sticky="nsew",
                        padx=28, pady=(0, 22))
        table_card.grid_rowconfigure(1, weight=1)
        table_card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(table_card, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 0))
        for ci, (text, w) in enumerate([
            ("TIME",   90),  ("KIND",   80),
            ("TARGET", 140), ("VALUE",  0),
        ]):
            ctk.CTkLabel(
                hdr, text=text,
                font=(_SF, 9, "bold"), text_color=_CLR_MUTED,
                anchor="w",
                **({"width": w} if w else {}),
            ).grid(row=0, column=ci, padx=(8 if ci else 12, 4), pady=8, sticky="w")
        hdr.grid_columnconfigure(3, weight=1)

        ctk.CTkFrame(table_card, height=1, fg_color=_CLR_BORDER).grid(
            row=0, column=0, sticky="sew", padx=10,
        )

        self._table_body = ctk.CTkScrollableFrame(
            table_card, fg_color="transparent", corner_radius=0,
        )
        self._table_body.grid(row=1, column=0, sticky="nsew",
                              padx=4, pady=(4, 8))
        self._table_body.grid_columnconfigure(0, weight=1)

    # ------------------------------------------------------------------ #

    def _on_show(self) -> None:
        self._do_refresh()
        # Start the polling timer if not already running.
        if self._refresh_job is None:
            self._refresh_job = self.after(1000, self._tick)

    def _tick(self) -> None:
        self._do_refresh()
        self._refresh_job = self.after(1000, self._tick)

    def _kind_value(self) -> Optional[str]:
        label = self._kind_var.get()
        for key, lbl in self._KINDS:
            if lbl == label:
                return None if key == "all" else key
        return None

    def _do_refresh(self) -> None:
        af = self._app._frames.get("attack")
        inspector = getattr(af, "_mitm_inspector", None) if af else None

        if inspector is None:
            self._badge.configure(
                text="Idle — start an ARP attack with Inspector enabled",
                text_color=_CLR_MUTED,
            )
            self._card_targets.configure(text="0", text_color=_CLR_MUTED)
            self._card_dns.configure(text="0", text_color=_CLR_MUTED)
            self._card_sni.configure(text="0", text_color=_CLR_MUTED)
            self._card_http.configure(text="0", text_color=_CLR_MUTED)
            self._card_cred.configure(text="0", text_color=_CLR_MUTED)
            for w in self._table_body.winfo_children():
                w.destroy()
            ctk.CTkLabel(
                self._table_body,
                text="No active capture.\n\nLaunch an ARP attack with "
                     "the MITM Inspector toggle enabled — events will "
                     "appear here in real time.",
                font=_FONT_LABEL, text_color=_CLR_MUTED, justify="center",
            ).pack(padx=20, pady=30)
            return

        snap = inspector.snapshot()
        per = snap["per_target"]
        total_dns = sum(s.get("dns", 0) for s in per.values())
        total_sni = sum(s.get("sni", 0) for s in per.values())
        total_http = sum(s.get("http", 0) for s in per.values())
        total_cred = sum(s.get("cred", 0) for s in per.values())

        up = int(snap["uptime"])
        self._badge.configure(
            text=f"● LIVE  ·  {up}s uptime",
            text_color=_CLR_SUCCESS,
        )
        self._card_targets.configure(text=str(len(per)),
                                     text_color=_CLR_DANGER)
        self._card_dns.configure(text=f"{total_dns:,}",
                                 text_color=_CLR_SUCCESS)
        self._card_sni.configure(text=f"{total_sni:,}",
                                 text_color=_CLR_ACCENT2)
        self._card_http.configure(text=f"{total_http:,}",
                                  text_color=_CLR_WARNING)
        self._card_cred.configure(
            text=f"{total_cred:,}",
            text_color=_CLR_DANGER if total_cred else _CLR_MUTED,
        )

        # Sync target filter dropdown with discovered targets.
        ips = sorted(per.keys(), key=_ip_sort_key)
        current_values = ["all", *ips]
        if list(self._target_combo.cget("values")) != current_values:
            self._target_combo.configure(values=current_values)

        # Render most-recent events with current filters.
        kind = self._kind_value()
        events = inspector.recent_events(kind=kind, limit=200)
        chosen_target = self._target_filter.get().strip()
        if chosen_target and chosen_target != "all":
            events = [e for e in events if e["target"] == chosen_target]

        for w in self._table_body.winfo_children():
            w.destroy()

        if not events:
            ctk.CTkLabel(
                self._table_body,
                text="Waiting for traffic from victims…",
                font=_FONT_LABEL, text_color=_CLR_MUTED,
            ).pack(padx=20, pady=20)
            return

        for i, ev in enumerate(events):
            bg = _CLR_ROW_ODD if i % 2 == 0 else _CLR_ROW_EVEN
            row = ctk.CTkFrame(self._table_body, fg_color=bg, corner_radius=6)
            row.pack(fill="x", padx=4, pady=1)
            row.grid_columnconfigure(3, weight=1)

            ts = time.strftime("%H:%M:%S", time.localtime(ev["ts"]))
            ctk.CTkLabel(row, text=ts, font=_FONT_MONO,
                         text_color=_CLR_MUTED, width=90, anchor="w").grid(
                row=0, column=0, padx=(14, 4), pady=6, sticky="w")

            kind_label = ev["kind"].upper()
            kind_color = {
                "DNS":  _CLR_SUCCESS,
                "SNI":  _CLR_ACCENT2,
                "HTTP": _CLR_WARNING,
                "CRED": _CLR_DANGER,
            }.get(kind_label, _CLR_TEXT)
            ctk.CTkLabel(row, text=kind_label, font=(_SF, 10, "bold"),
                         text_color=kind_color, width=80, anchor="w").grid(
                row=0, column=1, padx=(0, 4), pady=6, sticky="w")

            ctk.CTkLabel(row, text=ev["target"], font=_FONT_MONO,
                         text_color=_CLR_TEXT, width=140, anchor="w").grid(
                row=0, column=2, padx=(0, 4), pady=6, sticky="w")

            ctk.CTkLabel(row, text=ev["value"][:120],
                         font=_FONT_LABEL, text_color=_CLR_TEXT,
                         anchor="w", justify="left").grid(
                row=0, column=3, padx=(0, 14), pady=6, sticky="ew")


# ===========================================================================
# About Frame
# ===========================================================================

class AboutFrame(ctk.CTkFrame):
    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._build()

    def _build(self) -> None:
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            inner, text="📡  Wifi-Killer",
            font=(_SF, 36, "bold"), text_color=_CLR_ACCENT,
        ).pack(pady=(0, 4))

        ctk.CTkLabel(
            inner, text=f"v{_VERSION}  ·  Modern Network Lab Tool",
            font=(_SF, 14), text_color=_CLR_MUTED,
        ).pack(pady=(0, 24))

        features = [
            "📊  Live dashboard with stat cards, recent-device feed and scan history",
            "🔍  Multi-mode host discovery (ARP · ICMP · TCP SYN with custom ports)",
            "🔎  Real-time search/filter across the host table",
            "☑️   Select All / Deselect All with one-click bulk actions",
            "📋  Copy All IPs to clipboard",
            "ℹ️   Host detail popup with live RTT ping and action shortcuts",
            "🌐  Multi-subnet scan – auto-detect & scan different network segments",
            "🔎  DNS Sniffer – capture DNS queries during MITM sessions",
            "📋  ARP Cache Viewer – view system ARP table, detect poisoning",
            "📦  Packet Capture – save traffic to pcap for Wireshark analysis",
            "📝  Session Logger – audit trail of all actions in JSON-lines format",
            "🖥️   CLI: --version, --scan-only, report export, signal handling",
            "📡  Continuous network monitor with join/leave alerts",
            "⚡  ARP-spoofing: Full MITM · Client-cut · Gateway-cut",
            "🚦  Client speed control – per-IP download/upload throttle sliders",
            "🏓  Ping monitor – live RTT table for multiple hosts",
            "🎭  MAC address anonymization (random / OUI-preserve / custom)",
            "🔆  Wake-on-LAN – send standard & SecureOn magic packets",
            "🧠  OS fingerprinting from TTL (Linux / Windows / Cisco)",
            "🏷️   Expanded device-type detection (Sonos, printers, game consoles, smart TV …)",
            "⚙️   Configurable attack speed with presets (aggressive / normal / stealth / paranoid)",
            "🌙  Dark / Light / System theme toggle",
            "💾  Export scan results to CSV or JSON",
            "📄  Export activity log to text file",
            "📋  Colour-coded activity log with Clear button",
            "🖥️   Modern dark-themed GUI (CustomTkinter)",
        ]

        for feat in features:
            ctk.CTkLabel(
                inner, text=feat, font=_FONT_LABEL, text_color=_CLR_TEXT,
            ).pack(anchor="w", pady=3)

        ctk.CTkFrame(inner, height=1, fg_color=_CLR_PANEL).pack(fill="x", pady=20)

        ctk.CTkLabel(
            inner,
            text="⚠  For educational and authorised lab use only.\n"
                 "   Always obtain explicit permission before scanning or attacking any network.",
            font=_FONT_LABEL, text_color=_CLR_WARNING, justify="left",
        ).pack(anchor="w")

        ctk.CTkLabel(
            inner, text="github.com/at0m-b0mb/Wifi-Killer",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).pack(pady=(16, 0))


# ===========================================================================
# Entry point
# ===========================================================================

def run_gui() -> None:
    if not CTK_AVAILABLE:
        print("[!] customtkinter is not installed.")
        print("    Install it with: pip install customtkinter>=5.2.0")
        sys.exit(1)

    if os.name != "nt" and os.geteuid() != 0:
        print("[!] This tool requires root privileges for network operations.")
        print("    Please run: sudo python3 gui.py")
        sys.exit(1)

    app = WifiKillerApp()
    app.mainloop()


if __name__ == "__main__":
    run_gui()
