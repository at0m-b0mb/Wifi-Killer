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

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
_VERSION = "4.0.0"

# Colours / theme constants
# ---------------------------------------------------------------------------
_CLR_BG       = "#1a1a2e"
_CLR_SIDEBAR  = "#16213e"
_CLR_PANEL    = "#0f3460"
_CLR_ACCENT   = "#e94560"
_CLR_ACCENT2  = "#533483"
_CLR_TEXT     = "#eaeaea"
_CLR_MUTED    = "#8892b0"
_CLR_SUCCESS  = "#64ffda"
_CLR_WARNING  = "#ffb347"
_CLR_DANGER   = "#ff6b6b"
_CLR_ROW_ODD  = "#1e1e3a"
_CLR_ROW_EVEN = "#252545"

_FONT_TITLE   = ("Segoe UI", 22, "bold")
_FONT_HEAD    = ("Segoe UI", 14, "bold")
_FONT_LABEL   = ("Segoe UI", 11)
_FONT_MONO    = ("Courier New", 10)
_FONT_SMALL   = ("Segoe UI", 9)


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
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4
        self._tip = tk.Toplevel(self._widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        tk.Label(
            self._tip, text=self._text,
            bg="#1c2333", fg="#eaeaea",
            font=("Segoe UI", 9), padx=8, pady=4,
            relief="flat", bd=1,
        ).pack()


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
        self._topbar.set_own_ip(self._get_own_ip())
        self.log(f"Interface changed to {iface}  |  Gateway: {self._gateway or '(unknown)'}")

    @staticmethod
    def _get_own_ip() -> str:
        """Best-effort detection of the local IP used for outbound traffic."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "?"

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

    def record_scan(self, host_count: int) -> None:
        """Record a completed scan in the history (kept to last 5)."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self._scan_history.append((ts, host_count))
        self._scan_history = self._scan_history[-5:]  # keep last 5

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
    _NAV = [
        ("dashboard",    "📊  Dashboard"),
        ("scan",         "🔍  Scan Network"),
        ("network_map",  "🗺️   Network Map"),
        ("multi_subnet", "🌐  Multi-Subnet"),
        ("dns_sniffer",  "🔎  DNS Sniffer"),
        ("arp_cache",    "🗂️   ARP Cache"),
        ("throttle",     "🚦  Speed Control"),
        ("ping_monitor", "🏓  Ping Monitor"),
        ("attack",       "⚡  ARP Attack"),
        ("anonymize",    "🎭  MAC Anonymize"),
        ("wol",          "🔆  Wake-on-LAN"),
        ("settings",     "⚙️   Settings"),
        ("about",        "ℹ️   About"),
    ]

    def __init__(self, parent: ctk.CTk, on_select) -> None:
        super().__init__(parent, fg_color=_CLR_SIDEBAR, corner_radius=0, width=210)
        self._on_select = on_select
        self._buttons: dict[str, ctk.CTkButton] = {}
        self._active: str = ""
        self._build()

    def _build(self) -> None:
        self.grid_propagate(False)

        logo = ctk.CTkLabel(
            self,
            text="📡 Wifi-Killer",
            font=("Segoe UI", 17, "bold"),
            text_color=_CLR_ACCENT,
        )
        logo.pack(pady=(28, 6), padx=16, anchor="w")

        sub = ctk.CTkLabel(
            self,
            text="Network Lab Tool",
            font=_FONT_SMALL,
            text_color=_CLR_MUTED,
        )
        sub.pack(pady=(0, 20), padx=16, anchor="w")

        sep = ctk.CTkFrame(self, height=1, fg_color=_CLR_PANEL)
        sep.pack(fill="x", padx=12, pady=(0, 16))

        for key, label in self._NAV:
            btn = ctk.CTkButton(
                self,
                text=label,
                anchor="w",
                fg_color="transparent",
                hover_color=_CLR_PANEL,
                text_color=_CLR_TEXT,
                font=_FONT_LABEL,
                corner_radius=8,
                height=42,
                command=lambda k=key: self._on_select(k),
            )
            btn.pack(fill="x", padx=10, pady=2)
            self._buttons[key] = btn

        # Version label at bottom
        ver = ctk.CTkLabel(
            self,
            text=f"v{_VERSION}  |  For authorised use only",
            font=_FONT_SMALL,
            text_color=_CLR_MUTED,
        )
        ver.pack(side="bottom", pady=14)

    def set_active(self, key: str) -> None:
        for k, btn in self._buttons.items():
            if k == key:
                btn.configure(fg_color=_CLR_PANEL, text_color=_CLR_ACCENT)
            else:
                btn.configure(fg_color="transparent", text_color=_CLR_TEXT)
        self._active = key


# ===========================================================================
# Top bar
# ===========================================================================

class _TopBar(ctk.CTkFrame):
    def __init__(self, parent, on_iface_change) -> None:
        super().__init__(parent, fg_color=_CLR_SIDEBAR, corner_radius=0, height=52)
        self._on_iface_change = on_iface_change
        self._iface_var = tk.StringVar()
        self._build()

    def _build(self) -> None:
        self.pack_propagate(False)
        self.grid_columnconfigure(5, weight=1)

        ctk.CTkLabel(self, text="Interface:", font=_FONT_LABEL, text_color=_CLR_MUTED).grid(
            row=0, column=0, padx=(16, 4), pady=12)

        self._combo = ctk.CTkComboBox(
            self,
            variable=self._iface_var,
            values=[],
            width=160,
            command=self._on_iface_change,
            font=_FONT_LABEL,
        )
        self._combo.grid(row=0, column=1, padx=(0, 16), pady=12)
        _ToolTip(self._combo, "Select the network interface to use for all operations")

        ctk.CTkLabel(self, text="Gateway:", font=_FONT_LABEL, text_color=_CLR_MUTED).grid(
            row=0, column=2, padx=(0, 4), pady=12)

        self._gw_label = ctk.CTkLabel(
            self, text="—", font=_FONT_LABEL, text_color=_CLR_SUCCESS)
        self._gw_label.grid(row=0, column=3, padx=(0, 24), pady=12, sticky="w")

        ctk.CTkLabel(self, text="My IP:", font=_FONT_LABEL, text_color=_CLR_MUTED).grid(
            row=0, column=4, padx=(0, 4), pady=12)

        self._ip_label = ctk.CTkLabel(
            self, text="—", font=_FONT_LABEL, text_color=_CLR_WARNING)
        self._ip_label.grid(row=0, column=5, padx=(0, 16), pady=12, sticky="w")

        # Keyboard shortcut hint on right
        hint = ctk.CTkLabel(
            self,
            text="F5=Scan  Ctrl+A=Select All  Esc=Stop  Ctrl+Q=Quit  Ctrl+E=Export",
            font=("Segoe UI", 8), text_color=_CLR_MUTED,
        )
        hint.grid(row=0, column=6, padx=(0, 16), pady=12, sticky="e")

    def populate_interfaces(self, ifaces: list[str], selected: str) -> None:
        self._combo.configure(values=ifaces)
        if selected:
            self._iface_var.set(selected)

    def set_gateway(self, gw: str) -> None:
        self._gw_label.configure(text=gw or "unknown")

    def set_own_ip(self, ip: str) -> None:
        self._ip_label.configure(text=ip or "—")


# ===========================================================================
# Scan Frame
# ===========================================================================

class ScanFrame(ctk.CTkFrame):
    """Host discovery panel."""

    _COLS = ("IP Address", "MAC Address", "Vendor", "Hostname", "Type", "Open Ports", "Ping")

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
        self._scanning = False
        self._monitor_running = False
        self._monitor_obj = None
        self._build()

    def _build(self) -> None:
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ── Top controls ──────────────────────────────────────────────
        ctrl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        ctrl.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        ctrl.grid_columnconfigure(6, weight=1)

        ctk.CTkLabel(ctrl, text="Scan type:", font=_FONT_LABEL, text_color=_CLR_MUTED).grid(
            row=0, column=0, padx=(16, 4), pady=12)

        self._scan_type = ctk.CTkComboBox(
            ctrl,
            values=["Fast (ARP)", "Balanced (ARP+ICMP)", "Stealth (TCP SYN)"],
            width=190,
            font=_FONT_LABEL,
            command=self._on_scan_type_changed,
        )
        self._scan_type.set("Fast (ARP)")
        self._scan_type.grid(row=0, column=1, padx=(0, 12), pady=12)
        _ToolTip(self._scan_type,
                 "Fast=ARP only  |  Balanced=ARP+ICMP  |  Stealth=TCP SYN (slow, needs root)")

        self._scan_btn = ctk.CTkButton(
            ctrl, text="▶  Start Scan", fg_color=_CLR_ACCENT,
            hover_color="#c73652", font=_FONT_LABEL, width=130,
            command=self._start_scan,
        )
        self._scan_btn.grid(row=0, column=2, padx=(0, 8), pady=12)
        _ToolTip(self._scan_btn, "Start scanning the local network for devices  (F5)")

        self._monitor_btn = ctk.CTkButton(
            ctrl, text="📡  Monitor", fg_color=_CLR_ACCENT2,
            hover_color="#6b44a8", font=_FONT_LABEL, width=120,
            command=self._toggle_monitor,
        )
        self._monitor_btn.grid(row=0, column=3, padx=(0, 8), pady=12)
        _ToolTip(self._monitor_btn, "Continuously monitor for devices joining or leaving the network")

        self._export_btn = ctk.CTkButton(
            ctrl, text="💾  Export", fg_color=_CLR_PANEL,
            hover_color="#1a4a80", font=_FONT_LABEL, width=110,
            command=self._export_results,
        )
        self._export_btn.grid(row=0, column=4, padx=(0, 8), pady=12)
        _ToolTip(self._export_btn, "Save scan results to CSV or JSON  (Ctrl+E)")

        self._import_btn = ctk.CTkButton(
            ctrl, text="📂  Import", fg_color=_CLR_PANEL,
            hover_color="#1a4a80", font=_FONT_LABEL, width=110,
            command=self._import_hosts,
        )
        self._import_btn.grid(row=0, column=5, padx=(0, 8), pady=12)
        _ToolTip(self._import_btn, "Load hosts from a CSV, JSON, or plain-text file (one IP per line)")

        self._attack_sel_btn = ctk.CTkButton(
            ctrl, text="⚡  Attack Selected", fg_color="#7b3f00",
            hover_color="#a05000", font=_FONT_LABEL, width=150,
            command=self._go_attack_selected,
        )
        self._attack_sel_btn.grid(row=0, column=6, padx=(0, 16), pady=12)
        _ToolTip(self._attack_sel_btn, "Send selected hosts to the ARP Attack frame")

        # host count label
        self._count_label = ctk.CTkLabel(
            ctrl, text="No hosts yet", font=_FONT_SMALL, text_color=_CLR_MUTED)
        self._count_label.grid(row=0, column=7, padx=8, sticky="e")

        # ── Second row: select-all / copy-IPs + optional stealth ports ──
        row2 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row2.grid(row=1, column=0, columnspan=7, sticky="ew", padx=12, pady=(0, 8))

        ctk.CTkButton(
            row2, text="☑  Select All", width=110, height=28,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=_FONT_SMALL, command=self._select_all,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            row2, text="☐  Deselect All", width=120, height=28,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=_FONT_SMALL, command=self._deselect_all,
        ).pack(side="left", padx=(0, 16))

        ctk.CTkButton(
            row2, text="📋  Copy All IPs", width=120, height=28,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=_FONT_SMALL, command=self._copy_all_ips,
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
        flt.grid(row=2, column=0, columnspan=7, sticky="ew", padx=12, pady=(0, 8))
        flt.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(flt, text="🔎  Filter:", font=_FONT_LABEL,
                     text_color=_CLR_MUTED).grid(row=0, column=0, padx=(0, 6))
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())
        self._filter_entry = ctk.CTkEntry(
            flt, textvariable=self._filter_var,
            placeholder_text="Type IP, vendor, hostname, or device type…",
            font=_FONT_LABEL, height=30,
        )
        self._filter_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ctk.CTkButton(
            flt, text="✕", width=30, height=30,
            fg_color=_CLR_PANEL, hover_color=_CLR_DANGER,
            font=_FONT_LABEL,
            command=lambda: self._filter_var.set(""),
        ).grid(row=0, column=2)

        # ── Host table ────────────────────────────────────────────────
        tbl_frame = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        tbl_frame.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 8))
        tbl_frame.grid_rowconfigure(1, weight=1)
        tbl_frame.grid_columnconfigure(0, weight=1)

        # Header row
        hdr = ctk.CTkFrame(tbl_frame, fg_color=_CLR_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        for ci, col in enumerate(self._COLS):
            ctk.CTkLabel(
                hdr, text=col, font=("Segoe UI", 10, "bold"),
                text_color=_CLR_ACCENT, anchor="w",
            ).grid(row=0, column=ci, padx=(12 if ci == 0 else 4, 4), pady=8, sticky="w")
        hdr.grid_columnconfigure(len(self._COLS) - 1, weight=1)

        # Scrollable body
        self._table_body = ctk.CTkScrollableFrame(
            tbl_frame, fg_color=_CLR_BG, corner_radius=0)
        self._table_body.grid(row=1, column=0, sticky="nsew")
        self._table_body.grid_columnconfigure(0, weight=1)

        self._row_frames: list[_HostRow] = []

        # ── Log console ───────────────────────────────────────────────
        log_frame = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        log_frame.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 18))
        log_frame.grid_columnconfigure(0, weight=1)

        log_hdr = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_hdr.grid(row=0, column=0, sticky="ew", padx=12, pady=(8, 2))
        log_hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(log_hdr, text="Activity Log", font=("Segoe UI", 10, "bold"),
                     text_color=_CLR_ACCENT).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            log_hdr, text="💾 Export Log", width=100, height=24,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=_FONT_SMALL, command=self._export_log,
        ).grid(row=0, column=1, padx=(0, 6))

        ctk.CTkButton(
            log_hdr, text="🗑 Clear", width=70, height=24,
            fg_color="#4a1010", hover_color=_CLR_DANGER,
            font=_FONT_SMALL, command=self._clear_log,
        ).grid(row=0, column=2)

        self._log_text = ctk.CTkTextbox(
            log_frame, height=130, font=_FONT_MONO,
            fg_color="#0d0d1a", text_color=_CLR_SUCCESS,
            scrollbar_button_color=_CLR_PANEL,
        )
        self._log_text.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))
        self._log_text.configure(state="disabled")

        # Progress bar (hidden by default)
        self._progress = ctk.CTkProgressBar(self, mode="indeterminate",
                                             fg_color=_CLR_SIDEBAR,
                                             progress_color=_CLR_ACCENT)

    # ── Scan ──────────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        if self._scanning:
            return
        if not self._app._iface:
            messagebox.showerror("No Interface", "Please select a network interface first.")
            return
        self._scanning = True
        self._scan_btn.configure(state="disabled", text="Scanning…")
        self._progress.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 4))
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

            self._app._hosts = enriched
            self._app.record_scan(len(enriched))
            self.after(0, lambda: self._populate_table(enriched))
            self.after(0, lambda: self._app.log(
                f"Scan complete – {len(enriched)} host(s) found.", "ok"))
            self.after(0, self._app.refresh_dashboard)

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
            self._app._hosts.append(info)
            self.after(0, lambda i=info: self._add_row(i, len(self._row_frames)))
            self.after(0, lambda: self._app.log(
                f"New device: {h['ip']} ({info.get('vendor','?')})", "ok"))

        def on_left(h: dict) -> None:
            self.after(0, lambda: self._app.log(
                f"Device left: {h['ip']}", "warn"))

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
    _WIDTHS = (130, 150, 160, 150, 140, 130, 50)

    def __init__(self, parent, info: dict, idx: int, app: WifiKillerApp) -> None:
        bg = _CLR_ROW_ODD if idx % 2 == 0 else _CLR_ROW_EVEN
        super().__init__(parent, fg_color=bg, corner_radius=6)
        self.info = info
        self._app = app
        self.selected = tk.BooleanVar(value=False)
        self._build()

    def _build(self) -> None:
        self.grid_columnconfigure(8, weight=1)

        chk = ctk.CTkCheckBox(
            self, text="", variable=self.selected,
            width=24, checkbox_width=18, checkbox_height=18,
        )
        chk.grid(row=0, column=0, padx=(8, 2), pady=6)

        vals = [
            self.info.get("ip", ""),
            self.info.get("mac", ""),
            self.info.get("vendor", "Unknown"),
            self.info.get("hostname") or "—",
            self.info.get("type", "Unknown"),
            _fmt_ports(self.info.get("open_ports", [])),
            "✓" if self.info.get("ping") else "—",
        ]
        for ci, (val, w) in enumerate(zip(vals, self._WIDTHS)):
            lbl = ctk.CTkLabel(
                self, text=val, font=_FONT_LABEL,
                text_color=_CLR_SUCCESS if ci == 0 else _CLR_TEXT,
                anchor="w", width=w,
            )
            lbl.grid(row=0, column=ci + 1, padx=4, pady=6, sticky="w")
            lbl.bind("<Button-3>", self._show_context_menu)

        # Action buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=0, column=9, padx=(4, 8), pady=4, sticky="e")

        info_btn = ctk.CTkButton(
            btn_frame, text="ℹ️", width=32, height=28,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=("Segoe UI", 11), command=self._show_detail,
        )
        info_btn.pack(side="left", padx=2)
        _ToolTip(info_btn, "View full details for this host")

        copy_btn = ctk.CTkButton(
            btn_frame, text="📋", width=32, height=28,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=("Segoe UI", 11), command=self._copy_info,
        )
        copy_btn.pack(side="left", padx=2)
        _ToolTip(copy_btn, "Copy host info to clipboard")

        atk_btn = ctk.CTkButton(
            btn_frame, text="⚡", width=32, height=28,
            fg_color="#7b3f00", hover_color=_CLR_WARNING,
            font=("Segoe UI", 11), command=self._quick_attack,
        )
        atk_btn.pack(side="left", padx=2)
        _ToolTip(atk_btn, "Launch ARP attack on this host")

        # Right-click on the row itself
        self.bind("<Button-3>", self._show_context_menu)

    # ── Context menu ─────────────────────────────────────────────────

    def _show_context_menu(self, event: tk.Event) -> None:
        ip  = self.info.get("ip", "")
        mac = self.info.get("mac", "")
        menu = tk.Menu(
            self, tearoff=0,
            bg=_CLR_PANEL, fg=_CLR_TEXT,
            activebackground=_CLR_ACCENT, activeforeground="white",
            font=("Segoe UI", 10),
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

        # Title bar
        ctk.CTkLabel(
            self, text=f"📡  {info.get('ip','?')}",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).pack(padx=24, pady=(20, 4), anchor="w")

        ctk.CTkLabel(
            self, text=info.get("vendor", "Unknown Vendor"),
            font=_FONT_HEAD, text_color=_CLR_TEXT,
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
            ("Device Type", info.get("type", "Unknown")),
            ("Open Ports",  _fmt_ports(info.get("open_ports", []))),
            ("Ping",        "✓ Alive" if info.get("ping") else "—"),
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
        self._targets: list[dict] = []
        self._build()

    def set_targets(self, targets: list[dict]) -> None:
        self._targets = targets
        names = ", ".join(t["ip"] for t in targets[:5])
        if len(targets) > 5:
            names += f" + {len(targets)-5} more"
        self._target_label.configure(text=names or "None selected")

    def _build(self) -> None:
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Title
        ctk.CTkLabel(
            self, text="⚡  ARP Attack / Control",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, padx=28, pady=(24, 4), sticky="w")

        ctk.CTkLabel(
            self,
            text="ARP-spoofing attacks for authorised network testing only.",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).grid(row=1, column=0, padx=28, pady=(0, 16), sticky="w")

        # Config panel
        panel = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        panel.grid(row=2, column=0, padx=28, pady=0, sticky="ew")
        panel.grid_columnconfigure(1, weight=1)

        # Targets row
        ctk.CTkLabel(panel, text="Targets:", font=_FONT_LABEL,
                     text_color=_CLR_MUTED).grid(row=0, column=0, padx=16, pady=(16, 8), sticky="w")
        self._target_label = ctk.CTkLabel(
            panel, text="None – go to Scan tab and select hosts",
            font=_FONT_LABEL, text_color=_CLR_WARNING)
        self._target_label.grid(row=0, column=1, padx=8, pady=(16, 8), sticky="w")

        ctk.CTkButton(
            panel, text="Use All Scanned Hosts", width=180,
            fg_color=_CLR_PANEL, hover_color=_CLR_ACCENT2,
            font=_FONT_LABEL, command=self._use_all_hosts,
        ).grid(row=0, column=2, padx=16, pady=(16, 8))

        # Method
        ctk.CTkLabel(panel, text="Method:", font=_FONT_LABEL,
                     text_color=_CLR_MUTED).grid(row=1, column=0, padx=16, pady=8, sticky="w")
        self._method = ctk.CTkComboBox(
            panel, width=280, font=_FONT_LABEL,
            values=[
                "A – Full MITM (bi-directional)",
                "B – Cut Client Only",
                "C – Cut Gateway Only",
            ],
        )
        self._method.set("A – Full MITM (bi-directional)")
        self._method.grid(row=1, column=1, padx=8, pady=8, sticky="w")

        # Gateway override
        ctk.CTkLabel(panel, text="Gateway IP:", font=_FONT_LABEL,
                     text_color=_CLR_MUTED).grid(row=2, column=0, padx=16, pady=8, sticky="w")
        self._gw_entry = ctk.CTkEntry(panel, width=180, font=_FONT_LABEL,
                                      placeholder_text="auto-detected")
        self._gw_entry.grid(row=2, column=1, padx=8, pady=8, sticky="w")

        # Buttons
        btn_row = ctk.CTkFrame(panel, fg_color="transparent")
        btn_row.grid(row=3, column=0, columnspan=3, padx=16, pady=(12, 16), sticky="w")

        self._start_btn = ctk.CTkButton(
            btn_row, text="⚡  Launch Attack",
            fg_color=_CLR_ACCENT, hover_color="#c73652",
            font=_FONT_LABEL, width=150, command=self._start_attack,
        )
        self._start_btn.pack(side="left", padx=(0, 12))

        self._stop_btn = ctk.CTkButton(
            btn_row, text="⏹  Stop & Restore",
            fg_color=_CLR_PANEL, hover_color="#c73652",
            font=_FONT_LABEL, width=150, state="disabled",
            command=self._stop_attack,
        )
        self._stop_btn.pack(side="left")

        # Status
        self._status_label = ctk.CTkLabel(
            self, text="Idle", font=_FONT_LABEL, text_color=_CLR_MUTED)
        self._status_label.grid(row=3, column=0, padx=28, pady=(20, 0), sticky="w")

        # Packet counter
        self._pkt_label = ctk.CTkLabel(
            self, text="", font=_FONT_MONO, text_color=_CLR_SUCCESS)
        self._pkt_label.grid(row=4, column=0, padx=28, pady=(4, 0), sticky="w")

        self._timer_id = None

    def _use_all_hosts(self) -> None:
        self.set_targets(self._app._hosts)

    def _start_attack(self) -> None:
        if self._running:
            return
        if not self._targets:
            messagebox.showwarning("No Targets", "Select targets in the Scan tab first.")
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
        target_ips = ", ".join(t["ip"] for t in self._targets[:5])
        if len(self._targets) > 5:
            target_ips += f" + {len(self._targets) - 5} more"

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

        try:
            from wifi_killer.modules.attacker import ArpAttack, MultiTargetAttack

            if len(self._targets) == 1:
                self._attack_obj = ArpAttack(
                    method_str, self._targets[0]["ip"], gw, self._app._iface)
            else:
                self._attack_obj = MultiTargetAttack(
                    method_str, self._targets, gw, self._app._iface)

            self._attack_obj.start()
        except Exception as exc:
            messagebox.showerror("Attack Error", str(exc))
            return

        self._running = True
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_label.configure(
            text=f"🔴  ATTACKING  {len(self._targets)} target(s)  |  Method {method_str}",
            text_color=_CLR_DANGER,
        )
        self._start_counter()
        self._app.log(
            f"Attack started – Method {method_str}  |  {len(self._targets)} target(s)  |  GW {gw}",
            "warn",
        )

    def _stop_attack(self) -> None:
        if not self._running:
            return
        if self._attack_obj:
            _thread(self._attack_obj.stop)
        self._running = False
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._status_label.configure(text="Stopped – ARP tables restoring…", text_color=_CLR_WARNING)
        if self._timer_id:
            self.after_cancel(self._timer_id)
            self._timer_id = None
        self._app.log("Attack stopped, restoring ARP caches.", "ok")

    def _start_counter(self) -> None:
        self._counter_start = time.time()
        self._tick()

    def _tick(self) -> None:
        if not self._running:
            return
        elapsed = int(time.time() - self._counter_start)
        self._pkt_label.configure(
            text=f"Running for {elapsed}s  |  Interval: {attack_config.interval}s  |  Burst: {attack_config.burst} pkt/interval"
        )
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

        # Title
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 0))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header, text="📊  Dashboard",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, sticky="w")

        self._last_refresh_label = ctk.CTkLabel(
            header, text="", font=_FONT_SMALL, text_color=_CLR_MUTED)
        self._last_refresh_label.grid(row=0, column=1, sticky="e")

        # ── Stat cards ────────────────────────────────────────────────
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.grid(row=1, column=0, sticky="ew", padx=22, pady=(14, 10))
        for i in range(5):
            cards_frame.grid_columnconfigure(i, weight=1)

        self._card_hosts   = self._make_card(cards_frame, "🖥️  Hosts Found",    "0",          0)
        self._card_iface   = self._make_card(cards_frame, "📡  Interface",       "—",          1)
        self._card_gw      = self._make_card(cards_frame, "🌐  Gateway",         "—",          2)
        self._card_monitor = self._make_card(cards_frame, "👁️  Monitor",         "Idle",       3)
        self._card_attack  = self._make_card(cards_frame, "⚡  Active Attack",   "None",       4)

        # ── Recent devices + Quick actions ────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=22, pady=(0, 18))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=1)

        # Recent devices table
        recent = ctk.CTkFrame(body, fg_color=_CLR_SIDEBAR, corner_radius=12)
        recent.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        recent.grid_rowconfigure(2, weight=1)
        recent.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(recent, text="Recent Devices",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).grid(
            row=0, column=0, padx=16, pady=(14, 6), sticky="w")

        hdr = ctk.CTkFrame(recent, fg_color=_CLR_PANEL, corner_radius=0)
        hdr.grid(row=1, column=0, sticky="ew")
        for ci, col in enumerate(("IP Address", "Vendor", "Type", "Hostname")):
            ctk.CTkLabel(hdr, text=col,
                         font=("Segoe UI", 10, "bold"),
                         text_color=_CLR_ACCENT, anchor="w").grid(
                row=0, column=ci,
                padx=(14 if ci == 0 else 8, 4), pady=7, sticky="w")
        hdr.grid_columnconfigure(3, weight=1)

        self._recent_body = ctk.CTkScrollableFrame(
            recent, fg_color=_CLR_BG, corner_radius=0)
        self._recent_body.grid(row=2, column=0, sticky="nsew")
        self._recent_body.grid_columnconfigure(0, weight=1)

        # Quick actions
        qa = ctk.CTkFrame(body, fg_color=_CLR_SIDEBAR, corner_radius=12)
        qa.grid(row=0, column=1, sticky="nsew")
        qa.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(qa, text="Quick Actions",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).pack(
            padx=16, pady=(14, 10), anchor="w")

        for label, key, color in [
            ("🔍  Run Fast Scan",      "scan",         _CLR_ACCENT),
            ("🌐  Multi-Subnet Scan",  "multi_subnet", _CLR_PANEL),
            ("⚡  ARP Attack",         "attack",       "#7b3f00"),
            ("🚦  Speed Control",      "throttle",     _CLR_ACCENT2),
            ("🏓  Ping Monitor",       "ping_monitor", _CLR_PANEL),
            ("🎭  MAC Anonymize",      "anonymize",    _CLR_PANEL),
        ]:
            ctk.CTkButton(
                qa, text=label, fg_color=color,
                hover_color=_CLR_ACCENT2, font=_FONT_LABEL,
                height=36, anchor="w",
                command=lambda k=key: self._app._show_frame(k),
            ).pack(fill="x", padx=12, pady=4)

        ctk.CTkFrame(qa, height=1, fg_color=_CLR_PANEL).pack(fill="x", padx=12, pady=8)

        ctk.CTkButton(
            qa, text="▶  Start Scan Now",
            fg_color=_CLR_ACCENT, hover_color="#c73652",
            font=_FONT_LABEL, height=40,
            command=self._quick_scan,
        ).pack(fill="x", padx=12, pady=(0, 8))

        # Scan history
        ctk.CTkFrame(qa, height=1, fg_color=_CLR_PANEL).pack(fill="x", padx=12, pady=(4, 8))
        ctk.CTkLabel(qa, text="Scan History",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).pack(
            padx=16, pady=(0, 6), anchor="w")
        self._history_body = ctk.CTkFrame(qa, fg_color="transparent")
        self._history_body.pack(fill="x", padx=12, pady=(0, 12))

    @staticmethod
    def _make_card(parent: ctk.CTkFrame, title: str,
                   value: str, col: int) -> ctk.CTkLabel:
        card = ctk.CTkFrame(parent, fg_color=_CLR_SIDEBAR, corner_radius=12)
        card.grid(row=0, column=col, sticky="nsew", padx=5, pady=4)
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text=title, font=_FONT_SMALL,
                     text_color=_CLR_MUTED).pack(padx=14, pady=(12, 2), anchor="w")
        val_label = ctk.CTkLabel(card, text=value,
                                 font=("Segoe UI", 20, "bold"),
                                 text_color=_CLR_SUCCESS)
        val_label.pack(padx=14, pady=(0, 12), anchor="w")
        return val_label

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
                for ci, (val, w, color) in enumerate([
                    (h.get("ip", ""),             110, _CLR_SUCCESS),
                    (h.get("vendor", "Unknown"),   150, _CLR_TEXT),
                    (h.get("type", "Unknown"),     120, _CLR_MUTED),
                    (h.get("hostname") or "—",     0,   _CLR_TEXT),
                ]):
                    ctk.CTkLabel(
                        row, text=val, font=_FONT_LABEL,
                        text_color=color, anchor="w",
                        **({"width": w} if w else {}),
                    ).grid(row=0, column=ci,
                           padx=(14 if ci == 0 else 8, 4), pady=7, sticky="w")

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
                         font=("Segoe UI", 10, "bold"),
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
                hdr, text=col, font=("Segoe UI", 10, "bold"),
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

            # Merge into global host list (de-dup by IP)
            existing_ips = {h["ip"] for h in self._app._hosts}
            for h in enriched:
                if h["ip"] not in existing_ips:
                    self._app._hosts.append(h)

            self.after(0, lambda: self._populate_results(enriched))
            self.after(0, lambda: self._app.log(
                f"Multi-subnet complete – {len(enriched)} host(s) across {total} subnet(s).", "ok"))

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

    def __init__(self, parent, app: WifiKillerApp) -> None:
        super().__init__(parent, fg_color=_CLR_BG, corner_radius=0)
        self._app = app
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
            font=_FONT_LABEL, command=self.redraw,
        ).grid(row=0, column=2, padx=(12, 0), sticky="e")

        # ── Canvas ────────────────────────────────────────────────────
        self._canvas = tk.Canvas(
            self, bg=self._MAP_BG, highlightthickness=0, bd=0,
        )
        self._canvas.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self._canvas.bind("<Configure>", lambda _e: self.redraw())

    def redraw(self) -> None:
        """Redraw the network topology on the canvas."""
        canvas = self._canvas
        canvas.delete("all")

        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 10 or h < 10:
            return  # widget not yet rendered

        hosts  = self._app._hosts
        gw_ip  = self._app._gateway or "Gateway"
        n      = len(hosts)
        cx, cy = w // 2, h // 2

        if n == 0:
            canvas.create_text(
                cx, cy,
                text="No hosts discovered.\nRun a scan first (Scan Network or Multi-Subnet).",
                fill=_CLR_MUTED, font=("Segoe UI", 13), justify="center",
            )
            self._lbl_count.configure(text="No hosts loaded – run a scan first.")
            return

        self._lbl_count.configure(text=f"{n} host(s) in map")

        radius = min(w, h) * 0.38   # circle radius for host nodes

        # ── Edges ─────────────────────────────────────────────────────
        for i in range(n):
            angle = 2 * math.pi * i / n - math.pi / 2
            hx = cx + radius * math.cos(angle)
            hy = cy + radius * math.sin(angle)
            canvas.create_line(
                cx, cy, hx, hy,
                fill=_CLR_PANEL, width=2, dash=(6, 4),
            )

        # ── Gateway node ───────────────────────────────────────────────
        gr = self._GW_R
        canvas.create_oval(
            cx - gr, cy - gr, cx + gr, cy + gr,
            fill=_CLR_ACCENT, outline=_CLR_TEXT, width=2,
        )
        canvas.create_text(cx, cy, text="GW", fill="#ffffff", font=("Segoe UI", 11, "bold"))
        canvas.create_text(
            cx, cy - gr - 14,
            text=gw_ip, fill=_CLR_TEXT, font=("Segoe UI", 9, "bold"),
        )

        # ── Host nodes ────────────────────────────────────────────────
        r = self._NODE_R
        for i, host in enumerate(hosts):
            angle = 2 * math.pi * i / n - math.pi / 2
            hx = cx + radius * math.cos(angle)
            hy = cy + radius * math.sin(angle)

            ip     = host.get("ip", "?")
            vendor = host.get("vendor", "")
            htype  = host.get("type", "").lower()

            if "router" in htype or "gateway" in htype:
                fill = _CLR_ACCENT
            elif "mobile" in htype or "phone" in htype:
                fill = "#5bc0de"
            elif "printer" in htype:
                fill = _CLR_WARNING
            else:
                fill = _CLR_ACCENT2

            canvas.create_oval(
                hx - r, hy - r, hx + r, hy + r,
                fill=fill, outline=_CLR_TEXT, width=1,
            )

            # IP label
            label_y = hy + r + 14
            canvas.create_text(
                hx, label_y,
                text=ip, fill=_CLR_TEXT, font=("Segoe UI", 8, "bold"),
            )

            # Vendor label (truncated)
            if vendor and vendor not in ("Unknown", ""):
                short = vendor[:18] + ("…" if len(vendor) > 18 else "")
                canvas.create_text(
                    hx, label_y + 13,
                    text=short, fill=_CLR_MUTED, font=("Segoe UI", 7),
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
                hdr, text=col, font=("Segoe UI", 10, "bold"),
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

        # ── Tip from selected host ─────────────────────────────────────
        tip = ctk.CTkFrame(body, fg_color=_CLR_SIDEBAR, corner_radius=14)
        tip.grid(row=0, column=1, sticky="new", padx=(0, 0), pady=(8, 0))
        tip.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(tip, text="Fill from Scan",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).pack(
            padx=16, pady=(16, 6), anchor="w")
        ctk.CTkLabel(
            tip,
            text=(
                "Select a host in the Scan frame, then click\n"
                "the WoL shortcut in the detail popup to pre-fill\n"
                "the MAC address here automatically."
            ),
            font=_FONT_LABEL, text_color=_CLR_MUTED, justify="left",
        ).pack(padx=16, pady=(0, 8), anchor="w")

        ctk.CTkLabel(tip, text="How WoL Works",
                     font=_FONT_HEAD, text_color=_CLR_TEXT).pack(
            padx=16, pady=(8, 4), anchor="w")
        ctk.CTkLabel(
            tip,
            text=(
                "1. The target device must have WoL enabled in BIOS/UEFI.\n"
                "2. The NIC must remain powered (stand-by / hibernate is OK).\n"
                "3. Broadcasts cross subnets only if your router forwards them.\n"
                "4. Use the subnet broadcast (e.g. 192.168.1.255) for reliability."
            ),
            font=_FONT_SMALL, text_color=_CLR_MUTED, justify="left",
        ).pack(padx=16, pady=(0, 16), anchor="w")

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
# DNS Sniffer Frame
# ===========================================================================

class DnsSnifferFrame(ctk.CTkFrame):
    """Live DNS query sniffer panel."""

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
        ).grid(row=0, column=0, padx=28, pady=(22, 2), sticky="w")

        ctk.CTkLabel(
            self,
            text="Capture DNS queries to see which domains devices are resolving. "
                 "Requires an active MITM or monitor mode.",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).grid(row=1, column=0, padx=28, pady=(0, 10), sticky="w")

        # Controls
        ctrl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        ctrl.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 10))

        self._start_btn = ctk.CTkButton(
            ctrl, text="▶  Start Sniffing", fg_color=_CLR_ACCENT,
            hover_color="#c73652", font=_FONT_LABEL, width=150,
            command=self._toggle_sniffer,
        )
        self._start_btn.pack(side="left", padx=(16, 8), pady=12)

        ctk.CTkButton(
            ctrl, text="🗑  Clear", fg_color=_CLR_PANEL,
            hover_color=_CLR_DANGER, font=_FONT_LABEL, width=80,
            command=self._clear,
        ).pack(side="left", padx=(0, 8), pady=12)

        ctk.CTkButton(
            ctrl, text="💾  Export CSV", fg_color=_CLR_PANEL,
            hover_color="#1a4a80", font=_FONT_LABEL, width=120,
            command=self._export,
        ).pack(side="left", padx=(0, 8), pady=12)

        self._count_label = ctk.CTkLabel(
            ctrl, text="0 queries captured", font=_FONT_SMALL, text_color=_CLR_MUTED)
        self._count_label.pack(side="right", padx=16, pady=12)

        # Table
        tbl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        tbl.grid(row=3, column=0, sticky="nsew", padx=24, pady=(0, 20))
        tbl.grid_rowconfigure(1, weight=1)
        tbl.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(tbl, fg_color=_CLR_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        for ci, col in enumerate(("Timestamp", "Source IP", "Domain", "Query Type")):
            ctk.CTkLabel(hdr, text=col,
                         font=("Segoe UI", 10, "bold"),
                         text_color=_CLR_ACCENT, anchor="w").grid(
                row=0, column=ci, padx=(14 if ci == 0 else 8, 4), pady=8, sticky="w")
        hdr.grid_columnconfigure(2, weight=1)

        self._tbl_body = ctk.CTkScrollableFrame(
            tbl, fg_color=_CLR_BG, corner_radius=0)
        self._tbl_body.grid(row=1, column=0, sticky="nsew")
        self._tbl_body.grid_columnconfigure(0, weight=1)

        self._displayed_count = 0

    def _toggle_sniffer(self) -> None:
        if self._running:
            self._stop_sniffer()
        else:
            self._start_sniffer()

    def _start_sniffer(self) -> None:
        try:
            from wifi_killer.modules.dns_sniffer import DnsSniffer
        except ImportError:
            messagebox.showerror("Module Error", "DNS sniffer module not available.")
            return
        iface = self._app._iface or None
        self._sniffer = DnsSniffer(iface=iface)
        self._sniffer.start()
        self._running = True
        self._start_btn.configure(text="⏹  Stop Sniffing", fg_color=_CLR_DANGER)
        self._app.log("DNS sniffer started.", "ok")
        self._schedule_refresh()

    def _stop_sniffer(self) -> None:
        if self._sniffer:
            self._sniffer.stop()
        self._running = False
        self._start_btn.configure(text="▶  Start Sniffing", fg_color=_CLR_ACCENT)
        if self._refresh_id:
            self.after_cancel(self._refresh_id)
            self._refresh_id = None
        self._app.log("DNS sniffer stopped.", "warn")

    def _schedule_refresh(self) -> None:
        if not self._running:
            return
        self._refresh_table()
        self._refresh_id = self.after(1000, self._schedule_refresh)

    def _refresh_table(self) -> None:
        if not self._sniffer:
            return
        queries = self._sniffer.queries
        new_count = len(queries)
        self._count_label.configure(text=f"{new_count} queries captured")

        # Only add new rows
        for i in range(self._displayed_count, new_count):
            q = queries[i]
            bg = _CLR_ROW_ODD if i % 2 == 0 else _CLR_ROW_EVEN
            row = ctk.CTkFrame(self._tbl_body, fg_color=bg, corner_radius=6)
            row.pack(fill="x", padx=4, pady=1)
            for ci, val in enumerate([
                q.get("timestamp", ""),
                q.get("src_ip", ""),
                q.get("domain", ""),
                q.get("query_type", ""),
            ]):
                ctk.CTkLabel(
                    row, text=str(val), font=_FONT_LABEL,
                    text_color=_CLR_SUCCESS if ci == 2 else _CLR_TEXT,
                    anchor="w",
                ).grid(row=0, column=ci, padx=(14 if ci == 0 else 8, 4), pady=6, sticky="w")
            row.grid_columnconfigure(2, weight=1)
        self._displayed_count = new_count

    def _clear(self) -> None:
        if self._sniffer:
            self._sniffer.clear()
        for w in self._tbl_body.winfo_children():
            w.destroy()
        self._displayed_count = 0
        self._count_label.configure(text="0 queries captured")

    def _export(self) -> None:
        if not self._sniffer or not self._sniffer.queries:
            messagebox.showinfo("Export", "No DNS queries to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv"), ("All files", "*.*")],
            title="Export DNS Queries",
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
    """ARP cache viewer with poisoning detection."""

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
            self, text="🗂️  ARP Cache Viewer",
            font=_FONT_TITLE, text_color=_CLR_ACCENT,
        ).grid(row=0, column=0, padx=28, pady=(22, 2), sticky="w")

        ctk.CTkLabel(
            self,
            text="View the system ARP table and detect potential ARP poisoning.",
            font=_FONT_SMALL, text_color=_CLR_MUTED,
        ).grid(row=1, column=0, padx=28, pady=(0, 10), sticky="w")

        # Controls
        ctrl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        ctrl.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 10))

        ctk.CTkButton(
            ctrl, text="🔄  Refresh", fg_color=_CLR_ACCENT,
            hover_color="#c73652", font=_FONT_LABEL, width=120,
            command=self._refresh,
        ).pack(side="left", padx=(16, 8), pady=12)

        self._auto_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            ctrl, text="Auto-refresh (5s)", variable=self._auto_var,
            font=_FONT_LABEL, command=self._toggle_auto_refresh,
        ).pack(side="left", padx=(0, 16), pady=12)

        self._count_label = ctk.CTkLabel(
            ctrl, text="", font=_FONT_SMALL, text_color=_CLR_MUTED)
        self._count_label.pack(side="left", padx=8, pady=12)

        self._warning_label = ctk.CTkLabel(
            ctrl, text="", font=_FONT_LABEL, text_color=_CLR_DANGER)
        self._warning_label.pack(side="right", padx=16, pady=12)

        # Table
        tbl = ctk.CTkFrame(self, fg_color=_CLR_SIDEBAR, corner_radius=12)
        tbl.grid(row=3, column=0, sticky="nsew", padx=24, pady=(0, 20))
        tbl.grid_rowconfigure(1, weight=1)
        tbl.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(tbl, fg_color=_CLR_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        for ci, col in enumerate(("IP Address", "MAC Address", "State", "Interface", "Status")):
            ctk.CTkLabel(hdr, text=col,
                         font=("Segoe UI", 10, "bold"),
                         text_color=_CLR_ACCENT, anchor="w").grid(
                row=0, column=ci, padx=(14 if ci == 0 else 8, 4), pady=8, sticky="w")
        hdr.grid_columnconfigure(4, weight=1)

        self._tbl_body = ctk.CTkScrollableFrame(
            tbl, fg_color=_CLR_BG, corner_radius=0)
        self._tbl_body.grid(row=1, column=0, sticky="nsew")
        self._tbl_body.grid_columnconfigure(0, weight=1)

    def _refresh(self) -> None:
        try:
            from wifi_killer.modules.arp_cache import read_arp_cache, detect_poisoning
        except ImportError:
            self._count_label.configure(text="ARP cache module not available")
            return

        entries = read_arp_cache()
        suspicious = detect_poisoning(entries)

        # Build set of suspicious MACs for highlighting
        suspicious_macs = set()
        for s in suspicious:
            suspicious_macs.add(s["mac"].upper())

        # Clear table
        for w in self._tbl_body.winfo_children():
            w.destroy()

        self._count_label.configure(text=f"{len(entries)} ARP entries")

        if suspicious:
            warnings = "; ".join(s["warning"] for s in suspicious[:3])
            self._warning_label.configure(
                text=f"⚠  Potential poisoning: {warnings}")
        else:
            self._warning_label.configure(text="✓ No poisoning detected")

        for i, entry in enumerate(entries):
            mac_upper = entry.get("mac", "").upper()
            is_suspicious = mac_upper in suspicious_macs
            bg = _CLR_DANGER if is_suspicious else (
                _CLR_ROW_ODD if i % 2 == 0 else _CLR_ROW_EVEN)

            row = ctk.CTkFrame(self._tbl_body, fg_color=bg, corner_radius=6)
            row.pack(fill="x", padx=4, pady=1)

            status = "⚠  SUSPICIOUS" if is_suspicious else "OK"
            for ci, val in enumerate([
                entry.get("ip", ""),
                entry.get("mac", ""),
                entry.get("state", ""),
                entry.get("interface", ""),
                status,
            ]):
                color = _CLR_DANGER if is_suspicious and ci == 4 else (
                    _CLR_SUCCESS if ci == 0 else _CLR_TEXT)
                ctk.CTkLabel(
                    row, text=str(val), font=_FONT_LABEL,
                    text_color=color, anchor="w",
                ).grid(row=0, column=ci, padx=(14 if ci == 0 else 8, 4), pady=6, sticky="w")
            row.grid_columnconfigure(4, weight=1)

    def _toggle_auto_refresh(self) -> None:
        if self._auto_var.get():
            self._auto_refresh_loop()
        else:
            if self._auto_refresh_id:
                self.after_cancel(self._auto_refresh_id)
                self._auto_refresh_id = None

    def _auto_refresh_loop(self) -> None:
        if not self._auto_var.get():
            return
        self._refresh()
        self._auto_refresh_id = self.after(5000, self._auto_refresh_loop)


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
            font=("Segoe UI", 36, "bold"), text_color=_CLR_ACCENT,
        ).pack(pady=(0, 4))

        ctk.CTkLabel(
            inner, text=f"v{_VERSION}  ·  Modern Network Lab Tool",
            font=("Segoe UI", 14), text_color=_CLR_MUTED,
        ).pack(pady=(0, 24))

        features = [
            "📊  Live dashboard with stat cards, recent-device feed and scan history",
            "🔍  Multi-mode host discovery (ARP · ICMP · TCP SYN with custom ports)",
            "🔎  Real-time search/filter across the host table",
            "☑️   Select All / Deselect All with one-click bulk actions",
            "📋  Copy All IPs to clipboard",
            "ℹ️   Host detail popup with live RTT ping and action shortcuts",
            "🌐  Multi-subnet scan – auto-detect & scan different network segments",
            "📡  Continuous network monitor with join/leave alerts",
            "🔎  DNS query sniffer – live capture of DNS lookups during MITM",
            "🗂️   ARP cache viewer with poisoning detection",
            "📦  Packet capture with pcap export for Wireshark analysis",
            "📝  Session audit logger – full JSON-lines trail of all actions",
            "⚡  ARP-spoofing: Full MITM · Client-cut · Gateway-cut",
            "🚦  Client speed control – per-IP download/upload throttle sliders",
            "🏓  Ping monitor – live RTT table for multiple hosts",
            "🎭  MAC address anonymization (random / OUI-preserve / custom / restore)",
            "🔆  Wake-on-LAN – send standard & SecureOn magic packets",
            "🧠  OS fingerprinting from TTL (Linux / Windows / Cisco)",
            "🏷️   Expanded device-type detection (Sonos, printers, game consoles, smart TV …)",
            "⚙️   Configurable attack speed with presets (aggressive / normal / stealth / paranoid)",
            "🌙  Dark / Light / System theme toggle",
            "💾  Export scan results to CSV, JSON, or HTML reports",
            "📄  Export activity log to text file",
            "📋  Colour-coded activity log with Clear button",
            "🖥️   Modern dark-themed GUI (CustomTkinter)",
            "🖥️   CLI with --version, --scan-only, and report export flags",
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
