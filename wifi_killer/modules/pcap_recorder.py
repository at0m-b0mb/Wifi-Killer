"""
pcap_recorder.py — Save MITM session traffic to a Wireshark-readable PCAP.

Spawns a Scapy ``sniff`` thread on the active interface, filters to the
attacked target IPs, and writes every captured packet to a rotating
PCAP file via a ``PcapWriter`` opened in append mode.

The recorder is purely passive — kernel forwarding is unaffected, and
this module does not inspect or modify packets. Its job is to make
the captured session reproducible offline (in Wireshark, ``tshark``,
``zeek``, or similar).

Usage:

    rec = PCAPRecorder(
        iface="en0",
        target_ips=["10.0.0.55", "10.0.0.72"],
        output_path="/tmp/mitm-session.pcap",
    )
    rec.start()
    ...
    rec.stop()
    # Open /tmp/mitm-session.pcap in Wireshark.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Optional

try:
    from scapy.all import sniff, PcapWriter  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


class PCAPRecorder:
    """Background packet capture writing to a PCAP file."""

    def __init__(
        self,
        iface: Optional[str],
        target_ips: list[str],
        output_path: str,
        max_bytes: int = 200 * 1024 * 1024,
    ) -> None:
        self.iface = iface
        self.target_ips = list(target_ips or [])
        self.output_path = output_path
        # Stop capturing once the PCAP grows past this many bytes so we
        # don't fill the disk during a forgotten session. The user can
        # bump it by changing ``max_bytes``.
        self.max_bytes = int(max_bytes)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._writer: Optional["PcapWriter"] = None
        self.packets_written: int = 0
        self.bytes_written: int = 0
        self.started_at: float = 0.0
        self.error: Optional[str] = None

    # ------------------------------------------------------------------ #

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.started_at if self.started_at else 0.0

    def start(self) -> None:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for PCAP recording.")
        if not self.output_path:
            raise RuntimeError("PCAP recorder needs an output path.")
        directory = os.path.dirname(os.path.abspath(self.output_path)) or "."
        if not os.path.isdir(directory):
            raise RuntimeError(
                f"PCAP directory does not exist: {directory}"
            )
        if not os.access(directory, os.W_OK):
            raise RuntimeError(
                f"No write permission for PCAP directory: {directory}"
            )
        if self.is_running:
            return
        self._stop_event.clear()
        self.started_at = time.time()
        self.error = None
        try:
            self._writer = PcapWriter(
                self.output_path, append=True, sync=False,
            )
        except Exception as exc:
            self.error = f"Failed to open PCAP file: {exc}"
            self._writer = None
            raise
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        with self._lock:
            if self._writer is not None:
                try:
                    self._writer.close()
                except Exception:
                    pass
                self._writer = None

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "running":         self.is_running,
                "uptime":          self.uptime_seconds,
                "output":          self.output_path,
                "packets_written": self.packets_written,
                "bytes_written":   self.bytes_written,
                "max_bytes":       self.max_bytes,
                "error":           self.error,
            }

    # ------------------------------------------------------------------ #

    def _sniff_loop(self) -> None:
        # BPF filter restricted to the targets so we don't grab the
        # whole link.
        if self.target_ips:
            bpf = " or ".join(f"host {ip}" for ip in self.target_ips)
        else:
            bpf = None
        try:
            sniff(
                iface=self.iface,
                filter=bpf,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _p: self._stop_event.is_set(),
            )
        except Exception as exc:
            self.error = str(exc)

    def _on_packet(self, packet) -> None:
        try:
            with self._lock:
                if self._writer is None or self._stop_event.is_set():
                    return
                if self.bytes_written >= self.max_bytes:
                    # Trip the stop flag so subsequent packets are ignored
                    # and the sniff thread exits cleanly.
                    self._stop_event.set()
                    return
                self._writer.write(packet)
                self.packets_written += 1
                self.bytes_written += len(packet)
        except Exception:
            pass
