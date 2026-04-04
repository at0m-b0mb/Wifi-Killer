"""
modules/packet_capture.py – Packet capture and storage.

Provides a threaded packet-capture interface backed by Scapy's ``sniff``
function.  Captured packets can be saved to standard pcap files for later
analysis in Wireshark or similar tools.

**Educational / authorized-use only.**  This module is part of the
Wifi-Killer educational Wi-Fi network analysis toolkit.  Only use it on
networks you own or have explicit written permission to test.  Unauthorized
packet interception is illegal in most jurisdictions.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

try:
    from scapy.all import sniff, wrpcap, IP  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _check_scapy() -> None:
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "Scapy is not installed. Install it with: pip install scapy"
        )


# ------------------------------------------------------------------ #
# PacketCapture                                                        #
# ------------------------------------------------------------------ #

class PacketCapture:
    """Thread-safe packet capture engine.

    Runs Scapy's ``sniff`` in a background thread and accumulates packets
    in memory.  An optional BPF filter can restrict capture to traffic
    involving a specific IP address.

    Example::

        cap = PacketCapture(iface="wlan0", target_ip="192.168.1.42")
        cap.start()
        # … wait …
        cap.stop()
        cap.save("/tmp/capture.pcap")
        print(f"Captured {cap.packet_count} packets ({cap.byte_count} bytes)")
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        target_ip: Optional[str] = None,
    ) -> None:
        """Initialize the capture engine.

        Args:
            iface:     Network interface to capture on (e.g. ``'wlan0'``).
                       ``None`` lets Scapy choose the default interface.
            target_ip: If given, only packets whose source **or** destination
                       matches this IPv4 address are captured (BPF filter).
        """
        self._iface: Optional[str] = iface
        self._target_ip: Optional[str] = target_ip

        self._packets: list = []
        self._packet_count: int = 0
        self._byte_count: int = 0

        self._lock: threading.Lock = threading.Lock()
        self._stop_event: threading.Event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ---------------------------------------------------------------- #
    # Public API                                                         #
    # ---------------------------------------------------------------- #

    def start(self) -> None:
        """Start capturing packets in a background daemon thread.

        Raises:
            RuntimeError: If Scapy is not installed or capture is already
                running.
        """
        _check_scapy()
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("Capture is already running.")
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        logger.info(
            "Packet capture started (iface=%s, filter=%s)",
            self._iface or "default",
            self._target_ip or "none",
        )

    def stop(self) -> None:
        """Signal the capture thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info(
            "Packet capture stopped (%d packets, %d bytes)",
            self._packet_count,
            self._byte_count,
        )

    def save(self, path: str) -> None:
        """Save captured packets to a pcap file.

        Args:
            path: Filesystem path for the output ``.pcap`` file.

        Raises:
            RuntimeError: If Scapy is not installed.
            ValueError:   If there are no packets to save.
        """
        _check_scapy()
        with self._lock:
            if not self._packets:
                raise ValueError("No packets to save.")
            wrpcap(path, self._packets)
        logger.info("Saved %d packets to %s", self._packet_count, path)

    def clear(self) -> None:
        """Discard all captured packets and reset counters."""
        with self._lock:
            self._packets.clear()
            self._packet_count = 0
            self._byte_count = 0
        logger.debug("Packet buffer cleared.")

    # ---------------------------------------------------------------- #
    # Properties                                                         #
    # ---------------------------------------------------------------- #

    @property
    def packet_count(self) -> int:
        """Number of packets captured so far."""
        return self._packet_count

    @property
    def byte_count(self) -> int:
        """Total bytes captured so far."""
        return self._byte_count

    @property
    def is_running(self) -> bool:
        """Return ``True`` if the capture thread is currently active."""
        return self._thread is not None and self._thread.is_alive()

    # ---------------------------------------------------------------- #
    # Internal capture loop                                              #
    # ---------------------------------------------------------------- #

    def _capture_loop(self) -> None:
        """Run Scapy's ``sniff`` until the stop event is set.

        Uses ``stop_filter`` to check the event between packets and a
        short ``timeout`` so the thread does not block indefinitely when
        no traffic is seen.
        """
        kwargs: dict = {
            "prn": self._process_packet,
            "store": False,
            "stop_filter": lambda _pkt: self._stop_event.is_set(),
            "timeout": 1,
        }
        if self._iface is not None:
            kwargs["iface"] = self._iface

        # Build BPF filter for the target IP (matches src OR dst).
        if self._target_ip is not None:
            kwargs["filter"] = f"host {self._target_ip}"

        # Keep re-entering sniff in 1-second windows so we can honour the
        # stop event even when no packets arrive.
        while not self._stop_event.is_set():
            try:
                sniff(**kwargs)
            except OSError as exc:
                # Interface may have gone away or permissions were revoked.
                logger.error("Capture error: %s", exc)
                break
            except Exception:
                logger.exception("Unexpected error in capture loop")
                break

    def _process_packet(self, pkt) -> None:  # noqa: ANN001  (scapy Packet)
        """Callback invoked by ``sniff`` for every captured packet.

        Updates internal counters and stores the packet for later saving.

        Args:
            pkt: A Scapy ``Packet`` object.
        """
        with self._lock:
            self._packets.append(pkt)
            self._packet_count += 1
            self._byte_count += len(pkt)
