"""
modules/throttler.py – Client bandwidth throttling via Linux tc (traffic control).

Uses HTB (Hierarchical Token Bucket) queuing discipline to apply per-IP
rate limits on a network interface.

How it works (MITM context)
---------------------------
When the attacker is performing an ARP MITM attack, all traffic between
the victim and the gateway flows through the attacker machine.  With IP
forwarding enabled the attacker can apply ``tc`` rules to shape how fast
that traffic is forwarded:

* **Download** – traffic leaving the attacker toward the victim
  (matched by ``ip dst <victim_ip>``).
* **Upload**   – traffic leaving the attacker toward the gateway
  (matched by ``ip src <victim_ip>``).

Both directions are implemented as egress HTB classes on the outbound
interface, which avoids the need for the more complex IFB redirect trick.

Requirements
------------
* Root / CAP_NET_ADMIN privileges
* ``iproute2`` installed (``tc`` command)

Usage
-----
    throttler = BandwidthThrottler("eth0")
    throttler.setup()
    throttler.set_speed("192.168.1.5", download_kbps=512, upload_kbps=256)
    # … later …
    throttler.remove("192.168.1.5")   # restore that host
    throttler.cleanup()               # tear down everything
"""

from __future__ import annotations

import subprocess
import threading
from typing import Optional


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    """Run a tc command silently; never raises unless *check* is True."""
    return subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=check,
    )


def enable_ip_forward() -> None:
    """Enable IPv4 packet forwarding (required for MITM + throttling)."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
    except Exception as exc:
        import sys
        print(f"[WARN] Could not enable IP forwarding: {exc}", file=sys.stderr)


def disable_ip_forward() -> None:
    """Restore IPv4 forwarding to disabled (call only when nothing else needs it)."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0\n")
    except Exception as exc:
        import sys
        print(f"[WARN] Could not disable IP forwarding: {exc}", file=sys.stderr)


def get_ip_forward() -> bool:
    """Return True if IPv4 forwarding is currently enabled."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# BandwidthThrottler
# ---------------------------------------------------------------------------

class BandwidthThrottler:
    """Per-IP bandwidth throttler using Linux tc HTB.

    Class ID scheme (under handle 1:)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    1:999  – default / unlimited class (all unmatched traffic)
    1:10   – download class for target #1  (dst match)
    1:11   – upload   class for target #1  (src match)
    1:12   – download class for target #2  …
    1:13   – upload   class for target #2  …
    … and so on, incrementing by 2 per host.
    """

    _MAX_RATE_KBIT: int = 1_000_000   # 1 Gbit – ceiling for the default class
    _MIN_RATE_KBIT: int = 1           # minimum enforced (tc rejects 0)

    def __init__(self, iface: str) -> None:
        self.iface: str = iface
        self._lock: threading.Lock = threading.Lock()
        self._initialized: bool = False
        # ip → (download_class_id, upload_class_id)
        self._targets: dict[str, tuple[int, int]] = {}
        self._next_id: int = 10

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def setup(self) -> None:
        """Initialize the root HTB qdisc on *iface*.

        Removes any existing root qdisc first, so it is safe to call more
        than once (e.g. after a previous dirty exit).
        """
        with self._lock:
            # Tear down any pre-existing qdisc (ignore errors – may not exist)
            _run(["tc", "qdisc", "del", "dev", self.iface, "root"])

            # Root HTB qdisc.  Unclassified traffic goes to class 999.
            _run(
                ["tc", "qdisc", "add", "dev", self.iface,
                 "root", "handle", "1:", "htb", "default", "999"],
                check=True,
            )
            # Default (unlimited) class
            _run(
                ["tc", "class", "add", "dev", self.iface,
                 "parent", "1:", "classid", "1:999",
                 "htb",
                 "rate", f"{self._MAX_RATE_KBIT}kbit",
                 "ceil", f"{self._MAX_RATE_KBIT}kbit"],
                check=True,
            )
            enable_ip_forward()
            self._initialized = True

    def set_speed(
        self,
        target_ip: str,
        download_kbps: int,
        upload_kbps: int,
    ) -> None:
        """Apply or update rate limits for *target_ip*.

        A value of **0** means "block completely" (enforced as 1 kbit/s so
        that ``tc`` does not reject the rule; the host effectively has no
        usable bandwidth).

        Args:
            target_ip:     IPv4 address of the victim device.
            download_kbps: Victim's download speed cap in Kbps.
            upload_kbps:   Victim's upload speed cap in Kbps.
        """
        dl_rate = max(self._MIN_RATE_KBIT, download_kbps)
        ul_rate = max(self._MIN_RATE_KBIT, upload_kbps)

        with self._lock:
            if not self._initialized:
                raise RuntimeError("Call setup() before set_speed().")

            if target_ip in self._targets:
                dl_id, ul_id = self._targets[target_ip]
                self._update_class(dl_id, dl_rate)
                self._update_class(ul_id, ul_rate)
            else:
                dl_id = self._next_id
                ul_id = self._next_id + 1
                self._next_id += 2
                self._targets[target_ip] = (dl_id, ul_id)

                # Download: traffic TO the victim (dst match, egress)
                self._add_class(dl_id, dl_rate)
                self._add_filter(dl_id, target_ip, "dst")

                # Upload: traffic FROM the victim (src match, egress)
                self._add_class(ul_id, ul_rate)
                self._add_filter(ul_id, target_ip, "src")

    def remove(self, target_ip: str) -> None:
        """Remove rate-limiting for *target_ip*, restoring unlimited speed."""
        with self._lock:
            if target_ip not in self._targets:
                return
            dl_id, ul_id = self._targets.pop(target_ip)
            for cid in (dl_id, ul_id):
                _run(["tc", "class", "del", "dev", self.iface,
                      "parent", "1:", "classid", f"1:{cid}"])

    def cleanup(self) -> None:
        """Remove the root qdisc completely, restoring normal operation."""
        with self._lock:
            _run(["tc", "qdisc", "del", "dev", self.iface, "root"])
            self._targets.clear()
            self._initialized = False

    @property
    def is_setup(self) -> bool:
        """Return True if the HTB qdisc has been initialized."""
        return self._initialized

    @property
    def active_targets(self) -> dict[str, tuple[int, int]]:
        """Return a snapshot of the active target → (dl_id, ul_id) map."""
        with self._lock:
            return dict(self._targets)

    def get_speed(self, target_ip: str) -> Optional[tuple[int, int]]:
        """Return (dl_class_id, ul_class_id) for *target_ip*, or None."""
        with self._lock:
            return self._targets.get(target_ip)

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _add_class(self, class_id: int, rate_kbps: int) -> None:
        _run([
            "tc", "class", "add", "dev", self.iface,
            "parent", "1:", "classid", f"1:{class_id}",
            "htb",
            "rate", f"{rate_kbps}kbit",
            "ceil", f"{rate_kbps}kbit",
            "burst", "15k",
        ])

    def _update_class(self, class_id: int, rate_kbps: int) -> None:
        _run([
            "tc", "class", "change", "dev", self.iface,
            "parent", "1:", "classid", f"1:{class_id}",
            "htb",
            "rate", f"{rate_kbps}kbit",
            "ceil", f"{rate_kbps}kbit",
            "burst", "15k",
        ])

    def _add_filter(self, class_id: int, ip: str, direction: str) -> None:
        """Add a u32 packet filter matching src or dst *ip*."""
        _run([
            "tc", "filter", "add", "dev", self.iface,
            "protocol", "ip", "parent", "1:0",
            "prio", "1", "u32",
            "match", "ip", direction, f"{ip}/32",
            "flowid", f"1:{class_id}",
        ])


# ---------------------------------------------------------------------------
# Convenience: kbps ↔ human-readable conversions
# ---------------------------------------------------------------------------

def kbps_to_label(kbps: int) -> str:
    """Return a human-readable speed string, e.g. '1.5 Mbps' or '512 Kbps'."""
    if kbps <= 0:
        return "Blocked"
    if kbps >= 1000:
        mbps = kbps / 1000
        return f"{mbps:.1f} Mbps" if mbps != int(mbps) else f"{int(mbps)} Mbps"
    return f"{kbps} Kbps"


def mbps_to_kbps(mbps: float) -> int:
    """Convert Mbps float to integer Kbps."""
    return max(0, int(mbps * 1000))
