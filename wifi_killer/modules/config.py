"""
modules/config.py – Module 4: Speed / Intensity Control.

Defines attack presets and a mutable Config object shared across modules.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AttackConfig:
    """Configurable parameters that govern ARP-spoof intensity."""

    # Seconds between each ARP-spoof burst
    interval: float = 2.0
    # Number of ARP packets sent per interval
    burst: int = 1
    # Seconds between individual packets inside a burst
    inter_burst_delay: float = 0.05
    # Deauth frames per burst (802.11; only used when injection is available)
    deauth_count: int = 5
    # Seconds between deauth bursts
    deauth_delay: float = 1.0
    # Preset name (informational)
    preset: str = "normal"

    # ------------------------------------------------------------------ #
    # Presets                                                              #
    # ------------------------------------------------------------------ #

    def apply_preset(self, name: str) -> None:
        """Apply a named speed preset."""
        name = name.lower()
        if name == "aggressive":
            self.interval = 0.5
            self.burst = 5
            self.inter_burst_delay = 0.02
            self.deauth_count = 10
            self.deauth_delay = 0.5
            self.preset = "aggressive"
        elif name == "normal":
            self.interval = 2.0
            self.burst = 1
            self.inter_burst_delay = 0.05
            self.deauth_count = 5
            self.deauth_delay = 1.0
            self.preset = "normal"
        elif name in ("stealth", "slow"):
            self.interval = 10.0
            self.burst = 1
            self.inter_burst_delay = 0.2
            self.deauth_count = 2
            self.deauth_delay = 5.0
            self.preset = "stealth"
        elif name == "paranoid":
            # Absolute minimum footprint – one packet every 30 s with a
            # 1-second gap between individual frames inside the burst.
            self.interval = 30.0
            self.burst = 1
            self.inter_burst_delay = 1.0
            self.deauth_count = 1
            self.deauth_delay = 15.0
            self.preset = "paranoid"
        else:
            raise ValueError(
                f"Unknown preset '{name}'. Choose: aggressive, normal, stealth, paranoid"
            )

    def display(self) -> str:
        lines = [
            f"  Preset           : {self.preset}",
            f"  Interval (s)     : {self.interval}",
            f"  Burst size       : {self.burst}",
            f"  Deauth count     : {self.deauth_count}",
            f"  Deauth delay (s) : {self.deauth_delay}",
        ]
        return "\n".join(lines)


# Module-level singleton – all modules import this instance.
attack_config = AttackConfig()
