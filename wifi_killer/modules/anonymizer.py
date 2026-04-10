"""
modules/anonymizer.py – Module 5: Random MAC Address (Anonymization).

Platform support:
  Linux   – uses ``ip link set dev <iface> address <mac>``
  macOS   – uses ``ifconfig <iface> ether <mac>``
  Windows – raises NotImplementedError (registry-level change not automated)

Requires root / Administrator privileges.
"""

from __future__ import annotations

import random
import re
import subprocess
import sys
from typing import Optional

from wifi_killer.utils.network import get_interface_mac

_IS_LINUX = sys.platform.startswith("linux")
_IS_MACOS = sys.platform == "darwin"
_IS_WINDOWS = sys.platform == "win32"

# ------------------------------------------------------------------ #
# Original MAC tracking                                               #
# ------------------------------------------------------------------ #

_stored_originals: dict[str, str] = {}


def _store_original(iface: str) -> None:
    """Store the original MAC for *iface* if not already recorded."""
    if iface not in _stored_originals:
        mac = get_interface_mac(iface)
        if mac:
            _stored_originals[iface] = mac


def get_original_mac(iface: str) -> Optional[str]:
    """Return the stored original MAC for *iface*, or None."""
    return _stored_originals.get(iface)


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _generate_random_mac(preserve_oui: bool = False, original_mac: str = "") -> str:
    """Generate a random unicast, locally administered MAC address."""
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02  # unicast + locally administered

    if preserve_oui and original_mac:
        norm = re.sub(r"[^0-9A-Fa-f]", "", original_mac)
        if len(norm) >= 6:
            for i in range(3):
                octets[i] = int(norm[i * 2 : i * 2 + 2], 16)
            octets[0] = (octets[0] & 0xFE) | 0x02

    return ":".join(f"{b:02X}" for b in octets)


def _is_valid_mac(mac: str) -> bool:
    pattern = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    return bool(pattern.match(mac))


# ------------------------------------------------------------------ #
# Public API                                                          #
# ------------------------------------------------------------------ #

def randomize_mac(
    iface: str,
    new_mac: Optional[str] = None,
    preserve_oui: bool = False,
) -> str:
    """Change the MAC address of *iface* to *new_mac* (or a random one).

    Args:
        iface:        Network interface name (e.g. 'eth0', 'en0').
        new_mac:      Specific MAC to set; generated randomly if None.
        preserve_oui: Keep original vendor OUI when generating a random MAC.

    Returns:
        The new MAC address string.

    Raises:
        RuntimeError:       If the operation fails or privileges are missing.
        NotImplementedError: On Windows.
    """
    if _IS_WINDOWS:
        raise NotImplementedError(
            "Automatic MAC address changing is not supported on Windows.\n"
            "To change your MAC manually, use a tool like Technitium MAC "
            "Address Changer (https://technitium.com/tmac/) or edit the "
            "'NetworkAddress' registry value under:\n"
            "  HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
            "{4D36E972-E325-11CE-BFC1-08002BE10318}\\<adapter-index>"
        )

    _store_original(iface)
    original_mac = get_interface_mac(iface) or ""

    if new_mac is None:
        new_mac = _generate_random_mac(
            preserve_oui=preserve_oui, original_mac=original_mac
        )

    if not _is_valid_mac(new_mac):
        raise ValueError(f"Invalid MAC address format: '{new_mac}'")

    try:
        if _IS_LINUX:
            subprocess.check_call(
                ["ip", "link", "set", "dev", iface, "down"], timeout=5
            )
            subprocess.check_call(
                ["ip", "link", "set", "dev", iface, "address", new_mac.lower()],
                timeout=5,
            )
            subprocess.check_call(
                ["ip", "link", "set", "dev", iface, "up"], timeout=5
            )

        elif _IS_MACOS:
            # Bring interface down, set MAC, bring back up
            subprocess.check_call(
                ["ifconfig", iface, "down"], timeout=5
            )
            subprocess.check_call(
                ["ifconfig", iface, "ether", new_mac.lower()], timeout=5
            )
            subprocess.check_call(
                ["ifconfig", iface, "up"], timeout=5
            )

    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Failed to change MAC on {iface}: {exc}. "
            "Make sure you are running as root/sudo."
        ) from exc

    return new_mac


def restore_mac(iface: str, original_mac: Optional[str] = None) -> None:
    """Restore the original MAC address for *iface*."""
    if original_mac is None:
        original_mac = get_original_mac(iface)
    if not original_mac:
        raise RuntimeError(
            f"No original MAC recorded for '{iface}'. Cannot restore."
        )
    randomize_mac(iface, new_mac=original_mac)


def get_current_mac(iface: str) -> Optional[str]:
    """Return the current MAC address of *iface*."""
    return get_interface_mac(iface)
