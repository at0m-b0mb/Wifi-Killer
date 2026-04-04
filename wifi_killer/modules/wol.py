"""
modules/wol.py – Wake-on-LAN (WoL) support.

Constructs and broadcasts the 102-byte magic packet defined in AMD's
original "Magic Packet" specification:
    6 × 0xFF  followed by  16 × <target MAC> (6 bytes each)

Public API
----------
build_magic_packet(mac)  → bytes
    Returns the 102-byte magic packet for the given MAC address.
    Accepts any common delimiter (colon, dash, dot, none).

send_wol(mac, broadcast, port)  → None
    Sends the magic packet as a UDP broadcast.  Requires that the target
    machine has WoL enabled in its firmware/OS.
"""

from __future__ import annotations

import re
import socket


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_mac(mac: str) -> bytes:
    """Strip any delimiters from *mac* and return raw 6 bytes.

    Accepts formats: ``AA:BB:CC:DD:EE:FF``, ``AA-BB-CC-DD-EE-FF``,
    ``AABBCCDDEEFF``, ``aabb.ccdd.eeff``.

    Raises ``ValueError`` if the result is not exactly 12 hex digits.
    """
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) != 12:
        raise ValueError(
            f"Invalid MAC address {mac!r}: expected 12 hex digits, got {len(clean)}."
        )
    return bytes.fromhex(clean)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_magic_packet(mac: str, secure_on: str = "") -> bytes:
    """Return the WoL magic packet for *mac*, optionally with a SecureOn password.

    The standard magic packet is 102 bytes:
      ``FF FF FF FF FF FF`` + ``<MAC>`` × 16

    When *secure_on* is provided (a 6-byte password expressed as a
    MAC-style hex string, e.g. ``'01:02:03:04:05:06'``), it is appended
    to the packet for a total of 108 bytes.  This is the AMD SecureOn
    extension used by some managed network cards and switches.

    Args:
        mac:       Target MAC address in any common format.
        secure_on: Optional SecureOn password in MAC-style hex format
                   (any common delimiter accepted, e.g. ``'AA:BB:CC:DD:EE:FF'``).
                   Pass an empty string (the default) to send a standard
                   102-byte packet without a password.

    Returns:
        A 102- or 108-byte :class:`bytes` object.

    Raises:
        ValueError: if *mac* or *secure_on* is not a valid 48-bit address.
    """
    mac_bytes = _normalise_mac(mac)
    packet = b"\xff" * 6 + mac_bytes * 16
    if secure_on:
        packet += _normalise_mac(secure_on)
    return packet


def send_wol(
    mac: str,
    broadcast: str = "255.255.255.255",
    port: int = 9,
    secure_on: str = "",
) -> None:
    """Send a Wake-on-LAN magic packet for *mac*.

    The packet is sent as a UDP broadcast.  Most routers forward directed
    broadcasts to ``<subnet>.255``; use the subnet broadcast address if the
    target is on a different subnet.

    Args:
        mac:       Target MAC address.
        broadcast: Broadcast address (default ``255.255.255.255``).
        port:      UDP destination port – 7 or 9 are standard (default 9).
        secure_on: Optional SecureOn 6-byte password (MAC-style hex string).
                   When non-empty, it is appended to the magic packet.

    Raises:
        ValueError: if *mac* or *secure_on* is invalid.
        OSError:    if the socket cannot be created or the packet cannot
                    be sent.
    """
    packet = build_magic_packet(mac, secure_on=secure_on)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.connect((broadcast, port))
        sock.send(packet)
