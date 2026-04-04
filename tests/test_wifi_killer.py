"""
Tests for wifi_killer – no root/Scapy required.

Covers:
  - OUI database lookup
  - Device-type inference
  - AttackConfig presets
  - MAC address generation
  - Network helpers (pure-Python, no actual network access)
"""

from __future__ import annotations

import pytest

# ------------------------------------------------------------------ #
# Module 2 – OUI & Identification                                      #
# ------------------------------------------------------------------ #


class TestOUIDatabase:
    def setup_method(self):
        from wifi_killer.modules.identifier import OUIDatabase
        self.db = OUIDatabase()

    def test_known_apple_oui(self):
        assert "Apple" in self.db.lookup("00:0A:95:AA:BB:CC")

    def test_known_amazon_oui(self):
        assert "Amazon" in self.db.lookup("C0:95:CF:11:22:33")

    def test_known_cisco_oui(self):
        assert "Cisco" in self.db.lookup("00:00:0C:01:02:03")

    def test_unknown_oui(self):
        assert self.db.lookup("00:00:00:00:00:00") == "Unknown"

    def test_case_insensitive(self):
        result_upper = self.db.lookup("C0:95:CF:00:00:00")
        result_lower = self.db.lookup("c0:95:cf:00:00:00")
        assert result_upper == result_lower

    def test_dash_delimiter(self):
        result = self.db.lookup("C0-95-CF-00-00-00")
        assert "Amazon" in result

    def test_short_mac_returns_unknown(self):
        assert self.db.lookup("AB:CD") == "Unknown"


class TestGuessDeviceType:
    def setup_method(self):
        from wifi_killer.modules.identifier import guess_device_type
        self.fn = guess_device_type

    def test_gateway_detection(self):
        result = self.fn("192.168.1.1", "AA:BB:CC:DD:EE:FF", "Cisco", "", [], "192.168.1.1")
        assert "Router" in result or "Gateway" in result

    def test_apple_device(self):
        result = self.fn("192.168.1.5", "00:0A:95:AA:BB:CC", "Apple Inc.", "", [], "192.168.1.1")
        assert "Apple" in result

    def test_amazon_device(self):
        result = self.fn("192.168.1.10", "C0:95:CF:00:00:01", "Amazon Technologies", "", [], "192.168.1.1")
        assert "Amazon" in result

    def test_windows_pc_via_ports(self):
        result = self.fn("192.168.1.20", "00:50:F2:00:00:01", "Unknown", "DESKTOP-XYZ", [445, 139], "192.168.1.1")
        assert "Windows" in result

    def test_tp_link_router(self):
        result = self.fn("192.168.1.30", "14:CF:92:AA:BB:CC", "TP-Link Technologies", "", [], "192.168.1.1")
        assert "Router" in result or "Access Point" in result

    def test_unknown_iot(self):
        result = self.fn("192.168.1.99", "DE:AD:BE:EF:CA:FE", "Unknown", "", [], "192.168.1.1")
        assert "Unknown" in result

    def test_raspberry_pi(self):
        result = self.fn("192.168.1.50", "B8:27:EB:00:00:01", "Raspberry Pi Foundation", "", [], "192.168.1.1")
        assert "Raspberry" in result


# ------------------------------------------------------------------ #
# Module 4 – AttackConfig                                              #
# ------------------------------------------------------------------ #


class TestAttackConfig:
    def setup_method(self):
        from wifi_killer.modules.config import AttackConfig
        self.cfg = AttackConfig()

    def test_default_preset(self):
        assert self.cfg.preset == "normal"
        assert self.cfg.interval == 2.0
        assert self.cfg.burst == 1

    def test_aggressive_preset(self):
        self.cfg.apply_preset("aggressive")
        assert self.cfg.preset == "aggressive"
        assert self.cfg.interval < 2.0
        assert self.cfg.burst > 1

    def test_stealth_preset(self):
        self.cfg.apply_preset("stealth")
        assert self.cfg.preset == "stealth"
        assert self.cfg.interval > 2.0

    def test_normal_preset(self):
        self.cfg.apply_preset("aggressive")  # change first
        self.cfg.apply_preset("normal")
        assert self.cfg.preset == "normal"
        assert self.cfg.interval == 2.0

    def test_invalid_preset(self):
        with pytest.raises(ValueError):
            self.cfg.apply_preset("turbo")

    def test_display_contains_interval(self):
        text = self.cfg.display()
        assert "Interval" in text

    def test_case_insensitive_preset(self):
        self.cfg.apply_preset("AGGRESSIVE")
        assert self.cfg.preset == "aggressive"


# ------------------------------------------------------------------ #
# Module 5 – MAC Generation                                            #
# ------------------------------------------------------------------ #


class TestMacGeneration:
    def setup_method(self):
        from wifi_killer.modules.anonymizer import _generate_random_mac, _is_valid_mac
        self.generate = _generate_random_mac
        self.valid = _is_valid_mac

    def test_format(self):
        mac = self.generate()
        assert self.valid(mac), f"Bad MAC format: {mac}"

    def test_unicast_bit(self):
        for _ in range(20):
            mac = self.generate()
            first_octet = int(mac.split(":")[0], 16)
            assert first_octet & 0x01 == 0, "Multicast bit should be 0"

    def test_locally_administered_bit(self):
        for _ in range(20):
            mac = self.generate()
            first_octet = int(mac.split(":")[0], 16)
            assert first_octet & 0x02 == 0x02, "LA bit should be 1"

    def test_preserve_oui(self):
        original = "00:0A:95:11:22:33"
        mac = self.generate(preserve_oui=True, original_mac=original)
        assert self.valid(mac)
        # OUI bytes should match (after masking LA bit back in)
        orig_oui = original.upper().split(":")[:3]
        new_oui = mac.upper().split(":")[:3]
        # First byte may differ only in LA bit
        assert new_oui[1] == orig_oui[1]
        assert new_oui[2] == orig_oui[2]

    def test_valid_mac_checker(self):
        assert self.valid("AA:BB:CC:DD:EE:FF")
        assert self.valid("00:11:22:33:44:55")
        assert not self.valid("ZZ:BB:CC:DD:EE:FF")
        assert not self.valid("AA:BB:CC:DD:EE")
        assert not self.valid("")

    def test_uniqueness(self):
        macs = {self.generate() for _ in range(50)}
        # Should produce mostly unique MACs
        assert len(macs) > 40


# ------------------------------------------------------------------ #
# Network utils (pure-Python, no socket calls)                         #
# ------------------------------------------------------------------ #


class TestNetworkUtils:
    def test_ip_int_roundtrip(self):
        from wifi_killer.utils.network import ip_to_int, int_to_ip
        for ip in ["192.168.1.1", "10.0.0.1", "172.16.0.1"]:
            assert int_to_ip(ip_to_int(ip)) == ip

    def test_int_to_ip_known(self):
        from wifi_killer.utils.network import int_to_ip
        # 192.168.1.1 = 0xC0A80101
        assert int_to_ip(0xC0A80101) == "192.168.1.1"

    def test_ip_to_int_known(self):
        from wifi_killer.utils.network import ip_to_int
        assert ip_to_int("192.168.1.1") == 0xC0A80101


# ------------------------------------------------------------------ #
# format_host                                                          #
# ------------------------------------------------------------------ #


class TestFormatHost:
    def test_format_contains_fields(self):
        from wifi_killer.modules.identifier import format_host
        info = {
            "ip": "192.168.1.5",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "Apple Inc.",
            "hostname": "macbook.local",
            "type": "Apple Mac",
            "open_ports": [22, 80],
        }
        text = format_host(info, "ONLINE")
        assert "192.168.1.5" in text
        assert "Apple Inc." in text
        assert "macbook.local" in text
        assert "ONLINE" in text
        assert "22" in text

    def test_format_empty_ports(self):
        from wifi_killer.modules.identifier import format_host
        info = {
            "ip": "10.0.0.1",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "Unknown",
            "hostname": "",
            "type": "Unknown Device",
            "open_ports": [],
        }
        text = format_host(info)
        assert "10.0.0.1" in text


# ------------------------------------------------------------------ #
# Throttler – pure-Python logic (no tc / root required)               #
# ------------------------------------------------------------------ #

class TestThrottler:
    def setup_method(self):
        from wifi_killer.modules.throttler import BandwidthThrottler, kbps_to_label, mbps_to_kbps
        self.Throttler = BandwidthThrottler
        self.kbps_to_label = kbps_to_label
        self.mbps_to_kbps = mbps_to_kbps

    def test_initial_state(self):
        t = self.Throttler("eth0")
        assert not t.is_setup
        assert t.active_targets == {}

    def test_active_targets_empty(self):
        t = self.Throttler("eth0")
        assert len(t.active_targets) == 0

    def test_class_id_allocation(self):
        """Calling set_speed twice should allocate different class IDs."""
        t = self.Throttler("eth0")
        # Bypass setup by directly manipulating internal state
        t._initialized = True
        # Patch _add_class, _update_class, _add_filter to no-ops
        t._add_class = lambda *a: None
        t._update_class = lambda *a: None
        t._add_filter = lambda *a: None

        t.set_speed("10.0.0.1", 1000, 500)
        t.set_speed("10.0.0.2", 2000, 1000)

        targets = t.active_targets
        assert "10.0.0.1" in targets
        assert "10.0.0.2" in targets

        dl1, ul1 = targets["10.0.0.1"]
        dl2, ul2 = targets["10.0.0.2"]
        # IDs must be unique across hosts
        assert len({dl1, ul1, dl2, ul2}) == 4

    def test_set_speed_updates_existing(self):
        """Calling set_speed for the same IP should call _update_class."""
        t = self.Throttler("eth0")
        t._initialized = True
        calls: list[str] = []
        t._add_class = lambda *a: calls.append("add")
        t._update_class = lambda *a: calls.append("update")
        t._add_filter = lambda *a: None

        t.set_speed("10.0.0.1", 1000, 500)
        t.set_speed("10.0.0.1", 2000, 1000)   # second call → update

        assert calls.count("add") == 2       # two classes created on first call
        assert calls.count("update") == 2    # two classes updated on second call

    def test_remove_clears_target(self):
        t = self.Throttler("eth0")
        t._initialized = True
        t._add_class = lambda *a: None
        t._update_class = lambda *a: None
        t._add_filter = lambda *a: None
        t._targets["10.0.0.1"] = (10, 11)

        # Patch the tc del call to a no-op so no real command is run
        import subprocess
        orig_run = __import__("wifi_killer.modules.throttler", fromlist=["_run"])._run
        import wifi_killer.modules.throttler as _mod
        _mod._run = lambda *a, **kw: None

        t.remove("10.0.0.1")
        assert "10.0.0.1" not in t.active_targets

        _mod._run = orig_run  # restore

    def test_remove_unknown_ip_noop(self):
        """Removing an IP that was never throttled should not raise."""
        t = self.Throttler("eth0")
        t._initialized = True
        t.remove("1.2.3.4")   # should not raise

    def test_set_speed_requires_setup(self):
        t = self.Throttler("eth0")
        with pytest.raises(RuntimeError, match="setup"):
            t.set_speed("10.0.0.1", 1000, 500)

    def test_get_speed_returns_ids(self):
        t = self.Throttler("eth0")
        t._targets["192.168.1.5"] = (10, 11)
        assert t.get_speed("192.168.1.5") == (10, 11)
        assert t.get_speed("1.2.3.4") is None

    def test_kbps_to_label_blocked(self):
        assert self.kbps_to_label(0) == "Blocked"

    def test_kbps_to_label_kbps(self):
        assert self.kbps_to_label(512) == "512 Kbps"

    def test_kbps_to_label_mbps_integer(self):
        assert self.kbps_to_label(10_000) == "10 Mbps"

    def test_kbps_to_label_mbps_fractional(self):
        assert self.kbps_to_label(1_500) == "1.5 Mbps"

    def test_mbps_to_kbps(self):
        assert self.mbps_to_kbps(1.5) == 1500
        assert self.mbps_to_kbps(10) == 10_000
        assert self.mbps_to_kbps(0) == 0
        assert self.mbps_to_kbps(-5) == 0   # negative clamped to 0

    def test_min_rate_enforcement(self):
        """0 kbps input is clamped to MIN_RATE_KBIT internally."""
        t = self.Throttler("eth0")
        t._initialized = True
        applied: list[tuple] = []
        t._add_class = lambda cid, rate: applied.append(("add", cid, rate))
        t._update_class = lambda *a: None
        t._add_filter = lambda *a: None

        t.set_speed("10.0.0.1", download_kbps=0, upload_kbps=0)
        # both classes should use MIN_RATE_KBIT (1), not 0
        assert all(rate == t._MIN_RATE_KBIT for _, _, rate in applied)


# ------------------------------------------------------------------ #
# Network subnet helpers                                              #
# ------------------------------------------------------------------ #

class TestSubnetHelpers:
    def test_split_no_op_for_24(self):
        from wifi_killer.utils.network import split_large_subnet
        result = split_large_subnet("192.168.1.0/24")
        assert result == ["192.168.1.0/24"]

    def test_split_16_into_24s(self):
        from wifi_killer.utils.network import split_large_subnet
        result = split_large_subnet("192.168.0.0/16", max_prefix=24)
        assert len(result) == 256
        assert "192.168.0.0/24" in result
        assert "192.168.255.0/24" in result

    def test_split_capped_at_1024(self):
        from wifi_killer.utils.network import split_large_subnet
        # /8 would produce 16 million /24s; must be capped
        result = split_large_subnet("10.0.0.0/8", max_prefix=24)
        assert len(result) <= 1024

    def test_split_invalid_cidr(self):
        from wifi_killer.utils.network import split_large_subnet
        # Should not raise, just return the input as-is
        result = split_large_subnet("not-a-cidr")
        assert result == ["not-a-cidr"]

    def test_get_candidate_subnets_returns_list(self):
        from wifi_killer.utils.network import get_candidate_subnets
        # Runs in a sandboxed env; may return empty list – just verify it doesn't crash
        result = get_candidate_subnets()
        assert isinstance(result, list)
        for item in result:
            assert "/" in item  # every item is CIDR notation

    def test_get_all_routes_returns_list(self):
        from wifi_killer.utils.network import get_all_routes
        result = get_all_routes()
        assert isinstance(result, list)



# ------------------------------------------------------------------ #
# GUI utility helpers – _ping_once, filter logic                      #
# ------------------------------------------------------------------ #

class TestPingOnce:
    def test_returns_float_or_none(self):
        """ping_once must return a non-negative float or None."""
        from wifi_killer.utils.network import ping_once
        result = ping_once("127.0.0.1", timeout=0.5)
        assert result is None or (isinstance(result, float) and result >= 0)

    def test_unreachable_host_returns_none(self):
        """An unrouteable address should produce None within the timeout."""
        from wifi_killer.utils.network import ping_once
        result = ping_once("192.0.2.1", timeout=0.3)   # RFC 5737 TEST-NET-1
        assert result is None

    def test_invalid_host_returns_none(self):
        """Garbage host string must not raise, just return None."""
        from wifi_killer.utils.network import ping_once
        result = ping_once("not-a-valid-host.invalid", timeout=0.3)
        assert result is None


class TestSearchFilter:
    """Unit-test the filter predicate used in ScanFrame._apply_filter."""

    @staticmethod
    def _matches(query: str, host: dict) -> bool:
        q = query.strip().lower()
        return any(
            q in str(host.get(k, "")).lower()
            for k in ("ip", "mac", "vendor", "hostname", "type")
        )

    def test_ip_match(self):
        h = {"ip": "192.168.1.42", "mac": "", "vendor": "", "hostname": "", "type": ""}
        assert self._matches("192.168.1", h)
        assert not self._matches("10.0.0", h)

    def test_vendor_match_case_insensitive(self):
        h = {"ip": "", "mac": "", "vendor": "Apple, Inc.", "hostname": "", "type": ""}
        assert self._matches("apple", h)
        assert self._matches("APPLE", h)
        assert not self._matches("samsung", h)

    def test_hostname_match(self):
        h = {"ip": "", "mac": "", "vendor": "", "hostname": "my-router", "type": ""}
        assert self._matches("router", h)

    def test_type_match(self):
        h = {"ip": "", "mac": "", "vendor": "", "hostname": "", "type": "Smartphone"}
        assert self._matches("smart", h)

    def test_empty_query_matches_everything(self):
        """Empty query → empty string is always a substring → matches all hosts."""
        h = {"ip": "10.0.0.1", "mac": "AA:BB:CC:DD:EE:FF",
             "vendor": "Test", "hostname": "host", "type": "PC"}
        # "" is in any string → the predicate returns True for every field
        assert self._matches("", h) is True

    def test_mac_match(self):
        h = {"ip": "", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "", "hostname": "", "type": ""}
        assert self._matches("AA:BB", h)
        assert self._matches("aa:bb", h)


class TestPingStatistics:
    """Verify the RTT statistics math used in PingMonitorFrame._update_row."""

    def _stats(self, samples):
        import statistics
        return {
            "last": samples[-1],
            "min":  min(samples),
            "avg":  statistics.mean(samples),
            "max":  max(samples),
        }

    def test_single_sample(self):
        s = self._stats([25.0])
        assert s["last"] == s["min"] == s["avg"] == s["max"] == 25.0

    def test_multi_sample(self):
        s = self._stats([10.0, 20.0, 30.0])
        assert s["min"] == 10.0
        assert s["avg"] == 20.0
        assert s["max"] == 30.0
        assert s["last"] == 30.0

    def test_colour_thresholds(self):
        """Verify the < 30 ms / < 100 ms colour-selection logic."""
        # Inline the colour constants (avoid tkinter import in test env)
        CLR_SUCCESS = "#64ffda"
        CLR_WARNING = "#ffb347"
        CLR_DANGER  = "#ff6b6b"

        def colour(rtt):
            return (
                CLR_SUCCESS if rtt < 30 else
                CLR_WARNING if rtt < 100 else
                CLR_DANGER
            )
        assert colour(5)   == CLR_SUCCESS
        assert colour(50)  == CLR_WARNING
        assert colour(200) == CLR_DANGER


# ------------------------------------------------------------------ #
# AttackConfig – paranoid preset                                       #
# ------------------------------------------------------------------ #

class TestParanoidPreset:
    def setup_method(self):
        from wifi_killer.modules.config import AttackConfig
        self.cfg = AttackConfig()

    def test_paranoid_preset_applies(self):
        self.cfg.apply_preset("paranoid")
        assert self.cfg.preset == "paranoid"

    def test_paranoid_interval_long(self):
        self.cfg.apply_preset("paranoid")
        # Must be longer than both stealth (10 s) and normal (2 s)
        assert self.cfg.interval >= 30.0

    def test_paranoid_burst_minimal(self):
        self.cfg.apply_preset("paranoid")
        assert self.cfg.burst == 1

    def test_paranoid_deauth_minimal(self):
        self.cfg.apply_preset("paranoid")
        assert self.cfg.deauth_count == 1

    def test_invalid_preset_still_raises(self):
        import pytest
        with pytest.raises(ValueError):
            self.cfg.apply_preset("turbo")

    def test_case_insensitive_paranoid(self):
        self.cfg.apply_preset("PARANOID")
        assert self.cfg.preset == "paranoid"

    def test_display_includes_interval(self):
        self.cfg.apply_preset("paranoid")
        text = self.cfg.display()
        assert "Interval" in text


# ------------------------------------------------------------------ #
# OS fingerprinting from TTL                                           #
# ------------------------------------------------------------------ #

class TestOsFingerprint:
    def setup_method(self):
        from wifi_killer.modules.identifier import os_fingerprint_from_ttl
        self.fn = os_fingerprint_from_ttl

    def test_linux_ttl_64(self):
        result = self.fn(64)
        assert "Linux" in result or "macOS" in result or "Android" in result

    def test_linux_ttl_low(self):
        result = self.fn(1)
        assert "Linux" in result or "macOS" in result

    def test_windows_ttl_128(self):
        result = self.fn(128)
        assert "Windows" in result

    def test_windows_ttl_mid(self):
        result = self.fn(100)
        assert "Windows" in result

    def test_cisco_ttl_255(self):
        result = self.fn(255)
        assert "Cisco" in result or "Network" in result

    def test_cisco_ttl_high(self):
        result = self.fn(200)
        assert "Cisco" in result or "Network" in result

    def test_zero_ttl_unknown(self):
        result = self.fn(0)
        assert "Unknown" in result

    def test_negative_ttl_unknown(self):
        result = self.fn(-1)
        assert "Unknown" in result


# ------------------------------------------------------------------ #
# identifier.identify_host – TTL adds os_hint                         #
# ------------------------------------------------------------------ #

class TestIdentifyHostTtl:
    def test_os_hint_absent_without_ttl(self):
        from wifi_killer.modules.identifier import identify_host
        info = identify_host("192.168.1.5", "00:0A:95:AA:BB:CC")
        assert "os_hint" not in info

    def test_os_hint_present_with_ttl(self):
        from wifi_killer.modules.identifier import identify_host
        info = identify_host("192.168.1.5", "00:0A:95:AA:BB:CC", ttl=64)
        assert "os_hint" in info

    def test_os_hint_windows(self):
        from wifi_killer.modules.identifier import identify_host
        info = identify_host("192.168.1.20", "AA:BB:CC:DD:EE:FF", ttl=128)
        assert "Windows" in info["os_hint"]


# ------------------------------------------------------------------ #
# New device-type hints                                                #
# ------------------------------------------------------------------ #

class TestExtendedDeviceTypes:
    def setup_method(self):
        from wifi_killer.modules.identifier import guess_device_type
        self.fn = guess_device_type

    def test_printer_hp(self):
        result = self.fn("192.168.1.50", "AA:BB:CC:DD:EE:FF",
                         "Hewlett Packard", "", [], "192.168.1.1")
        assert "Printer" in result

    def test_printer_canon(self):
        result = self.fn("192.168.1.51", "AA:BB:CC:DD:EE:FF",
                         "Canon Inc.", "", [], "192.168.1.1")
        assert "Printer" in result

    def test_sonos_speaker(self):
        result = self.fn("192.168.1.60", "AA:BB:CC:DD:EE:FF",
                         "Sonos Inc.", "", [], "192.168.1.1")
        assert "Sonos" in result

    def test_smart_home_philips(self):
        result = self.fn("192.168.1.70", "AA:BB:CC:DD:EE:FF",
                         "Philips Lighting", "", [], "192.168.1.1")
        assert "Smart Home" in result or "SmartHome" in result

    def test_smart_home_ring(self):
        result = self.fn("192.168.1.71", "AA:BB:CC:DD:EE:FF",
                         "Ring LLC", "", [], "192.168.1.1")
        assert "Smart Home" in result or "SmartHome" in result

    def test_ubiquiti_router(self):
        result = self.fn("192.168.1.1", "AA:BB:CC:DD:EE:FF",
                         "Ubiquiti Networks", "", [], "10.0.0.1")
        assert "Router" in result or "Access Point" in result

    def test_game_console_nintendo(self):
        result = self.fn("192.168.1.80", "AA:BB:CC:DD:EE:FF",
                         "Nintendo Co., Ltd.", "", [], "192.168.1.1")
        assert "Console" in result or "Game" in result

    def test_smart_tv_roku(self):
        result = self.fn("192.168.1.90", "AA:BB:CC:DD:EE:FF",
                         "Roku, Inc.", "", [], "192.168.1.1")
        assert "TV" in result or "Smart" in result


# ------------------------------------------------------------------ #
# Wake-on-LAN – SecureOn password                                     #
# ------------------------------------------------------------------ #

class TestWolSecureOn:
    def setup_method(self):
        from wifi_killer.modules.wol import build_magic_packet
        self.build = build_magic_packet

    def test_standard_packet_length(self):
        pkt = self.build("AA:BB:CC:DD:EE:FF")
        assert len(pkt) == 102

    def test_secureon_packet_length(self):
        pkt = self.build("AA:BB:CC:DD:EE:FF", secure_on="01:02:03:04:05:06")
        assert len(pkt) == 108

    def test_secureon_password_appended(self):
        pkt = self.build("AA:BB:CC:DD:EE:FF", secure_on="11:22:33:44:55:66")
        # Last 6 bytes should be the SecureOn password
        assert pkt[-6:] == bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

    def test_standard_starts_with_ff(self):
        pkt = self.build("AA:BB:CC:DD:EE:FF")
        assert pkt[:6] == b"\xff" * 6

    def test_empty_secureon_is_standard(self):
        pkt_no_pwd = self.build("AA:BB:CC:DD:EE:FF", secure_on="")
        pkt_std = self.build("AA:BB:CC:DD:EE:FF")
        assert pkt_no_pwd == pkt_std

    def test_invalid_secureon_raises(self):
        import pytest
        with pytest.raises(ValueError):
            self.build("AA:BB:CC:DD:EE:FF", secure_on="ZZ:ZZ:ZZ:ZZ:ZZ:ZZ")

    def test_secureon_dash_delimiter(self):
        pkt = self.build("AA:BB:CC:DD:EE:FF", secure_on="01-02-03-04-05-06")
        assert len(pkt) == 108
        assert pkt[-6:] == bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])


# ------------------------------------------------------------------ #
# Reporter – ScanReport                                                #
# ------------------------------------------------------------------ #

_SAMPLE_HOSTS = [
    {
        "ip": "192.168.1.10",
        "mac": "AA:BB:CC:DD:EE:01",
        "vendor": "Apple Inc.",
        "hostname": "macbook.local",
        "type": "Apple Mac",
        "open_ports": [22, 80],
    },
    {
        "ip": "192.168.1.20",
        "mac": "AA:BB:CC:DD:EE:02",
        "vendor": "Unknown",
        "hostname": "",
        "type": "Unknown IoT Device",
        "open_ports": [],
        "os_hint": "Linux / macOS / Android",
    },
]


class TestScanReportJson:
    def setup_method(self):
        from wifi_killer.modules.reporter import ScanReport
        self.report = ScanReport(
            _SAMPLE_HOSTS,
            gateway="192.168.1.1",
            iface="eth0",
            scan_type="fast",
            generated_at="2025-01-01 12:00:00",
        )

    def test_json_is_valid(self):
        import json
        data = json.loads(self.report.to_json())
        assert data["host_count"] == 2

    def test_json_contains_hosts(self):
        import json
        data = json.loads(self.report.to_json())
        ips = [h["ip"] for h in data["hosts"]]
        assert "192.168.1.10" in ips
        assert "192.168.1.20" in ips

    def test_json_metadata(self):
        import json
        data = json.loads(self.report.to_json())
        assert data["gateway"] == "192.168.1.1"
        assert data["interface"] == "eth0"
        assert data["scan_type"] == "fast"

    def test_json_generated_at(self):
        import json
        data = json.loads(self.report.to_json())
        assert data["generated_at"] == "2025-01-01 12:00:00"


class TestScanReportText:
    def setup_method(self):
        from wifi_killer.modules.reporter import ScanReport
        self.report = ScanReport(
            _SAMPLE_HOSTS,
            gateway="192.168.1.1",
            iface="eth0",
            scan_type="balanced",
            generated_at="2025-01-01 12:00:00",
        )

    def test_text_contains_ips(self):
        text = self.report.to_text()
        assert "192.168.1.10" in text
        assert "192.168.1.20" in text

    def test_text_contains_vendor(self):
        text = self.report.to_text()
        assert "Apple Inc." in text

    def test_text_contains_ports(self):
        text = self.report.to_text()
        assert "22" in text
        assert "80" in text

    def test_text_contains_os_hint(self):
        text = self.report.to_text()
        assert "Linux" in text or "OS Hint" in text

    def test_text_no_ports_dash(self):
        text = self.report.to_text()
        # The host with no open ports should show a dash
        assert "—" in text

    def test_text_contains_gateway(self):
        text = self.report.to_text()
        assert "192.168.1.1" in text


class TestScanReportHtml:
    def setup_method(self):
        from wifi_killer.modules.reporter import ScanReport
        self.report = ScanReport(
            _SAMPLE_HOSTS,
            gateway="192.168.1.1",
            iface="eth0",
            scan_type="stealth",
            generated_at="2025-01-01 12:00:00",
        )

    def test_html_is_string(self):
        html = self.report.to_html()
        assert isinstance(html, str)

    def test_html_doctype(self):
        assert self.report.to_html().startswith("<!DOCTYPE html>")

    def test_html_contains_ips(self):
        html = self.report.to_html()
        assert "192.168.1.10" in html
        assert "192.168.1.20" in html

    def test_html_contains_vendor(self):
        html = self.report.to_html()
        assert "Apple Inc." in html

    def test_html_xss_escaping(self):
        from wifi_killer.modules.reporter import ScanReport
        malicious_hosts = [{
            "ip": "<script>alert(1)</script>",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "Unknown",
            "hostname": "",
            "type": "Unknown",
            "open_ports": [],
        }]
        html = ScanReport(malicious_hosts).to_html()
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


class TestScanReportSave:
    def test_save_json(self, tmp_path):
        import json
        from wifi_killer.modules.reporter import ScanReport
        path = str(tmp_path / "out.json")
        ScanReport(_SAMPLE_HOSTS).save(path, fmt="json")
        with open(path) as f:
            data = json.load(f)
        assert data["host_count"] == 2

    def test_save_text(self, tmp_path):
        from wifi_killer.modules.reporter import ScanReport
        path = str(tmp_path / "out.txt")
        ScanReport(_SAMPLE_HOSTS).save(path, fmt="text")
        content = open(path).read()
        assert "192.168.1.10" in content

    def test_save_html(self, tmp_path):
        from wifi_killer.modules.reporter import ScanReport
        path = str(tmp_path / "out.html")
        ScanReport(_SAMPLE_HOSTS).save(path, fmt="html")
        content = open(path).read()
        assert "<!DOCTYPE html>" in content

    def test_save_unknown_format_raises(self, tmp_path):
        import pytest
        from wifi_killer.modules.reporter import ScanReport
        with pytest.raises(ValueError):
            ScanReport(_SAMPLE_HOSTS).save(str(tmp_path / "x.xyz"), fmt="xml")

    def test_save_txt_alias(self, tmp_path):
        from wifi_killer.modules.reporter import ScanReport
        path = str(tmp_path / "out.txt")
        ScanReport(_SAMPLE_HOSTS).save(path, fmt="txt")
        assert open(path).read().strip() != ""

    def test_auto_generated_at(self):
        from wifi_killer.modules.reporter import ScanReport
        import re
        r = ScanReport(_SAMPLE_HOSTS)
        # Should look like YYYY-MM-DD HH:MM:SS
        assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", r.generated_at)

    def test_empty_hosts(self):
        from wifi_killer.modules.reporter import ScanReport
        r = ScanReport([])
        assert r.to_text().count("host_count") == 0 or True  # just no crash
        import json
        data = json.loads(r.to_json())
        assert data["host_count"] == 0


# ------------------------------------------------------------------ #
# DNS Sniffer – pure-Python logic (no Scapy/root required)           #
# ------------------------------------------------------------------ #

class TestDnsSnifferQtype:
    """Test the _qtype_name helper and _QTYPE_MAP coverage."""

    def setup_method(self):
        from wifi_killer.modules.dns_sniffer import _qtype_name, _QTYPE_MAP
        self.qtype_name = _qtype_name
        self.qtype_map = _QTYPE_MAP

    def test_a_record(self):
        assert self.qtype_name(1) == "A"

    def test_aaaa_record(self):
        assert self.qtype_name(28) == "AAAA"

    def test_mx_record(self):
        assert self.qtype_name(15) == "MX"

    def test_ns_record(self):
        assert self.qtype_name(2) == "NS"

    def test_cname_record(self):
        assert self.qtype_name(5) == "CNAME"

    def test_soa_record(self):
        assert self.qtype_name(6) == "SOA"

    def test_ptr_record(self):
        assert self.qtype_name(12) == "PTR"

    def test_txt_record(self):
        assert self.qtype_name(16) == "TXT"

    def test_srv_record(self):
        assert self.qtype_name(33) == "SRV"

    def test_any_record(self):
        assert self.qtype_name(255) == "ANY"

    def test_caa_record(self):
        assert self.qtype_name(257) == "CAA"

    def test_unknown_type_returns_typeN(self):
        assert self.qtype_name(9999) == "TYPE9999"

    def test_zero_type(self):
        assert self.qtype_name(0) == "TYPE0"


class TestDnsSnifferInit:
    """Test DnsSniffer initialization and state without requiring Scapy."""

    def test_initial_state(self):
        from wifi_killer.modules.dns_sniffer import DnsSniffer
        sniffer = DnsSniffer(iface="eth0", target_ip="192.168.1.5")
        assert sniffer.queries == []
        assert not sniffer.is_running

    def test_clear_queries(self):
        from wifi_killer.modules.dns_sniffer import DnsSniffer
        sniffer = DnsSniffer()
        # Manually inject a query
        sniffer._queries.append({"domain": "test.com"})
        assert len(sniffer.queries) == 1
        sniffer.clear()
        assert sniffer.queries == []

    def test_queries_returns_copy(self):
        from wifi_killer.modules.dns_sniffer import DnsSniffer
        sniffer = DnsSniffer()
        sniffer._queries.append({"domain": "a.com"})
        snapshot = sniffer.queries
        sniffer._queries.append({"domain": "b.com"})
        assert len(snapshot) == 1  # snapshot is not affected

    def test_export_csv(self, tmp_path):
        import csv
        from wifi_killer.modules.dns_sniffer import DnsSniffer
        sniffer = DnsSniffer()
        sniffer._queries.extend([
            {"timestamp": "2025-01-01 12:00:00", "src_ip": "10.0.0.1",
             "domain": "example.com", "query_type": "A"},
            {"timestamp": "2025-01-01 12:00:01", "src_ip": "10.0.0.2",
             "domain": "test.org", "query_type": "AAAA"},
        ])
        path = str(tmp_path / "dns.csv")
        sniffer.export_csv(path)
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["domain"] == "example.com"
        assert rows[1]["query_type"] == "AAAA"

    def test_export_csv_empty(self, tmp_path):
        from wifi_killer.modules.dns_sniffer import DnsSniffer
        sniffer = DnsSniffer()
        path = str(tmp_path / "empty.csv")
        sniffer.export_csv(path)
        with open(path) as f:
            content = f.read()
        assert "timestamp" in content  # header row still present


# ------------------------------------------------------------------ #
# ARP Cache – parsing and poisoning detection                         #
# ------------------------------------------------------------------ #

class TestArpCacheFlags:
    """Test _flags_to_state helper."""

    def setup_method(self):
        from wifi_killer.modules.arp_cache import _flags_to_state
        self.fn = _flags_to_state

    def test_complete_flag(self):
        assert self.fn("0x2") == "REACHABLE"

    def test_incomplete_flag(self):
        assert self.fn("0x0") == "INCOMPLETE"

    def test_permanent_flag(self):
        assert self.fn("0x6") == "PERMANENT"

    def test_noarp_flag(self):
        assert self.fn("0x4") == "NOARP"

    def test_invalid_string(self):
        assert self.fn("invalid") == "UNKNOWN"

    def test_empty_string(self):
        assert self.fn("") == "UNKNOWN"

    def test_decimal_input(self):
        assert self.fn("2") == "REACHABLE"


class TestArpCacheDetectPoisoning:
    """Test detect_poisoning with synthetic ARP entries."""

    def setup_method(self):
        from wifi_killer.modules.arp_cache import detect_poisoning
        self.fn = detect_poisoning

    def test_no_poisoning(self):
        entries = [
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01"},
            {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:02"},
        ]
        warnings = self.fn(entries)
        assert warnings == []

    def test_duplicate_mac_detected(self):
        entries = [
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01"},
            {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:01"},
        ]
        warnings = self.fn(entries)
        assert len(warnings) == 1
        assert "AA:BB:CC:DD:EE:01" in warnings[0]["mac"]
        assert len(warnings[0]["ips"]) == 2

    def test_incomplete_mac_skipped(self):
        entries = [
            {"ip": "192.168.1.1", "mac": "00:00:00:00:00:00"},
            {"ip": "192.168.1.2", "mac": "00:00:00:00:00:00"},
        ]
        warnings = self.fn(entries)
        assert warnings == []

    def test_empty_entries(self):
        assert self.fn([]) == []

    def test_three_ips_one_mac(self):
        entries = [
            {"ip": "10.0.0.1", "mac": "FF:FF:FF:FF:FF:01"},
            {"ip": "10.0.0.2", "mac": "FF:FF:FF:FF:FF:01"},
            {"ip": "10.0.0.3", "mac": "FF:FF:FF:FF:FF:01"},
        ]
        warnings = self.fn(entries)
        assert len(warnings) == 1
        assert len(warnings[0]["ips"]) == 3

    def test_warning_message_content(self):
        entries = [
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF"},
            {"ip": "192.168.1.99", "mac": "AA:BB:CC:DD:EE:FF"},
        ]
        warnings = self.fn(entries)
        assert "Possible ARP poisoning" in warnings[0]["warning"]


class TestArpCacheFormatTable:
    """Test format_arp_table output."""

    def setup_method(self):
        from wifi_killer.modules.arp_cache import format_arp_table
        self.fn = format_arp_table

    def test_empty_entries(self):
        assert self.fn([]) == "(ARP cache is empty)"

    def test_single_entry_formatting(self):
        entries = [{
            "ip": "192.168.1.1",
            "mac": "AA:BB:CC:DD:EE:FF",
            "state": "REACHABLE",
            "interface": "eth0",
        }]
        text = self.fn(entries)
        assert "192.168.1.1" in text
        assert "AA:BB:CC:DD:EE:FF" in text
        assert "REACHABLE" in text
        assert "eth0" in text

    def test_header_present(self):
        entries = [{
            "ip": "10.0.0.1",
            "mac": "11:22:33:44:55:66",
            "state": "STALE",
            "interface": "wlan0",
        }]
        text = self.fn(entries)
        assert "IP Address" in text
        assert "MAC Address" in text

    def test_multiple_entries(self):
        entries = [
            {"ip": "10.0.0.1", "mac": "AA:AA:AA:AA:AA:AA",
             "state": "REACHABLE", "interface": "eth0"},
            {"ip": "10.0.0.2", "mac": "BB:BB:BB:BB:BB:BB",
             "state": "STALE", "interface": "eth0"},
        ]
        text = self.fn(entries)
        assert "10.0.0.1" in text
        assert "10.0.0.2" in text


# ------------------------------------------------------------------ #
# Session Logger – file I/O and entries                               #
# ------------------------------------------------------------------ #

class TestSessionLogger:
    """Test SessionLogger without requiring ~/.wifi_killer directory."""

    def test_log_and_get_entries(self, tmp_path):
        from wifi_killer.modules.session_logger import SessionLogger
        logger = SessionLogger(session_dir=str(tmp_path))
        logger.log("test_action", {"key": "value"})
        entries = logger.get_entries()
        # First entry is session_start, second is test_action
        assert len(entries) >= 2
        assert entries[0]["action"] == "session_start"
        assert entries[-1]["action"] == "test_action"
        assert entries[-1]["details"]["key"] == "value"

    def test_session_path(self, tmp_path):
        from wifi_killer.modules.session_logger import SessionLogger
        logger = SessionLogger(session_dir=str(tmp_path))
        assert str(tmp_path) in logger.session_path
        assert "session_" in logger.session_path
        assert logger.session_path.endswith(".jsonl")

    def test_log_without_details(self, tmp_path):
        from wifi_killer.modules.session_logger import SessionLogger
        logger = SessionLogger(session_dir=str(tmp_path))
        logger.log("simple_event")
        entries = logger.get_entries()
        last = entries[-1]
        assert last["action"] == "simple_event"
        assert "details" not in last

    def test_close_logs_session_end(self, tmp_path):
        from wifi_killer.modules.session_logger import SessionLogger
        logger = SessionLogger(session_dir=str(tmp_path))
        logger.close()
        entries = logger.get_entries()
        assert entries[-1]["action"] == "session_end"

    def test_export_json(self, tmp_path):
        import json
        from wifi_killer.modules.session_logger import SessionLogger
        logger = SessionLogger(session_dir=str(tmp_path / "sessions"))
        logger.log("scan", {"hosts": 5})
        export_path = str(tmp_path / "export.json")
        logger.export(export_path, fmt="json")
        with open(export_path) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) >= 2

    def test_export_text(self, tmp_path):
        from wifi_killer.modules.session_logger import SessionLogger
        logger = SessionLogger(session_dir=str(tmp_path / "sessions"))
        logger.log("attack_start")
        export_path = str(tmp_path / "export.txt")
        logger.export(export_path, fmt="text")
        with open(export_path) as f:
            content = f.read()
        assert "attack_start" in content

    def test_export_invalid_format(self, tmp_path):
        from wifi_killer.modules.session_logger import SessionLogger
        logger = SessionLogger(session_dir=str(tmp_path))
        with pytest.raises(ValueError, match="Unknown export format"):
            logger.export(str(tmp_path / "out.xml"), fmt="xml")

    def test_entries_have_timestamps(self, tmp_path):
        from wifi_killer.modules.session_logger import SessionLogger
        logger = SessionLogger(session_dir=str(tmp_path))
        logger.log("check")
        entries = logger.get_entries()
        for entry in entries:
            assert "timestamp" in entry


# ------------------------------------------------------------------ #
# Packet Capture – initialization and state (no Scapy needed)         #
# ------------------------------------------------------------------ #

class TestPacketCaptureInit:
    """Test PacketCapture initialization without Scapy."""

    def test_initial_state(self):
        from wifi_killer.modules.packet_capture import PacketCapture
        cap = PacketCapture(iface="eth0", target_ip="10.0.0.5")
        assert cap.packet_count == 0
        assert cap.byte_count == 0
        assert not cap.is_running

    def test_initial_state_no_args(self):
        from wifi_killer.modules.packet_capture import PacketCapture
        cap = PacketCapture()
        assert cap.packet_count == 0
        assert not cap.is_running

    def test_clear_resets_counters(self):
        from wifi_killer.modules.packet_capture import PacketCapture
        cap = PacketCapture()
        cap._packet_count = 100
        cap._byte_count = 5000
        cap._packets = ["fake"] * 100
        cap.clear()
        assert cap.packet_count == 0
        assert cap.byte_count == 0

    def test_save_raises_when_empty(self):
        from wifi_killer.modules.packet_capture import PacketCapture, SCAPY_AVAILABLE
        cap = PacketCapture()
        if SCAPY_AVAILABLE:
            with pytest.raises(ValueError, match="No packets"):
                cap.save("/tmp/test.pcap")

    def test_start_raises_without_scapy(self):
        from wifi_killer.modules.packet_capture import PacketCapture, SCAPY_AVAILABLE
        if not SCAPY_AVAILABLE:
            cap = PacketCapture()
            with pytest.raises(RuntimeError, match="Scapy"):
                cap.start()


# ------------------------------------------------------------------ #
# Anonymizer – stored original MAC tracking                           #
# ------------------------------------------------------------------ #

class TestAnonymizerStoredOriginals:
    """Test the _stored_originals tracking for MAC restore."""

    def test_get_original_mac_empty(self):
        from wifi_killer.modules.anonymizer import get_original_mac
        # Non-existent interface returns None
        result = get_original_mac("nonexistent_iface_xyz")
        assert result is None

    def test_store_and_get_original(self):
        from wifi_killer.modules import anonymizer
        # Directly manipulate _stored_originals to verify get_original_mac
        anonymizer._stored_originals["test_iface"] = "AA:BB:CC:DD:EE:FF"
        assert anonymizer.get_original_mac("test_iface") == "AA:BB:CC:DD:EE:FF"
        # Cleanup
        del anonymizer._stored_originals["test_iface"]

    def test_restore_mac_raises_without_stored(self):
        from wifi_killer.modules.anonymizer import restore_mac
        with pytest.raises(RuntimeError, match="No original MAC"):
            restore_mac("nonexistent_iface_xyz_999")

    def test_valid_mac_format(self):
        from wifi_killer.modules.anonymizer import _is_valid_mac
        assert _is_valid_mac("AA:BB:CC:DD:EE:FF")
        assert _is_valid_mac("00:11:22:33:44:55")
        assert not _is_valid_mac("ZZZZ")
        assert not _is_valid_mac("AA:BB:CC:DD:EE")
        assert not _is_valid_mac("")
        assert not _is_valid_mac("AA-BB-CC-DD-EE-FF")


# ------------------------------------------------------------------ #
# Input validation helpers (from main.py)                             #
# ------------------------------------------------------------------ #

class TestInputValidation:
    """Test the CLI input validation helpers."""

    def setup_method(self):
        from wifi_killer.main import _validate_ip, _validate_mac, _validate_iface, _validate_cidr
        self.validate_ip = _validate_ip
        self.validate_mac = _validate_mac
        self.validate_iface = _validate_iface
        self.validate_cidr = _validate_cidr

    def test_valid_ipv4(self):
        assert self.validate_ip("192.168.1.1")
        assert self.validate_ip("10.0.0.1")
        assert self.validate_ip("255.255.255.255")
        assert self.validate_ip("0.0.0.0")

    def test_invalid_ipv4(self):
        assert not self.validate_ip("999.999.999.999")
        assert not self.validate_ip("abc")
        assert not self.validate_ip("")
        assert not self.validate_ip("192.168.1")
        assert not self.validate_ip("192.168.1.1.1")

    def test_valid_mac(self):
        assert self.validate_mac("AA:BB:CC:DD:EE:FF")
        assert self.validate_mac("00:11:22:33:44:55")
        assert self.validate_mac("aa:bb:cc:dd:ee:ff")

    def test_invalid_mac(self):
        assert not self.validate_mac("AA:BB:CC:DD:EE")
        assert not self.validate_mac("ZZ:BB:CC:DD:EE:FF")
        assert not self.validate_mac("AA-BB-CC-DD-EE-FF")
        assert not self.validate_mac("")

    def test_valid_iface(self):
        assert self.validate_iface("eth0")
        assert self.validate_iface("wlan0")
        assert self.validate_iface("br-lan")
        assert self.validate_iface("veth123.4")

    def test_invalid_iface(self):
        assert not self.validate_iface("")
        assert not self.validate_iface("eth 0")
        assert not self.validate_iface("eth/0")

    def test_valid_cidr(self):
        assert self.validate_cidr("192.168.1.0/24")
        assert self.validate_cidr("10.0.0.0/8")
        assert self.validate_cidr("172.16.0.0/12")

    def test_invalid_cidr(self):
        assert not self.validate_cidr("not-a-cidr")
        assert not self.validate_cidr("")
        assert not self.validate_cidr("192.168.1.0/33")


# ------------------------------------------------------------------ #
# CLI argument parsing                                                 #
# ------------------------------------------------------------------ #

class TestCliArgParsing:
    """Test the argparse configuration in main.py."""

    def setup_method(self):
        from wifi_killer.main import _parse_args
        self.parse = _parse_args

    def test_default_args(self):
        import sys
        orig = sys.argv
        sys.argv = ["wifi-killer"]
        args = self.parse()
        assert not args.scan_only
        assert args.iface is None
        assert args.scan_type == "fast"
        assert args.export is None
        assert args.export_fmt == "json"
        sys.argv = orig

    def test_scan_only_flag(self):
        import sys
        orig = sys.argv
        sys.argv = ["wifi-killer", "--scan-only", "--iface", "wlan0"]
        args = self.parse()
        assert args.scan_only
        assert args.iface == "wlan0"
        sys.argv = orig

    def test_scan_type_choices(self):
        import sys
        orig = sys.argv
        for st in ("fast", "balanced", "stealth"):
            sys.argv = ["wifi-killer", "--scan-type", st]
            args = self.parse()
            assert args.scan_type == st
        sys.argv = orig

    def test_export_options(self):
        import sys
        orig = sys.argv
        sys.argv = ["wifi-killer", "--scan-only", "--export", "/tmp/out.json",
                     "--export-fmt", "html"]
        args = self.parse()
        assert args.export == "/tmp/out.json"
        assert args.export_fmt == "html"
        sys.argv = orig

    def test_invalid_scan_type_raises(self):
        import sys
        orig = sys.argv
        sys.argv = ["wifi-killer", "--scan-type", "invalid"]
        with pytest.raises(SystemExit):
            self.parse()
        sys.argv = orig


# ------------------------------------------------------------------ #
# _default_iface moved to utils/network                               #
# ------------------------------------------------------------------ #

class TestDefaultIface:
    """Test that _default_iface is available from utils.network."""

    def test_returns_string(self):
        from wifi_killer.utils.network import _default_iface
        result = _default_iface()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_fallback_is_eth0(self):
        from wifi_killer.utils import network
        orig = network.list_interfaces
        network.list_interfaces = lambda: []
        try:
            result = network._default_iface()
            assert result == "eth0"
        finally:
            network.list_interfaces = orig


# ------------------------------------------------------------------ #
# Throttler – IP forwarding helpers (read-only tests)                 #
# ------------------------------------------------------------------ #

class TestIpForwardHelpers:
    def test_get_ip_forward_returns_bool(self):
        from wifi_killer.modules.throttler import get_ip_forward
        result = get_ip_forward()
        assert isinstance(result, bool)


# ------------------------------------------------------------------ #
# Network helpers – additional coverage                                #
# ------------------------------------------------------------------ #

class TestNetworkHelpersExtended:
    def test_list_interfaces_returns_list(self):
        from wifi_killer.utils.network import list_interfaces
        result = list_interfaces()
        assert isinstance(result, list)

    def test_get_default_gateway_returns_str_or_none(self):
        from wifi_killer.utils.network import get_default_gateway
        result = get_default_gateway()
        assert result is None or isinstance(result, str)

    def test_list_all_subnets_returns_list(self):
        from wifi_killer.utils.network import list_all_subnets
        result = list_all_subnets()
        assert isinstance(result, list)

