"""
main.py – Interactive CLI for Wifi-Killer.

For educational and authorised lab use only.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from typing import Optional, Union

# Ensure the package root is importable when run directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_VERSION = "4.0.0"

from wifi_killer.modules.config import attack_config
from wifi_killer.modules.identifier import identify_host, format_host
from wifi_killer.utils.network import (
    get_default_gateway,
    get_interface_mac,
    get_interface_subnet,
    get_candidate_subnets,
    list_interfaces,
)

# ------------------------------------------------------------------ #
# Pretty helpers                                                       #
# ------------------------------------------------------------------ #

BANNER = r"""
 __        __  _  __ _       _  __ _  _ _
 \ \      / (_) |/ _(_)     | |/ /(_)| | | ___ _ __
  \ \ /\ / /| | | |_| |_____| ' / | || | |/ _ \ '__|
   \ V  V / | | |  _| |_____| . \ | || | |  __/ |
    \_/\_/  |_|_|_| |_|     |_|\_\|_||_|_|\___|_|

  Educational Wi-Fi control tool – authorised use only
"""

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"


def _c(text: str, color: str) -> str:
    return f"{color}{text}{_RESET}"


def _header(title: str) -> None:
    print(f"\n{_BOLD}{_CYAN}{'='*60}{_RESET}")
    print(f"{_BOLD}{_CYAN}  {title}{_RESET}")
    print(f"{_BOLD}{_CYAN}{'='*60}{_RESET}")


def _input(prompt: str) -> str:
    return input(f"{_YELLOW}[?]{_RESET} {prompt}").strip()


def _ok(msg: str) -> None:
    print(f"{_GREEN}[+]{_RESET} {msg}")


def _err(msg: str) -> None:
    print(f"{_RED}[!]{_RESET} {msg}")


def _info(msg: str) -> None:
    print(f"{_CYAN}[*]{_RESET} {msg}")


# ------------------------------------------------------------------ #
# Interface selection                                                  #
# ------------------------------------------------------------------ #

def select_interface() -> str:
    ifaces = list_interfaces()
    if not ifaces:
        _err("No active network interfaces found.")
        return _input("Enter interface name manually: ")
    _header("Select Network Interface")
    for i, iface in enumerate(ifaces, 1):
        mac = get_interface_mac(iface) or "?"
        subnet = get_interface_subnet(iface) or "?"
        print(f"  {i}. {iface}  [{mac}]  {subnet}")
    choice = _input(f"Choose interface [1-{len(ifaces)}] or enter name: ")
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(ifaces):
            return ifaces[idx]
    return choice


# ------------------------------------------------------------------ #
# Module 1 – Host Discovery                                            #
# ------------------------------------------------------------------ #

def menu_scan(iface: str, gateway_ip: str) -> list[dict]:
    _header("MODULE 1 – Host Discovery")
    print("  1. Fast Scan         (ARP broadcast, ~2 s)")
    print("  2. Balanced Scan     (ARP + ICMP, parallel)")
    print("  3. Stealth Scan      (TCP SYN to common ports)")
    print("  4. Continuous Monitor Mode")
    print("  5. Multi-Subnet Scan (auto-discover all reachable networks)")
    choice = _input("Choose scan type [1-5]: ")

    try:
        from wifi_killer.modules import scanner
    except ImportError as exc:
        _err(f"Scanner module unavailable: {exc}")
        return []

    subnet = get_interface_subnet(iface)
    if not subnet:
        subnet = _input("Enter subnet (e.g. 192.168.1.0/24): ")

    hosts: list[dict] = []

    if choice == "1":
        _info(f"Running fast ARP scan on {subnet} …")
        hosts = scanner.fast_scan(subnet=subnet, iface=iface, timeout=2.0)

    elif choice == "2":
        _info(f"Running balanced scan on {subnet} …")
        hosts = scanner.balanced_scan(subnet=subnet, iface=iface, timeout=2.0)

    elif choice == "3":
        delay_str = _input("Probe delay in seconds [default 0.5]: ") or "0.5"
        try:
            delay = float(delay_str)
        except ValueError:
            delay = 0.5
        _info(f"Running stealth TCP SYN scan on {subnet} with delay={delay}s …")
        hosts = scanner.stealth_scan(subnet=subnet, iface=iface, delay=delay)

    elif choice == "4":
        _run_monitor(subnet, iface, gateway_ip)
        return []

    elif choice == "5":
        hosts = _menu_multi_subnet(iface, gateway_ip)
        return hosts

    else:
        _err("Invalid choice.")
        return []

    _print_hosts(hosts, gateway_ip)
    return hosts


def _menu_multi_subnet(iface: str, gateway_ip: str) -> list[dict]:
    """Interactive multi-subnet scan wizard."""
    _header("Multi-Subnet Scan")

    _info("Detecting all reachable subnets …")
    candidates = get_candidate_subnets()

    if not candidates:
        _err("No candidate subnets detected. Enter manually.")
        candidates = []

    if candidates:
        _ok(f"Detected {len(candidates)} subnet(s):")
        for i, s in enumerate(candidates, 1):
            print(f"  {i:>3}. {s}")

    extra = _input("Add extra subnets (comma-separated CIDR, or Enter to skip): ")
    for cidr in extra.split(","):
        cidr = cidr.strip()
        if cidr and cidr not in candidates:
            candidates.append(cidr)

    if not candidates:
        _err("No subnets to scan.")
        return []

    scan_type_str = _input("Scan type [fast/balanced/stealth, default=fast]: ").lower() or "fast"
    workers_str = _input("Max parallel threads [default=8]: ") or "8"
    try:
        workers = int(workers_str)
    except ValueError:
        workers = 8

    completed = [0]

    def _progress(subnet: str, done: int, total: int) -> None:
        completed[0] = done
        pct = int(done / total * 100)
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r  [{bar}] {pct:3d}%  {done}/{total}  last: {subnet}   ", end="", flush=True)

    _info(f"Scanning {len(candidates)} subnet(s) with up to {workers} parallel thread(s) …")
    try:
        from wifi_killer.modules.scanner import multi_subnet_scan
        raw = multi_subnet_scan(
            subnets=candidates,
            iface=iface,
            scan_type=scan_type_str,
            max_workers=workers,
            progress_cb=_progress,
        )
    except Exception as exc:
        print()
        _err(f"Multi-subnet scan error: {exc}")
        return []

    print()  # newline after progress bar

    # Enrich results
    enriched: list[dict] = []
    for h in raw:
        info = identify_host(h["ip"], h["mac"],
                              open_ports=h.get("open_ports", []),
                              gateway_ip=gateway_ip)
        info["ping"] = h.get("ping", False)
        info["subnet"] = h.get("subnet", "")
        enriched.append(info)

    _print_hosts(enriched, gateway_ip)
    _ok(f"Multi-subnet scan complete: {len(enriched)} unique host(s) across {len(candidates)} subnet(s).")
    return enriched


def _print_hosts(hosts: list[dict], gateway_ip: str) -> None:
    if not hosts:
        _info("No hosts found.")
        return
    _ok(f"Found {len(hosts)} host(s):")
    for i, h in enumerate(hosts, 1):
        # Enrich with identification
        info = identify_host(
            h["ip"], h["mac"],
            open_ports=h.get("open_ports", []),
            gateway_ip=gateway_ip,
        )
        print(f"\n  [{i}] {_c(h['ip'], _BOLD)}")
        print(format_host(info))


def _run_monitor(subnet: str, iface: str, gateway_ip: str) -> None:
    interval_str = _input("Scan interval in seconds [default 30]: ") or "30"
    try:
        interval = float(interval_str)
    except ValueError:
        interval = 30.0

    from wifi_killer.modules.scanner import NetworkMonitor

    def on_new(host: dict) -> None:
        ts = time.strftime("%H:%M:%S")
        info = identify_host(host["ip"], host["mac"], gateway_ip=gateway_ip)
        print(f"\n{_GREEN}[{ts}] NEW DEVICE JOINED:{_RESET}")
        print(format_host(info, "JOINED"))

    def on_left(host: dict) -> None:
        ts = time.strftime("%H:%M:%S")
        print(
            f"\n{_RED}[{ts}] DEVICE LEFT: {host['ip']} "
            f"({host.get('vendor','?')}){_RESET}"
        )

    monitor = NetworkMonitor(
        subnet=subnet,
        iface=iface,
        interval=interval,
        on_new=on_new,
        on_left=on_left,
    )
    _info("Starting continuous monitor. Press Ctrl+C to stop.")
    monitor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    monitor.stop()
    _ok("Monitor stopped.")


# ------------------------------------------------------------------ #
# Module 3 – Attack / Control                                          #
# ------------------------------------------------------------------ #

def menu_attack(hosts: list[dict], iface: str, gateway_ip: str) -> None:
    _header("MODULE 3 – ARP Attack / Control")
    print("  A. Full MITM       (poison client ↔ gateway, bi-directional)")
    print("  B. Cut Client Only (tell client that gateway = attacker)")
    print("  C. Cut Gateway Only (tell gateway that client = attacker)")
    method = _input("Choose method [A/B/C]: ").upper()
    if method not in ("A", "B", "C"):
        _err("Invalid method.")
        return

    target = _select_target(hosts)
    if not target:
        return

    from wifi_killer.modules.attacker import ArpAttack, MultiTargetAttack

    if target == "ALL":
        attack: ArpAttack | MultiTargetAttack = MultiTargetAttack(
            method, hosts, gateway_ip, iface
        )
    else:
        attack = ArpAttack(method, target["ip"], gateway_ip, iface)

    try:
        attack.start()
        _info("Attack running. Press Ctrl+C to stop and restore ARP tables.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        attack.stop()


def _select_target(hosts: list[dict]) -> Union[dict, str, None]:
    if not hosts:
        _err("No hosts discovered. Run a scan first (Module 1).")
        return None

    print("\nDiscovered hosts:")
    for i, h in enumerate(hosts, 1):
        vendor = h.get("vendor", "?")
        print(f"  {i}. {h['ip']:18s} {h['mac']}  {vendor}")
    print("  0. ALL hosts")

    choice = _input("Select target [0 for all, or number, or IP]: ")
    if choice == "0":
        return "ALL"
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(hosts):
            return hosts[idx]
    # Try to match by IP
    for h in hosts:
        if h["ip"] == choice:
            return h

    _err("Invalid selection.")
    return None


# ------------------------------------------------------------------ #
# Module 4 – Speed Control                                             #
# ------------------------------------------------------------------ #

def menu_speed() -> None:
    _header("MODULE 4 – Speed / Intensity Control")
    print(f"\n  Current config:\n{attack_config.display()}\n")
    print("  1. Apply preset  (aggressive / normal / stealth)")
    print("  2. Manual config")
    choice = _input("Choose [1/2]: ")

    if choice == "1":
        preset = _input("Preset name [aggressive/normal/stealth]: ").lower()
        try:
            attack_config.apply_preset(preset)
            _ok(f"Applied preset '{preset}'.")
        except ValueError as exc:
            _err(str(exc))
    elif choice == "2":
        _manual_speed_config()


def _manual_speed_config() -> None:
    val = _input(f"Interval between bursts in seconds [{attack_config.interval}]: ")
    if val:
        try:
            attack_config.interval = float(val)
        except ValueError:
            pass

    val = _input(f"Burst size (ARP pkts per interval) [{attack_config.burst}]: ")
    if val:
        try:
            attack_config.burst = int(val)
        except ValueError:
            pass

    val = _input(f"Deauth frame count [{attack_config.deauth_count}]: ")
    if val:
        try:
            attack_config.deauth_count = int(val)
        except ValueError:
            pass

    val = _input(f"Deauth delay (s) [{attack_config.deauth_delay}]: ")
    if val:
        try:
            attack_config.deauth_delay = float(val)
        except ValueError:
            pass

    attack_config.preset = "custom"
    _ok("Configuration updated.")
    print(attack_config.display())


# ------------------------------------------------------------------ #
# Module 5 – MAC Anonymization                                         #
# ------------------------------------------------------------------ #

def menu_anonymize(iface: str) -> Optional[str]:
    _header("MODULE 5 – MAC Address Anonymization")
    current = get_interface_mac(iface)
    _info(f"Current MAC on {iface}: {current}")

    print("  1. Generate fully random MAC")
    print("  2. Generate random MAC (preserve vendor OUI)")
    print("  3. Enter specific MAC manually")
    print("  4. Restore original MAC")
    choice = _input("Choose [1-4]: ")

    from wifi_killer.modules.anonymizer import randomize_mac, restore_mac

    try:
        if choice == "1":
            new_mac = randomize_mac(iface)
            _ok(f"MAC changed to {new_mac}")
            return new_mac
        elif choice == "2":
            new_mac = randomize_mac(iface, preserve_oui=True)
            _ok(f"MAC changed to {new_mac}")
            return new_mac
        elif choice == "3":
            mac = _input("Enter MAC address (XX:XX:XX:XX:XX:XX): ")
            new_mac = randomize_mac(iface, new_mac=mac)
            _ok(f"MAC changed to {new_mac}")
            return new_mac
        elif choice == "4":
            if not current:
                _err("Cannot restore – original MAC unknown.")
                return None
            restore_mac(iface, current)
            _ok(f"MAC restored to {current}")
            return current
        else:
            _err("Invalid choice.")
    except RuntimeError as exc:
        _err(str(exc))
    return None


# ------------------------------------------------------------------ #
# Main menu                                                            #
# ------------------------------------------------------------------ #

# ------------------------------------------------------------------ #
# Input validation helpers                                             #
# ------------------------------------------------------------------ #

import re as _re
import ipaddress as _ipaddress


def _validate_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 address."""
    try:
        _ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def _validate_mac(mac: str) -> bool:
    """Return True if *mac* matches XX:XX:XX:XX:XX:XX format."""
    return bool(_re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac))


def _validate_iface(name: str) -> bool:
    """Return True if *name* looks like a valid interface name."""
    return bool(_re.fullmatch(r"[a-zA-Z0-9_.\-]+", name))


def _validate_cidr(cidr: str) -> bool:
    """Return True if *cidr* is a valid CIDR notation."""
    try:
        _ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        return False


# ------------------------------------------------------------------ #
# Report export                                                        #
# ------------------------------------------------------------------ #

def _export_report(hosts: list[dict], fmt: str, path: str,
                   gateway: str = "", iface: str = "",
                   scan_type: str = "fast") -> None:
    """Export scan results using the reporter module."""
    from wifi_killer.modules.reporter import ScanReport
    report = ScanReport(hosts, gateway=gateway, iface=iface, scan_type=scan_type)
    report.save(path, fmt=fmt)
    _ok(f"Report saved to {path} ({fmt})")


def menu_export(hosts: list[dict], gateway: str = "", iface: str = "") -> None:
    """Interactive report export menu."""
    _header("Export Scan Report")
    if not hosts:
        _err("No hosts to export. Run a scan first.")
        return
    print("  Formats: json, text, html, csv")
    fmt = _input("Choose format [json/text/html/csv]: ").lower() or "json"
    if fmt == "csv":
        fmt = "text"  # ScanReport doesn't have CSV, text is similar
    if fmt not in ("json", "text", "txt", "html"):
        _err(f"Unknown format '{fmt}'. Use json, text, or html.")
        return
    path = _input(f"Output file path [default: scan_report.{fmt}]: ")
    if not path:
        path = f"scan_report.{fmt}"
    try:
        _export_report(hosts, fmt, path, gateway=gateway, iface=iface)
    except Exception as exc:
        _err(f"Export failed: {exc}")


# ------------------------------------------------------------------ #
# Signal handler                                                       #
# ------------------------------------------------------------------ #

_active_attack = None


def _signal_handler(sig: int, frame) -> None:
    """Handle Ctrl+C for clean shutdown."""
    global _active_attack
    print()
    _info("Caught interrupt signal. Cleaning up…")
    if _active_attack is not None:
        try:
            _active_attack.stop()
            _ok("Attack stopped and ARP tables restored.")
        except Exception:
            pass
        _active_attack = None
    _info("Goodbye.")
    sys.exit(0)


# ------------------------------------------------------------------ #
# Non-interactive scan mode                                            #
# ------------------------------------------------------------------ #

def _scan_only(iface: str, scan_type: str = "fast",
               export_path: Optional[str] = None,
               export_fmt: str = "json") -> None:
    """Run a scan and print results non-interactively."""
    gateway_ip = get_default_gateway() or ""
    subnet = get_interface_subnet(iface)
    if not subnet:
        _err(f"Could not detect subnet for {iface}.")
        sys.exit(1)

    _info(f"Interface: {iface}   Gateway: {gateway_ip or '(unknown)'}")
    _info(f"Scanning {subnet} (type: {scan_type})…")

    try:
        from wifi_killer.modules import scanner
    except ImportError as exc:
        _err(f"Scanner module unavailable: {exc}")
        sys.exit(1)

    if scan_type == "balanced":
        hosts = scanner.balanced_scan(subnet=subnet, iface=iface, timeout=2.0)
    elif scan_type == "stealth":
        hosts = scanner.stealth_scan(subnet=subnet, iface=iface, delay=0.3)
    else:
        hosts = scanner.fast_scan(subnet=subnet, iface=iface, timeout=2.0)

    _print_hosts(hosts, gateway_ip)
    _ok(f"Scan complete: {len(hosts)} host(s) found.")

    if export_path:
        try:
            _export_report(hosts, export_fmt, export_path,
                          gateway=gateway_ip, iface=iface, scan_type=scan_type)
        except Exception as exc:
            _err(f"Export failed: {exc}")


# ------------------------------------------------------------------ #
# CLI argument parsing                                                 #
# ------------------------------------------------------------------ #

def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="wifi-killer",
        description="Educational Wi-Fi network control tool – authorised use only",
    )
    parser.add_argument("--version", action="version", version=f"wifi-killer {_VERSION}")
    parser.add_argument("--scan-only", action="store_true",
                        help="Run a single scan and exit (non-interactive)")
    parser.add_argument("--iface", type=str, default=None,
                        help="Network interface to use")
    parser.add_argument("--scan-type", type=str, default="fast",
                        choices=["fast", "balanced", "stealth"],
                        help="Scan type for --scan-only mode (default: fast)")
    parser.add_argument("--export", type=str, default=None, metavar="PATH",
                        help="Export scan results to file (use with --scan-only)")
    parser.add_argument("--export-fmt", type=str, default="json",
                        choices=["json", "text", "html"],
                        help="Export format (default: json)")
    return parser.parse_args()


# ------------------------------------------------------------------ #
# Main menu                                                            #
# ------------------------------------------------------------------ #

def main() -> None:
    args = _parse_args()

    # Install signal handler for clean Ctrl+C shutdown
    signal.signal(signal.SIGINT, _signal_handler)

    print(_c(BANNER, _CYAN))

    if os.geteuid() != 0:
        _err("This tool requires root privileges. Please run with sudo.")
        sys.exit(1)

    # Non-interactive scan-only mode
    if args.scan_only:
        iface = args.iface
        if not iface:
            ifaces = list_interfaces()
            if ifaces:
                iface = ifaces[0]
            else:
                _err("No active network interfaces found. Use --iface to specify.")
                sys.exit(1)
        _scan_only(iface, scan_type=args.scan_type,
                   export_path=args.export, export_fmt=args.export_fmt)
        return

    iface = args.iface or select_interface()
    gateway_ip = get_default_gateway() or ""
    _ok(f"Interface: {iface}   Gateway: {gateway_ip or '(unknown)'}")

    hosts: list[dict] = []
    global _active_attack

    while True:
        _header("Main Menu")
        print("  1. Host Discovery        (scan single network)")
        print("  2. Multi-Subnet Scan     (discover all reachable subnets)")
        print("  3. ARP Attack / Control  (cut off / MITM a device)")
        print("  4. Speed / Intensity     (configure attack timing)")
        print("  5. MAC Anonymization     (randomize interface MAC)")
        print("  6. Export Scan Report    (JSON/text/HTML)")
        print("  7. Change interface")
        print("  0. Exit")
        choice = _input("Choose option: ")

        if choice == "1":
            hosts = menu_scan(iface, gateway_ip)
        elif choice == "2":
            hosts = _menu_multi_subnet(iface, gateway_ip)
        elif choice == "3":
            menu_attack(hosts, iface, gateway_ip)
        elif choice == "4":
            menu_speed()
        elif choice == "5":
            menu_anonymize(iface)
        elif choice == "6":
            menu_export(hosts, gateway=gateway_ip, iface=iface)
        elif choice == "7":
            iface = select_interface()
            gateway_ip = get_default_gateway() or ""
            hosts = []
        elif choice == "0":
            _info("Goodbye.")
            break
        else:
            _err("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
