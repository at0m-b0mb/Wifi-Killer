<div align="center">

# 📡 Wifi-Killer

**A modern, educational Wi-Fi network control & analysis toolkit**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)](https://kernel.org)
[![GUI](https://img.shields.io/badge/GUI-CustomTkinter-purple?style=flat-square)](https://github.com/TomSchimansky/CustomTkinter)

> ⚠️ **For educational and authorised lab/CTF use only.**  
> Always obtain explicit permission before scanning or attacking any network you do not own.

</div>

---

## ✨ Features

| Feature | CLI | GUI |
|---|---|---|
| 📊 **Live dashboard** with stat cards and recent-device feed | ❌ | ✅ |
| 🔍 **Fast ARP host discovery** | ✅ | ✅ |
| 🔍 **Balanced scan (ARP + ICMP)** | ✅ | ✅ |
| 🔍 **Stealth TCP SYN scan** | ✅ | ✅ |
| 🔎 **Real-time search & filter** across the host table | ❌ | ✅ |
| ℹ️ **Host detail popup** with live RTT ping & action shortcuts | ❌ | ✅ |
| 🌐 **Multi-subnet scan** (auto-detect all network segments) | ✅ | ✅ |
| 📡 **Continuous network monitor** (join/leave alerts) | ✅ | ✅ |
| 🏷️ **Device identification** (vendor, hostname, type) | ✅ | ✅ |
| ⚡ **Full MITM** ARP-spoof (bi-directional) | ✅ | ✅ |
| ⚡ **Client-cut / Gateway-cut** ARP-spoof | ✅ | ✅ |
| 🚦 **Client speed control** (download/upload sliders via `tc` HTB) | ❌ | ✅ |
| 🏓 **Ping Monitor** – live RTT table for multiple hosts | ❌ | ✅ |
| 🎭 **MAC address anonymization** (random / OUI-preserve / custom) | ✅ | ✅ |
| ⚙️ **Attack speed presets** (aggressive / normal / stealth) | ✅ | ✅ |
| 💾 **Export scan results** to CSV or JSON | ❌ | ✅ |
| 📋 **Colour-coded activity log** | ❌ | ✅ |
| 🖥️ **Modern dark-themed GUI** | ❌ | ✅ |

---

## 🖥️ GUI Preview

The GUI is built with [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) and features a sleek dark theme with a sidebar navigation, live host table, log console, and action buttons.

**Panels:**
- **Scan Network** – Run scans, view live host table, export results, launch monitor mode
- **Multi-Subnet** – Auto-detect all network segments, manage CIDR checklist, parallel scan
- **Speed Control** – Throttle a client's download/upload speed with sliders (`tc` HTB)
- **ARP Attack** – Configure & launch ARP-spoofing attacks with real-time status
- **MAC Anonymize** – Randomize or set a custom MAC address on your interface
- **Settings** – Apply attack-speed presets or configure manually
- **About** – Feature list and usage disclaimer

---

## 🚀 Quick Start

### Prerequisites

- **Linux** (tested on Kali, Ubuntu, Debian)
- **Python 3.9+**
- **Root privileges** (required for raw socket / packet injection)
- `scapy`, `customtkinter` (installed below)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/at0m-b0mb/Wifi-Killer.git
cd Wifi-Killer

# 2. Install dependencies
pip install -r requirements.txt
```

### Launch – GUI (recommended)

```bash
sudo python3 gui.py
```

### Launch – CLI (interactive terminal)

```bash
sudo python3 main.py
```

---

## 📖 Usage Guide

### GUI Workflow

1. **Select interface** – the interface dropdown at the top auto-detects your active adapters and the gateway.
2. **Scan Network tab** – choose a scan type and click *Start Scan*. Results appear in the live table with vendor, hostname, and device-type enrichment.
3. **Select hosts** – tick the checkboxes next to the hosts you want to target, then click *Attack Selected*.
4. **ARP Attack tab** – confirm the targets, pick a method, and click *Launch Attack*. Click *Stop & Restore* to cleanly reset ARP caches.
5. **MAC Anonymize tab** – randomize your MAC before attacking to reduce traceability.
6. **Export** – save the scan results as CSV or JSON from the Scan tab.

### CLI Menu Map

```
Main Menu
 ├─ 1. Host Discovery     → Fast / Balanced / Stealth / Continuous Monitor
 ├─ 2. ARP Attack         → Full MITM / Client-cut / Gateway-cut
 ├─ 3. Speed / Intensity  → Presets or manual config
 ├─ 4. MAC Anonymization  → Random / OUI-preserve / Custom / Restore
 └─ 5. Change interface
```

---

## 🔍 Scan Modes Explained

| Mode | Technique | Speed | Stealth |
|---|---|---|---|
| **Fast** | ARP broadcast sweep | ~2 s | Low |
| **Balanced** | ARP + ICMP ping (parallel) | ~3 s | Medium |
| **Stealth** | ARP seed + TCP SYN probes | ~10–30 s | High |
| **Monitor** | Repeated ARP sweeps every N seconds | Continuous | Low |

---

## ⚡ Attack Methods

| Method | Description |
|---|---|
| **A – Full MITM** | Poisons both client ↔ gateway ARP caches. All traffic flows through the attacker. |
| **B – Client Only** | Tells the client that the gateway's MAC is the attacker's. Cuts the client's outbound traffic. |
| **C – Gateway Only** | Tells the gateway that the client's MAC is the attacker's. Cuts inbound traffic to the client. |

ARP caches are **automatically restored** when you stop the attack.

---

## 🚦 Client Speed Control

Throttle a specific client's internet speed while an ARP MITM attack is active.  Uses Linux **`tc` HTB** (Hierarchical Token Bucket) to shape traffic in both directions.

| Preset | Download | Upload | Use-case |
|---|---|---|---|
| 🔴 **Block** | 0 | 0 | Completely cut the client off |
| 🐢 **Dial-Up** | 56 Kbps | 28 Kbps | Simulate ancient modem speeds |
| 🟡 **1 Mbps** | 1 Mbps | 0.5 Mbps | Highly degraded browsing |
| 🔵 **5 Mbps** | 5 Mbps | 2 Mbps | Slow but usable |
| 🟢 **25 Mbps** | 25 Mbps | 10 Mbps | Moderate throttle |
| ⚡ **Full** | 100 Mbps | 100 Mbps | Restore normal speed |

Or drag the sliders to any value between 0 and 100 Mbps.  
Rules are removed cleanly (tc qdisc deleted) when you click **Clear All** or the app exits.

> **Note:** Throttling only works when an ARP MITM attack is active so traffic actually flows through the attacker machine.  IP forwarding is enabled automatically when an attack starts.

---

## ⚙️ Attack Speed Presets

| Preset | Interval | Burst | Use-case |
|---|---|---|---|
| **Normal** | 2 s | 1 pkt | Default – works for most scenarios |
| **Aggressive** | 0.5 s | 5 pkt | Reliable on noisy networks |
| **Stealth** | 10 s | 1 pkt | Slow re-poisoning to avoid IDS |

---

## 🎭 MAC Anonymization

```
Options
 ├─ 1. Fully random MAC  (unicast + locally-administered bits set correctly)
 ├─ 2. Random MAC, preserve OUI  (keep vendor's first 3 octets)
 ├─ 3. Set a specific MAC manually
 └─ 4. Restore original MAC
```

---

## 🗂️ Project Structure

```
Wifi-Killer/
├── gui.py                        # GUI entry point  (sudo python3 gui.py)
├── main.py                       # CLI entry point  (sudo python3 main.py)
├── requirements.txt
├── setup.py
├── wifi_killer/
│   ├── gui.py                    # Modern CustomTkinter GUI
│   ├── main.py                   # Interactive CLI
│   ├── modules/
│   │   ├── scanner.py            # Host discovery (ARP / ICMP / TCP SYN / multi-subnet)
│   │   ├── attacker.py           # ARP-spoof engine (MITM / cut-off)
│   │   ├── throttler.py          # Bandwidth throttling via Linux tc HTB
│   │   ├── anonymizer.py         # MAC address changer
│   │   ├── identifier.py         # OUI lookup, hostname resolve, device-type guess
│   │   └── config.py             # Attack speed config & presets
│   ├── utils/
│   │   └── network.py            # Gateway, MAC, subnet, route, multi-subnet helpers
│   └── data/
│       └── oui.json              # OUI → vendor database
└── tests/
    └── test_wifi_killer.py       # Unit tests (52 tests, no root required)
```

---

## 🧪 Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Tests cover OUI lookup, device-type inference, attack config presets, MAC generation, network utility functions, throttler logic, and subnet helpers — all without requiring root or network access.

---

## 🔒 Legal & Ethical Disclaimer

This project is provided **strictly for educational purposes** — understanding how ARP spoofing, network scanning, and MITM techniques work in controlled lab environments, CTF competitions, or on networks you explicitly own and administer.

**Do NOT use this tool against any network or device without explicit written permission from the owner.** Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, or equivalent laws in your jurisdiction.

The author assumes no liability for any misuse of this software.

---

## 📄 License

MIT License – see [LICENSE](LICENSE) for details.

