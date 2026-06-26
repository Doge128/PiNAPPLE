# 🍍 PiNAPPLE
### A DIY WiFi auditing platform built on a Raspberry Pi 4 — for $30 instead of $200.

![Hardware](https://img.shields.io/badge/Hardware-Raspberry%20Pi%204-c51a4a?style=flat-square&logo=raspberry-pi)
![OS](https://img.shields.io/badge/OS-Pi%20OS%20Bookworm-darkgreen?style=flat-square)
![Python](https://img.shields.io/badge/Backend-Python%20Flask-3776AB?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Stardance](https://img.shields.io/badge/Hack%20Club-Stardance%202026-FF6B6B?style=flat-square)

---

> ⚠️ **For authorized testing, CTF competitions, and home lab use only.**  
> Never use on networks you don't own or have explicit written permission to test.

---

## What is PiNAPPLE?

The [Hak5 WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple) is a professional WiFi auditing tool used by pentesters worldwide. It costs $100–$200. PiNAPPLE replicates its core functionality on a Raspberry Pi 4 using open source tools — for the cost of a USB dongle.

Built from scratch as a learning project to understand how rogue APs, captive portals, DNS hijacking, and WiFi recon actually work at the protocol level.

---

## Features

| Feature | Status |
|---|---|
| 🔴 Rogue Access Point (hostapd) | ✅ |
| 📡 Monitor Mode Scanning (AR9271) | ✅ |
| 🌐 Captive Portal (3 variants) | ✅ |
| 🔀 DNS Hijacking (dnsmasq) | ✅ |
| 🔁 Internet Passthrough (NAT) | ✅ |
| 📊 Web Dashboard (Flask) | ✅ |
| 💻 Ethernet Tethering (laptop → Pi) | ✅ |
| 🔄 Auto-start on boot (systemd) | ✅ |
| 🎭 MAC Randomization | ✅ |

---

## Hardware

| Component | Role |
|---|---|
| Raspberry Pi 4 (1GB) | Main compute |
| AR9271 USB WiFi dongle | Monitor mode + scanning |
| BCM43455 (onboard) | Rogue AP |
| Ethernet cable | Internet from laptop + management channel |

**Total cost:** ~$30 (just the dongle, if you already have a Pi)  
**Pineapple cost:** $100–$200

---

## Architecture

```
Internet → Router → Your Laptop (WiFi)
                         │
                    Ethernet cable
                    (ICS + SSH + Dashboard access)
                         │
                    Pi eth0 (10.42.0.x)
                         │
          ┌──────────────┴──────────────┐
          │                             │
   wlan0 BCM43455               wlan1 AR9271
   Rogue AP (10.0.0.1)          Monitor Mode
   Targets connect here          Passive scanning
```

Your laptop shares internet to the Pi over ethernet. Both WiFi interfaces are completely free for auditing. SSH in from your laptop, hit the dashboard from your browser — no separate management network needed.

---

## Dashboard

A custom dark-themed Flask web UI accessible at `http://[pi-ip]:8080`.

**Pages:**
- **Overview** — live status of all services, connected clients, toggle switches
- **AP Control** — change SSID, channel, security mode, start/stop the AP
- **Clients** — live table of connected devices (MAC, IP, hostname, timestamps)
- **Recon** — nearby SSIDs from wlan1 monitor scan, auto-refreshes every 30s
- **Credentials** — captured portal submissions with export to CSV
- **Logs** — live tail of all PiNAPPLE logs
- **Settings** — portal type, MAC randomization, DNS hijack toggle

---

## Captive Portal Variants

Three portal types, switchable from the dashboard:

1. **Credentials** — "Free WiFi, login to continue" (email + password capture)
2. **Hotel** — room number + last name style portal
3. **Splash** — accept terms only, no credential capture

---

## Setup

### Requirements
- Raspberry Pi 4 (1GB+ RAM)
- Pi OS Bookworm Lite 64-bit (**not Trixie** — BCM43455 firmware crash bug on kernel 6.12)
- AR9271-based USB WiFi adapter (TP-Link TL-WN722N v1 or similar)
- Laptop with ethernet port and internet sharing capability

### Install

```bash
# SSH into your Pi
ssh admin@[pi-ip]

# Clone the repo
git clone https://github.com/Doge128/PiNAPPLE.git /opt/pinapple
cd /opt/pinapple

# Run the installer
sudo bash install.sh
```

The installer handles everything: package installation, service configuration, iptables rules, and systemd setup.

### Verify

```bash
pinapple-status
```

Then hit `http://[pi-ip]:8080` from your browser. Default dashboard login: `admin / pinapple` (change this immediately in Settings).

---

## Helper Scripts

| Script | Description |
|---|---|
| `pinapple-status` | Print status of all services + connected clients |
| `pinapple-internet on\|off` | Toggle internet passthrough for AP clients |
| `pinapple-portal on\|off` | Toggle captive portal redirect |
| `pinapple-reset` | Stop everything, randomize MAC, restart clean |

---

## File Structure

```
/opt/pinapple/          # Flask app + templates
/etc/pinapple/          # Config files
/var/log/pinapple/      # Logs + scan results + captured creds
/usr/local/bin/         # Helper scripts
```

---

## Systemd Services

All services auto-start on boot in dependency order:

```
pinapple-ap       → hostapd (rogue AP)
pinapple-dhcp     → dnsmasq (DHCP + DNS)
pinapple-portal   → nginx (captive portal)
pinapple-dashboard→ Flask (web UI)
pinapple-monitor  → wlan1 monitor mode + scanning
```

---

## Why Not Just Buy the Pineapple?

You could. But:

- You won't know *why* it works
- You can't modify it at the kernel/driver level
- You don't learn hostapd, dnsmasq, iptables, or how captive portals actually trick devices
- It costs $200

Building this taught me more about WiFi security in one night than months of reading.

---

## Roadmap

- [ ] KARMA attack support (hostapd-wpe)
- [ ] Evil twin automation
- [ ] HackRF spectrum analysis integration
- [ ] Flipper Zero bridge
- [ ] Mobile-responsive dashboard
- [ ] WireGuard VPN tunnel support
- [ ] Automated recon reporting

---

## Built With

- [hostapd](https://w1.fi/hostapd/) — AP management
- [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) — DHCP + DNS
- [Flask](https://flask.palletsprojects.com/) — Dashboard backend
- [nginx](https://nginx.org/) — Captive portal server
- [iptables](https://www.netfilter.org/) — NAT + traffic routing
- [Claude Code](https://claude.ai/code) — AI-assisted development

---

## Legal

This tool is for **authorized security testing only**. You are responsible for ensuring you have permission before testing any network. Unauthorized interception of network traffic is illegal in most jurisdictions.

---

## Author

**[@Hackshiz](https://github.com/Doge128)** — cybersec learner, Computer Geek, Outdoor Enthusiest

---

*"I am not in danger. I am the danger."* — Waltuh
