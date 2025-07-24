# 🛡️ WANNACRY? - Red Team, Blue Team, and SOC Toolkit

> **DISCLAIMER**: This tool is for educational and ethical testing purposes only. The author does not condone illegal use.

---

## 📦 Overview

**WANNACRY?** is a beginner-friendly Bash-based toolkit combining basic offensive (Red Team), defensive (Blue Team), and monitoring (SOC) functionalities into a single, easy-to-use interface. The goal is to help users learn fundamental security operations, from port scanning to brute-force simulations and basic defense scans.

---

## 🧰 Features

### 🔴 Red Team (Offensive)
- Full port scanning with `nmap`
- DDoS simulation using `hping3`
- Hidden directory scanning with `gobuster`
- Brute-force login attempts with `hydra` (SSH, FTP, HTTP)

### 🔵 Blue Team (Defensive)
- Scan localhost for open ports
- Discover live hosts on local network *(auto-detects subnet)*
- View active listening services
- View system logs

### ⚪ SOC Mode (Monitoring)
- Scan for suspicious open ports
- Monitor recent authentication logs
- Fast external target scan
- Find readable configuration files on the system

---

## ✅ Requirements

Ensure the following tools are installed:

- `nmap`
- `hydra`
- `hping3`
- `gobuster`
- `figlet`
- `lolcat`
- `ss`, `ip`, `find`, `journalctl`

> Install them on Debian-based systems with:
```bash
sudo apt install nmap hydra hping3 gobuster figlet lolcat net-tools iproute2
