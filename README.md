# Honeypot
# 🛡️ Python Honeypot with Nmap, Telnet, and DDoS Detection

This is a Python-based honeypot designed to monitor and detect malicious activity on a network. It identifies:

- 📡 **Nmap scans**
- 🔐 **Telnet login attempts**
- 🚨 **DDoS attacks**

The honeypot simulates a Telnet service and logs suspicious behavior. It also includes basic real-time detection logic for port scans and volumetric denial-of-service attacks.

---

## 📌 Features

- ✅ Simulated Telnet service
- 🔍 Nmap scan detection (based on SYN, FIN, NULL, and Xmas scans)
- 🧠 Telnet login attempt logging and pattern analysis
- 🛑 DDoS detection based on connection rate and IP entropy
- 💾 Logs events to file with timestamps
- 📊 GUI or dashboard support 

---

## 🧰 Requirements

- Python 3.8+
- Linux-based OS (recommended)
- `iptables` or similar tool (optional for traffic redirection)
- Recommended Python libraries:
  - `scapy`
  - `socket`
  - `threading`
  - `datetime`
  - `collections`
  - `argparse`
  - `logging`
