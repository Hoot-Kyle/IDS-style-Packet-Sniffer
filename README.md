# IDS-style-Packet-Sniffer
I asked Claude to help me build a lightweight, intrusion-detection-style packet sniffer written in Python with Scapy. It passively monitors network traffic and raises alerts on patterns associated with common network attacks: port scans, SYN floods, and ARP spoofing.

Why this project?
Most "packet sniffer" tutorials stop at printing captured packets. This project goes a step further by implementing actual detection logic — the same category of pattern-matching that commercial IDS/IPS tools use, just at a much smaller scale.


This project demonstrates:
- Practical understanding of TCP/IP internals (handshakes, flags, headers)
- Stateful traffic analysis (tracking behavior over time, not just single packets)
- Security relevant software design: configurability, logging, and operational safety (log rotation)

Assumptions and limitations:
Runs on a single host and only sees traffic that host can observe (its own segment, or a mirrored/SPAN port if configured at the switch level)
Thresholds are heuristic, not behavioral-ML-based — tuned for clarity and explainability, not evasion-resistance
Not intended for use on networks you don't own or have permission to monitor


Architecture:

┌─────────────┐     ┌──────────────┐     ┌────────────────┐     ┌───────────┐
│ Packet       │ →  │ Parser/       │ →  │ Detection       │ →  │ Alerting  │
│ Capture      │     │ Feature       │     │ Rules Engine    │     │ (console/ │
│ (Scapy)      │     │ Extraction    │     │ (port scan,     │     │  log file)│
│              │     │               │     │  ARP spoof, etc)│     │           │
└─────────────┘     └──────────────┘     └────────────────┘     └───────────┘


Capture: scapy.sniff() pulls raw packets off the interface in promiscuous mode
Feature extraction: relevant fields (source IP, destination port, TCP flags, ARP operation) are pulled from each packet
Detection engine: sliding time-window counters per source IP flag abnormal patterns
Alerting: Python's logging module writes alerts to both console and a rotating log file


Installation:
Requires Python 3 and Scapy.

(bash)
pip3 install scapy --break-system-packages

Raw socket access requires elevated privileges, so the script must be run with sudo.

Usage:
(bash)
sudo python3 ids_sniffer.py -i en0

FlagDescription-i, --interfaceNetwork interface to sniff on (e.g. en0).
Overrides config.json.-v, --verbosePrint a one-line summary of every captured packet to the console.
-c, --configPath to a JSON config file (default: config.json).

Example:
sudo python3 ids_sniffer.py -i en0 -v

To find your interface name on macOS: ifconfig.

Testing:
Do not test against machines or networks you don't own or have explicit permission to test.

 Terminal 1
sudo python3 ids_sniffer.py -i en0

 Terminal 2 — simulate a port scan against yourself
nmap -p 1-100 localhost

Example alert output:
2026-07-14 14:32:01 [INFO] Starting IDS sniffer... (Ctrl+C to stop)
2026-07-14 14:32:01 [INFO] Config loaded from config.json
2026-07-14 14:32:04 [WARNING] Possible port scan from 127.0.0.1: 22 distinct ports in 5s

Disclaimer (IMPORTANT PLEASE READ):
This tool is for educational purposes and authorized network monitoring only. Only run it on networks and systems you own or have explicit permission to monitor.
