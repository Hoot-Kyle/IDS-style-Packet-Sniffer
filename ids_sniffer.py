
"""
ids_sniffer.py — A lightweight intrusion-detection-style packet sniffer.

Detects:
  1. Port scans        — one source IP hitting many distinct ports quickly
  2. SYN floods         — excessive SYN packets without completed handshakes
  3. ARP spoofing       — an IP address suddenly associated with a new MAC

Run with sudo (raw socket access is required):
    sudo python3 ids_sniffer.py -i en0

Requires: scapy (pip3 install scapy --break-system-packages)
"""

import argparse
import json
import time
import logging
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
from scapy.all import sniff, IP, TCP, ARP, Ether

# Configuration (Used when config.json is missing)

DEFAULT_CONFIG = {
    "detection": {
        "port_scan_threshold": 15,
        "port_scan_window_seconds": 5,
        "syn_flood_threshold": 50,
        "syn_flood_window_seconds": 5,
    },
    "logging": {
        "log_file": "ids_alerts.log",
        "max_log_bytes": 1_000_000,
        "log_backup_count": 3,
    },
    "capture": {
        "interface": None,
    },
}
 
 
def load_config(path):
    """Load JSON config from `path`, filling in any missing keys with
    defaults. Falls back entirely to DEFAULT_CONFIG if the file is missing
    or invalid, printing a warning either way (before the logger exists)."""
    config = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy of defaults
 
    try:
        with open(path, "r") as f:
            user_config = json.load(f)
        for section, values in user_config.items():
            if section in config and isinstance(values, dict):
                config[section].update(values)
            else:
                config[section] = values
    except FileNotFoundError:
        print(f"[WARN] Config file '{path}' not found — using default settings.")
    except json.JSONDecodeError as e:
        print(f"[WARN] Config file '{path}' has invalid JSON ({e}) — using default settings.")
 
    return config
 
 
# These are populated from config in main() and read by the detection
# functions below.
PORT_SCAN_THRESHOLD = DEFAULT_CONFIG["detection"]["port_scan_threshold"]
PORT_SCAN_WINDOW = DEFAULT_CONFIG["detection"]["port_scan_window_seconds"]
SYN_FLOOD_THRESHOLD = DEFAULT_CONFIG["detection"]["syn_flood_threshold"]
SYN_FLOOD_WINDOW = DEFAULT_CONFIG["detection"]["syn_flood_window_seconds"]
 
LOG_FILE = DEFAULT_CONFIG["logging"]["log_file"]
MAX_LOG_BYTES = DEFAULT_CONFIG["logging"]["max_log_bytes"]
LOG_BACKUP_COUNT = DEFAULT_CONFIG["logging"]["log_backup_count"]
 

# Logger setup 

logger = logging.getLogger("ids_sniffer")
logger.setLevel(logging.INFO)
 
formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
 
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
 
file_handler = None  # created in main() once we know the final LOG_FILE path


# State tracking
# src_ip -> deque of (timestamp, dst_port) for recent SYN packets
syn_activity = defaultdict(lambda: deque())

# ip -> mac, to detect ARP spoofing
ip_to_mac = {}

alerted_scanners = set()   # avoid re-alerting every packet once flagged
alerted_floods = set()

VERBOSE = False

def prune_old(dq, window):
    """Remove entries older than `window` seconds from the front of a deque."""
    now = time.time()
    while dq and now - dq[0][0] > window:
        dq.popleft()


def check_port_scan(src_ip):
    dq = syn_activity[src_ip]
    prune_old(dq, PORT_SCAN_WINDOW)
    distinct_ports = {port for _, port in dq}
    if len(distinct_ports) >= PORT_SCAN_THRESHOLD and src_ip not in alerted_scanners:
        logger.warning(
            "Possible port scan from %s: %d distinct ports in %ds",
            src_ip, len(distinct_ports), PORT_SCAN_WINDOW
        )
        alerted_scanners.add(src_ip)


def check_syn_flood(src_ip):
    dq = syn_activity[src_ip]
    prune_old(dq, SYN_FLOOD_WINDOW)
    if len(dq) >= SYN_FLOOD_THRESHOLD and src_ip not in alerted_floods:
        logger.warning(
            "Possible SYN flood from %s: %d SYN packets in %ds",
            src_ip, len(dq), SYN_FLOOD_WINDOW
        )
        alerted_floods.add(src_ip)


def check_arp_spoof(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  
        sender_ip = pkt[ARP].psrc
        sender_mac = pkt[ARP].hwsrc
        known_mac = ip_to_mac.get(sender_ip)
        if known_mac and known_mac != sender_mac:
            logger.warning(
                "Possible ARP spoofing: %s changed from %s to %s",
                sender_ip, known_mac, sender_mac
            )
            ip_to_mac[sender_ip] = sender_mac


def handle_packet(pkt):
    if VERBOSE:
        # pkt.summary() gives a one-line human-readable breakdown, e.g.
        # "Ether / IP / TCP 192.168.1.5:51322 > 192.168.1.1:443 S"
        logger.debug(pkt.summary())
 
    # ARP spoof detection runs independent of IP/TCP logic
    if pkt.haslayer(ARP):
        check_arp_spoof(pkt)
        return
 
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags
 
        # SYN flag set, ACK not set => this is a connection attempt (SYN), not
        # part of an already-established handshake
        is_syn_only = (flags & 0x02) and not (flags & 0x10)
 
        if is_syn_only:
            syn_activity[src_ip].append((time.time(), dst_port))
            check_port_scan(src_ip)
            check_syn_flood(src_ip)


def main():
    parser = argparse.ArgumentParser(description="Simple IDS-style packet sniffer")
    parser.add_argument("-i", "--interface", default=None,
                         help="Network interface to sniff on (e.g. en0). "
                              "Overrides the 'interface' value in config.json.")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Print a one-line summary of every captured packet "
                              "to the console (does not bloat the log file).")
    parser.add_argument("-c", "--config", default="config.json",
                         help="Path to JSON config file (default: config.json)")
    args = parser.parse_args()
 
    #  Load config and apply it to the module-level settings 
    config = load_config(args.config)
 
    global PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW, SYN_FLOOD_THRESHOLD, SYN_FLOOD_WINDOW
    global LOG_FILE, MAX_LOG_BYTES, LOG_BACKUP_COUNT, VERBOSE, file_handler
 
    PORT_SCAN_THRESHOLD = config["detection"]["port_scan_threshold"]
    PORT_SCAN_WINDOW = config["detection"]["port_scan_window_seconds"]
    SYN_FLOOD_THRESHOLD = config["detection"]["syn_flood_threshold"]
    SYN_FLOOD_WINDOW = config["detection"]["syn_flood_window_seconds"]
 
    LOG_FILE = config["logging"]["log_file"]
    MAX_LOG_BYTES = config["logging"]["max_log_bytes"]
    LOG_BACKUP_COUNT = config["logging"]["log_backup_count"]
 
    # CLI --interface overrides config.json's capture.interface if given
    interface = args.interface or config["capture"]["interface"]
 
    # --- Now that LOG_FILE/rotation settings are final, attach file handler ---
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=MAX_LOG_BYTES, backupCount=LOG_BACKUP_COUNT
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
 
    VERBOSE = args.verbose
 
    if VERBOSE:
        # Only the console handler drops to DEBUG; the file handler stays at
        # INFO so ids_alerts.log keeps only meaningful events, not raw traffic.
        logger.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        console_handler.setLevel(logging.INFO)
 
    file_handler.setLevel(logging.INFO)
 
    logger.info("Starting IDS sniffer... (Ctrl+C to stop)")
    logger.info("Config loaded from %s", args.config)
    logger.info("Logging alerts to %s", LOG_FILE)
    logger.info("Port scan threshold: %d ports / %ds", PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW)
    logger.info("SYN flood threshold: %d SYNs / %ds", SYN_FLOOD_THRESHOLD, SYN_FLOOD_WINDOW)
    if VERBOSE:
        logger.info("Verbose mode ON — printing every packet summary to console")
 
    sniff(iface=interface, prn=handle_packet, store=False)
 

if __name__ == "__main__":
    main()