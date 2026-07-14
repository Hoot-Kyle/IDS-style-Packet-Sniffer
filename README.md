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

#mermaid-r1a3-r2 { font-family: "Anthropic Sans", system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 16px; fill: rgb(229, 229, 229); }
#mermaid-r1a3-r2 .edge-animation-slow { stroke-dashoffset: 900; animation: 50s linear 0s infinite normal none running dash; stroke-linecap: round; stroke-dasharray: 9, 5 !important; }
#mermaid-r1a3-r2 .edge-animation-fast { stroke-dashoffset: 900; animation: 20s linear 0s infinite normal none running dash; stroke-linecap: round; stroke-dasharray: 9, 5 !important; }
#mermaid-r1a3-r2 .error-icon { fill: rgb(204, 120, 92); }
#mermaid-r1a3-r2 .error-text { fill: rgb(51, 135, 163); stroke: rgb(51, 135, 163); }
#mermaid-r1a3-r2 .edge-thickness-normal { stroke-width: 1px; }
#mermaid-r1a3-r2 .edge-thickness-thick { stroke-width: 3.5px; }
#mermaid-r1a3-r2 .edge-pattern-solid { stroke-dasharray: 0; }
#mermaid-r1a3-r2 .edge-thickness-invisible { stroke-width: 0; fill: none; }
#mermaid-r1a3-r2 .edge-pattern-dashed { stroke-dasharray: 3; }
#mermaid-r1a3-r2 .edge-pattern-dotted { stroke-dasharray: 2; }
#mermaid-r1a3-r2 .marker { fill: rgb(161, 161, 161); stroke: rgb(161, 161, 161); }
#mermaid-r1a3-r2 .marker.cross { stroke: rgb(161, 161, 161); }
#mermaid-r1a3-r2 svg { font-family: "Anthropic Sans", system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 16px; }
#mermaid-r1a3-r2 p { margin: 0px; }
#mermaid-r1a3-r2 .label { font-family: "Anthropic Sans", system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: rgb(229, 229, 229); }
#mermaid-r1a3-r2 .cluster-label text { fill: rgb(51, 135, 163); }
#mermaid-r1a3-r2 .cluster-label span { color: rgb(51, 135, 163); }
#mermaid-r1a3-r2 .cluster-label span p { background-color: transparent; }
#mermaid-r1a3-r2 .label text, #mermaid-r1a3-r2 span { fill: rgb(229, 229, 229); color: rgb(229, 229, 229); }
#mermaid-r1a3-r2 .node rect, #mermaid-r1a3-r2 .node circle, #mermaid-r1a3-r2 .node ellipse, #mermaid-r1a3-r2 .node polygon, #mermaid-r1a3-r2 .node path { fill: transparent; stroke: rgb(161, 161, 161); stroke-width: 1px; }
#mermaid-r1a3-r2 .rough-node .label text, #mermaid-r1a3-r2 .node .label text, #mermaid-r1a3-r2 .image-shape .label, #mermaid-r1a3-r2 .icon-shape .label { text-anchor: middle; }
#mermaid-r1a3-r2 .node .katex path { fill: rgb(0, 0, 0); stroke: rgb(0, 0, 0); stroke-width: 1px; }
#mermaid-r1a3-r2 .rough-node .label, #mermaid-r1a3-r2 .node .label, #mermaid-r1a3-r2 .image-shape .label, #mermaid-r1a3-r2 .icon-shape .label { text-align: center; }
#mermaid-r1a3-r2 .node.clickable { cursor: pointer; }
#mermaid-r1a3-r2 .root .anchor path { stroke-width: 0; stroke: rgb(161, 161, 161); fill: rgb(161, 161, 161) !important; }
#mermaid-r1a3-r2 .arrowheadPath { fill: rgb(11, 11, 11); }
#mermaid-r1a3-r2 .edgePath .path { stroke: rgb(161, 161, 161); stroke-width: 1px; }
#mermaid-r1a3-r2 .flowchart-link { stroke: rgb(161, 161, 161); fill: none; }
#mermaid-r1a3-r2 .edgeLabel { background-color: transparent; text-align: center; }
#mermaid-r1a3-r2 .edgeLabel p { background-color: transparent; }
#mermaid-r1a3-r2 .edgeLabel rect { opacity: 0.5; background-color: transparent; fill: transparent; }
#mermaid-r1a3-r2 .labelBkg { background-color: rgba(0, 0, 0, 0.5); }
#mermaid-r1a3-r2 .cluster rect { fill: rgb(204, 120, 92); stroke: rgb(138, 115, 107); stroke-width: 1px; }
#mermaid-r1a3-r2 .cluster text { fill: rgb(51, 135, 163); }
#mermaid-r1a3-r2 .cluster span { color: rgb(51, 135, 163); }
#mermaid-r1a3-r2 div.mermaidTooltip { position: absolute; text-align: center; max-width: 200px; padding: 2px; font-family: "Anthropic Sans", system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 12px; background: rgb(204, 120, 92); border: 1px solid rgb(138, 115, 107); border-radius: 2px; pointer-events: none; z-index: 100; }
#mermaid-r1a3-r2 .flowchartTitleText { text-anchor: middle; font-size: 18px; fill: rgb(229, 229, 229); }
#mermaid-r1a3-r2 rect.text { fill: none; stroke-width: 0; }
#mermaid-r1a3-r2 .icon-shape, #mermaid-r1a3-r2 .image-shape { background-color: transparent; text-align: center; }
#mermaid-r1a3-r2 .icon-shape p, #mermaid-r1a3-r2 .image-shape p { background-color: transparent; padding: 2px; }
#mermaid-r1a3-r2 .icon-shape .label rect, #mermaid-r1a3-r2 .image-shape .label rect { opacity: 0.5; background-color: transparent; fill: transparent; }
#mermaid-r1a3-r2 .label-icon { display: inline-block; height: 1em; overflow: visible; vertical-align: -0.125em; }
#mermaid-r1a3-r2 .node .label-icon path { fill: currentcolor; stroke: revert; stroke-width: revert; }
#mermaid-r1a3-r2 .node .neo-node { stroke: rgb(161, 161, 161); }
#mermaid-r1a3-r2 [data-look="neo"].node rect, #mermaid-r1a3-r2 [data-look="neo"].cluster rect, #mermaid-r1a3-r2 [data-look="neo"].node polygon { stroke: url("#mermaid-r1a3-r2-gradient"); filter: drop-shadow(rgb(185, 185, 185) 1px 2px 2px); }
#mermaid-r1a3-r2 [data-look="neo"].node path { stroke: url("#mermaid-r1a3-r2-gradient"); stroke-width: 1px; }
#mermaid-r1a3-r2 [data-look="neo"].node .outer-path { filter: drop-shadow(rgb(185, 185, 185) 1px 2px 2px); }
#mermaid-r1a3-r2 [data-look="neo"].node .neo-line path { stroke: rgb(161, 161, 161); filter: none; }
#mermaid-r1a3-r2 [data-look="neo"].node circle { stroke: url("#mermaid-r1a3-r2-gradient"); filter: drop-shadow(rgb(185, 185, 185) 1px 2px 2px); }
#mermaid-r1a3-r2 [data-look="neo"].node circle .state-start { fill: rgb(0, 0, 0); }
#mermaid-r1a3-r2 [data-look="neo"].icon-shape .icon { fill: url("#mermaid-r1a3-r2-gradient"); filter: drop-shadow(rgb(185, 185, 185) 1px 2px 2px); }
#mermaid-r1a3-r2 [data-look="neo"].icon-shape .icon-neo path { stroke: url("#mermaid-r1a3-r2-gradient"); filter: drop-shadow(rgb(185, 185, 185) 1px 2px 2px); }
#mermaid-r1a3-r2 :root { --mermaid-font-family: "Anthropic Sans",system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }Packet Capture<i> Scapy sniff() </i>Parser /Feature ExtractionDetection Rules Engine<i> port scan, SYN flood,ARP spoof </i>Alerting<i> console + rotating logfile </i>


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
