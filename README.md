# Network Traffic Sniffer v2.0

A modular, real-time Python network traffic sniffer and protocol analyzer built with Scapy. Passively captures, dissects, logs, and exports network packets with kernel-level Berkeley Packet Filter (BPF) support.

---

## Features

- **Multi-Layer Protocol Dissection (OSI Stack)**:
  - **Layer 3 (Network)**: IPv4 & IPv6 addressing, TTL, IP protocol types.
  - **Layer 4 (Transport)**: TCP port numbers & flags (SYN, ACK, FIN, RST, PSH, URG), UDP ports, ICMP type/code.
  - **Layer 7 (Application - DPI)**: DNS domain name queries & query types, unencrypted HTTP request methods, Host headers, and User-Agent strings.
- **Kernel-Level BPF Filtering**: Direct pass-through of Berkeley Packet Filter syntax (`tcp port 80`, `udp port 53`, `icmp`, `host 192.168.1.1`) to filter traffic before user-space processing.
- **Real-Time Telemetry Dashboard**: Live periodic console dashboard tracking packet velocity (packets/sec), protocol distribution, and top communicating endpoints (Top Talkers).
- **Zero-Loss PCAP Export**: Streams packets synchronously to `.pcap` files using Scapy's `PcapWriter(sync=True)` without accumulative RAM consumption (`store=False`).
- **Forensic Session Summary**: Graceful `Ctrl+C` interrupt handling providing a formatted post-capture report with protocol distribution charts.
- **Strictly Passive**: No packet injection, no ARP spoofing, no session hijacking, and no payload tampering.

---

## Prerequisites

- **Python 3.10+**
- **Operating System Requirements**:
  - **Windows**: Install [Npcap](https://npcap.com/) (ensure *"Install Npcap in WinPcap API-compatible Mode"* is checked).
  - **Linux / macOS**: Standard `libpcap` library (`sudo apt install libpcap-dev` on Debian/Ubuntu).
- **Administrative Privileges**: Raw socket access and promiscuous mode capture require Administrator/root privileges.

---

## Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/<your-username>/network-traffic-sniffer.git
   cd network-traffic-sniffer
   ```

2. Create and activate a virtual environment (optional but recommended):
   ```bash
   python -m venv .venv
   
   # Linux / macOS:
   source .venv/bin/activate

   # Windows:
   .venv\Scripts\activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

> **Important**: Always launch from an elevated shell (**Run as Administrator** on Windows or `sudo` on Linux/macOS).

### Basic Execution (Default Interface, All Traffic)
```bash
python network_sniffer.py
```

### Export to PCAP File
```bash
python network_sniffer.py -w session_capture.pcap
```

### Apply BPF Filters
```bash
# Capture only HTTP (port 80) and DNS (port 53)
python network_sniffer.py -f "tcp port 80 or udp port 53" -w web_traffic.pcap

# Capture only ICMP (ping) traffic
python network_sniffer.py -f "icmp"

# Capture traffic to/from a specific host
python network_sniffer.py -f "host 192.168.1.1"
```

### Limit Packet Count
```bash
# Capture 100 packets and terminate
python network_sniffer.py -c 100 -w sample.pcap
```

### Full CLI Options
```bash
python network_sniffer.py --help
```

```
options:
  -h, --help            show this help message and exit
  -i, --interface INTERFACE
                        Network interface to bind (e.g., eth0, wlan0, Wi-Fi)
  -f, --filter FILTER   Berkeley Packet Filter (BPF) syntax string
  -w, --write PCAP_PATH
                        Path to export captured packets to PCAP file
  -c, --count COUNT     Packet count limit before terminating (0 = infinite)
  -d, --dashboard-interval DASHBOARD_INTERVAL
                        Packet interval for live console dashboard (default: 25)
```

---

## PCAP Analysis in Wireshark

Saved `.pcap` files can be opened in [Wireshark](https://www.wireshark.org/) for deep forensic inspection:

1. Open **Wireshark** ➔ **File** ➔ **Open** ➔ Select your `.pcap` file.
2. Filter packets using Wireshark Display Filters:
   - `http.request` — View captured cleartext HTTP requests.
   - `dns.flags.response == 0` — Filter DNS queries.
   - `tcp.flags.syn == 1 && tcp.flags.ack == 0` — Isolate TCP handshake initiations.
   - `ip.addr == <target_ip>` — Isolate a specific host.
3. Right-click any TCP packet and select **Follow ➔ TCP Stream** to reconstruct the entire application conversation.

---

## Project Structure

```
network-traffic-sniffer/
├── network_sniffer.py   # Core packet capture and dissection engine
├── requirements.txt     # Python package dependencies
├── .gitignore           # Git ignore file for temp & pcap artifacts
├── LICENSE              # MIT License
└── README.md            # Project documentation
```

---

## Disclaimer

This software is developed strictly for educational, network diagnostic, and authorized administrative analysis. Capturing network packets without explicit authorization on networks you do not own or administer is illegal under cybersecurity regulations (e.g., Computer Fraud and Abuse Act, 18 U.S.C. § 2511, and regional data protection laws). The author assumes no liability for misuse.
