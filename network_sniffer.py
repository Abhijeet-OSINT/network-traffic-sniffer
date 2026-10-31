#!/usr/bin/env python3
"""
================================================================================
                     NETWORK TRAFFIC SNIFFER v2.0
================================================================================
Purpose: Passive packet inspection, deep packet dissection (DPI), real-time 
         telemetry, and educational PCAP export.
Architecture: Modular Scapy-driven engine with BPF kernel-level filtering.

================================================================================
EDUCATIONAL ARCHITECTURE: THE OSI MODEL & PACKET ANATOMY
================================================================================
In packet telemetry, network protocols are conceptualized across the OSI stack:

  [Layer 7 - Application] -> DNS queries, HTTP headers (Host, User-Agent)
                             | (Encapsulated in L4 Data Payload)
  [Layer 4 - Transport]   -> TCP (Ports, SYN/ACK Flags), UDP (Ports), ICMP
                             | (Encapsulated inside L3 IP Datagram)
  [Layer 3 - Network]     -> IPv4 / IPv6 (Source/Destination IP addresses, TTL)
                             | (Encapsulated inside L2 Ethernet Frame)
  [Layer 2 - Data Link]   -> Ethernet (MAC addresses, VLAN tags, EtherType)
  [Layer 1 - Physical]    -> Raw physical bits / RF signals traversing NIC

EDUCATIONAL ARCHITECTURE: THE LIBPCAP FILE STRUCTURE (.pcap)
================================================================================
When packets are saved to disk, Scapy serializes them into standard Libpcap format:
  1. Global Header (24 bytes):
     - Magic Number (4 bytes) : Identifies byte order (0xa1b2c3d4 for standard)
     - Version Major (2 bytes): File format version major (typically 2)
     - Version Minor (2 bytes): File format version minor (typically 4)
     - Thiszone (4 bytes)     : GMT to local correction offset
     - Sigfigs (4 bytes)      : Accuracy of timestamps
     - SnapLen (4 bytes)      : Max octets of each packet saved (e.g., 65535)
     - Network (4 bytes)      : Data Link type (e.g., LINKTYPE_ETHERNET = 1)
  
  2. For Each Captured Packet:
     - Packet Header (16 bytes):
       * Timestamp Seconds (4 bytes)
       * Timestamp Microseconds/Nanoseconds (4 bytes)
       * Captured Packet Length (caplen - 4 bytes)
       * Original Wire Packet Length (len - 4 bytes)
     - Packet Data (caplen bytes):
       * Raw binary octets of the frame traversing the wire.
================================================================================
"""

import argparse
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone

# Explicit layer imports resolve static analysis and Pyright/Pylance stubs
try:
    from scapy.config import conf
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw
    from scapy.sendrecv import sniff
    from scapy.utils import PcapWriter

    # Set Scapy runtime verbosity to quiet mode
    conf.verb = 0
except ImportError:
    print("[!] Dependency Error: Scapy is not installed.")
    print("    Please install Scapy via: pip install scapy")
    sys.exit(1)


# ==============================================================================
# 1. ETHICAL & COMPLIANCE MANDATE
# ==============================================================================
DISCLAIMER = """
================================================================================
              *** ETHICAL & LEGAL USE MANDATE ***
================================================================================
[!] NOTICE: This utility is engineered exclusively for authorized network 
    administration, traffic diagnostics, protocol education, and defensive
    security research.
    
    Unauthorized packet sniffing, passive interception, or wiretapping on 
    networks where you do not possess explicit, written consent violates federal
    and international computer crime regulations (e.g., U.S. 18 U.S.C. § 2511, 
    Computer Fraud and Abuse Act, GDPR, and regional telecom acts).
    
    This software operates STRICTLY IN PASSIVE MODE:
      - No packet injection
      - No ARP spoofing / poisoning
      - No payload tampering or credential interception
================================================================================
"""


# ==============================================================================
# 2. PRIVILEGE VERIFICATION ENGINE
# ==============================================================================
def verify_administrative_privileges() -> None:
    """
    Enforces root or Administrator execution privileges.
    
    OSI Context:
    Creating raw network sockets (AF_PACKET on Linux/UNIX or Npcap/WinPcap 
    on Windows) requires kernel-level promiscuous mode binding. Unprivileged 
    users are restricted by the OS kernel from inspecting raw link-layer frames.
    """
    is_admin = False
    
    if os.name == "nt":
        # Windows API check via shell32.IsUserAnAdmin
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            is_admin = False
    else:
        # POSIX systems check effective User ID 0 (root)
        is_admin = (os.geteuid() == 0)

    if not is_admin:
        print("\n[!] FATAL: INSUFFICIENT PRIVILEGES DETECTED.")
        print("    Raw socket initialization and promiscuous capture require elevated rights.")
        if os.name == "nt":
            print("    -> Action Required: Open PowerShell or Command Prompt with 'Run as Administrator'.")
        else:
            print("    -> Action Required: Execute script with superuser privileges (e.g., sudo python3 sniffer.py).")
        sys.exit(1)


# ==============================================================================
# 3. TELEMETRY & STATISTICAL TRACKER
# ==============================================================================
class SnifferMetrics:
    """
    Maintains thread-safe in-memory metrics for real-time dashboard telemetry
    and post-capture forensic reporting.
    """
    def __init__(self):
        self.start_time = time.time()
        self.total_packets = 0
        self.protocol_counts = Counter()
        self.ip_talkers = Counter()
        self.dns_queries = Counter()
        self.http_hosts = Counter()

    def update(self, packet):
        self.total_packets += 1

        # Track Network Layer (Layer 3) Communicators
        if IP in packet:
            self.ip_talkers[packet[IP].src] += 1
            self.ip_talkers[packet[IP].dst] += 1
        elif IPv6 in packet:
            self.ip_talkers[packet[IPv6].src] += 1
            self.ip_talkers[packet[IPv6].dst] += 1

        # Track Transport Layer (Layer 4) Protocols
        if TCP in packet:
            self.protocol_counts["TCP"] += 1
        elif UDP in packet:
            self.protocol_counts["UDP"] += 1
        elif ICMP in packet:
            self.protocol_counts["ICMP"] += 1
        else:
            self.protocol_counts["Other"] += 1

    def display_live_summary(self):
        """Prints a periodic terminal dashboard showing protocol velocity and top IPs."""
        elapsed = max(time.time() - self.start_time, 0.001)
        pps = self.total_packets / elapsed
        
        print("\n" + "-" * 75)
        print(f" [LIVE DASHBOARD] Elapsed: {elapsed:0.1f}s | Captured: {self.total_packets} pkts | Rate: {pps:0.1f} pkt/s")
        print(f" Protocols => TCP: {self.protocol_counts['TCP']} | UDP: {self.protocol_counts['UDP']} | "
              f"ICMP: {self.protocol_counts['ICMP']} | Other: {self.protocol_counts['Other']}")
        
        # Display Top 3 Communicating IP Endpoints
        top_ips = self.ip_talkers.most_common(3)
        if top_ips:
            top_str = " | ".join(f"{ip}: {cnt}" for ip, cnt in top_ips)
            print(f" Top Talkers => {top_str}")
        print("-" * 75 + "\n")


# ==============================================================================
# 4. DEEP PACKET INSPECTION (DPI) & PROTOCOL DISSECTOR
# ==============================================================================
class PacketDissector:
    """
    Modular Layer-by-Layer packet dissector aligned with the OSI Reference Model:
      - Layer 3 (Network): IPv4 / IPv6 addresses, TTL, packet length
      - Layer 4 (Transport): TCP (ports, flags), UDP (ports), ICMP (type/code)
      - Layer 7 (Application): DNS (queries), unencrypted HTTP (methods, Host, User-Agent)
    """

    @staticmethod
    def dissect_application_layer(packet, metrics: SnifferMetrics) -> str:
        """
        Deep Packet Inspection (DPI) for Layer 7 protocols.
        Extracts metadata non-intrusively without altering packet streams.
        """
        app_details = []

        # ----------------------------------------------------------------------
        # Application Protocol: DNS (Domain Name System - UDP/TCP 53)
        # ----------------------------------------------------------------------
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                # DNSQR represents a DNS Question Record
                query_name = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                qtype = packet[DNSQR].qtype
                metrics.dns_queries[query_name] += 1
                app_details.append(f"[DNS Qry: '{query_name}' (Type {qtype})]")
            except (AttributeError, UnicodeDecodeError):
                pass

        # ----------------------------------------------------------------------
        # Application Protocol: HTTP/1.x (Hypertext Transfer Protocol - Cleartext)
        # ----------------------------------------------------------------------
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                
                # Verify if the payload begins with a standard HTTP Request verb
                http_methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ")
                if payload.startswith(http_methods):
                    lines = payload.split("\r\n")
                    request_line = lines[0]
                    host_header = "N/A"
                    user_agent = "N/A"

                    for line in lines[1:]:
                        lower_line = line.lower()
                        if lower_line.startswith("host:"):
                            host_header = line.split(":", 1)[1].strip()
                        elif lower_line.startswith("user-agent:"):
                            user_agent = line.split(":", 1)[1].strip()

                    metrics.http_hosts[host_header] += 1
                    # Truncate user-agent for clean console formatting
                    ua_short = (user_agent[:40] + "...") if len(user_agent) > 40 else user_agent
                    app_details.append(f"[HTTP Request: {request_line} | Host: {host_header} | UA: {ua_short}]")
            except (AttributeError, UnicodeDecodeError):
                pass

        return " ".join(app_details)

    @classmethod
    def format_packet_log(cls, packet, metrics: SnifferMetrics) -> str:
        """
        Generates a human-readable, single-line dissection log for real-time display.
        """
        timestamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc).astimezone().strftime("%H:%M:%S.%f")[:-3]
        
        # 1. Network Layer (Layer 3) Parsing
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            l3_info = f"{src_ip} -> {dst_ip}"
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            l3_info = f"[{src_ip}] -> [{dst_ip}]"
        else:
            # Non-IP layer (e.g. ARP, STP)
            return f"[{timestamp}] Non-IP Frame: {packet.summary()}"

        # 2. Transport Layer (Layer 4) Parsing
        l4_info = ""
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].underlayer.sprintf("%TCP.flags%")
            l4_info = f"TCP {sport} > {dport} [Flags: {flags}]"
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            l4_info = f"UDP {sport} > {dport}"
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            l4_info = f"ICMP Type: {icmp_type} Code: {icmp_code}"
        else:
            l4_info = f"IP Proto: {packet.sprintf('%IP.proto%')}"

        # 3. Application Layer (Layer 7) DPI
        l7_info = cls.dissect_application_layer(packet, metrics)

        # Assemble unified telemetry record
        log_entry = f"[{timestamp}] {l3_info:38} | {l4_info:28}"
        if l7_info:
            log_entry += f" | {l7_info}"

        return log_entry


# ==============================================================================
# 5. CORE SNIFFER CONTROLLER
# ==============================================================================
class NetworkSniffer:
    """
    Coordinates capture loop execution, BPF compilation, asynchronous PCAP 
    serialization, and terminal visualization.
    """
    def __init__(self, interface: str | None = None, bpf_filter: str = "", pcap_path: str | None = None, 
                 packet_limit: int = 0, dashboard_interval: int = 25):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.pcap_path = pcap_path
        self.packet_limit = packet_limit
        self.dashboard_interval = dashboard_interval
        
        self.metrics = SnifferMetrics()
        self.pcap_writer = None

        if self.pcap_path:
            # Initialize Scapy PcapWriter with sync=True to flush writes immediately to disk
            # preventing packet data loss on abrupt termination.
            self.pcap_writer = PcapWriter(self.pcap_path, append=True, sync=True)

    def packet_handler(self, packet):
        """
        Callback triggered by scapy.sniff() for each captured frame.
        Must execute with high computational efficiency to prevent socket buffer drops.
        """
        # Update statistical metrics
        self.metrics.update(packet)

        # Persist to PCAP storage stream if requested
        if self.pcap_writer:
            self.pcap_writer.write(packet)

        # Dissect and print packet stream
        log_line = PacketDissector.format_packet_log(packet, self.metrics)
        print(log_line)

        # Trigger periodic live metrics dashboard
        if self.dashboard_interval and (self.metrics.total_packets % self.dashboard_interval == 0):
            self.metrics.display_live_summary()

    def start(self):
        """Executes the passive capture engine."""
        print(DISCLAIMER)
        print("[*] Sniffer Initialized.")
        print(f"    Interface   : {self.interface or 'Default / Any'}")
        print(f"    BPF Filter  : '{self.bpf_filter or 'None (Capturing All IP Traffic)'}'")
        print(f"    PCAP Target : {self.pcap_path or 'Disabled (Memory-Only Capture)'}")
        print(f"    Packet Limit: {self.packet_limit if self.packet_limit > 0 else 'Unlimited (Ctrl+C to Stop)'}")
        print("-" * 80)
        print(f"{'TIMESTAMP':12} | {'NETWORK LAYER (L3)':38} | {'TRANSPORT & APP LAYERS (L4/L7)'}")
        print("-" * 80)

        try:
            # Scapy sniff loop:
            # - prn: per-packet processing function
            # - filter: Berkeley Packet Filter (BPF) expression executed inside kernel space
            # - store=False: ensures captured packets are not retained in RAM indefinitely
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self.packet_handler,
                store=False,
                count=self.packet_limit
            )
        except KeyboardInterrupt:
            # User initiated stop
            print("\n[!] KeyboardInterrupt received. Concluding capture session...")
        finally:
            self.shutdown()

    def shutdown(self):
        """Flushes storage streams and renders the post-capture analytical report."""
        if self.pcap_writer and self.pcap_path:
            self.pcap_writer.close()
            print(f"[+] PCAP file saved and closed: {os.path.abspath(self.pcap_path)}")

        self.print_final_report()

    def print_final_report(self):
        """Displays formatted session summary and protocol distribution."""
        duration = max(time.time() - self.metrics.start_time, 0.001)
        total = self.metrics.total_packets

        print("\n" + "=" * 80)
        print("                  CAPTURE SESSION FORENSIC REPORT")
        print("=" * 80)
        print(f" Total Session Duration : {duration:0.2f} seconds")
        print(f" Total Frames Processed : {total}")
        print(f" Average Packet Rate    : {total / duration:0.2f} packets/second")
        print("-" * 80)
        
        print(" [Protocol Distribution (Transport Layer)]")
        if total > 0:
            for proto in ["TCP", "UDP", "ICMP", "Other"]:
                cnt = self.metrics.protocol_counts[proto]
                pct = (cnt / total) * 100
                bar = "█" * int(pct // 4)
                print(f"   {proto:<6}: {cnt:>6} ({pct:>5.1f}%) | {bar}")
        else:
            print("   No packets were captured.")

        print("-" * 80)
        print(" [Top 5 Active Communicating IP Endpoints]")
        top_talkers = self.metrics.ip_talkers.most_common(5)
        if top_talkers:
            for rank, (ip, count) in enumerate(top_talkers, 1):
                pct = (count / (total * 2)) * 100 if total > 0 else 0
                print(f"   {rank}. {ip:<30} : {count:>5} occurrences ({pct:>5.1f}% of endpoints)")
        else:
            print("   No IP endpoints recorded.")

        if self.metrics.dns_queries:
            print("-" * 80)
            print(" [Top DNS Query Lookups]")
            for rank, (domain, count) in enumerate(self.metrics.dns_queries.most_common(5), 1):
                print(f"   {rank}. {domain:<35} : {count} queries")

        if self.metrics.http_hosts:
            print("-" * 80)
            print(" [Dissected HTTP Cleartext Hosts]")
            for rank, (host, count) in enumerate(self.metrics.http_hosts.most_common(5), 1):
                print(f"   {rank}. {host:<35} : {count} requests")

        print("=" * 80)
        print("[*] Sniffer protocol decommissioned cleanly.\n")


# ==============================================================================
# 6. COMMAND-LINE INTERFACE PARSER
# ==============================================================================
def parse_arguments():
    """
    Parses CLI parameters for granular control over network interfaces,
    BPF filtering rules, and PCAP persistence.
    """
    parser = argparse.ArgumentParser(
        description="Network Traffic Sniffer v2.0 - Passive Traffic Dissector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture all traffic on default interface:
  python sniffer.py

  # Filter HTTP and DNS traffic, saving to session.pcap:
  python sniffer.py -f "tcp port 80 or udp port 53" -w session.pcap

  # Capture only ICMP traffic on a specific interface:
  python sniffer.py -i eth0 -f "icmp"

  # Capture 100 packets from a specific host:
  python sniffer.py -f "host 192.168.1.1" -c 100
        """
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to bind (e.g., eth0, wlan0, Wi-Fi). Default: Auto-detect")
    parser.add_argument("-f", "--filter", default="",
                        help="Berkeley Packet Filter (BPF) syntax string (e.g., 'tcp port 443', 'udp', 'icmp')")
    parser.add_argument("-w", "--write", default=None, dest="pcap_path",
                        help="Path to export captured packets to PCAP file format (e.g., capture.pcap)")
    parser.add_argument("-c", "--count", default=0, type=int,
                        help="Total packet count limit before auto-terminating (default: 0 = infinite)")
    parser.add_argument("-d", "--dashboard-interval", default=25, type=int,
                        help="Packet frequency interval for live console metrics dashboard (default: 25)")
    return parser.parse_args()


# ==============================================================================
# 7. EXECUTION ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    # Parse user runtime arguments first (permits displaying --help without elevation)
    args = parse_arguments()

    # Enforce root / Administrator privilege gate before attempting socket binding
    verify_administrative_privileges()

    # Instantiate and engage the sniffer protocol
    sniffer = NetworkSniffer(
        interface=args.interface,
        bpf_filter=args.filter,
        pcap_path=args.pcap_path,
        packet_limit=args.count,
        dashboard_interval=args.dashboard_interval
    )
    sniffer.start()
