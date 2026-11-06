#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              PACKET SNIFFER - Network Analysis Tool          ║
║         Captures & Analyzes Network Packets in Real-Time     ║
╚══════════════════════════════════════════════════════════════╝

Tool #6 - Cybersecurity Learning Series
Definition: Captures and analyzes network packets flowing through
            a network interface.
"""

import socket
import struct
import textwrap
import sys
import os
import time
import datetime
from collections import defaultdict

# ─── ANSI Color Codes ───────────────────────────────────────────────────────
class Colors:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'
    DIM     = '\033[2m'

# ─── Protocol Mapping ───────────────────────────────────────────────────────
PROTOCOLS = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    89:  "OSPF",
    132: "SCTP",
}

# ─── Well-Known Port Mapping ─────────────────────────────────────────────────
WELL_KNOWN_PORTS = {
    20:   "FTP-DATA", 21:  "FTP",   22:  "SSH",   23:  "TELNET",
    25:   "SMTP",     53:  "DNS",   67:  "DHCP",  68:  "DHCP",
    80:   "HTTP",     110: "POP3",  143: "IMAP",  443: "HTTPS",
    445:  "SMB",      3306:"MySQL", 3389:"RDP",   5432:"PostgreSQL",
    6379: "Redis",    8080:"HTTP-ALT", 8443:"HTTPS-ALT",
}

# ─── Statistics Tracker ──────────────────────────────────────────────────────
class PacketStats:
    def __init__(self):
        self.total      = 0
        self.protocols  = defaultdict(int)
        self.src_ips    = defaultdict(int)
        self.dst_ips    = defaultdict(int)
        self.start_time = time.time()

    def update(self, proto, src_ip, dst_ip):
        self.total += 1
        self.protocols[proto] += 1
        self.src_ips[src_ip]  += 1
        self.dst_ips[dst_ip]  += 1

    def elapsed(self):
        return round(time.time() - self.start_time, 1)

stats = PacketStats()

# ─── Helper Functions ────────────────────────────────────────────────────────
def format_mac(raw_bytes):
    """Convert raw bytes to human-readable MAC address."""
    return ':'.join(f'{b:02x}' for b in raw_bytes)

def format_ip(raw_bytes):
    """Convert 4 raw bytes to dotted-quad IP string."""
    return '.'.join(str(b) for b in raw_bytes)

def get_protocol_name(proto_num):
    """Return protocol name or hex code."""
    return PROTOCOLS.get(proto_num, f"UNKNOWN(0x{proto_num:02X})")

def get_port_service(port):
    """Return service name for well-known ports."""
    return WELL_KNOWN_PORTS.get(port, "")

def protocol_color(proto_name):
    """Assign color based on protocol."""
    colors = {
        "TCP":  Colors.GREEN,
        "UDP":  Colors.CYAN,
        "ICMP": Colors.YELLOW,
        "DNS":  Colors.MAGENTA,
    }
    return colors.get(proto_name, Colors.WHITE)

# ─── Ethernet Frame Parser ────────────────────────────────────────────────────
def parse_ethernet(raw_data):
    """
    Parse Ethernet II frame.
    Structure: [DST MAC 6B][SRC MAC 6B][EtherType 2B][Payload]
    """
    if len(raw_data) < 14:
        raise ValueError("Truncated Ethernet frame.")
    dest_mac, src_mac, eth_proto = struct.unpack("!6s6sH", raw_data[:14])
    return format_mac(dest_mac), format_mac(src_mac), eth_proto, raw_data[14:]

# ─── IPv4 Packet Parser ───────────────────────────────────────────────────────
def parse_ipv4(raw_data):
    """
    Parse IPv4 header.
    Fields: Version, IHL, ToS, Total Length, ID, Flags, TTL, Protocol,
            Checksum, Src IP, Dst IP
    """
    if len(raw_data) < 20:
        raise ValueError("Truncated IPv4 header.")
    version_ihl = raw_data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or ihl > len(raw_data):
        raise ValueError("Invalid IPv4 version or header length.")
    ttl, proto, src, dst = struct.unpack("!8xBB2x4s4s", raw_data[:20])
    return version, ihl, ttl, proto, format_ip(src), format_ip(dst), raw_data[ihl:]

# ─── ICMP Packet Parser ───────────────────────────────────────────────────────
def parse_icmp(raw_data):
    """
    Parse ICMP header.
    Type 0 = Echo Reply, Type 8 = Echo Request
    """
    if len(raw_data) < 4:
        raise ValueError("Truncated ICMP header.")
    icmp_type, code, checksum = struct.unpack("!BBH", raw_data[:4])
    return icmp_type, code, checksum, raw_data[4:]

ICMP_TYPES = {
    0: "Echo Reply",    3: "Dest Unreachable",
    8: "Echo Request",  11: "Time Exceeded",
}

# ─── TCP Segment Parser ───────────────────────────────────────────────────────
def parse_tcp(raw_data):
    """
    Parse TCP segment header.
    Extracts ports, sequence numbers, flags, and payload.
    """
    if len(raw_data) < 20:
        raise ValueError("Truncated TCP header.")
    src_port, dst_port, seq, ack, offset_flags = struct.unpack("!HHIIH", raw_data[:14])
    offset = (offset_flags >> 12) * 4
    if offset < 20 or offset > len(raw_data):
        raise ValueError("Invalid TCP data offset.")
    flags = offset_flags & 0x1FF

    flag_str = ""
    if flags & 0x002: flag_str += "SYN "
    if flags & 0x010: flag_str += "ACK "
    if flags & 0x001: flag_str += "FIN "
    if flags & 0x004: flag_str += "RST "
    if flags & 0x008: flag_str += "PSH "
    if flags & 0x020: flag_str += "URG "

    return src_port, dst_port, seq, ack, flag_str.strip(), raw_data[offset:]

# ─── UDP Segment Parser ───────────────────────────────────────────────────────
def parse_udp(raw_data):
    """
    Parse UDP datagram header.
    Simple: source port, dest port, length, checksum.
    """
    if len(raw_data) < 8:
        raise ValueError("Truncated UDP header.")
    src_port, dst_port, size = struct.unpack("!HH2xH", raw_data[:8])
    if size < 8:
        raise ValueError("Invalid UDP length.")
    return src_port, dst_port, size, raw_data[8:min(size, len(raw_data))]

# ─── Display Functions ────────────────────────────────────────────────────────
def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║  ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗              ║
║  ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝              ║
║  ██████╔╝███████║██║     █████╔╝ █████╗     ██║                 ║
║  ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║                 ║
║  ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║                 ║
║  ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝                ║
║                                                                  ║
║         🔍 S N I F F E R  —  Network Packet Analyzer            ║
║              Tool #6 · Cybersecurity Learning Series             ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}""")

def print_separator(char="─", width=68, color=Colors.DIM):
    print(f"{color}{char * width}{Colors.RESET}")

def print_packet_header(pkt_num, proto_name, src_ip, dst_ip, timestamp):
    color = protocol_color(proto_name)
    print(f"\n{color}{Colors.BOLD}[#{pkt_num:04d}] [{timestamp}] ◀─── {proto_name} ───▶{Colors.RESET}")
    print(f"  {Colors.YELLOW}SRC:{Colors.RESET} {src_ip:<18} {Colors.YELLOW}DST:{Colors.RESET} {dst_ip}")

def display_tcp(src_port, dst_port, seq, ack, flags, payload, show_payload=False):
    src_svc = f" ({get_port_service(src_port)})" if get_port_service(src_port) else ""
    dst_svc = f" ({get_port_service(dst_port)})" if get_port_service(dst_port) else ""
    print(f"  {Colors.GREEN}SRC Port:{Colors.RESET} {src_port}{src_svc}  "
          f"{Colors.GREEN}DST Port:{Colors.RESET} {dst_port}{dst_svc}")
    print(f"  {Colors.GREEN}SEQ:{Colors.RESET} {seq}  "
          f"{Colors.GREEN}ACK:{Colors.RESET} {ack}  "
          f"{Colors.GREEN}Flags:{Colors.RESET} [{flags}]")
    if payload and show_payload:
        preview = payload[:60]
        try:
            txt = preview.decode('utf-8', errors='replace').replace('\n','↵').replace('\r','')
            print(f"  {Colors.DIM}Data: {txt[:60]}{'...' if len(payload)>60 else ''}{Colors.RESET}")
        except:
            pass

def display_udp(src_port, dst_port, size, payload, show_payload=False):
    src_svc = f" ({get_port_service(src_port)})" if get_port_service(src_port) else ""
    dst_svc = f" ({get_port_service(dst_port)})" if get_port_service(dst_port) else ""
    print(f"  {Colors.CYAN}SRC Port:{Colors.RESET} {src_port}{src_svc}  "
          f"{Colors.CYAN}DST Port:{Colors.RESET} {dst_port}{dst_svc}  "
          f"{Colors.CYAN}Size:{Colors.RESET} {size}B")

def display_icmp(icmp_type, code, checksum):
    type_name = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
    print(f"  {Colors.YELLOW}Type:{Colors.RESET} {icmp_type} ({type_name})  "
          f"{Colors.YELLOW}Code:{Colors.RESET} {code}  "
          f"{Colors.YELLOW}Checksum:{Colors.RESET} {checksum}")

def display_stats():
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}")
    print("╔══════════════════════ CAPTURE STATISTICS ══════════════════════╗")
    print(f"║  Total Packets : {stats.total:<10}  Elapsed: {stats.elapsed()}s{' '*(28-len(str(stats.elapsed())))}║")
    print("║──────────────────────────────────────────────────────────────║")
    print("║  Protocol Breakdown:                                          ║")
    for proto, count in sorted(stats.protocols.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 30)
        print(f"║    {proto:<8} {count:>5}  {Colors.GREEN}{bar}{Colors.MAGENTA}{'░'*(30-min(count,30))}  ║")
    print("║──────────────────────────────────────────────────────────────║")
    print("║  Top Source IPs:                                              ║")
    for ip, count in sorted(stats.src_ips.items(), key=lambda x: -x[1])[:5]:
        print(f"║    {ip:<18} → {count} packets{' '*(24-len(str(count)))}║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(Colors.RESET)

# ─── Core Sniffer Logic ───────────────────────────────────────────────────────
def sniff(interface=None, packet_limit=0, filter_protocol=None, verbose=False, show_payload=False):
    """
    Main sniffing loop.

    Parameters:
        interface      – Network interface name (Linux: 'eth0', 'wlan0')
        packet_limit   – Stop after N packets (0 = unlimited)
        filter_protocol– Only show 'TCP', 'UDP', 'ICMP', or None for all
        verbose        – Show Ethernet layer details
    """
    if packet_limit < 0:
        raise ValueError("Packet count must be zero (unlimited) or a positive integer.")
    if filter_protocol and filter_protocol.upper() not in {"TCP", "UDP", "ICMP"}:
        raise ValueError("Protocol filter must be TCP, UDP, or ICMP.")

    try:
        # AF_PACKET captures raw Ethernet frames (Linux only)
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        if interface:
            conn.bind((interface, 0))
    except PermissionError:
        print(f"{Colors.RED}[ERROR] Root privileges required. Run: sudo python3 packet_sniffer.py{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR] {e}{Colors.RESET}")
        sys.exit(1)

    print_banner()
    iface_label = interface if interface else "all interfaces"
    print(f"{Colors.GREEN}[*] Sniffing on: {Colors.BOLD}{iface_label}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Filter: {filter_protocol or 'ALL PROTOCOLS'}{Colors.RESET}")
    print(f"{Colors.GREEN}[*] Press Ctrl+C to stop and view statistics.{Colors.RESET}")
    print_separator("═")

    pkt_num = 0
    try:
        while True:
            raw_data, _ = conn.recvfrom(65535)
            now = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

            # ── Layer 2: Ethernet ──
            try:
                dest_mac, src_mac, eth_proto, eth_payload = parse_ethernet(raw_data)
                if eth_proto != 0x0800:
                    continue
                version, ihl, ttl, proto_num, src_ip, dst_ip, ip_payload = parse_ipv4(eth_payload)
            except (ValueError, struct.error):
                continue
            proto_name = get_protocol_name(proto_num)

            # Apply protocol filter
            if filter_protocol and proto_name != filter_protocol.upper():
                continue

            stats.update(proto_name, src_ip, dst_ip)
            pkt_num += 1
            print_packet_header(pkt_num, proto_name, src_ip, dst_ip, now)

            if verbose:
                print(f"  {Colors.DIM}ETH  SRC:{src_mac} → DST:{dest_mac}{Colors.RESET}")
                print(f"  {Colors.DIM}IPv4 TTL:{ttl}  Version:{version}{Colors.RESET}")

            # ── Layer 4 ──
            if proto_num == 6:      # TCP
                sp, dp, seq, ack, flags, payload = parse_tcp(ip_payload)
                display_tcp(sp, dp, seq, ack, flags, payload, show_payload=show_payload)

            elif proto_num == 17:   # UDP
                sp, dp, size, payload = parse_udp(ip_payload)
                display_udp(sp, dp, size, payload, show_payload=show_payload)

            elif proto_num == 1:    # ICMP
                icmp_type, code, checksum, _ = parse_icmp(ip_payload)
                display_icmp(icmp_type, code, checksum)

            print_separator()

            if packet_limit and pkt_num >= packet_limit:
                print(f"\n{Colors.YELLOW}[*] Packet limit ({packet_limit}) reached.{Colors.RESET}")
                break

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Capture stopped by user.{Colors.RESET}")

    finally:
        conn.close()
        display_stats()


# ─── Demo / Simulation Mode (no root needed) ─────────────────────────────────
def run_demo():
    """
    Simulates packet capture for educational demonstration
    when root privileges are not available.
    """
    import random

    print_banner()
    print(f"{Colors.YELLOW}[DEMO MODE] Simulating packet capture (no root required){Colors.RESET}")
    print(f"{Colors.GREEN}[*] Press Ctrl+C to stop.\n{Colors.RESET}")
    print_separator("═")

    sample_ips = [
        "192.168.1.1","192.168.1.105","10.0.0.1",
        "8.8.8.8","142.250.80.46","104.21.33.11",
        "172.16.0.5","93.184.216.34"
    ]
    sample_protos = [("TCP",6), ("UDP",17), ("ICMP",1)]
    tcp_ports     = [80, 443, 22, 8080, 3306, 53]

    pkt_num = 0
    try:
        while True:
            time.sleep(random.uniform(0.3, 1.2))
            now   = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            src   = random.choice(sample_ips)
            dst   = random.choice([ip for ip in sample_ips if ip != src])
            proto_name, proto_num = random.choice(sample_protos)

            stats.update(proto_name, src, dst)
            pkt_num += 1
            print_packet_header(pkt_num, proto_name, src, dst, now)

            if proto_num == 6:
                sp = random.randint(1024, 65535)
                dp = random.choice(tcp_ports)
                flags = random.choice(["SYN", "SYN ACK", "ACK", "PSH ACK", "FIN ACK"])
                svc = get_port_service(dp)
                print(f"  {Colors.GREEN}SRC Port:{Colors.RESET} {sp}  "
                      f"{Colors.GREEN}DST Port:{Colors.RESET} {dp}"
                      f"{' ('+svc+')' if svc else ''}  "
                      f"{Colors.GREEN}Flags:{Colors.RESET} [{flags}]")
            elif proto_num == 17:
                sp = random.randint(1024, 65535)
                dp = random.choice([53, 67, 123, 5353])
                svc = get_port_service(dp)
                print(f"  {Colors.CYAN}SRC Port:{Colors.RESET} {sp}  "
                      f"{Colors.CYAN}DST Port:{Colors.RESET} {dp}"
                      f"{' ('+svc+')' if svc else ''}  "
                      f"{Colors.CYAN}Size:{Colors.RESET} {random.randint(40,512)}B")
            elif proto_num == 1:
                t = random.choice([0, 8])
                print(f"  {Colors.YELLOW}Type:{Colors.RESET} {t} ({ICMP_TYPES[t]})  "
                      f"{Colors.YELLOW}Code:{Colors.RESET} 0")

            print_separator()

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Demo stopped.{Colors.RESET}")
        display_stats()


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="🔍 Packet Sniffer — Cybersecurity Tool #6",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 packet_sniffer.py                   # Sniff all interfaces
  sudo python3 packet_sniffer.py -i eth0           # Sniff eth0
  sudo python3 packet_sniffer.py -f TCP            # TCP only
  sudo python3 packet_sniffer.py -n 50             # Capture 50 packets
  sudo python3 packet_sniffer.py -v                # Verbose (show Ethernet layer)
  python3 packet_sniffer.py --demo                 # Demo mode (no root needed)
        """
    )
    parser.add_argument('-i', '--interface', help='Network interface (e.g. eth0, wlan0)')
    parser.add_argument('-f', '--filter',    help='Protocol filter: TCP | UDP | ICMP')
    parser.add_argument('-n', '--count',     type=int, default=0, help='Number of packets to capture')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show Ethernet layer details')
    parser.add_argument('--show-payload', action='store_true',
                        help='Opt in to displaying up to 60 bytes of TCP/UDP payload (may contain secrets)')
    parser.add_argument('--demo',            action='store_true',  help='Run in demo/simulation mode')

    args = parser.parse_args()

    if args.demo:
        run_demo()
    else:
        sniff(
            interface       = args.interface,
            packet_limit    = args.count,
            filter_protocol = args.filter,
            verbose         = args.verbose,
            show_payload    = args.show_payload
        )
