#!/usr/bin/env python3
"""
Packet Sniffer — Cross-Platform Version (using Scapy)
Works on Linux, macOS, and Windows.

Install: pip install scapy
Run:     sudo python3 packet_sniffer_scapy.py
"""

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
except ImportError:
    print("[ERROR] Scapy not installed. Run: pip install scapy")
    import sys; sys.exit(1)

import datetime

# ─── Color codes ─────────────────────────────────────────────────────────────
class C:
    R='\033[91m'; G='\033[92m'; Y='\033[93m'
    B='\033[94m'; M='\033[95m'; CY='\033[96m'
    BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

pkt_count = 0

def process_packet(pkt):
    global pkt_count
    if not pkt.haslayer(IP):
        return

    pkt_count += 1
    now    = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    ttl    = pkt[IP].ttl

    # ── Determine Protocol ──────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        proto = "TCP"
        color = C.G
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags
        layer_info = f"  {color}Ports:{C.RESET} {sport} → {dport}  {color}Flags:{C.RESET} {str(flags)}"

    elif pkt.haslayer(UDP):
        proto = "UDP"
        color = C.CY
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        dns_info = ""
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            try:
                dns_info = f"  Query: {pkt[DNS].qd.qname.decode()}"
            except:
                pass
        layer_info = f"  {color}Ports:{C.RESET} {sport} → {dport}{dns_info}"

    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        color = C.Y
        itype = pkt[ICMP].type
        icode = pkt[ICMP].code
        layer_info = f"  {color}Type:{C.RESET} {itype}  {color}Code:{C.RESET} {icode}"

    else:
        proto = "OTHER"
        color = C.DIM
        layer_info = ""

    print(f"\n{color}{C.BOLD}[#{pkt_count:04d}] [{now}] ── {proto} ──{C.RESET}")
    print(f"  {C.Y}SRC:{C.RESET} {src_ip:<18}  {C.Y}DST:{C.RESET} {dst_ip}  TTL:{ttl}")
    if layer_info:
        print(layer_info)
    print("─" * 60)


def main():
    print(f"{C.CYAN}{C.BOLD}[*] Scapy Packet Sniffer — Cross Platform{C.RESET}")
    print(f"{C.GREEN}[*] Sniffing... Press Ctrl+C to stop{C.RESET}\n")
    try:
        sniff(prn=process_packet, store=False, filter="ip")
    except KeyboardInterrupt:
        print(f"\n{C.Y}[*] Capture stopped. Total: {pkt_count} packets{C.RESET}")

if __name__ == "__main__":
    main()
