# 📦 Packet Sniffer — Cybersecurity Tool #6


## Get this repository

Clone the current project (this repository's canonical GitHub URL), then follow the installation and usage steps below.

```bash
git clone https://github.com/cyberworlduniversity/packet_sniffer_tool6.git
cd packet_sniffer_tool6
```

> **Definition:** A Packet Sniffer captures and analyzes network packets flowing through a network interface, displaying source IP, destination IP, protocol, ports, flags, and payload data in real time.

---
\n## 📚 Table of Contents

1. [What is a Packet Sniffer?](#what-is-a-packet-sniffer)
2. [How the Program Works — Full Flow](#how-the-program-works--full-flow)
3. [Learning Definitions (All Key Terms)](#learning-definitions-all-key-terms)
4. [OSI Model Context](#osi-model-context)
5. [Network Protocols Explained](#network-protocols-explained)
6. [Installation & Requirements](#installation--requirements)
7. [Usage & Examples](#usage--examples)
8. [Sample Output](#sample-output)
9. [File Structure](#file-structure)
10. [Ethical & Legal Notice](#ethical--legal-notice)

---

## 🔍 What is a Packet Sniffer?

A **packet sniffer** (also called a **network analyzer** or **protocol analyzer**) is a tool that intercepts and logs network traffic passing through a digital network. It works by putting a network interface into **promiscuous mode**, allowing it to capture all packets on the network segment — not just those addressed to that machine.

### Real-World Uses:
| Use Case | Description |
|----------|-------------|
| 🔐 Security Auditing | Detect suspicious traffic, intrusion attempts |
| 🐛 Debugging | Diagnose application network issues |
| 📊 Performance Analysis | Measure bandwidth, latency, bottlenecks |
| 🎓 Education | Learn how TCP/IP protocols actually work |
| 🔍 Forensics | Reconstruct network events after an incident |

### Famous Tools in the Wild:
- **Wireshark** — GUI packet analyzer (uses libpcap)
- **tcpdump** — Command-line classic
- **Scapy** — Python-based packet crafting & sniffing
- **Zeek (Bro)** — Network security monitor

---

## ⚙️ How the Program Works — Full Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                     PACKET SNIFFER FLOW DIAGRAM                     │
└─────────────────────────────────────────────────────────────────────┘

  [ Network Interface Card (NIC) ]
           │
           │  Raw Ethernet Frame arrives
           ▼
  ┌─────────────────┐
  │  Raw Socket     │  socket(AF_PACKET, SOCK_RAW, ntohs(3))
  │  (Layer 2)      │  Captures ALL frames on the wire
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │  Ethernet Frame │  parse_ethernet()
  │  Parser         │  ├── Destination MAC  (6 bytes)
  │                 │  ├── Source MAC       (6 bytes)
  │                 │  └── EtherType        (2 bytes) ──► 0x0800 = IPv4
  └────────┬────────┘
           │ (filter: only IPv4)
           ▼
  ┌─────────────────┐
  │  IPv4 Header    │  parse_ipv4()
  │  Parser         │  ├── Version + IHL
  │                 │  ├── TTL
  │                 │  ├── Protocol Number ──► 6=TCP, 17=UDP, 1=ICMP
  │                 │  ├── Source IP
  │                 │  └── Destination IP
  └────────┬────────┘
           │
     ┌─────┴──────┬──────────┐
     ▼            ▼          ▼
  [TCP=6]      [UDP=17]   [ICMP=1]
     │            │          │
     ▼            ▼          ▼
 parse_tcp()  parse_udp() parse_icmp()
 ├─ Src Port  ├─ Src Port  ├─ Type
 ├─ Dst Port  ├─ Dst Port  ├─ Code
 ├─ Seq Num   ├─ Length    └─ Checksum
 ├─ Ack Num   └─ Payload
 ├─ Flags
 └─ Payload
           │
           ▼
  ┌─────────────────┐
  │  Display Layer  │  Colorized terminal output
  │                 │  + Service name lookup (port 80 = HTTP)
  │                 │  + Statistics tracker
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │  Stats Summary  │  On Ctrl+C: show totals, protocol breakdown,
  │                 │  top talker IPs
  └─────────────────┘
```

### Step-by-Step Execution:

**Step 1 — Socket Creation**
```python
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
```
Creates a raw socket at Layer 2. `ntohs(3)` = `ETH_P_ALL` meaning capture every EtherType. Requires root/administrator privileges.

**Step 2 — Capture Loop**
```python
raw_data, addr = conn.recvfrom(65535)
```
Blocks until a frame arrives. 65535 bytes = max Ethernet jumbo frame.

**Step 3 — Ethernet Parsing**
```python
dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
```
`!` = network (big-endian) byte order. `6s` = 6-byte string (MAC). `H` = unsigned short (EtherType).

**Step 4 — IPv4 Filtering**
Only process frames where EtherType = 8 (IPv4). Skip ARP, IPv6, etc.

**Step 5 — Protocol Dispatch**
Read `proto` field from IPv4 header → route to TCP / UDP / ICMP parser.

**Step 6 — Display & Stats**
Colorized output. Stats accumulate in `PacketStats` object. Final summary on exit.

---

## 📖 Learning Definitions (All Key Terms)

### Core Networking

| Term | Definition |
|------|-----------|
| **Packet** | A unit of data transmitted over a network. Contains header (routing info) + payload (actual data). |
| **Frame** | Layer 2 data unit. An Ethernet frame wraps an IP packet with MAC addresses. |
| **Socket** | An endpoint for network communication. A raw socket can read/write at the packet level. |
| **Raw Socket** | A socket type that allows access to the underlying transport provider (bypasses TCP/UDP stack). |
| **Promiscuous Mode** | NIC setting that allows capturing all packets on the segment, not just those addressed to this host. |
| **Network Interface** | A hardware or software component connecting a computer to a network (e.g., eth0, wlan0). |
| **MTU** | Maximum Transmission Unit — largest packet that can be sent on a network (typically 1500 bytes for Ethernet). |

### Addressing

| Term | Definition |
|------|-----------|
| **IP Address** | 32-bit (IPv4) or 128-bit (IPv6) numeric label assigned to a device on a network. |
| **MAC Address** | 48-bit hardware address burned into a NIC. Used for local delivery (Layer 2). Format: `AA:BB:CC:DD:EE:FF` |
| **Source IP** | The IP address of the device that sent the packet. |
| **Destination IP** | The IP address of the intended recipient. |
| **Port** | 16-bit number (0–65535) identifying a specific application/service on a host. |
| **Well-Known Port** | Ports 0–1023 reserved for system services (80=HTTP, 443=HTTPS, 22=SSH). |
| **Ephemeral Port** | Temporary port (1024–65535) used by clients for outbound connections. |

### Protocols

| Term | Definition |
|------|-----------|
| **Protocol** | A set of rules governing how data is formatted and transmitted between devices. |
| **IPv4** | Internet Protocol version 4. Routes packets using 32-bit addresses (e.g., 192.168.1.1). |
| **TCP** | Transmission Control Protocol. Connection-oriented, reliable, ordered delivery. Uses 3-way handshake. |
| **UDP** | User Datagram Protocol. Connectionless, fast, no delivery guarantee. Used for DNS, streaming, gaming. |
| **ICMP** | Internet Control Message Protocol. Used for diagnostics (ping = ICMP Echo). Not for data transfer. |
| **HTTPS** | HTTP Secure — HTTP encrypted with TLS. Port 443. |
| **DNS** | Domain Name System — translates hostnames to IPs. Uses UDP port 53. |
| **DHCP** | Dynamic Host Configuration Protocol — automatically assigns IP addresses. UDP ports 67/68. |
| **SSH** | Secure Shell — encrypted remote terminal. TCP port 22. |
| **ARP** | Address Resolution Protocol — maps IP addresses to MAC addresses on a LAN. |

### TCP Specifics

| Term | Definition |
|------|-----------|
| **3-Way Handshake** | TCP connection setup: SYN → SYN-ACK → ACK. Establishes sequence numbers. |
| **SYN Flag** | Synchronize — initiates a connection. |
| **ACK Flag** | Acknowledge — confirms receipt of data. |
| **FIN Flag** | Finish — gracefully closes a connection. |
| **RST Flag** | Reset — abruptly terminates a connection (port closed, error). |
| **PSH Flag** | Push — tells receiver to pass data to application immediately. |
| **Sequence Number** | 32-bit number tracking byte position in the stream. |
| **Acknowledgment Number** | Next byte the receiver expects to receive. |
| **Header Length** | Size of the TCP header in 32-bit words × 4 = bytes. Min 20B, max 60B. |

### Packet Analysis

| Term | Definition |
|------|-----------|
| **Header** | Control information prepended to data at each layer (IP header, TCP header, etc.). |
| **Payload** | The actual data being carried. Each layer's payload becomes the next layer's frame. |
| **Checksum** | Error-detection value. Receiver recalculates and compares to detect corruption. |
| **TTL** | Time To Live — decremented by each router hop. Packet discarded when TTL reaches 0. |
| **Byte Order** | Network byte order = Big-Endian. Python struct uses `!` prefix for this. |
| **Struct Unpacking** | Using Python's `struct.unpack()` to parse binary data using format strings. |
| **Wireshark** | Industry-standard GUI packet analyzer. Supports hundreds of protocols. |
| **pcap** | Packet CAPture — file format for storing captured packets (`.pcap` files). |
| **Deep Packet Inspection (DPI)** | Analyzing packet contents (not just headers) to identify applications or threats. |
| **Promiscuous Sniffing** | Capturing packets not addressed to your machine. Requires NIC to be in promiscuous mode. |

### Security Terms

| Term | Definition |
|------|-----------|
| **Man-in-the-Middle (MitM)** | Attack where a sniffer intercepts traffic between two parties. |
| **Passive Sniffing** | Capture-only, no traffic injection. Harder to detect. |
| **Active Sniffing** | Involves sending packets (ARP spoofing) to redirect traffic to the attacker. |
| **ARP Poisoning** | Sending fake ARP replies to associate attacker's MAC with victim's IP. |
| **Encryption** | Protects payload from sniffers. HTTPS, SSH, VPN all encrypt in transit. |
| **IDS** | Intrusion Detection System — uses sniffing techniques to detect attacks. |
| **Firewall** | Filters packets based on rules (IP, port, protocol). Complements sniffers. |

---

## 🌐 OSI Model Context

```
┌─────────────────────────────────────────────────────┐
│                   OSI MODEL                         │
├───────┬─────────────┬──────────────────────────────┤
│ Layer │ Name        │ What This Tool Sees           │
├───────┼─────────────┼──────────────────────────────┤
│   7   │ Application │ HTTP data in payload          │
│   6   │ Presentation│ Encoding (TLS shown as binary)│
│   5   │ Session     │ Not directly visible          │
│   4   │ Transport   │ ✅ TCP/UDP headers, ports     │
│   3   │ Network     │ ✅ IPv4 headers, src/dst IP   │
│   2   │ Data Link   │ ✅ Ethernet frames, MACs      │
│   1   │ Physical    │ Electrical signals (NIC level)│
└───────┴─────────────┴──────────────────────────────┘
```

This tool operates at **Layers 2–4**, giving full visibility into network addressing and transport behavior.

---

## 🔌 Network Protocols Explained

### TCP Connection Lifecycle
```
Client                    Server
  │                          │
  │──────── SYN ────────────►│   Step 1: Client initiates
  │◄──── SYN + ACK ──────────│   Step 2: Server acknowledges
  │──────── ACK ────────────►│   Step 3: Connection established
  │                          │
  │══════ DATA FLOWS ════════│   Normal data exchange
  │                          │
  │──────── FIN ────────────►│   Step 4: Client closes
  │◄──── FIN + ACK ──────────│   Step 5: Server confirms close
```

### IPv4 Packet Structure
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┬─┬─┬─┼─┬─┬─┬─┬─┬─┬─┬─┼─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┤
│Version│ IHL   │   ToS   │           Total Length                │
├───────┴───────┴─────────┼─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┤
│         Identification  │ │ │ │ │ │     Fragment Offset        │
├─────────────────────────┼─┴─┴─┴─┴─┴─────────────────────────────┤
│    TTL    │  Protocol   │         Header Checksum               │
├───────────┴─────────────┴───────────────────────────────────────┤
│                       Source IP Address                         │
├─────────────────────────────────────────────────────────────────┤
│                    Destination IP Address                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠 Installation & Requirements

### System Requirements
- **OS:** Linux (required for `AF_PACKET` raw sockets)
- **Python:** 3.6+
- **Privileges:** Root / sudo (for live capture)
- **Dependencies:** None (uses Python standard library only)

### Quick Start
```bash
# Clone or download the files
git clone https://github.com/cyberworlduniversity/packet_sniffer_tool6.git
cd packet_sniffer_tool6

# Run demo mode (no root needed)
python3 packet_sniffer.py --demo

# Live capture (requires root)
sudo python3 packet_sniffer.py

# macOS/Windows alternative using Scapy:
pip install scapy
sudo python3 packet_sniffer_scapy.py
```

---

## 📟 Usage & Examples

```
usage: packet_sniffer.py [-h] [-i INTERFACE] [-f FILTER] [-n COUNT] [-v] [--demo]

optional arguments:
  -h, --help            show this help message and exit
  -i, --interface       Network interface (e.g. eth0, wlan0)
  -f, --filter          Protocol filter: TCP | UDP | ICMP
  -n, --count           Number of packets to capture (0 = unlimited)
  -v, --verbose         Show Ethernet layer details
  --demo                Run in simulation mode (no root required)
```

### Examples:
```bash
# Capture everything on default interface
sudo python3 packet_sniffer.py

# Capture only TCP on eth0, verbose
sudo python3 packet_sniffer.py -i eth0 -f TCP -v

# Capture 100 UDP packets then stop
sudo python3 packet_sniffer.py -f UDP -n 100

# Demo mode — perfect for learning without a network
python3 packet_sniffer.py --demo
```

---

## 🖥 Sample Output

```
[#0001] [14:32:07.841] ◀─── TCP ───▶
  SRC: 192.168.1.105       DST: 142.250.80.46
  SRC Port: 52341  DST Port: 443 (HTTPS)  Flags: [PSH ACK]

────────────────────────────────────────────────────────────────────

[#0002] [14:32:07.902] ◀─── UDP ───▶
  SRC: 192.168.1.105       DST: 8.8.8.8
  SRC Port: 54821  DST Port: 53 (DNS)  Size: 67B

════════════════════════ CAPTURE STATISTICS ═════════════════════════
  Total Packets : 47         Elapsed: 12.3s
  Protocol Breakdown:
    TCP       34  ████████████████████████████████████
    UDP       10  ████████████
    ICMP       3  ████
  Top Source IPs:
    192.168.1.105      → 38 packets
    8.8.8.8            → 6 packets
```

---

## 📁 File Structure

```
packet_sniffer/
├── packet_sniffer.py       # Main packet sniffer (raw sockets, Linux)
├── packet_sniffer_scapy.py # Cross-platform version using Scapy
├── README.md               # This file
└── sample_output.txt       # Example captured output
```

---

## ⚖️ Ethical & Legal Notice

> **⚠️ IMPORTANT:** Only use this tool on networks you own or have **explicit written permission** to monitor.

- Sniffing network traffic without authorization is **illegal** in most jurisdictions under laws such as:
  - Computer Fraud and Abuse Act (CFAA) — USA
  - Computer Misuse Act — UK
  - GDPR data interception provisions — EU
- Use only on:
  - Your own home network
  - Lab/test environments
  - Networks where you have written authorization
- **Educational use only** — this tool is part of a cybersecurity learning series.

---

*Part of the Cybersecurity Learning Series — Tool #6 of 10*
*Built with Python standard library — zero external dependencies for live capture*
