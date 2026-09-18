# Deep Packet Inspection Engine (Java)

A multi-threaded **Deep Packet Inspection (DPI) Engine** written in pure Java. It reads raw network traffic captures (`.pcap` files), tracks active connection flows, inspects packet headers and TLS payloads (Server Name Indication / SNI), applies rule-based filtering, and writes the surviving traffic to an output `.pcap` file.

This is a dependency-free engine: there is no `libpcap` or JNI binding involved. Reading and writing `.pcap` files is handled by a hand-written parser for the classic PCAP binary file format.

---

## Table of Contents
1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Architecture Overview](#3-architecture-overview)
4. [Project Layout](#4-project-layout)
5. [The Journey of a Packet](#5-the-journey-of-a-packet)
6. [Component Deep Dive](#6-component-deep-dive)
   - [PCAP Binary I/O](#pcap-binary-io)
   - [Protocol Header Parser](#protocol-header-parser)
   - [TLS SNI Extraction](#tls-sni-extraction)
   - [Connection Tracking & Hash Routing](#connection-tracking--hash-routing)
   - [Rule Engine & App Signatures](#rule-engine--app-signatures)
7. [Building and Running](#7-building-and-running)
8. [Understanding the Output](#8-understanding-the-output)
9. [Operational Notes](#9-operational-notes)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a network processing technology used to examine the content of data packets passing through an inspection point. Standard firewalls only inspect basic packet headers (Layer 3 / Layer 4, such as IP addresses and port numbers). DPI looks *inside* the Layer 7 application payload.

```
Input Capture (.pcap) ──► [ DPI Engine ] ──► Output Capture (.pcap)
                             │
                             ├── Tracks 5-tuple flows
                             ├── Extracts TLS SNI Hostnames
                             ├── Filters by IP / Domain / App rules
                             └── Generates execution statistics
```

### Primary Uses:
* **Network Management**: Regulating bandwidth usage for high-consumption apps (e.g. streaming, file sharing).
* **Security & Filtering**: Blocking malicious domains or unauthorized network traffic.
* **Parental & Enterprise Controls**: Restricting access to specific domains or services.

---

## 2. Networking Background

### The Network Stack (OSI Layers)
Data traveling over a network is encapsulated across multiple abstraction layers:

```
┌───────────────────────────────────────────────────────────┐
│ Layer 7: Application     │ HTTP, TLS (SNI), DNS           │
├───────────────────────────────────────────────────────────┤
│ Layer 4: Transport       │ TCP, UDP                       │
├───────────────────────────────────────────────────────────┤
│ Layer 3: Network         │ IPv4, IPv6                     │
├───────────────────────────────────────────────────────────┤
│ Layer 2: Data Link       │ Ethernet (MAC Addresses)       │
└───────────────────────────────────────────────────────────┘
```

### Packet Encapsulation
Each frame inside a `.pcap` file wraps protocol headers layer-by-layer:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                             │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ IPv4 Header (20+ bytes)                                            │ │
│ │ ┌────────────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20+ bytes)                                         │ │ │
│ │ │ ┌────────────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Application Payload                                        │ │ │ │
│ │ │ │ (e.g. TLS ClientHello containing SNI Hostname)             │ │ │ │
│ │ │ └────────────────────────────────────────────────────────────┘ │ │ │
│ │ └────────────────────────────────────────────────────────────────┘ │ │
│ └────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

### The 5-Tuple Connection Key
A network conversation (flow) between two endpoints is uniquely identified by 5 fields:

| Field | Description | Example |
|-------|-------------|---------|
| **Source IP** | Sender IP address | `192.168.1.100` |
| **Destination IP** | Target IP address | `142.250.190.46` |
| **Source Port** | Sender port number | `54321` |
| **Destination Port** | Service port number | `443` (HTTPS) |
| **Protocol** | Transport layer protocol | `6` (TCP) |

---

## 3. Architecture Overview

The engine uses a 3-stage pipeline architecture designed for multi-core processing with lock-free worker paths:

```
+──────────────────+     +───────────────────────+     +──────────────────────────+     +────────────────------+     +───────────────────+
|  Input PCAP File | ──► | Load Balancer Thread  | ──► | N Worker Threads         | ──► | Output Writer Thread | ──► | Output PCAP File  |
| (PcapReader.java)|     | (LoadBalancer.java)   |     | (Worker.java)            |     | (OutputWriter.java)  |     | (PcapWriter.java) |
+──────────────────+     +───────────────────────+     +──────────────────────────+     +────────────────------+     +───────────────────+
                               |                             |
                       Header Parsing                TLS SNI Extraction &
                     & 5-Tuple Hashing               Blocking Rules Verdict
```

1. **Load Balancer Thread (`LoadBalancer.java`)**: Sequentially reads the capture file, parses network headers, constructs a direction-independent 5-tuple hash key, and routes each packet to the worker thread assigned to that connection.
2. **Worker Threads (`Worker.java`)**: Each worker thread independently owns a subset of connection flows. It inspects packet payloads (extracting TLS SNI on first sight), evaluates rules, and records verdicts. Routing by connection ensures per-connection state requires **no locking**.
3. **Output Writer Thread (`OutputWriter.java`)**: Buffers out-of-order worker results and writes forwarded packets strictly in their original capture sequence order to maintain monotonic timestamps.

---

## 4. Project Layout

```
src/main/java/com/dpi/
├── Main.java                    # Command-line entry point & argument parser
├── pcap/                        # Binary PCAP format parsing and writing
│   ├── PcapGlobalHeader.java    # 24-byte global header & endianness detection
│   ├── PcapReader.java          # Sequential pcap packet reader
│   ├── PcapWriter.java          # Pcap file writer
│   └── RawPacket.java           # Captured frame data, timestamp, and sequence ID
├── parser/                      # Layer 2-4 protocol decoder
│   ├── PacketParser.java        # Decodes Ethernet, IPv4, TCP, and UDP headers
│   └── ParsedPacket.java        # Parsed header fields and payload location
├── sni/                         # Layer 7 payload analysis
│   └── SniExtractor.java        # TLS ClientHello SNI extractor
├── connection/                  # Stateful flow tracking
│   ├── ConnectionKey.java       # Direction-independent 5-tuple hash key
│   ├── Connection.java          # Per-flow state (SNI, block flag, packet counts)
│   └── ConnectionTable.java     # Thread-safe connection tracking map
├── rules/                       # Rule matching & app signature lookup
│   ├── Rule.java                # Verdict encapsulation (FORWARD vs DROP)
│   ├── RuleEngine.java          # IP, domain substring, and application blocklists
│   └── AppSignatures.java       # Pre-configured app name -> domain keyword map
├── engine/                      # Threading pipeline orchestrator
│   ├── PacketTask.java          # Unit of work passed to worker threads
│   ├── LoadBalancer.java        # Reader & flow dispatcher thread
│   ├── Worker.java              # Fast-path worker thread implementation
│   ├── OutputWriter.java        # Sequence re-ordering writer thread
│   └── DpiEngine.java           # Pipeline setup & thread lifecycle manager
└── stats/                       # Run counters
    └── DpiStats.java            # Forwarded/dropped packet counters
```

---

## 5. The Journey of a Packet

Here is how a packet flows through the engine from input to output:

```
[ Input .pcap ]
       │
       ▼
1. PcapReader ───────────► Reads raw frame bytes and 16-byte PCAP packet header
       │
       ▼
2. PacketParser ─────────► Decodes Ethernet, IPv4, and TCP/UDP headers
       │
       ▼
3. ConnectionKey ────────► Constructs 5-tuple; normalizes IP/Port order for bidirectional tracking
       │
       ▼
4. LoadBalancer ─────────► Calculates key.bucket(workerCount) and places task in Worker Queue
       │
       ▼
5. Worker Thread ────────► Pulls task from queue:
       │                   ├── Inspects TCP payload for TLS ClientHello
       │                   ├── SniExtractor parses SNI hostname (e.g. "www.youtube.com")
       │                   └── RuleEngine checks IP / Domain / App signature blocklists
       │
       ▼
6. OutputWriter ─────────► Receives verdict (FORWARD or DROP):
                           ├── Re-orders packets to original capture sequence (0, 1, 2...)
                           └── Writes allowed packets to output .pcap file
```

---

## 6. Component Deep Dive

### PCAP Binary I/O
The `.pcap` binary format starts with a 24-byte **Global Header** followed by repeating packet records:

```
┌────────────────────────────────────────────────────────┐
│ Global Header (24 bytes)                               │  ← Read once at start
├────────────────────────────────────────────────────────┤
│ Packet Record Header (16 bytes: timestamp, length)     │  ← Packet 1
│ Packet Payload (incl_len bytes)                        │
├────────────────────────────────────────────────────────┤
│ Packet Record Header (16 bytes: timestamp, length)     │  ← Packet 2
│ Packet Payload (incl_len bytes)                        │
└────────────────────────────────────────────────────────┘
```

* `PcapGlobalHeader.java` checks magic bytes (`0xa1b2c3d4` or swapped `0xd4c3b2a1`) to handle little-endian and big-endian captures seamlessly.

### Protocol Header Parser
`PacketParser.java` inspects raw frame bytes slice-by-slice:
* **Ethernet (14 bytes)**: Verifies EtherType `0x0800` (IPv4).
* **IPv4 (20+ bytes)**: Extracts Internet Header Length (IHL), Total Length, Protocol (`6` for TCP, `17` for UDP), Source IP, and Destination IP.
* **TCP / UDP**: Extracts Source Port, Destination Port, Data Offset, and computes payload slice bounds.

### TLS SNI Extraction
During an HTTPS handshake, the client sends a `ClientHello` containing the domain name in plaintext before encryption begins:

```
TLS Record Header:  Content Type = 0x16 (Handshake)
Handshake Header:   Handshake Type = 0x01 (ClientHello)
ClientHello Body:   Skip Version, Random (32B), Session ID, Cipher Suites, Compression
Extensions:         Search for Extension Type 0x0000 (SNI)
Server Name List:   Name Type = 0x00 (Hostname) ──► Extract "www.youtube.com"
```

`SniExtractor.java` parses these binary fields directly without external SSL dependencies.

### Connection Tracking & Hash Routing
* `ConnectionKey.java` enforces directional normalization: `(IP_A, Port_A)` and `(IP_B, Port_B)` are ordered deterministically so client-to-server and server-to-client packets share the exact same key.
* The bucket index `Math.abs(key.hashCode() % workerCount)` assigns all packets of a connection to one worker thread.

### Rule Engine & App Signatures
* `RuleEngine.java` supports three blocking mechanisms:
  1. **IP Blacklist**: Exact match on source or destination IPv4 address.
  2. **Domain Keywords**: Case-insensitive substring match against extracted SNI hostnames.
  3. **App Signatures**: `AppSignatures.java` expands application names (`YouTube`, `Netflix`, `TikTok`, `Instagram`, `Facebook`, `Twitter`, `WhatsApp`, `Spotify`, `Twitch`, `PrimeVideo`, `DisneyPlus`, `Steam`) into domain keyword rules.

---

## 7. Building and Running

### Prerequisites
* **JDK 17 or higher**
* (Optional) **Maven 3.6+**

### Build

**Option A: Using Maven**
```bash
mvn package
# Produces target/dpi-engine.jar
```

**Option B: Direct `javac` (No Maven needed)**
```powershell
mkdir out
javac -d out (Get-ChildItem -Recurse -Filter *.java src/main/java).FullName
```

---

### Run Examples

**Basic run (Inspect capture & print summary):**
```bash
java -jar target/dpi-engine.jar input.pcap output.pcap
```

**Run with blocking rules:**
```bash
java -jar target/dpi-engine.jar input.pcap output.pcap \
    --block-app YouTube \
    --block-domain tiktok \
    --block-ip 1.2.3.4 \
    --threads 8
```

**Using direct `javac` compiled classes:**
```powershell
java -cp out com.dpi.Main input.pcap output.pcap --block-app YouTube --threads 4
```

### CLI Options

| Option | Description |
|---|---|
| `--block-app NAME` | Block an application by name (`YouTube`, `TikTok`, `Netflix`, etc.). |
| `--block-domain STRING` | Block any connection whose TLS SNI contains this substring. |
| `--block-ip IP` | Block any packet to or from this IPv4 address. |
| `--threads N` | Number of fast-path worker threads (default: CPU core count). |

---

## 8. Understanding the Output

At the end of processing, the engine displays execution statistics:

```
Deep Packet Inspection Engine (Java)
  Input:   input.pcap
  Output:  output.pcap
  Workers: 8
  Blocked apps:    [YouTube]
  Blocked domains: [tiktok]
  Blocked IPs:     [1.2.3.4]

Run complete in 42 ms
----------------------------------------
Total packets:       15042
Forwarded packets:   14210 (94.5%)
Dropped packets:     832 (5.5%)
Connections tracked: 613
Connections blocked: 37

Blocked by rule:
  blocked-domain:youtube.com -> 512 packets
  blocked-domain:tiktok.com -> 320 packets
```

---

## 9. Operational Notes

- **Single Packet SNI Inspection**: SNI extraction operates on individual packet payloads without full TCP stream reassembly. The TLS `ClientHello` almost always fits within the first data segment of a TLS connection.
- **IPv4 Scope**: Non-IPv4 frames (e.g. ARP, IPv6) are passed through unmodified rather than dropped.
