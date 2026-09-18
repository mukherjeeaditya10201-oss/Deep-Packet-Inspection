# DPI Engine (Java)

A multi-threaded Deep Packet Inspection engine, ported from the original
C++ project to Java. It reads a `.pcap` capture, groups packets into
connections, inspects headers and TLS SNI to apply blocking rules, and
writes the packets that survive inspection to an output `.pcap`.

This is a pure-Java, dependency-free port: there is no libpcap/JNI
binding involved. Reading and writing `.pcap` files is done with a small
hand-written parser for the classic pcap file format, which is all that's
needed to process a capture that was itself produced by tcpdump/Wireshark
(or a script like `generate_test_pcap.py`).

## Architecture

The same three-stage pipeline as the original project:

```
PCAP file --> Load Balancer thread --> N Worker (fast-path) threads --> Output Writer thread --> PCAP file
                     |                        |
              parses headers,          inspects SNI, applies
              builds connection        block rules, decides
              key, routes packet       forward vs. drop
              to the worker that
              owns that connection
```

- **Load balancer** (`engine/LoadBalancer.java`) reads the input file
  sequentially, parses Ethernet/IPv4/TCP/UDP headers just far enough to
  build a 5-tuple connection key, and dispatches each packet to whichever
  worker thread owns that connection (`ConnectionKey#bucket`). Routing by
  connection - not round-robin - means a connection's state (its SNI,
  its block decision) is only ever touched by one thread, so no locking
  is needed around it.
- **Workers** (`engine/Worker.java`) are the "postman": for TCP packets
  they look for a TLS ClientHello and extract the SNI hostname the first
  time they see one (`sni/SniExtractor.java`), then ask the rule engine
  (`rules/RuleEngine.java`) whether the connection should be forwarded or
  dropped, based on blocked IPs, blocked domain keywords, and named apps
  (`rules/AppSignatures.java`) expanded into their domain keywords.
- **Output writer** (`engine/OutputWriter.java`) is a single thread that
  reassembles the workers' out-of-order results back into the original
  capture order before writing forwarded packets to the output file, so
  the result stays well-formed and its timestamps stay monotonic for
  tools like Wireshark.

## Prerequisites

| Component | Requirement |
|---|---|
| Runtime | Java 17+ (JDK) |
| Build | Maven 3.6+ (optional - `javac`/`java` directly also works) |
| Test data | Any `.pcap` file, e.g. from `generate_test_pcap.py` or `tcpdump -w` |

## Build

**Option A: Maven**

```bash
mvn package
# produces target/dpi-engine.jar
```

**Option B: Direct javac**

```bash
mkdir -p out
javac -d out $(find src/main/java -name "*.java")
```

## Run

**With the Maven-built jar:**

```bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap
```

**With direct javac output:**

```bash
java -cp out com.dpi.Main test_dpi.pcap output.pcap
```

**With blocking rules:**

```bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap \
    --block-app YouTube --block-domain tiktok --block-ip 1.2.3.4 --threads 8
```

### Options

| Flag | Description |
|---|---|
| `--block-app NAME` | Block a known app by name (YouTube, Netflix, TikTok, Instagram, Facebook, Twitter, WhatsApp, Spotify, Twitch, PrimeVideo, DisneyPlus, Steam - see `rules/AppSignatures.java`). Unknown names are treated as a domain keyword. |
| `--block-domain STRING` | Block any connection whose TLS SNI contains this substring. |
| `--block-ip IP` | Block any packet to or from this exact IP address. |
| `--threads N` | Number of fast-path worker threads (default: number of CPU cores). |

## Output

At the end of a run the engine prints a summary:

```
Run complete in 42 ms
----------------------------------------
Total packets:      15042
Forwarded packets:  14210 (94.5%)
Dropped packets:    832 (5.5%)
Connections tracked: 613
Connections blocked: 37

Blocked by rule:
  blocked-domain:youtube.com -> 512 packets
  blocked-domain:tiktok.com -> 320 packets
```

## Project layout

```
src/main/java/com/dpi/
  Main.java                    CLI entry point
  pcap/
    PcapGlobalHeader.java       .pcap global (24-byte) header, byte-order detection
    PcapReader.java             sequential .pcap file reader
    PcapWriter.java             .pcap file writer
    RawPacket.java              one captured frame + timestamp
  parser/
    PacketParser.java           Ethernet / IPv4 / TCP / UDP header parsing
    ParsedPacket.java           parsed header fields + payload location
  sni/
    SniExtractor.java           TLS ClientHello -> SNI hostname extraction
  connection/
    ConnectionKey.java          normalized 5-tuple, direction-independent
    Connection.java             per-connection mutable state (SNI, block flag, counters)
    ConnectionTable.java        thread-safe connection map
  rules/
    Rule.java                   forward/drop verdict
    RuleEngine.java              blocklists + decision logic
    AppSignatures.java           built-in app-name -> domain keyword table
  engine/
    PacketTask.java              unit of work handed to a worker
    LoadBalancer.java            reads pcap, routes packets to workers
    Worker.java                  fast-path inspection thread
    OutputWriter.java            single ordered writer thread
    DpiEngine.java                wires the pipeline together for one run
  stats/
    DpiStats.java                 run counters
```

## Notes on the port

- Functionality matches the original C++ engine: PCAP in, PCAP out,
  5-tuple connection tracking, a load-balancer/fast-path-worker threading
  model, header + SNI based blocking, and a forwarded/dropped summary.
- SNI extraction looks at a single packet's payload (no TCP stream
  reassembly), the same simplification the original engine made - the
  TLS ClientHello containing the SNI extension is almost always fully
  contained in the first data segment of a TLS connection.
- IPv6 is not handled (matching the original's IPv4-only scope); non-IPv4
  frames are passed through unmodified rather than dropped.
