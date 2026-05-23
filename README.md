# DPI Engine (Java)

A Java Deep Packet Inspection (DPI) pipeline that reads packets from a PCAP file, parses network headers, classifies traffic by app/domain heuristics, applies blocking rules, and writes allowed packets to an output PCAP.

This project supports:
- A multi-threaded pipeline (`dpi.DpiEngine`)
- A single-threaded reference pipeline (`dpi.DpiSimple`)
- A synthetic PCAP generator for local testing (`dpi.PcapGenerator`)

## Features

- PCAP read/write (Ethernet link type)
- IPv4 + TCP/UDP parsing
- Flow tracking using normalized 5-tuples
- TLS SNI extraction (ClientHello, port 443)
- HTTP Host header extraction
- App classification by host/SNI + fallback by destination port
- Rule-based blocking by:
  - Source IP
  - App type
  - Domain substring
- Throughput report summary:
  - Packet and byte totals
  - TCP/UDP counts
  - Forwarded/dropped counts
  - App breakdown
  - Detected SNIs

## Tech Stack

- Java 17
- Maven (build + packaging)
- No external runtime dependencies

## Project Structure

```text
src/main/java/dpi
  DpiEngine.java          # multi-threaded engine entry point
  DpiSimple.java          # single-threaded engine
  PcapGenerator.java      # synthetic test PCAP generator

src/main/java/dpi/engine
  AppClassifier.java      # host/SNI + port based classification
  ConnectionTracker.java  # simple-mode flow table
  FastPath.java           # per-worker DPI processor
  LoadBalancer.java       # flow-affine packet routing
  RuleManager.java        # block rules
  ThreadSafeQueue.java    # bounded queue wrapper (capacity 10,000)

src/main/java/dpi/inspector
  SniExtractor.java       # TLS SNI parser
  HttpHostExtractor.java  # HTTP Host parser

src/main/java/dpi/io
  PcapReader.java
  PcapWriter.java

src/main/java/dpi/model
  AppType.java
  FiveTuple.java
  Flow.java
  ParsedPacket.java
  RawPacket.java

src/main/java/dpi/parser
  PacketParser.java
```

## Prerequisites

- JDK 17+ installed
- Maven 3.8+ installed and available on `PATH`

Check:

```bash
java -version
javac -version
mvn -v
```

## Build

From project root:

```bash
mvn clean package
```

Artifacts:
- `target/dpi-engine.jar`

## Run

### 1) Generate sample PCAP

```bash
java -cp target/classes dpi.PcapGenerator input.pcap
```

### 2) Run multi-threaded engine (default)

```bash
java -jar target/dpi-engine.jar input.pcap output.pcap
```

### 3) Run single-threaded mode

```bash
java -jar target/dpi-engine.jar input.pcap output.pcap --simple
```

## CLI Options

Usage:

```text
java -jar target/dpi-engine.jar <input.pcap> <output.pcap> [options]
```

Options:
- `--simple`
  - Use single-threaded processing (`DpiSimple`).
- `--lbs <n>`
  - Number of load balancer threads (multi-thread mode only).
  - Default: `2`.
- `--fps <n>`
  - FastPath workers per load balancer (multi-thread mode only).
  - Default: `2`.
- `--block-app <App>`
  - Block app traffic by enum name.
  - Can be repeated.
- `--block-ip <IP>`
  - Block by source IPv4 string.
  - Can be repeated.
- `--block-domain <domain>`
  - Block if SNI/Host contains substring (case-insensitive).
  - Can be repeated.

### Supported app names for `--block-app`

`UNKNOWN`, `HTTP`, `HTTPS`, `DNS`, `YOUTUBE`, `FACEBOOK`, `GOOGLE`, `TWITTER`, `NETFLIX`, `TIKTOK`, `GITHUB`, `AMAZON`

Examples:

```bash
# Block YouTube + Facebook domains
java -jar target/dpi-engine.jar input.pcap output.pcap \
  --block-app youtube \
  --block-domain facebook.com
```

```bash
# Multi-thread tuning
java -jar target/dpi-engine.jar input.pcap output.pcap --lbs 4 --fps 4
```

```bash
# Block specific source hosts
java -jar target/dpi-engine.jar input.pcap output.pcap \
  --block-ip 192.168.1.10 \
  --block-ip 10.0.0.5
```

## Multi-threaded Pipeline Design

`Reader -> LoadBalancer(s) -> FastPath worker(s) -> Writer`

- Reader thread parses packets and routes to LB queues by flow hash.
- LB threads preserve flow affinity by hashing normalized `FiveTuple`.
- FastPath workers own private flow tables (no shared flow lock contention).
- Writer thread emits allowed packets in read/processing order from output queue consumption.
- Poison-pill packets coordinate graceful shutdown of each stage.

## Classification Logic

1. Attempt SNI extraction for TCP/443 payloads.
2. If no SNI, attempt HTTP Host extraction.
3. Classify by host/SNI keyword mapping:
   - YouTube, Facebook/Instagram, Google, Twitter, Netflix, TikTok, GitHub, Amazon
4. Fallback by destination port:
   - `443 -> HTTPS`
   - `80 -> HTTP`
   - `53 -> DNS`
5. Otherwise `UNKNOWN`.

## Current Scope and Limitations

- Ethernet + IPv4 only.
- TCP and UDP only.
- PCAP only (not PCAPNG).
- TLS parsing only inspects ClientHello SNI and only when destination port is 443.
- HTTP Host parsing expects recognizable HTTP request-line methods.
- App classification is heuristic keyword-based, not signature/ML based.

## Troubleshooting

### Maven command not found

- Open a new terminal after installing Maven.
- Verify with:

```bash
mvn -v
```

- Ensure `%MAVEN_HOME%/bin` is on `PATH`.

### IDE shows red lines but build works

- Reimport Maven project.
- Mark `src/main/java` as Sources Root.
- Ensure Project SDK is Java 17+.
- Invalidate IDE caches and restart.

### Invalid or unsupported PCAP

- `PcapReader` currently expects:
  - PCAP global header (not PCAPNG)
  - Link type 1 (Ethernet)

## Development Notes

- Main class configured in `pom.xml`: `dpi.DpiEngine`
- Default jar name: `dpi-engine.jar`
- `maven-shade-plugin` is configured at `package` phase.

## Quick Start (copy/paste)

```bash
mvn clean package
java -cp target/classes dpi.PcapGenerator input.pcap
java -jar target/dpi-engine.jar input.pcap output.pcap --lbs 2 --fps 2
```

