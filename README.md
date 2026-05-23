# DPI Engine (Java)

A production-grade Deep Packet Inspection engine written in pure Java that parses PCAP files, extracts TLS SNI / HTTP Host headers, classifies traffic by application, applies blocking rules, and generates structured reports.

**Two execution modes:**
- **CLI** — offline PCAP analysis with JSON/CSV export
- **Server** — Spring Boot REST API + single-page Web Dashboard

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Prerequisites](#prerequisites)
5. [Build](#build)
6. [CLI Usage](#cli-usage)
7. [REST API](#rest-api)
8. [Web Dashboard](#web-dashboard)
9. [Report Format](#report-format)
10. [Test Data Generation](#test-data-generation)
11. [Roadmap](#roadmap)

---

## Features

| Feature | Status |
|---------|--------|
| PCAP read/write (little-endian) | ✅ |
| Ethernet → IPv4 → TCP/UDP parsing | ✅ |
| TLS SNI extraction (Client Hello) | ✅ |
| HTTP Host header extraction | ✅ |
| Application classification (YouTube, Facebook, Google, etc.) | ✅ |
| Blocking rules by IP, App, Domain | ✅ |
| Single-threaded engine (`DpiSimple`) | ✅ |
| Multi-threaded pipeline (`DpiEngine`) | ✅ |
| Consistent hashing (flow affinity, lock-free) | ✅ |
| JSON & CSV report export | ✅ |
| Spring Boot REST API | ✅ |
| Web UI Dashboard (drag-drop, live charts) | ✅ |
| Poison-pill graceful shutdown | ✅ |

---

## Architecture

### Single-Threaded (`DpiSimple`)

```
PCAP Reader → Packet Parser → SNI/Host Extractor → Classifier → Rule Manager → Writer → Report
```

### Multi-Threaded (`DpiEngine`)

```
ReaderThread
      ↓
  hash(5-tuple) % numLBs
      ↓
LoadBalancer threads (default: 2)
      ↓
  hash(5-tuple) % numFPs
      ↓
FastPath threads (default: 2 per LB = 4 total)
      ↓
  OutputQueue
      ↓
WriterThread
```

**Key design decisions:**
- **Consistent hashing** ensures the same 5-tuple always lands on the same `FastPath` thread.
- **No shared state** — each `FastPath` owns a private `HashMap<FiveTuple, Flow>`; zero locks.
- **Poison-pill shutdown** — `RawPacket` with `null` data propagates through queues to signal EOF.
- **Byte order discipline** — `LITTLE_ENDIAN` for PCAP headers, `BIG_ENDIAN` for network protocols.

---

## Project Structure

```
src/main/java/dpi/
├── model/
│   ├── AppType.java              # Application enum
│   ├── FiveTuple.java            # Normalized bidirectional flow key
│   ├── Flow.java                 # Per-flow state (SNI, app, blocked, counters)
│   ├── RawPacket.java            # Raw bytes + PCAP timestamp
│   ├── ParsedPacket.java         # Parsed headers + payload offsets
│   └── TrafficReport.java        # Structured report for JSON/CSV/API
├── io/
│   ├── PcapReader.java           # PCAP input (global + packet headers)
│   └── PcapWriter.java           # PCAP output
├── parser/
│   └── PacketParser.java         # Ethernet → IP → TCP/UDP parser
├── inspector/
│   ├── SniExtractor.java         # TLS Client Hello SNI parser
│   └── HttpHostExtractor.java    # HTTP Host header parser
├── engine/
│   ├── AppClassifier.java        # Host/SNI → AppType mapping
│   ├── ConnectionTracker.java    # Single-threaded flow table
│   ├── FastPath.java             # Multi-threaded worker (own flow table)
│   ├── LoadBalancer.java         # Routes packets to FastPaths
│   ├── ReportBuilder.java        # Builds TrafficReport from counters
│   ├── ReportExporter.java       # JSON / CSV serialization
│   ├── RuleManager.java          # IP / App / Domain blocking logic
│   └── ThreadSafeQueue.java      # BlockingQueue wrapper (capacity 10,000)
├── api/
│   ├── AnalysisJob.java          # Job state machine (PENDING → RUNNING → COMPLETED)
│   ├── AnalysisService.java      # Async job orchestration
│   └── DpiController.java        # REST endpoints
├── DpiSimple.java                # Single-threaded CLI entry
├── DpiEngine.java                # Multi-threaded CLI entry
├── DpiLauncher.java              # Smart launcher (CLI vs Server auto-detect)
├── DpiApiApplication.java        # Spring Boot bootstrap
└── PcapGenerator.java            # Synthetic PCAP generator for testing

src/main/resources/
├── application.properties        # Server port, multipart limits
└── static/
    └── index.html                # Dashboard (Chart.js, vanilla JS)
```

---

## Prerequisites

- **Java 17** or later
- **Maven 3.8** or later
- **Browser** with internet access (Chart.js loads from CDN)

Verify:
```bash
java -version
mvn -version
```

---

## Build

```bash
cd dpi-engine
mvn clean package
```

Produces `target/dpi-engine.jar` (Spring Boot fat JAR).

---

## CLI Usage

The launcher auto-detects CLI mode when the first two arguments end in `.pcap`.

### Basic analysis
```bash
java -jar target/dpi-engine.jar input.pcap output.pcap --simple
```

### With blocking rules
```bash
java -jar target/dpi-engine.jar input.pcap output.pcap      --simple      --block-app YOUTUBE      --block-domain facebook      --block-ip 192.168.1.50
```

### With report export
```bash
java -jar target/dpi-engine.jar input.pcap output.pcap      --simple      --block-app YOUTUBE      --report-json report.json      --report-csv report.csv
```

### Multi-threaded engine
```bash
java -jar target/dpi-engine.jar input.pcap output.pcap      --lbs 2      --fps 2      --block-app TIKTOK
```

**CLI Options:**

| Flag | Description |
|------|-------------|
| `--simple` | Use single-threaded engine |
| `--lbs N` | Number of load balancers (multi-threaded only) |
| `--fps N` | FastPaths per load balancer (multi-threaded only) |
| `--block-app APP` | Block by application type (e.g., `YOUTUBE`) |
| `--block-ip IP` | Block by source/destination IPv4 address |
| `--block-domain STR` | Block if SNI/Host contains substring |
| `--report-json PATH` | Export structured report to JSON |
| `--report-csv PATH` | Export report to CSV |

---

## REST API

Start the server:
```bash
mvn spring-boot:run
```
Base URL: `http://localhost:8080`

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/analyze` | Upload PCAP + rules, returns job ID |
| `GET` | `/api/jobs/{id}` | Poll job status |
| `GET` | `/api/jobs/{id}/report` | Get JSON report |
| `GET` | `/api/jobs/{id}/output` | Download filtered PCAP |
| `GET` | `/api/jobs/{id}/report.csv` | Download CSV report |

### Example: cURL workflow

```bash
# 1. Submit analysis job
curl -X POST http://localhost:8080/api/analyze   -F "pcap=@test.pcap"   -F "blockApp=YOUTUBE"   -F "blockDomain=facebook"   -F "blockIp=192.168.1.50"   -F "simple=false"   -F "lbs=2"   -F "fps=2"

# Response: {"id":"a1b2c3d4-...","status":"PENDING"}

# 2. Poll until COMPLETED
curl http://localhost:8080/api/jobs/a1b2c3d4-...

# 3. Get JSON report
curl http://localhost:8080/api/jobs/a1b2c3d4-.../report

# 4. Download filtered PCAP
curl -O -J http://localhost:8080/api/jobs/a1b2c3d4-.../output

# 5. Download CSV
curl -O -J http://localhost:8080/api/jobs/a1b2c3d4-.../report.csv
```

---

## Web Dashboard

Open `http://localhost:8080` in your browser after starting the server.

### Workflow

1. **Upload PCAP** — Click *Choose File*, select `.pcap`.
2. **Select Engine Mode** — *Simple* or *Multi-threaded*.
3. **Add Rules** — Type and press Enter to create tags:
   - Applications: `YOUTUBE`, `FACEBOOK`, `TIKTOK` …
   - Domains: `facebook`, `google` … (substring match)
   - IPs: `192.168.1.50` …
4. **Analyze** — Click *Analyze Traffic*. Progress bar auto-updates.
5. **Review Results** — Metrics cards, doughnut chart (app breakdown), bar chart (allowed vs blocked), SNI table.
6. **Download** — *Output PCAP* (filtered capture) or *Report CSV*.

### Dashboard Features
- Drag-and-drop rule entry with removable tags
- Live polling (1-second intervals) during analysis
- Responsive charts via Chart.js
- Dark-themed UI optimized for network operations centers

---

## Report Format

### JSON Structure
```json
{
  "totalPackets": 77,
  "totalBytes": 5738,
  "tcpPackets": 73,
  "udpPackets": 4,
  "forwarded": 69,
  "dropped": 8,
  "processingTimeMs": 45,
  "appBreakdown": [
    {
      "appType": "HTTPS",
      "count": 39,
      "percentage": 50.6,
      "blocked": false,
      "bar": "##########"
    },
    {
      "appType": "YouTube",
      "count": 4,
      "percentage": 5.2,
      "blocked": true,
      "bar": "#"
    }
  ],
  "detectedSnis": [
    { "sni": "www.youtube.com", "appType": "YouTube" },
    { "sni": "www.facebook.com", "appType": "Facebook" }
  ]
}
```

### CSV Structure
```csv
Metric,Value
Total Packets,77
Total Bytes,5738
...

Application,Count,Percentage,Blocked
HTTPS,39,50.6,false
YouTube,4,5.2,true

SNI,Application
www.youtube.com,YouTube
www.facebook.com,Facebook
```

---

## Test Data Generation

Generate a synthetic PCAP with sample traffic for immediate testing:

```bash
# From compiled classes (not the fat JAR)
java -cp target/classes dpi.PcapGenerator test.pcap
```

Generated traffic includes:
- TLS Client Hello to `www.youtube.com`
- TLS Client Hello to `www.facebook.com`
- TLS Client Hello to `www.google.com`
- HTTP GET to `example.com`
- DNS query to `8.8.8.8`
- Random TCP noise

---

## Roadmap

### Phase 1 — Core Engine ✅
- [x] PCAP I/O
- [x] Protocol parsing (Ethernet / IPv4 / TCP / UDP)
- [x] TLS SNI extraction
- [x] HTTP Host extraction
- [x] Application classification
- [x] Rule engine (IP / App / Domain)
- [x] Single-threaded & multi-threaded engines

### Phase 2 — Reporting & API ✅
- [x] Structured JSON/CSV reports
- [x] Spring Boot REST API
- [x] Async job queue
- [x] Web dashboard with Chart.js

### Phase 3 — Detection Improvements (Next)
- [ ] DNS query/response parsing (UDP/53)
- [ ] TLS JA3 fingerprint hooks
- [ ] HTTP method/path statistics
- [ ] Direction-aware rules (src vs dst matching)

### Phase 4 — Enterprise Features
- [ ] Time-based rules (block only during business hours)
- [ ] Allowlist override for blocklist
- [ ] Rule priority & actions (ALLOW, DROP, LOG-ONLY)
- [ ] H2/PostgreSQL persistence for historical search
- [ ] Live capture mode (`--iface eth0`)
- [ ] Unit tests + benchmark mode (throughput/latency metrics)

---