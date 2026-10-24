# AI-Powered Contextual Firewall for Traffic Anomaly Detection

> Next-Generation Context-Aware AI Firewall, Real-Time Network Threat Defense Console, and Automated Incident Response System.

**AI-Powered Contextual Firewall for Traffic Anomaly Detection** is an enterprise-grade network security platform combining **Scapy live packet inspection**, **FastAPI high-concurrency microservices**, a **React 18 + Vite cyber operations console**, **scikit-learn machine learning classifiers**, **real-time WebSocket telemetry**, and an **autonomous AI response engine** with strict allowlist safety.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.2-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-5.4-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/Tests-131%2B%20Passing-brightgreen.svg)](#automated-testing)

---

## 📚 Technical Documentation Hub

Comprehensive, in-depth architectural and operational guides are available in the [`docs/`](docs/index.md) portal:

- **[Documentation Home & Overview](docs/index.md)**: Master portal and documentation directory.
- **[System Architecture & Design](docs/architecture.md)**: Packet pipeline, stateful connection tracking, dual-engine storage, and tech stack.
- **[Threat Detection & Machine Learning](docs/threat_detection.md)**: Brute-force sliding windows, Shannon entropy DNS tunneling, DGA analysis, 10-feature ML phishing model, and threat feeds.
- **[Autonomous Response & Safe Containment](docs/autonomous_response.md)**: Automated IP isolation, allowlist immunity invariant, self-cleaning unblock daemon, emergency killswitch, and multi-channel notifications.
- **[SQLite Database Maintenance & Storage](docs/database_maintenance.md)**: High-concurrency WAL pragmas, checkpointing (`TRUNCATE`), defragmentation (`VACUUM`), data retention, and integrity diagnostics.
- **[REST API & WebSocket Reference](docs/api_reference.md)**: Complete endpoint catalogue, JWT authentication, RBAC roles, request/response schemas, and real-time WebSocket protocol.
- **[Operations, Deployment & Testing](docs/operations_and_deployment.md)**: Single-command startup (`python run.py`), multi-stage Docker & Compose, 30 pytest unit/integration tests, attack simulation scenarios, and configuration reference.

---

## Table of Contents

- [Core Architectural Highlights](#core-architectural-highlights)
- [New Features & Modern Capabilities](#new-features--modern-capabilities)
- [Default Operator Credentials & RBAC](#default-operator-credentials--rbac)
- [Quickstart: One-Command Startup](#quickstart-one-command-startup)
- [Docker & Containerized Deployment](#docker--containerized-deployment)
- [Automated Testing](#automated-testing)
- [Detection Engines & Intelligence](#detection-engines--intelligence)
- [Autonomous Response & Safe Containment](#autonomous-response--safe-containment)
- [Grounded AI Security Copilot](#grounded-ai-security-copilot)
- [PCAP Forensics & Wireshark Buffer](#pcap-forensics--wireshark-buffer)
- [API Reference & WebSocket Events](#api-reference--websocket-events)
- [Attack Simulation Scenarios](#attack-simulation-scenarios)
- [Configuration Reference](#configuration-reference)
- [License](#license)

---

## Core Architectural Highlights

```text
 ┌─────────────────────────────────────────────────────────────┐
 │               React 18 + Vite Cyber Console                 │
 │  (Overview, Alerts Triage, Rules, AI Intel, Tools, Settings)│
 └──────────────┬──────────────────────────────▲───────────────┘
                │ REST API (JSON/JWT)          │ WebSockets (/ws/events)
                ▼                              │ (2s live metrics push)
 ┌─────────────────────────────────────────────┴───────────────┐
 │               Volcano FastAPI Backend Core                  │
 │                                                             │
 │ ┌──────────────────┐  ┌────────────────┐  ┌───────────────┐ │
 │ │  Scapy Sniffer   │  │ Threat Engine  │  │ Response Eng. │ │
 │ │  Rolling PCAP    │  │ Brute Force    │  │ Auto-Block    │ │
 │ │  Ring Buffer     │  │ DNS Tunnel/DGA │  │ Auto-Unblock  │ │
 │ │  (1000 Packets)  │  │ Phishing (10F) │  │ Allowlist Safe│ │
 │ └────────┬─────────┘  └───────┬────────┘  └───────┬───────┘ │
 │          │                    │                   │         │
 │ ┌────────▼────────────────────▼───────────────────▼───────┐ │
 │ │   Dual-Engine Storage: SQLite (WAL) / PostgreSQL 16      │ │
 │ │   Alembic Migrations + Role-Based Access Control (RBAC) │ │
 │ └─────────────────────────────────────────────────────────┘ │
 └─────────────────────────────────────────────────────────────┘
```

1. **Dual Storage Engine**: Zero-configuration SQLite with Write-Ahead Logging (`WAL` mode) for lightweight local deployments, with automatic connection pooling to PostgreSQL 16 when `DATABASE_URL` is configured.
2. **Real-time Push Telemetry**: High-frequency WebSocket server (`/ws/events`) broadcasting packet velocity, threat indices, device discoveries, and alert occurrences every 2 seconds.
3. **Fail-Safe Operation**: Every external subsystem (GeoLite2 MMDB, LLM APIs, external threat feeds, Scapy live capture) degrades gracefully without crashing the server.

---

## New Features & Modern Capabilities

- 🔐 **Direct Bcrypt Authentication & RBAC**: JWT Bearer token security supporting `admin`, `analyst`, and `viewer` roles with audit logging of all sensitive operations.
- 🎯 **Interactive Alert Triage**: Filter alerts by severity and status (`new`, `in_progress`, `resolved`, `false_positive`), assign alerts to operators, record investigation notes, and apply bulk actions.
- 🔨 **Sliding-Window Brute-Force Detector**: Real-time connection tracking on authentication ports (22 SSH, 3389 RDP, 21 FTP, 445 SMB, Databases) generating targeted containment rules.
- 📡 **DNS Threat & Tunneling Engine**: Shannon entropy computation detecting data exfiltration over subdomains (length > 45, entropy > 3.8) and algorithmically generated domains (DGA).
- 🎣 **10-Feature Machine Learning Phishing Classifier**: Lexical analysis extracting length, domain entropy, IP literals, punycode, URL shorteners, and suspicious TLD patterns. Retrainable via CLI (`python model_generator.py --dataset path.csv`).
- 🌐 **Dynamic Threat Intelligence Feeds**: Ingestion of abuse.ch Feodo Tracker botnet C2s, URLhaus malware distribution, and local blocklists with graceful offline caching.
- 🌍 **GeoIP Geolocation Enrichment**: MaxMind GeoLite2 lookup enriching threat metadata with country, city, and coordinates, with local network fallback.
- 🛡️ **Autonomous Response with Safe Allowlist**: Prohibits blocking loopback (`127.0.0.1`), network gateways, DNS resolvers, and operator-defined subnets. Background daemon thread automatically expires and deletes temporary block rules.
- 📣 **Multi-Channel Incident Notifier**: Dispatches structured alerts with cooldown throttling to Slack, Discord, Telegram, and SMTP Email.
- 🤖 **Grounded AI Security Copilot**: Context-aware incident analyst synthesizing live firewall telemetry (threat score, active rules, recent alerts) into actionable remediation guidance.
- 📦 **Rolling PCAP Forensics Buffer**: In-memory ring buffer capturing the last 1,000 raw packets with Wireshark `.pcap` export for the entire stream or specific security incidents.
- 🔍 **Defensive Port Scanner & Vulnerability Assessment**: Multi-threaded TCP connect scanner, service banner interrogation, and curated signature database correlating discovered exposures with known CVEs (EternalBlue, regreSSHion, Redis RCE, Apache Traversal), CVSS scoring, and 1-click firewall block remediation.
- 🛡️ **Layer-7 Deep Packet Inspection (DPI)**: Real-time application payload analysis intercepting SQL Injection (SQLi), Cross-Site Scripting (XSS), Directory Path Traversal, and Remote Command Injection in HTTP and raw socket streams with URL-decode normalization.
- 🪤 **Canary Honeytoken Tripwires & Ransomware Shield**: Automatic placement of decoy honeytoken files (`.canary_system_vault.docx`, `passwords_canary_honeytoken.xlsx`) with instant critical alerts on unauthorized tampering and known ransomware file encryption extension matching (`.locked`, `.crypto`, `.wnry`).
- 🌲 **Multi-Variate & Temporal AI Anomaly Scorers**: Unsupervised Isolation Forest (`/api/anomaly-score`) evaluating multi-variate flow metrics and PyTorch LSTM (`/api/lstm-flow-score`) evaluating temporal recurrent packet sequence bursts.

---

## Default Operator Credentials & RBAC

When first started, Volcano automatically initializes the database schema and seeds 3 default operator accounts:

| Username | Default Password | Role | Permissions |
| :--- | :--- | :--- | :--- |
| **`admin`** | `admin123` | **`admin`** | Full administrative rights: manage settings, create/edit users, modify firewall rules, trigger containment, inspect audit logs, download PCAP. |
| **`analyst`** | `analyst123` | **`analyst`** | Operational rights: triage alerts, assign investigations, query AI copilot, create rules, inspect network traffic. |
| **`viewer`** | `viewer123` | **`viewer`** | Read-only rights: inspect live telemetry, view dashboards, review historical metrics. |

> [!TIP]
> In production, change the default passwords immediately from the **Settings** tab or using the `/api/auth/users` API.

---

## Quickstart: One-Command Startup

The single launcher `python run.py` automatically checks your Python and Node environments, installs dependencies, trains the baseline phishing model if missing, migrates database tables, and starts both services:

```bash
# Clone the repository
git clone https://github.com/your-username/volcano-ai-firewall.git
cd volcano-ai-firewall

# Single-command setup and launch
python run.py
```

### Accessing the Interfaces
- **Operations Console**: [http://localhost:5173](http://localhost:5173)
- **FastAPI Backend**: [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **System Health Endpoint**: [http://localhost:8000/api/health](http://localhost:8000/api/health)

Press `Ctrl+C` in the terminal to cleanly shut down both servers.

---

## Docker & Containerized Deployment

Run Volcano AI Firewall along with a dedicated PostgreSQL 16 database using Docker Compose:

```bash
# Copy and customize environment variables
cp .env.example .env

# Build and start services in background
docker compose up -d --build

# View real-time logs
docker compose logs -f volcano
```

Stop services:
```bash
docker compose down
```

---

## Automated Testing

Volcano includes a comprehensive automated test suite powered by `pytest` covering authentication, detection algorithms, allowlist containment safety, threat feeds, and packet forensics:

```bash
# Run the complete test suite
python -m pytest backend/tests -v
```

**Test Coverage Summary:**
- `test_scanner_and_vulns.py`: Multi-threaded TCP port scanner, banner grabbing, CVE vulnerability catalogue, CVSS scoring, Layer-7 DPI (SQLi/XSS/Traversal/Cmd), and canary tripwires.
- `test_idp_missing_features.py`: Isolation Forest traffic anomaly detector, file download & ransomware inspector, application-aware rules, PyTorch LSTM sequence scorer, and compliance reporting.
- `test_auth.py`: Bcrypt password hashing, JWT token lifecycle, seeded accounts, user CRUD.
- `test_detections.py`: Brute-force sliding windows, DNS entropy, tunneling detection, DGA analysis, 10-feature phishing model.
- `test_allowlist_response.py`: Allowlist protection, loopback safety, auto-unblock expiration daemon thread.
- `test_feeds.py`: Threat feed parsing, offline degradation, GeoIP private subnet resolution.
- `test_pcap.py`: Ring buffer packet queuing, capacity boundary, PCAP binary export magic bytes.
- `test_triage.py`: Alert lifecycle, assignment, status updates, bulk operations, audit logging.

---

## Detection Engines & Intelligence

### 1. Brute Force Detection
Monitors high-risk authentication ports (22 SSH, 3389 RDP, 21 FTP, 445 SMB, 1433 MSSQL, 3306 MySQL, 5432 Postgres, 6379 Redis). Connection counts are calculated inside a rolling sliding window (default: 5 attempts in 10 seconds). Breaches generate an immediate `critical` alert with suggested containment rules.

### 2. DNS Threat Inspection
- **DNS Tunneling**: Identifies queries with abnormally long subdomains (> 45 chars) and high Shannon entropy (> 3.8 bits/char), typical of C2 exfiltration tools (e.g. `dnscat2`, `iodine`).
- **DGA Domains**: Flags pseudo-random domains generated by malware algorithms via consonant/vowel ratio analysis and base domain entropy.
- **Query Spike Detection**: Monitors query frequency per internal host to detect fast-flux DNS traffic.

### 3. Phishing ML Detector
Extracts a 10-feature vector from URLs:
`[url_length, domain_length, subdomain_count, domain_entropy, digit_ratio, has_raw_ip, is_shortener, is_punycode, suspicious_tld, keyword_density]`
Retrain with your own dataset:
```bash
python backend/model_generator.py --dataset path/to/dataset.csv --output backend/phishing_model.joblib
```

### 4. Defensive Port Scanning & CVE Vulnerability Assessment
- **Multi-Threaded TCP Port Scanner**: Discovers open ports and extracts service banners (`HEAD /`, SSH version identifiers, Telnet greetings, Redis `PING`, Memcached `version`).
- **Curated Signature Database**: Automatically correlates discovered services and banners against high-impact CVEs and CWEs:
  - Exposed SMB (CVE-2017-0144 EternalBlue / WannaCry lateral vector)
  - Unauthenticated Redis in-memory store RCE (CVE-2022-0543)
  - Cleartext Telnet & FTP credentials exposure (CWE-319)
  - Exposed database endpoints (MongoDB, MySQL, PostgreSQL, MSSQL, Elasticsearch)
  - OpenSSH regreSSHion signal vulnerability (CVE-2024-6387)
  - Apache HTTP Server path traversal and RCE (CVE-2021-41773)
  - Memcached UDP amplification DDoS reflector (CVE-2018-1000115)
- **1-Click Firewall Remediation**: Directly injects targeted `DROP` firewall rules to instantly shield vulnerable open ports.

### 5. Layer-7 Deep Packet Inspection (DPI)
Inspects active TCP payloads and HTTP request streams in real-time, decoding URL-encoded characters and flagging web attacks:
- **SQL Injection (SQLi)**: Union select queries, boolean blind patterns (`' OR 1=1`), time delays (`WAITFOR DELAY`, `SLEEP`).
- **Cross-Site Scripting (XSS)**: Inline script tags, DOM event injections (`onerror=`, `onload=`), cookie theft attempts.
- **Directory Path Traversal**: Encoded traversal sequences (`../../`), sensitive file access (`/etc/passwd`, `win.ini`).
- **Remote Command Injection**: Shell execution pivots (`; id`, `| bash`, `powershell -enc`, `cmd.exe /c`).

### 6. Canary Honeytoken Tripwires & Filesystem Ransomware Defense
- **Honeytoken Decoy Placement**: Deploys decoy canary files (`.canary_system_vault.docx`, `passwords_canary_honeytoken.xlsx`) in watched directories.
- **Instant Tripwire Alerting**: Immediately triggers a `critical` ransomware alert upon any modification or renaming of canary honeytokens.
- **File Encryption Detection**: Scans for known ransomware encryption extensions (`.locked`, `.crypto`, `.wnry`, `.lockbit`, `.blackcat`) and rapid file modification velocity.

### 7. Multi-Variate & Temporal Anomaly Scorers
- **Isolation Forest Flow Scorer** (`/api/anomaly-score`): Analyzes multi-variate metrics (packet size, ports, protocol, flow rate) against an unsupervised isolation forest baseline.
- **PyTorch LSTM Sequence Scorer** (`/api/lstm-flow-score`): Evaluates recurrent temporal packet sequences (inter-arrival microsecond intervals, packet sizes, flow directions) to uncover stealthy burst and flood attacks.

---

## Autonomous Response & Safe Containment

Volcano's `ResponseEngine` automatically mitigates threats while strictly enforcing safety guardrails:

1. **Allowlist Invariant**: Addresses in `VOLCANO_ALLOWLIST_IPS` (plus loopback `127.0.0.1`, `::1`, and local gateway interfaces) can **never** be blocked, even if requested by an automated engine or manual operator.
2. **Auto-Expiring Containment**: Dynamic blocks are injected with an expiration timestamp. A background daemon thread periodically polls for expired rules and deletes them, preventing permanent firewall rule bloat.
3. **Manual Override**: Operators can manually block or unblock IPs through the **Firewall Rules** or **Settings** tabs.

---

## Grounded AI Security Copilot

The AI Security Copilot synthesizes current firewall telemetry into grounded incident recommendations:
- Injects real-time metrics: current threat level, active alerts, suspicious source IPs, top targeted ports, and firewall rules.
- Supports **Local Heuristic Fallback** (default, no API key required) as well as external LLM providers (**OpenAI**, **Anthropic**, **Google Gemini**).
- Accessible via the **Security Tools** tab or `POST /api/copilot/ask`.

---

## PCAP Forensics & Wireshark Buffer

Volcano maintains a circular rolling buffer of the last 1,000 raw captured packets in memory:
- **Global Capture Download**: Download the recent traffic buffer as a `.pcap` file for Wireshark inspection via `GET /api/pcap/export`.
- **Forensic Alert Export**: Export PCAP packets captured around a specific incident via `GET /api/alerts/{alert_id}/pcap`.
- **Buffer Status**: Inspect packet count and capacity at `GET /api/pcap/stats`.

---

## API Reference & WebSocket Events

### Authentication & Users
- `POST /api/auth/login`: Authenticate and receive JWT Bearer token.
- `GET /api/auth/me`: Inspect current authenticated user identity.
- `GET /api/auth/users`: List registered operator accounts (Admin only).
- `POST /api/auth/users`: Create a new operator account (Admin only).
- `PUT /api/auth/users/{username}/role`: Update operator role (Admin only).

### Alert Triage
- `GET /api/alerts`: Retrieve alerts with status/severity filtering.
- `PUT /api/alerts/{id}/triage`: Update status, assignee, and notes.
- `POST /api/alerts/bulk`: Perform bulk resolve, dismiss, or delete actions.

### Detection & Threat Intelligence
- `GET /api/threats/feeds`: Retrieve sync status of threat feeds.
- `POST /api/threats/feeds/refresh`: Trigger manual re-synchronization.
- `GET /api/threats/lookup?target=...`: Query IP or domain against blocklists.
- `GET /api/geoip/{ip}`: Query geolocation metadata.
- `POST /api/security/dns/inspect`: Run static entropy and lexical analysis on a domain.

### Port Scanner & Vulnerability Assessment
- `POST /api/scanner/port-scan`: Execute multi-threaded TCP port scan and service banner grabbing.
- `POST /api/scanner/vuln-scan`: Execute combined port scan and CVE vulnerability assessment.
- `POST /api/scanner/vuln-audit`: Audit existing port findings against vulnerability database.
- `GET /api/scanner/signatures`: List all vulnerability signatures, CVSS scores, and remediation rules.
- `GET /api/scanner/history`: Retrieve recent port and vulnerability scan history log.

### AI Flow Scoring & File Security
- `POST /api/anomaly-score`: Evaluate multi-variate traffic flow metrics against Isolation Forest.
- `POST /api/lstm-flow-score`: Score recurrent temporal packet sequences using PyTorch LSTM.
- `POST /api/check-file`: Inspect files and downloads for ransomware heuristics, entropy, and double extensions.

### Packet Forensics
- `GET /api/pcap/stats`: Buffer capacity and metrics.
- `GET /api/pcap/export`: Download Wireshark `.pcap` capture file.
- `GET /api/alerts/{alert_id}/pcap`: Download forensic `.pcap` for an alert.

### System Configuration
- `GET /api/settings`: Fetch active thresholds and configurations.
- `PUT /api/settings`: Update settings with real-time runtime propagation.
- `POST /api/notifications/test`: Test Slack, Discord, Telegram, or Email notifications.
- `GET /api/audit-logs`: Review administrative action logs.

### WebSocket Stream
Connect to `ws://localhost:8000/ws/events`:
- `metrics_tick`: Broadcast every 2 seconds with packet velocity, threat indices, and alert counts.
- `alert_created`: Pushed immediately when a new security alert is triggered.

---

## Attack Simulation Scenarios

The included event simulator (`backend/simulate_events.py`) tests detection engines with realistic threat scenarios:

```bash
# 1. Simulate SSH/RDP Brute Force attack
python backend/simulate_events.py --scenario brute-force --intensity high

# 2. Simulate DNS Tunneling exfiltration
python backend/simulate_events.py --scenario dns-tunneling

# 3. Simulate Algorithmic DGA malware activity
python backend/simulate_events.py --scenario dga

# 4. Simulate Threat Feed IoC match
python backend/simulate_events.py --scenario threat-feed

# 5. Simulate Phishing campaign
python backend/simulate_events.py --scenario phishing

# 6. Simulate Ransomware file tampering
python backend/simulate_events.py --scenario ransomware
```

---

## Configuration Reference

All settings are tunable via environment variables or `backend/settings.json`:

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `VOLCANO_JWT_SECRET_KEY` | *(secure auto-key)* | Secret key for signing JWT tokens. |
| `DATABASE_URL` | `sqlite:///volcano.db` | SQLite or PostgreSQL connection string. |
| `VOLCANO_BRUTE_FORCE_THRESHOLD` | `5` | Failed attempts before triggering brute-force alert. |
| `VOLCANO_BRUTE_FORCE_WINDOW` | `10` | Time window (seconds) for brute force tracking. |
| `VOLCANO_DNS_TUNNELING_ENTROPY` | `3.8` | Shannon entropy threshold for DNS exfiltration. |
| `VOLCANO_DGA_ENTROPY_THRESHOLD` | `3.5` | Entropy threshold for algorithmic DGA domains. |
| `VOLCANO_ALLOWLIST_IPS` | `127.0.0.1,10.0.0.1...` | Safe IPs immune to automated blocking. |
| `VOLCANO_AUTO_BLOCK_DURATION_MINUTES` | `5` | Duration before temporary block rules are deleted. |
| `VOLCANO_NOTIFICATION_ENABLED` | `false` | Enable multi-channel incident dispatches. |
| `VOLCANO_LLM_PROVIDER` | `local` | Copilot provider: `local`, `openai`, `anthropic`, `gemini`. |

---

## License

Volcano AI Firewall is released under the [MIT License](LICENSE).
