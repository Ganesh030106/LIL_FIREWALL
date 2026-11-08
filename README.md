# Volcano AI Firewall V5.0 — Next-Generation Autonomous SOC Platform

> Next-Generation Autonomous SOC Platform, Predictive Cyber Defense Console, and Multi-Signal Threat Correlation Engine.

**Volcano AI Firewall V5.0** is an enterprise-grade cyber defense platform uniting **Scapy real-time packet inspection**, **FastAPI high-concurrency microservices**, a **React 18 + Vite cyber operations console**, **PyTorch LSTM temporal sequence models**, **Isolation Forest flow anomaly scoring**, **predictive early-warning telemetry**, **multi-signal threat correlation**, and an **autonomous mitigation engine** with safe allowlists and automatic sliding-TTL rollback.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI: 0.115](https://img.shields.io/badge/FastAPI-0.115-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React: 18.3](https://img.shields.io/badge/React-18.3-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![Vite: 5.4+](https://img.shields.io/badge/Vite-5.4%2B-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev/)
[![Docker: Ready](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![Tests: 150 Passing](https://img.shields.io/badge/Tests-150%20Passing-brightgreen.svg)](#automated-testing)
[![E2E Tab Tests: 41/41 Passing](https://img.shields.io/badge/E2E%20Tab%20Suite-41%2F41%20Passing-brightgreen.svg)](docs/TESTING_GUIDE.md)

---

## Table of Contents

- [Core Architectural Highlights](#core-architectural-highlights)
- [New Features & V5.0 Capabilities](#new-features--v50-capabilities)
- [Quickstart: One-Command Startup](#quickstart-one-command-startup)
- [Automated Testing & Tab Verification](#automated-testing--tab-verification)
- [Autonomous Response & Safe Containment](#autonomous-response--safe-containment)
- [Detection Engines & Intelligence](#detection-engines--intelligence)
- [Grounded AI Security Copilot](#grounded-ai-security-copilot)
- [PCAP Forensics & Wireshark Buffer](#pcap-forensics--wireshark-buffer)
- [API Reference & WebSocket Events](#api-reference--websocket-events)
- [Attack Simulation Scenarios](#attack-simulation-scenarios)
- [Configuration Reference](#configuration-reference)
- [License](#license)

---

## Core Architectural Highlights

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                     React 18 + Vite Cyber Operations Console                │
 │  (Overview, Incidents, Alerts Triage, Rules, Network, Threat Intel, Tools) │
 └──────────────┬──────────────────────────────────────────────▲───────────────┘
                │ REST API (JSON)                              │ WebSockets (/ws/events)
                ▼                                              │ (Sub-second live telemetry)
 ┌─────────────────────────────────────────────────────────────┴───────────────┐
 │               Volcano AI Firewall V5.0 Backend Core                         │
 │                                                                             │
 │ ┌──────────────────┐  ┌─────────────────────┐  ┌──────────────────────────┐ │
 │ │ Scapy Sniffer    │  │ Multi-Stage AI ML   │  │ Autonomous Mitigation    │ │
 │ │ Rolling PCAP     │  │ IsoForest Anomaly   │  │ 1-Click Containment      │ │
 │ │ Ring Buffer      │  │ PyTorch Recurrent   │  │ Safe Allowlists          │ │
 │ │ (1,000 Packets)  │  │ Random Forest Phish │  │ Auto-Unblock Daemon      │ │
 │ └────────┬─────────┘  └──────────┬──────────┘  └────────────┬─────────────┘ │
 │          │                       │                          │               │
 │ ┌────────▼───────────────────────▼──────────────────────────▼─────────────┐ │
 │ │ Threat Correlation Engine & Predictive Early-Warning Signals Radar      │ │
 │ │ Dual Storage Engine: SQLite (WAL) / PostgreSQL 16 + Audit Trail         │ │
 │ └─────────────────────────────────────────────────────────────────────────┘ │
 └─────────────────────────────────────────────────────────────────────────────┘
```

1. **Autonomous SOC Platform**: 8 mission-control operational tabs covering high-level overview, incident correlation, live alerts, 5-tuple firewall policies, network sessions, threat intelligence, security tools, and forensic history.
2. **Tactical Defense Radar**: Includes the **Active Attack Vector Defense Radar** and **Top Talkers & Host Risk Radar** with direct 1-click autonomous host containment.
3. **Predictive Early Warning**: Computes abnormal velocity, periodic beaconing, and deviation from historical baselines before breach confirmation.
4. **Multi-Signal Incident Correlation**: Automatically groups related alerts into unified incidents with MITRE ATT&CK attack progression timelines.
5. **Streamlined Direct Administration**: Zero login barriers for operators; complete operational control across all tabs backed by an immutable background audit log.
6. **Dual Storage Engine**: Zero-configuration SQLite with Write-Ahead Logging (`WAL` mode) for lightweight local deployments, with automatic connection pooling to PostgreSQL 16 when `DATABASE_URL` is configured.

---

## New Features & V5.0 Capabilities

- 🎯 **Security Incidents Workspace**: Dedicated incident management interface with status lifecycles (`New`, `Investigating`, `Contained`, `Resolved`, `False Positive`), analyst notes, and MITRE ATT&CK attack path visualization.
- 📡 **Predictive Threat Early-Warning Radar**: Early detection engine analyzing login failure acceleration, unusual outbound burst volume, and microsecond beaconing rhythms (`/api/predictive/signals`).
- 🛡️ **Active Attack Vector Defense Radar**: Real-time visual radar replacing obsolete static charts, monitoring SYN floods, port scans, DNS tunnels, web injection payloads, and credential stuffing.
- 💻 **Top Talkers & Host Risk Radar**: Live bandwidth consumption and endpoint risk tracking with direct 1-click autonomous host containment.
- 🌲 **Multivariate Flow Anomaly Scorer**: Unsupervised Isolation Forest (`/api/anomaly-score`) scoring multi-variate packet metrics without requiring prior attack labels.
- 🧠 **PyTorch Deep Recurrent LSTM Sequence Scorer**: Multi-layer recurrent neural network evaluating sequential inter-arrival timing ($\Delta t$) and byte size rhythms (`/api/lstm-flow-score`).
- 🔍 **Explainable AI (XAI) Feature Attribution**: Decomposes ML model outputs into positive and negative feature contributions with supporting network evidence (`/api/ai/explain`).
- 🎣 **16-Feature Random Forest Phishing Classifier**: Lexical analysis extracting length, domain entropy, IP literals, punycode, URL shorteners, and keyword densities (`/api/check-url`).
- 🪤 **Canary Honeytoken Tripwires & Ransomware Defense**: Decoy honeytokens (`.canary_system_vault.docx`) with instant critical alerts on unauthorized access, base64 byte entropy inspection, and ransomware extension matching.
- 🛡️ **Safe Autonomous Containment with TTL Rollback**: Prohibits blocking loopback (`127.0.0.1`), network gateways, DNS resolvers, and operator subnets. Sliding-TTL daemon automatically expires and deletes temporary block rules.
- 💾 **100% Dynamic Telemetry & Database Persistence**: Complete elimination of simulated fallbacks. Port scans and CVE audits persist to `vuln_scans`, historical posture scores save to `posture_history`, and DNS/file telemetry persists to `telemetry_history`.
- 🌐 **Real Live Network Topology**: Interactive network map populated entirely from live ARP discovery and active connection sessions (`/api/sessions`) with genuine packet counts and protocols.
- 📦 **Rolling PCAP Forensics Buffer**: In-memory ring buffer capturing the last 1,000 raw packets with direct Wireshark `.pcap` export (`/api/pcap/export`).

---

## Quickstart: One-Command Startup

The single launcher `python run.py` automatically checks your Python and Node environments, installs dependencies, trains baseline ML models if absent, migrates database tables, and boots both FastAPI and Vite servers:

```bash
# Clone the repository
git clone https://github.com/your-username/contextual-ai-firewall.git
cd contextual-ai-firewall

# Single-command setup, migration, and launch
python run.py
```

### Accessing the Interfaces
- **Operations Console**: [http://localhost:5173](http://localhost:5173)
- **FastAPI Backend**: [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **System Health Endpoint**: [http://localhost:8000/api/health](http://localhost:8000/api/health)

Press `Ctrl+C` in the terminal to cleanly shut down both servers.

---

## Automated Testing & Tab Verification

The platform includes two comprehensive testing suites:

### 1. Backend Unit Test Suite (150/150 Tests Passing)
Covers detection algorithms, allowlist containment safety, threat feeds, and packet forensics:
```bash
python -m pytest backend/tests -v
```

---

## Autonomous Response & Safe Containment

The `ResponseEngine` automatically mitigates threats while strictly enforcing safety guardrails:

1. **Allowlist Invariant**: Addresses in `VOLCANO_ALLOWLIST_IPS` (plus loopback `127.0.0.1`, `::1`, and local gateway interfaces) can **never** be blocked, even if requested by an automated engine or manual operator.
2. **Auto-Expiring Containment**: Dynamic blocks are injected with an expiration timestamp. A background daemon thread periodically sweeps for expired rules and deletes them, preventing permanent firewall rule bloat.
3. **1-Click Manual Containment**: Operators can instantly contain or unblock hosts directly from the Overview, Alerts, or Network tabs.

---

## Detection Engines & Intelligence

### 1. Predictive Threat Early Warning Radar
Monitors early signals of anomalous behavior:
- Accelerating authentication failures on administrative ports (SSH 22, RDP 3389, SMB 445).
- Unusual outbound burst data transfers.
- Repeated connection intervals with low jitter ($\le 0.15$).
- Divergence from 168-hour moving behavioral baselines.

### 2. Multi-Signal Threat Correlation Engine
Groups related security alerts across sliding windows by source IP, target, and behavioral signature into cohesive incidents with MITRE ATT&CK progression timelines.

### 3. Layer-7 Deep Packet Inspection (DPI)
Inspects active TCP payloads and HTTP request streams in real-time, decoding URL-encoded characters and flagging web attacks:
- **SQL Injection (SQLi)**: Union select queries, boolean blind patterns (`' OR 1=1`), time delays (`WAITFOR DELAY`, `SLEEP`).
- **Cross-Site Scripting (XSS)**: Inline script tags, DOM event injections (`onerror=`, `onload=`), cookie theft attempts.
- **Directory Path Traversal**: Encoded traversal sequences (`../../`), sensitive file access (`/etc/passwd`, `win.ini`).
- **Remote Command Injection**: Shell execution pivots (`; id`, `| bash`, `powershell -enc`, `cmd.exe /c`).

### 4. Shannon Entropy DNS Threat Hunter
- **DNS Tunneling**: Identifies queries with abnormally long subdomains (> 45 chars) and high Shannon entropy (> 3.8 bits/char), typical of C2 exfiltration tools (`dnscat2`, `iodine`).
- **DGA Domains**: Flags pseudo-random domains generated by malware algorithms via consonant/vowel ratio analysis and base domain entropy.

### 5. Multi-Variate & Temporal Anomaly Scorers
- **Isolation Forest Flow Scorer** (`/api/anomaly-score`): Analyzes multi-variate metrics (packet size, ports, protocol, flow rate) against an unsupervised isolation forest baseline.
- **PyTorch LSTM Sequence Scorer** (`/api/lstm-flow-score`): Evaluates recurrent temporal packet sequences (inter-arrival microsecond intervals, packet sizes, flow directions) to uncover stealthy burst and flood attacks.

---

## Grounded AI Security Copilot

The AI Security Copilot synthesizes current firewall telemetry into grounded incident recommendations:
- Injects real-time metrics: current threat level, active alerts, suspicious source IPs, top targeted ports, and firewall rules.
- Supports **Local Heuristic Fallback** (default, no API key required) as well as external LLM providers (**OpenAI**, **Anthropic**, **Google Gemini**).
- Accessible via the **Security Tools** tab or `POST /api/copilot/ask`.

---

## PCAP Forensics & Wireshark Buffer

The firewall engine maintains a circular rolling buffer of the last 1,000 raw captured packets in memory:
- **Global Capture Download**: Download the recent traffic buffer as a `.pcap` file for Wireshark inspection via `GET /api/pcap/export`.
- **Forensic Alert Export**: Export PCAP packets captured around a specific incident via `GET /api/alerts/{alert_id}/pcap`.
- **Buffer Status**: Inspect packet count and capacity at `GET /api/pcap/stats`.

---

## API Reference & WebSocket Events

| Category | Method & Route | Description |
| :--- | :--- | :--- |
| **System & Health** | `GET /api/health` | Healthcheck and core sensor readiness. |
| | `GET /api/metrics` | Real-time packet velocity, file changes, and system stats. |
| | `GET /api/threat-summary` | Unified risk score, threat level, and posture index. |
| | `GET /api/database/status` | Database connection metrics (SQLite WAL / Postgres). |
| **Predictive Signals** | `GET /api/predictive/signals` | Early-warning threat signals before breach confirmation. |
| | `GET /api/baseline/traffic` | 168-hour moving behavioral baseline. |
| **Incidents & Correlation** | `GET /api/incidents` | List correlated security incidents. |
| | `POST /api/incidents` | Ingest new security incident. |
| | `POST /api/incidents/correlate`| Execute multi-signal threat correlation. |
| | `POST /api/incidents/{id}/notes`| Attach forensic investigation notes. |
| **Autonomous Containment** | `POST /api/autonomous/block-ip` | 1-click host containment with safe allowlist verification. |
| | `POST /api/autonomous/unblock-ip`| Rollback / lift host containment. |
| | `POST /api/killswitch` | Emergency host isolation trigger (supports dry-run). |
| **Alert Management** | `GET /api/alerts` | Query ingested alert buffer with filters. |
| | `POST /api/alerts/bulk` | Bulk acknowledge, resolve, or dismiss alerts. |
| **Firewall Policies** | `GET /api/rules` | List active 5-tuple firewall rules. |
| | `POST /api/rules` | Deploy new 5-tuple firewall rule. |
| | `DELETE /api/rules/{id}` | Decommission firewall rule. |
| | `GET /api/acl` | Query subject-based access control list. |
| | `POST /api/acl` | Add subject access control entry. |
| **Network Sessions** | `GET /api/sessions` | Query active TCP sessions and sockets. |
| | `GET /api/network/sessions` | Route alias for network session telemetry. |
| | `GET /api/traffic` | Query temporal traffic history trends. |
| **AI ML & Tools** | `POST /api/check-url` | 16-feature Random Forest phishing URL classifier. |
| | `POST /api/check-file` | Base64 byte entropy ransomware inspector. |
| | `POST /api/anomaly-score` | Multivariate Isolation Forest flow anomaly scorer. |
| | `POST /api/lstm-flow-score` | PyTorch recurrent LSTM temporal sequence scorer. |
| | `POST /api/ai/explain` | Explainable AI (XAI) feature contribution breakdown. |
| | `POST /api/copilot/ask` | Grounded AI Security Copilot incident analyst. |
| | `POST /api/scanner/port-scan` | Multi-threaded TCP port scanner and service grabber. |
| | `POST /api/scanner/vuln-scan` | Automated CVE vulnerability assessment. |
| **Forensics & PCAP** | `GET /api/pcap/stats` | Rolling 1,000-packet buffer capacity and utilization. |
| | `GET /api/pcap/export` | Raw Wireshark binary `.pcap` capture stream export. |
| | `GET /api/audit-logs` | Immutable administrative audit log trail. |

### WebSocket Telemetry Stream
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
| `DATABASE_URL` | `sqlite:///backend/volcano.db` | SQLite or PostgreSQL connection string. |
| `VOLCANO_BRUTE_FORCE_THRESHOLD` | `5` | Failed attempts before triggering brute-force alert. |
| `VOLCANO_BRUTE_FORCE_WINDOW` | `10` | Time window (seconds) for brute force tracking. |
| `VOLCANO_DNS_TUNNELING_ENTROPY` | `3.8` | Shannon entropy threshold for DNS exfiltration. |
| `VOLCANO_DGA_ENTROPY_THRESHOLD` | `3.5` | Entropy threshold for algorithmic DGA domains. |
| `VOLCANO_ALLOWLIST_IPS` | `127.0.0.1,10.0.0.1...` | Safe IPs immune to automated blocking. |
| `VOLCANO_AUTO_BLOCK_DURATION_MINUTES` | `5` | Duration before temporary block rules are deleted. |
| `VOLCANO_NOTIFICATION_ENABLED` | `false` | Enable multi-channel incident dispatches. |
| `VOLCANO_LLM_PROVIDER` | `local` | Copilot provider: `local`, `openai`, `anthropic`, `gemini`. |

---

## Comprehensive Technical Documentation Center

For exhaustive algorithmic specifications, architectural deep dives, database designs, and technical presentation defense guides, refer to the documentation center in `docs/`:

- [Feature Logic Guide (docs/FEATURE_LOGIC_GUIDE.md)](file:///f:/AIPowered_firewall/docs/FEATURE_LOGIC_GUIDE.md): Standardized 11-point architectural breakdown of every feature across all 8 tabs.
- [Architecture Deep Dive (docs/ARCHITECTURE_DEEP_DIVE.md)](file:///f:/AIPowered_firewall/docs/ARCHITECTURE_DEEP_DIVE.md): 4-Tier SOC architecture, concurrency and thread models, state machines, and dual-engine persistence.
- [API & Data Flow (docs/API_AND_DATA_FLOW.md)](file:///f:/AIPowered_firewall/docs/API_AND_DATA_FLOW.md): Complete REST endpoint catalog, schemas, WebSocket envelopes, and end-to-end packet traces.
- [AI & ML Algorithms (docs/AI_ML_ALGORITHMS.md)](file:///f:/AIPowered_firewall/docs/AI_ML_ALGORITHMS.md): Mathematical formulations, KaTeX equations, loss functions, and feature engineering.
- [Network Security Engine (docs/NETWORK_SECURITY_ENGINE.md)](file:///f:/AIPowered_firewall/docs/NETWORK_SECURITY_ENGINE.md): Scapy/Npcap ingestion, 5-tuple flow engine, L7 DPI regex, C2 beaconing, and fan-out detection.
- [Firewall Policy Enforcement (docs/FIREWALL_ENFORCEMENT.md)](file:///f:/AIPowered_firewall/docs/FIREWALL_ENFORCEMENT.md): Multi-layer packet filtering, kernel synchronization, Sliding-TTL auto-rollback, and emergency killswitch.
- [Database Schema Explained (docs/DATABASE_SCHEMA_EXPLAINED.md)](file:///f:/AIPowered_firewall/docs/DATABASE_SCHEMA_EXPLAINED.md): Relational schema design, ER models, indexing strategy, and SQLite WAL / PostgreSQL 16 parity.
- [Testing & Verification Guide (docs/TESTING_AND_VERIFICATION.md)](file:///f:/AIPowered_firewall/docs/TESTING_AND_VERIFICATION.md): Verification procedures, 150 backend unit tests, and 47-check E2E tab verification.

---

## License

Volcano AI Firewall V5.0 is released under the [MIT License](LICENSE).
