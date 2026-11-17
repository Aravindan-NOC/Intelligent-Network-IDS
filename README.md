# 🛡️ Intelligent Network Intrusion Detection & Security Monitoring System (NIDS-SMS)

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.15-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Scapy](https://img.shields.io/badge/Packet%20Engine-Scapy%202.8-red.svg)](https://scapy.net/)
[![Machine Learning](https://img.shields.io/badge/ML-Isolation%20Forest%20(Scikit--Learn)-green.svg)](https://scikit-learn.org/)
[![Database](https://img.shields.io/badge/Database-SQLite%20(WAL%20Mode)-lightgrey.svg)](https://www.sqlite.org/)
[![Tests](https://img.shields.io/badge/Tests-58%2F58%20Passed%20(100%25)-brightgreen.svg)]()

An enterprise-grade, hybrid Network Intrusion Detection System (NIDS) and Security Operations Center (SOC) dashboard developed in Python. Designed to inspect real-time network traffic at Layers 2 through 7, detect deterministic cyber attacks, isolate novel Zero-Day flow anomalies using unsupervised Machine Learning (**Isolation Forest**), and deliver live security telemetry through a modern, responsive web dashboard.

---

## 📌 Key Architectural Highlights

* **Decoupled Packet Ingestion ($O(1)$)**: Asynchronous multi-threaded packet capture engine powered by **Scapy** and Windows **Npcap** kernel driver, feeding a thread-safe bounded memory queue (`maxsize=10,000`) with zero dropped frames.
* **Deep Protocol Parsing (L2–L7)**: Privacy-compliant dissection of Ethernet, IPv4, IPv6, TCP (all 9 flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS), UDP, ICMP/ICMPv6, ARP, and 25+ application port signatures without storing sensitive raw user payloads.
* **Dual-Core Hybrid Threat Detection**:
  * **Rule-Based Engine**: Stateful sliding-window heuristics detecting volumetric/stealth Port Scans (Xmas, Null, SYN-FIN), TCP SYN Floods, ICMP Ping Floods, and exploit/backdoor probes (Metasploit 4444, Back Orifice 31337, etc.).
  * **Machine Learning Engine**: 14-dimensional statistical flow feature extraction pipeline (PPS, BPS, packet size variance, SYN/ACK ratios, and **Shannon Port Entropy**) evaluated against a trained **Isolation Forest** model with **100% attack recall** and **97% normal specificity**.
* **Episode-Based Alert Throttling**: Aggregates recurring attacks within 30-second cooldown windows to eliminate alert fatigue.
* **Lock-Free Concurrency**: SQLite configured in **Write-Ahead Logging (`WAL`)** mode with `NORMAL` synchrony for concurrent writes from background analysis workers and rapid reads from the web server.
* **SOC Dark Dashboard**: Full-stack Flask REST API accompanied by an interactive cybersecurity UI featuring live Chart.js throughput streams, protocol distribution doughnuts, threat incident feeds, forensic packet inspector, and exportable CSV/JSON audit reports.
* **Terminal Access Control**: Operator gateway requiring cryptographic SHA-256 password authentication before starting capture engines.

---

## 🏗️ System Architecture

```text
[ Physical / Virtual NIC (Wi-Fi, Ethernet, Loopback) ]
                         │
                         ▼
       [ Npcap Packet Driver (WinPcap Mode) ]
                         │
                         ▼
     [ Ingestion Layer: Scapy SnifferWorker ]
                         │ (Raw packets)
                         ▼
        [ Thread-Safe Memory Buffer (Queue) ]
                         │ (Dequeued packets)
                         ▼
       [ Parsing & Sliding-Window Aggregator ]
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
  [ Rule Detection Core ]   [ ML Anomaly Core ]
  - Port Scan (Threshold)   - 14 Flow Features
  - SYN Flood (Half-Open)   - Isolation Forest
  - ICMP Flood (PPS Rate)   - Anomaly Scoring
  - Malformed Flag Checks             │
            │                         │
            └────────────┬────────────┘
                         ▼
          [ Alert Manager & Throttler ]
          - De-duplication (30s episodes)
          - Severity classification
                         │
                         ▼
          [ SQLite Database (WAL Mode) ]
          - security_alerts
          - traffic_snapshots
          - packet_logs
                         ▲
                         │ (SQL Queries)
              [ Flask REST API Server ]
                         ▲
                         │ (HTTP / JSON / Polling)
         [ SOC-Style Dark Web Dashboard ]
         - Real-time Chart.js visualizers
         - Critical alert ticker
         - Incident management & export
```

---

## ⚙️ Installation & Setup

### Prerequisites
* Windows 10/11 (Administrator privileges required for raw packet sockets)
* Python 3.10+
* [Npcap Driver](https://npcap.com/#download) (Installed in "WinPcap API-compatible Mode")

### 1. Clone Repository & Install Dependencies
```powershell
git clone https://github.com/your-username/Intelligent-Network-IDS.git
cd Intelligent-Network-IDS

pip install -r requirements.txt
```

### 2. Map Local Enterprise Domain (One-Time Setup)
Run PowerShell **as Administrator**:
```powershell
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n127.0.0.1  nids.local"
```

### 3. Launch NIDS Master Server
```powershell
python run.py --interface loopback
```
* **Default SOC Username**: `admin`
* **Default SOC Password**: `soc@2026`

Access the web console at: **`http://nids.local`** (or `http://localhost:5000`).

---

## 🧪 Automated Testing & Live Verification

Execute the complete automated test suite (58 unit & integration tests):
```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Run the end-to-end live attack simulator and verifier:
```powershell
python tests/verify_full_detection_live.py
```

```text
======================================================================
 VERIFICATION RESULTS CHECKLIST:
======================================================================
  Total Packets Captured : 346
  Total Packets Dequeued : 346
  Total Unique Incidents : 5
----------------------------------------------------------------------
  * Port Scan                  : PASSED [DETECTED]
  * SYN Flood                  : PASSED [DETECTED]
  * ICMP Flood                 : PASSED [DETECTED]
  * Suspicious Traffic         : PASSED [DETECTED]
  * ML Anomaly: Flow Deviation : PASSED [DETECTED]
======================================================================
[SUCCESS] All attack categories successfully detected in real time!
======================================================================
```

---

## 📂 Project Structure

```text
Intelligent-Network-IDS/
├── core/                           # Packet Ingestion & Dissection
│   ├── sniffer.py                  # Scapy AsyncSniffer background worker
│   ├── packet_parser.py            # Layer 2-7 Protocol Parser (ParsedPacket)
│   ├── network_utils.py            # Windows adapter discovery & GUID resolver
│   └── auth.py                     # SHA-256 Terminal Operator Authentication
│
├── detection/                      # Detection & Analytics
│   ├── rule_engine.py              # Stateful Port Scan, SYN Flood & ICMP rules
│   ├── anomaly_detector.py         # Isolation Forest ML Anomaly Engine
│   ├── flow_analyzer.py            # Sliding-window flow aggregator & velocity
│   └── alert_manager.py            # 30-second episode deduplication & scoring
│
├── ml/                             # Machine Learning Pipeline
│   ├── feature_pipeline.py         # 14 Flow Features & Shannon Entropy
│   ├── train_model.py              # Baseline normal flow training & calibration
│   └── models/
│       └── isolation_forest.pkl    # Serialized ML model
│
├── database/                       # Storage Layer
│   ├── db_manager.py               # SQLite WAL connection & CRUD queries
│   └── models.py                   # Alert, Snapshot & Forensic data models
│
├── web/                            # Flask Web Server & SOC Dashboard
│   ├── app.py                      # Flask Application Factory & Pipeline Manager
│   ├── routes/                     # REST API & HTML View routes
│   ├── static/                     # Dark SOC CSS & Chart.js controllers
│   └── templates/                  # Dashboard, Alerts, Packets, Reports HTML
│
├── documentation/                  # Technical Docs & Viva Defense Manual
│   ├── SYSTEM_ARCHITECTURE.md      # Detailed engineering specification
│   └── PROJECT_DEFENSE_GUIDE.md    # Viva Q&A, math formulas & demo protocol
│
├── tests/                          # 58 Unit & Integration Test Suites
├── config.py                       # Global detection thresholds & server configs
└── run.py                          # Master entrypoint CLI
```

---

## 📜 Academic Capstone Defense
For complete viva examination notes, mathematical equations (Shannon Entropy, Isolation Forest path lengths, SYN ratios), and presentation scripts, refer to:
📖 [PROJECT_DEFENSE_GUIDE.md](documentation/PROJECT_DEFENSE_GUIDE.md)

---

## ⚖️ License
Distributed under the MIT License. Developed for academic cyber defense research and security education.
