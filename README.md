# CyberSentinel — Big Data & AI-Driven SOC Telemetry Platform

CyberSentinel is an enterprise-grade, Big Data and AI-driven Security Operations Center (SOC) telemetry and network intrusion detection platform. It processes high-speed network traffic, aggregates raw packets into bi-directional 5-tuple flows, applies two-stage Machine Learning (Random Forest) detection and classification, correlates alerts into actionable SOC incidents, enriches telemetry with local Threat Intelligence and MITRE ATT&CK Enterprise v19.0 mappings, and delivers real-time operational analytics and model performance monitoring.

---

## Technical Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                            INPUT DATA SOURCES                                    |
|   CSE-CIC-IDS2018 Dataset  |  PCAP Files  |  Passive Live Interface Capture (eth0)   |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                        FLOW INGESTION & FEATURE ENGINEERING                       |
|        Bi-directional 5-Tuple Aggregation & Sliding Window Metric Calculation     |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                             MACHINE LEARNING ENGINE                               |
|   Stage 1: Binary Attack Detection  ──➔  Stage 2: Multi-class Attack Classifier   |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                      DETECTION RULES & THREAT INTELLIGENCE                        |
|   Behavioral Detection Rules (RULE-001..005)  |  Local Threat Indicator Store     |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                      MITRE ATT&CK ENTERPRISE V19.0 ENRICHMENT                     |
|     Technique Mapping (T1110, T1498, T1071, T1190) & Rationale Association       |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                        SOC INCIDENT CORRELATION ENGINE                            |
|       5-Minute Time Window Grouping & Explainable Risk Score (0-100 Clamped)      |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                   SOC ANALYTICS, MODEL MONITORING & DASHBOARD                     |
|        PySpark Dataset Analysis  |  FastAPI REST API  |  Streamlit Workspace      |
+-----------------------------------------------------------------------------------+
```

---

## Tech Stack & Environment Versions

- **Core Runtime**: Python `3.14.4` (Linux / WSL2 Ubuntu environment)
- **Big Data Analytics**: PySpark `4.2.0`
- **Machine Learning**: Scikit-learn (Random Forest Stage 1 Detector & Stage 2 Classifier)
- **Data Engineering**: Pandas `3.0.5`, NumPy `2.5.1`, PyArrow
- **Packet Capture**: Scapy `2.7.0` (Linux `AF_PACKET` raw socket engine)
- **REST API Backend**: FastAPI `0.141.1`, Uvicorn `0.52.1`
- **Analyst Workspace**: Streamlit `1.61.1`, Plotly `6.9.0`
- **Testing**: PyTest `9.1.1`

---

## Dataset

CyberSentinel is trained and benchmarked on the benchmark **CSE-CIC-IDS2018 Clean Parquet Dataset** (16,231,061 total network flows).
- **Train Split**: 12,984,848 flows (80%)
- **Test Split**: 3,246,213 flows (20%)
- **Supported Attack Categories**: `DDOS attack-HOIC`, `DDoS attacks-LOIC-HTTP`, `DoS attacks-Hulk`, `Bot`, `FTP-BruteForce`, `SSH-Bruteforce`, `Infilteration`, `DoS attacks-SlowHTTPTest`, `DoS attacks-GoldenEye`, `DoS attacks-Slowloris`, `DDOS attack-LOIC-UDP`, `Brute Force -Web`, `Brute Force -XSS`, `SQL Injection`.

---

## Key Platform Features

### 1. Two-Stage Machine Learning Pipeline
- **Stage 1 (Binary Detector)**: Predicts whether a flow is `BENIGN` or `ATTACK` with probability confidence scoring.
- **Stage 2 (Multi-Class Classifier)**: Classifies attack flows into precise attack families.

### 2. Real-Time Passive Live Interface Capture & PCAP Ingestion
- Passive network interface capture via Linux `AF_PACKET` raw socket without packet injection or external probing.
- On-the-fly 5-tuple flow assembly (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).

### 3. SOC Incident Correlation Engine
- Groups attack alerts within a 5-minute sliding window matching source entities, target entities, and attack vectors.
- Calculates explainable risk scores (0–100) based on severity base score, volume bonus, attack diversity bonus, model confidence bonus, and duration bonus.

### 4. Local Threat Intelligence & Behavioral Rules Engine
- Controlled local threat indicator store (`IP`, `DOMAIN`, `URL`, `HASH`) with format validation.
- 5 Behavioral Rules (`RULE-001` SSH brute-force, `RULE-002` FTP brute-force, `RULE-003` DoS volume, `RULE-004` Repeated critical alerts, `RULE-005` Known threat match).

### 5. MITRE ATT&CK Enterprise v19.0 Integration
- Maps CyberSentinel detections to official STIX 2.1 ATT&CK Enterprise v19.0 techniques (e.g. `T1110` Brute Force, `T1498` Network Denial of Service, `T1071` Command and Control, `T1190` Exploit Public-Facing App) with explicit rationales.

### 6. SOC Analytics & Model Performance Monitoring
- Operational SQL analytics for time windows (`15m`, `1h`, `24h`, `7d`, `all`).
- Stage 1 & Stage 2 confidence distributions, percentiles (`p25`–`p99`), low-confidence count (< 0.60), and distribution shift indicators.

---

## Installation & Setup

1. **Activate Environment**:
   ```bash
   source /home/charay/cybersentinel-venv/bin/activate
   ```

2. **Live Network Capture Privilege Setup (Optional for Live Interface Monitoring)**:
   Grant Linux raw socket capability to the Python executable:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/python3.14
   ```
   Verify capability:
   ```bash
   getcap /usr/bin/python3.14
   ```
   To remove capability:
   ```bash
   sudo setcap -r /usr/bin/python3.14
   ```
   *(Note: Historical dataset analytics, PCAP replay, and normal dashboard operation do NOT require live packet capture capabilities.)*

---

## Running the Platform

1. **Start FastAPI Backend**:
   ```bash
   uvicorn src.api.main:app --host 0.0.0.0 --port 8000
   ```

2. **Start Streamlit Dashboard**:
   ```bash
   streamlit run dashboard/app.py
   ```

---

## End-to-End 10-Step Safe Demo Sequence (5–10 Minutes)

1. **STEP 1 — Overview**: Open dashboard to view real-time system metrics, active alerts, and architectural status.
2. **STEP 2 — Historical Dataset Analytics**: Navigate to `SOC Analytics` -> View CSE-CIC-IDS2018 dataset scale (16.2M flows) and class distribution.
3. **STEP 3 — Simulated Real-Time Streaming**: Navigate to `Replay / Dataset Telemetry` -> Start dataset flow streaming.
4. **STEP 4 — Live Network Monitoring**: Navigate to `Real-Time Monitoring` -> Select interface `eth0` -> Click `START LIVE CAPTURE`. Observe passive packet capture without active network probing.
5. **STEP 5 — Offline Attack Flow Evaluation**: Trigger a safe dataset replay sample flow containing an SSH-Bruteforce or DoS attack vector.
6. **STEP 6 — SOC Alert Persistence**: Inspect generated alert under `Real-Time Monitoring` -> `Alert Feed`.
7. **STEP 7 — Correlated SOC Incident**: Navigate to `Incidents` -> Select created incident in the Analyst Workspace queue.
8. **STEP 8 — Threat Intelligence & MITRE ATT&CK**: Inspect the right panel for Threat Intel match, Behavioral Rule trigger, and MITRE ATT&CK `T1110` / `T1498` mapping rationale.
9. **STEP 9 — SOC Analytics**: Navigate to `SOC Analytics` -> Switch time windows (`15m`, `1h`, `24h`, `7d`) -> View activity trends, top source/target entities, and MTTR.
10. **STEP 10 — Model Performance & Monitoring**: Inspect Stage 1 & Stage 2 confidence distributions, mean confidence, and drift status indicators.

---

## Testing & Verification

Run the full automated test suite containing all 88 unit and integration tests:
```bash
python3 -m pytest tests/
```

Result:
```
======================= 88 passed, 2 warnings in 33.65s =======================
```

---

## Demo State Reset Procedure

To safely reset demo-generated alerts and incidents without losing database configuration, replay history, or threat intelligence indicators:
```bash
python3 src/utils/demo_reset.py --clear-demo-alerts
```
