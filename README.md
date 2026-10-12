# CyberSentinel — Big Data & AI-Driven SOC Telemetry Platform

CyberSentinel is an enterprise-grade, Big Data and AI-driven Security Operations Center (SOC) telemetry, network intrusion detection, incident response, detection engineering workbench, and role-based access control platform. It processes high-speed network traffic, aggregates raw packets into bi-directional 5-tuple flows, applies two-stage Machine Learning (Random Forest) detection and classification, correlates alerts into actionable SOC incidents, enriches telemetry with local Threat Intelligence and MITRE ATT&CK Enterprise v19.0 mappings, delivers real-time operational analytics, and enforces strict role-based access control (RBAC) across all API endpoints and analyst workflows.

---

## Technical Architecture Diagram

```
+---------------------------------------------------------------------------------------------------+
|                                     INPUT DATA SOURCES                                            |
|        CSE-CIC-IDS2018 Dataset   |   PCAP Files   |   Passive Live Interface Capture (eth0)       |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                               FLOW INGESTION & FEATURE ENGINEERING                                |
|             Bi-directional 5-Tuple Aggregation & Sliding Window Metric Calculation                |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                      MACHINE LEARNING ENGINE                                      |
|            Stage 1: Binary Attack Detection  ──➔  Stage 2: Multi-class Attack Classifier          |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                               DETECTION RULES & THREAT INTELLIGENCE                               |
|            Behavioral Detection Rules (RULE-001..005)   |   Local Threat Indicator Store          |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                               MITRE ATT&CK ENTERPRISE V19.0 ENRICHMENT                            |
|              Technique Mapping (T1110, T1498, T1071, T1190) & Rationale Association               |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                 SOC INCIDENT CORRELATION ENGINE                                   |
|                5-Minute Time Window Grouping & Explainable Risk Score (0-100 Clamped)             |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                           ROLE-BASED ACCESS CONTROL & API GATEWAY                                 |
|         FastAPI REST API  |  PBKDF2 Password Hashing  |  Bearer Session Tokens  |  Audit Log      |
|                      RBAC Enforcement: Admin  |  Analyst  |  Read-only                            |
+---------------------------------------------------------------------------------------------------+
                                 │                                                 │
                                 ▼                                                 ▼
+--------------------------------------------------+ +----------------------------------------------+
|             STREAMLIT ANALYST WORKSPACE          | |           RELIABLE PERSISTENCE LAYER         |
|  - Real-time Alert & Incident Feeds              | |  - SQLite ACID SOC Telemetry Store           |
|  - Investigation Notes, Evidence & Reports       | |  - Online Atomic Backups (sqlite3.backup)    |
|  - Detection Workbench & Offline Sandbox         | |  - Pre-Restore Safety Snapshots              |
|  - Role-Tailored Administration & Diagnostics    | |  - Integrity Checks (PRAGMA integrity_check) |
+--------------------------------------------------+ +----------------------------------------------+
```

---

## Tech Stack & Environment Versions

- **Core Runtime**: Python `3.14.4` (Linux / WSL2 Ubuntu environment)
- **Big Data Analytics**: PySpark `4.2.0`
- **Machine Learning**: Scikit-learn (Random Forest Stage 1 Detector & Stage 2 Classifier)
- **Data Engineering**: Pandas `3.0.5`, NumPy `2.5.1`, PyArrow
- **Packet Capture**: Scapy `2.7.0` (Linux `AF_PACKET` raw socket engine)
- **REST API Backend**: FastAPI `0.141.1`, Uvicorn `0.52.1`, Starlette `0.46.1`
- **Analyst Workspace**: Streamlit `1.61.1`, Plotly `6.9.0`
- **Security & Cryptography**: PBKDF2-HMAC-SHA256 (100,000 iterations), Secrets CSPRNG tokens
- **Persistence & Backups**: SQLite 3 with atomic online backup API (`sqlite3.Connection.backup`)
- **Testing Suite**: PyTest `9.1.1` (113 automated unit, integration, and security tests)

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

### 7. SOC Incident Response & Case Management (Phase 6)
- Timestamped investigation notes with analyst attribution and chronological timeline events.
- Validated incident assignment, lifecycle transitions, resolution summaries, and reassignment audit history.
- Evidence metadata registration for type, description, source, collection timestamp, and incident association. Evidence is metadata-only; uploaded files are not executed or stored by the dashboard.
- Contextual, reviewable response recommendations using incident severity, related alerts, attack types, and MITRE ATT&CK mappings. Recommendations never perform external response actions.
- JSON and Markdown incident reports containing metadata, alerts, notes, evidence, timeline, MITRE mapping, recommendations, and resolution details.

### 8. Detection Engineering Workbench (Phase 7)
- Rule Catalog & Live Threshold Tuning: inspect, tune validated threshold values and correlation windows, enable/disable rules with live propagation to the detection engine.
- Rule Studio: create, edit, and duplicate detection rules with structured allowlisted fields (`attack_type`, `severity`, `source_ip`, `destination_port`, `protocol`, `confidence`) and operators. No arbitrary code execution.
- Offline Sandbox Preview: test draft rules and adjusted thresholds against bounded offline telemetry flows; provides match counts, match rates, and explanatory reasons with zero production state changes.
- Change Audit History: persistent SQLite audit logging capturing all rule modifications, threshold adjustments, enable/disable transitions, analyst attribution, and timestamps.

### 9. Production Readiness, Security & Role-Based Access Control (Phase 8)
- **Centralized Configuration**: All operational parameters managed via `src/config.py` and `.env` template.
- **Secure Password Hashing**: Passwords stored exclusively as PBKDF2-HMAC-SHA256 hashes with 100,000 iterations and 16-byte cryptographically secure per-user salts.
- **Three-Tier Role-Based Access Control**:
  - `admin`: User lifecycle management, database backup/recovery operations, system diagnostics, plus analyst permissions.
  - `analyst`: Alert triaging, incident lifecycle management, investigation notes, evidence collection, recommendation review, detection rule authoring and threshold tuning.
  - `read_only`: Inspection of permitted alerts, incidents, analytics, rules, reports, and threat intel without data modification. Direct API mutations return `403 Forbidden`.
- **First-Run Administrator Bootstrap**: Zero default or hardcoded credentials. Administrators configure their initial account via environment variables or a one-time setup modal that permanently seals upon first creation.
- **Security Audit Trail**: Dedicated `auth_audit_log` recording all logins, logouts, user management events, and backup operations without logging secrets or plaintext tokens.
- **Safe Database Backup & Recovery**: Online, lock-free SQLite backups via `sqlite3.Connection.backup()`, pre-restoration integrity checks (`PRAGMA integrity_check`), deliberate confirmation token requirements (`CONFIRM_RESTORE`), and automatic safety pre-restore snapshots.
- **System Health & Readiness Probes**: Comprehensive `/health` and `/ready` endpoints verifying database connectivity, ML model availability, and backup directory readiness without exposing secret keys.

---

## Authentication & Role-Based Access Control (RBAC)

CyberSentinel enforces permissions **at the API layer**, ensuring that direct REST requests from unauthorized or read-only clients are rejected with HTTP `401 Unauthorized` or `403 Forbidden`.

### Role Permissions Matrix

| Feature / Operation | Admin | Analyst | Read-only | Unauthenticated |
| :--- | :---: | :---: | :---: | :---: |
| **System Health & Readiness** (`/health`, `/ready`) | Yes | Yes | Yes | Yes |
| **Auth Status & Login** (`/api/auth/*`) | Yes | Yes | Yes | Yes |
| **First-Admin Bootstrap** (One-time only) | N/A | N/A | N/A | Yes (if 0 users) |
| **View Alerts & Incidents** | Yes | Yes | Yes | No |
| **Update Incident Status / Assign** | Yes | Yes | No | No |
| **Add Notes & Evidence** | Yes | Yes | No | No |
| **Review Recommendations** | Yes | Yes | No | No |
| **Generate Incident Reports** (JSON/MD) | Yes | Yes | Yes | No |
| **View Detection Rules & History** | Yes | Yes | Yes | No |
| **Edit Rules & Adjust Thresholds** | Yes | Yes | No | No |
| **Run Offline Rule Previews** | Yes | Yes | Yes | No |
| **View SOC Analytics & Model Metrics** | Yes | Yes | Yes | No |
| **User Management** (Create, Deactivate, Reset) | Yes | No | No | No |
| **Create & Validate Database Backups** | Yes | No | No | No |
| **Execute Database Restoration** | Yes | No | No | No |
| **Inspect Security Audit Log** | Yes | No | No | No |

---

## Installation & Environment Setup

On Windows, run CyberSentinel within WSL2 (Ubuntu) to leverage Linux native socket capture and the POSIX Hadoop filesystem for PySpark:

1. **Clone the Repository & Navigate to Workspace**:
   ```bash
   cd /mnt/d/BDA/CyberSentinel
   ```

2. **Activate the Virtual Environment**:
   ```bash
   source /home/charay/cybersentinel-venv/bin/activate
   ```

3. **Configure Environment Variables**:
   Copy the example environment file and configure secrets:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` as needed:
   ```ini
   CYBERSENTINEL_AUTH_ENABLED=true
   CYBERSENTINEL_SESSION_SECRET=generate-a-secure-random-key-here
   CYBERSENTINEL_TOKEN_EXPIRE_MINUTES=480
   CYBERSENTINEL_API_PORT=8000
   CYBERSENTINEL_DASHBOARD_PORT=8501
   ```

4. **Bootstrap the First Administrator Account**:
   You have two secure options to set up the initial admin:
   - **Option A (Environment Variables)**: Set `CYBERSENTINEL_ADMIN_USERNAME` and `CYBERSENTINEL_ADMIN_PASSWORD` in your `.env` file before starting the API. CyberSentinel will automatically bootstrap the initial admin on startup.
   - **Option B (First-Run Web Setup)**: Start the platform with an empty user database. Open the dashboard; CyberSentinel will detect zero existing accounts and present a secure **First-Run Administrator Setup** form. Once created, self-registration permanently locks.

5. **Live Network Capture Privilege Setup (Optional)**:
   To permit passive packet monitoring without running the dashboard as root:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/python3.14
   getcap /usr/bin/python3.14
   ```
   *(Note: Dataset replay, ML inference, and dashboard operations do not require raw socket capabilities.)*

---

## Running the Platform in WSL2

Start the FastAPI backend and Streamlit dashboard in separate terminal windows:

### Terminal 1: Start FastAPI Backend
```bash
cd /mnt/d/BDA/CyberSentinel
source /home/charay/cybersentinel-venv/bin/activate
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```
- API Base URL: `http://localhost:8000`
- Interactive Swagger UI: `http://localhost:8000/docs`
- ReDoc API Specification: `http://localhost:8000/redoc`
- System Readiness Probe: `http://localhost:8000/ready`

### Terminal 2: Start Streamlit Analyst Workspace
```bash
cd /mnt/d/BDA/CyberSentinel
source /home/charay/cybersentinel-venv/bin/activate
streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0
```
- Analyst Dashboard URL: `http://localhost:8501`

---

## Database Backup and Recovery Procedures

CyberSentinel provides atomic, point-in-time SQLite backups and a guarded recovery subsystem to protect operational telemetry.

### Backup Creation
- **Via Admin UI**: Navigate to `Administration` -> `Backup & Recovery` -> Click **Create Immediate Backup**.
- **Via API**:
  ```bash
  curl -X POST http://localhost:8000/api/admin/backups \
    -H "Authorization: Bearer <ADMIN_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"label": "pre-upgrade"}'
  ```
- Backups are stored in `data/backups/` using the format `soc_backup_<label>_<YYYYMMDD_HHMMSS>.db`.
- SQLite's online backup API ensures zero disruption to concurrent reads or writes.

### Backup Validation
Before restoring any database file, CyberSentinel performs a three-stage validation:
1. Verifies minimum file size and existence.
2. Checks the 16-byte SQLite format 3 magic header bytes.
3. Executes `PRAGMA integrity_check` on the candidate file.
- **Via UI**: Click **Validate File** in the Backups table.
- **Via API**:
  ```bash
  curl "http://localhost:8000/api/admin/backups/validate?backup_path=data/backups/soc_backup_pre-upgrade_20261012_100000.db" \
    -H "Authorization: Bearer <ADMIN_TOKEN>"
  ```

### Safe Database Restoration
Restoration includes two mandatory safety mechanisms:
1. **Deliberate Confirmation**: The request must supply `confirmation="CONFIRM_RESTORE"`.
2. **Pre-Restore Snapshot**: CyberSentinel automatically generates an emergency pre-restore snapshot (`soc_backup_prerestore_safety_*.db`) of the live database before replacing it, preventing accidental data loss.
- **Via Admin UI**: Select the backup file -> Type `CONFIRM_RESTORE` -> Click **Execute Database Restore**.
- **Via API**:
  ```bash
  curl -X POST http://localhost:8000/api/admin/backups/restore \
    -H "Authorization: Bearer <ADMIN_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
      "backup_path": "data/backups/soc_backup_pre-upgrade_20261012_100000.db",
      "confirmation": "CONFIRM_RESTORE"
    }'
  ```

---

## Automated Testing & Verification

Run the complete automated test suite (113 unit, integration, and security tests) in WSL2:

```bash
cd /mnt/d/BDA/CyberSentinel
source /home/charay/cybersentinel-venv/bin/activate
python -m pytest tests/ -v
```

### Focused Security & RBAC Test Suite
To run Phase 8 authentication, authorization, and backup verification:
```bash
python -m pytest tests/test_phase8_security.py -v
```

### Full Test Suite Execution Summary
```
============================= test session starts ==============================
platform linux -- Python 3.14.4, pytest-9.1.1, pluggy-1.6.0
rootdir: /mnt/d/BDA/CyberSentinel
collected 113 items

tests/test_analytics.py .........................                       [ 22%]
tests/test_api.py ...........                                           [ 31%]
tests/test_live_engine.py ..........                                    [ 40%]
tests/test_phase5_threat_intel_mitre.py .............                   [ 52%]
tests/test_phase6_incidents.py ...........                              [ 61%]
tests/test_phase7_detection_workbench.py .............                  [ 73%]
tests/test_phase8_security.py ............                              [ 84%]
tests/test_pipeline.py ........                                         [ 91%]
tests/test_scapy_engine.py ..........                                   [100%]

======================== 113 passed, 2 warnings in 38.51s ========================
```

---

## End-to-End Demonstration Workflow (11 Steps)

1. **STEP 1 — Bootstrap & Admin Login**: Open `http://localhost:8501`. Log in with your configured administrator credentials. Notice the active session badge, username, and role in the sidebar.
2. **STEP 2 — User Management & RBAC Provisioning**: Navigate to `Administration` -> `User Management`. Provision an Analyst user (`analyst1`) and a Read-Only user (`auditor1`). Verify that passwords meet the minimum length policy.
3. **STEP 3 — Read-Only Verification**: Log out and log in as `auditor1`. Observe that incident assignment buttons, status transitions, rule editors, and threshold sliders are disabled. Attempting direct API modifications returns `403 Forbidden`.
4. **STEP 4 — Analyst Investigation Workspace**: Log out and log in as `analyst1`. Navigate to `Incidents`. Select an active incident, assign it to yourself, transition status to `IN_PROGRESS`, add a timestamped note, and attach evidence metadata.
5. **STEP 5 — AI Recommendations & Review**: Open the **Contextual Response Recommendations** accordion. Review recommended actions (e.g., host isolation, firewall rules) and click **Mark Reviewed** with analyst comments.
6. **STEP 6 — Case Report Export**: Download the comprehensive incident report in Markdown or JSON format containing the complete audit timeline, MITRE ATT&CK techniques, evidence, and notes.
7. **STEP 7 — Detection Engineering Workbench**: Navigate to `Detection Workbench`. Inspect the live rule catalog. Tune an existing rule threshold (e.g., threshold count or correlation window), or draft a new rule in Rule Studio.
8. **STEP 8 — Offline Sandbox Preview**: Run an offline rule preview against candidate telemetry samples. Inspect match rates and explanatory reasons with zero production state modification.
9. **STEP 9 — Telemetry & Threat Intelligence**: Navigate to `Replay / Dataset Telemetry` to stream flows or inspect passive packet captures. Observe live alert correlation into MITRE ATT&CK `T1110` / `T1498` techniques.
10. **STEP 10 — Database Backup & Validation**: Log back in as `admin`. Navigate to `Administration` -> `Backup & Recovery`. Create an immediate backup labeled `demo-snapshot`. Run the built-in integrity check to confirm `PRAGMA integrity_check` passes.
11. **STEP 11 — Security Audit Trail**: Open `Security Audit Log` in the Administration tab. Verify that all login events, role verifications, and backup activities are chronologically recorded with zero password or token leaks.

---

## Production Release Checklist

Before deploying CyberSentinel to a production or multi-user environment, verify each checklist item:

### 1. Security Configuration
- [ ] Ensure `CYBERSENTINEL_AUTH_ENABLED=true` in `.env`.
- [ ] Replace `CYBERSENTINEL_SESSION_SECRET` with a 256-bit high-entropy secret (`openssl rand -hex 32`).
- [ ] Ensure initial admin bootstrap credentials (`CYBERSENTINEL_ADMIN_PASSWORD`) are strong (>= 12 characters) and removed from plaintext files once created.
- [ ] Restrict file permissions on `.env` (`chmod 600 .env`).
- [ ] Ensure the database directory `data/` and backup directory `data/backups/` have restricted read/write permissions.

### 2. Operational Reliability
- [ ] Verify both `/health` and `/ready` endpoints return HTTP 200 and report all components as healthy.
- [ ] Verify test suite passes completely with `python -m pytest -q`.
- [ ] Confirm scheduled or automated backup scripts are configured with appropriate retention windows.
- [ ] Verify pre-restoration backup snapshots are preserved.

### 3. Network & Transport Security
- [ ] Deploy a reverse proxy (e.g., NGINX, Caddy, or Traefik) in front of FastAPI (port 8000) and Streamlit (port 8501) with TLS/HTTPS certificates.
- [ ] Configure reverse proxy rate limiting on `/api/auth/login` to prevent credential brute-forcing.
- [ ] Grant Linux capabilities (`cap_net_raw`) only if passive interface monitoring is explicitly required on the host; do not run application servers as root.

---

## Known Limitations & Security Considerations

1. **Single-Node SQLite Concurrency**:
   - The platform uses SQLite for local simplicity and zero external database overhead. SQLite utilizes file-level locking during writes. For high-volume multi-analyst teams (> 50 concurrent active users), migrating the persistent store to PostgreSQL or MySQL is recommended.
2. **In-Memory Session Invalidation**:
   - Active bearer tokens are stored in the `user_sessions` SQLite table and cached in memory. In multi-instance or load-balanced topologies, a distributed session store (such as Redis or signed JWTs with distributed revocation lists) would be required.
3. **Local Filesystem Backup Storage**:
   - By default, database backups are stored on local storage (`data/backups/`). In production environments, backups should be replicated to off-site, immutable object storage (such as AWS S3 with Object Lock or GCP Cloud Storage).
4. **Transport Layer Security (TLS)**:
   - The Uvicorn and Streamlit dev servers run unencrypted HTTP by default. Production deployments require a reverse proxy terminating HTTPS/TLS to safeguard credentials and session tokens over the wire.
5. **Passive Network Capture Privileges**:
   - Live packet sniffing on Linux requires `cap_net_raw` privileges. The application must never be run as root; file capabilities (`setcap`) or PCAP replay should always be used instead.
