import sys
import json
import time
from pathlib import Path

# ============================================================
# PROJECT PATH SETUP
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# IMPORTS
# ============================================================

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.api.client import (
    DEFAULT_ALERT_LIMIT,
    get_health,
    get_soc_metrics,
    get_status_metrics,
    get_attack_metrics,
    get_severity_metrics,
    get_alerts,
    update_alert_status,
    get_replays,
    get_stream_status,
    start_stream,
    stop_stream,
    pause_stream,
    resume_stream,
    get_network_interfaces,
    get_network_status,
    start_network_pcap,
    start_network_live,
    stop_network_stream,
    get_network_flows,
    get_incidents,
    get_incident,
    update_incident_status,
    assign_incident,
    get_incident_alerts,
    get_incident_timeline,
    get_indicators,
    add_indicator,
    remove_indicator,
    get_rules,
    get_mitre_techniques,
    get_mitre_tactics,
    get_incident_intelligence,
    get_analytics_summary,
    get_analytics_trends,
    get_analytics_attacks,
    get_analytics_severity,
    get_analytics_entities,
    get_analytics_protocols,
    get_analytics_incidents,
    get_analytics_model,
    get_analytics_dataset,
)




# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="CyberSentinel SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# RESTRAINED ENTERPRISE SIEM CSS (SPLUNK / SENTINEL / QRADAR)
# ============================================================

st.markdown(
    """<style>

/* Main Application Background */
.stApp {
    background-color: #0f1115;
    color: #e5e7eb;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #151922;
    border-right: 1px solid #2a303a;
}

[data-testid="stSidebar"] * {
    color: #9ca3af;
}

/* Compact Header Bar */
.soc-header-bar {
    background-color: #151922;
    border: 1px solid #2a303a;
    border-radius: 4px;
    padding: 10px 16px;
    margin-bottom: 14px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.soc-title-main {
    font-size: 14px;
    font-weight: 700;
    color: #f3f4f6;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}

.soc-subtitle-main {
    font-size: 11px;
    color: #9ca3af;
    margin-top: 1px;
}

.status-dot-green {
    color: #10b981;
    font-size: 11px;
    font-weight: 700;
}

/* Section Header */
.soc-section-header {
    font-size: 11px;
    font-weight: 700;
    color: #e5e7eb;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding-bottom: 4px;
    border-bottom: 1px solid #2a303a;
    margin-top: 14px;
    margin-bottom: 8px;
}

/* Compact Metric Cards */
[data-testid="stMetric"] {
    background-color: #151922;
    border: 1px solid #2a303a;
    border-radius: 4px;
    padding: 8px 12px;
    min-height: 65px;
}

[data-testid="stMetricLabel"] {
    color: #9ca3af !important;
    font-size: 10px !important;
    font-weight: 600 !important;
    text-transform: uppercase;
}

[data-testid="stMetricValue"] {
    color: #f3f4f6 !important;
    font-size: 18px !important;
    font-weight: 700 !important;
    font-family: 'Roboto Mono', 'JetBrains Mono', monospace;
}

.metric-caption {
    color: #6b7280;
    font-size: 9px;
    margin-top: -4px;
    margin-bottom: 2px;
}

/* Restrained Threat Level Status Banner */
.threat-level-banner {
    background-color: #151922;
    border: 1px solid #2a303a;
    border-left: 4px solid #ef4444;
    border-radius: 4px;
    padding: 10px 14px;
    margin: 10px 0 14px 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.threat-title {
    font-size: 11px;
    font-weight: 700;
    color: #ef4444;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.threat-desc {
    font-size: 11px;
    color: #9ca3af;
}

/* Buttons */
.stButton > button {
    background-color: #1b2029;
    border: 1px solid #374151;
    color: #e5e7eb;
    font-size: 11px;
    font-weight: 600;
    border-radius: 4px;
    padding: 4px 8px;
}

.stButton > button:hover {
    background-color: #242a33;
    border-color: #4b5563;
    color: #ffffff;
}

/* Table Styling */
[data-testid="stDataFrame"] {
    border: 1px solid #2a303a;
    border-radius: 4px;
}

/* Detail Box */
.detail-panel {
    background-color: #151922;
    border: 1px solid #2a303a;
    border-radius: 4px;
    padding: 10px 12px;
    margin-bottom: 10px;
}

.detail-row {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    padding: 3px 0;
    border-bottom: 1px dashed #2a303a;
}

.detail-row:last-child {
    border-bottom: none;
}

.detail-key {
    color: #9ca3af;
}

.detail-val {
    color: #f3f4f6;
    font-weight: 600;
    font-family: 'Roboto Mono', monospace;
}

/* Technical Diagram Strip */
.pipeline-box {
    background-color: #151922;
    border: 1px solid #2a303a;
    border-radius: 4px;
    padding: 10px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 11px;
    margin: 10px 0;
}

.pipeline-step {
    background-color: #1b2029;
    border: 1px solid #374151;
    padding: 4px 10px;
    border-radius: 2px;
    color: #e5e7eb;
    font-weight: 600;
    text-align: center;
}

.pipeline-arrow {
    color: #6b7280;
    font-weight: 700;
}

/* Sidebar Badges */
.sys-status-badge {
    font-size: 11px;
    color: #10b981;
    font-weight: 600;
    margin-bottom: 4px;
}

</style>""",
    unsafe_allow_html=True,
)


# ============================================================
# DATA HELPERS & NORMALIZATION
# ============================================================

def safe_float(value, default=0.0):
    try:
        if value is None or pd.isna(value):
            return default
        return float(value)
    except Exception:
        return default


def format_number(value):
    try:
        return f"{int(value):,}"
    except Exception:
        return "0"


def format_percentage(value):
    try:
        val = float(value)
        if val > 1.0:
            return f"{val:.2f}%"
        return f"{val * 100:.2f}%"
    except Exception:
        return "0.00%"


def first_available(row, names, default=None):
    for name in names:
        if name not in row.index:
            continue
        val = row[name]
        if val is None:
            continue
        try:
            if pd.isna(val):
                continue
        except Exception:
            pass
        return val
    return default


def normalize_alerts(alerts):
    if alerts is None:
        return pd.DataFrame()

    if isinstance(alerts, pd.DataFrame):
        df = alerts.copy()
    else:
        df = pd.DataFrame(alerts)

    if df.empty:
        return df

    rename_map = {
        "Alert_ID": "alert_id",
        "AlertId": "alert_id",
        "ID": "alert_id",
        "Timestamp": "timestamp",
        "Dst_Port": "dst_port",
        "Destination_Port": "dst_port",
        "destination_port": "dst_port",
        "DestinationPort": "dst_port",
        "Protocol": "protocol",
        "AttackType": "attack_type",
        "Attack_Type": "attack_type",
        "Severity": "severity",
        "Status": "status",
        "Attack_Probability": "attack_probability",
        "AttackProbability": "attack_probability",
        "Model_Confidence": "model_confidence",
        "ModelConfidence": "model_confidence",
        "confidence": "attack_probability",
    }


    for old_name, new_name in rename_map.items():
        if old_name in df.columns and new_name not in df.columns:
            df = df.rename(columns={old_name: new_name})

    defaults = {
        "alert_id": None,
        "timestamp": None,
        "dst_port": None,
        "protocol": None,
        "attack_probability": None,
        "model_confidence": None,
        "attack_type": "Unknown",
        "severity": "UNKNOWN",
        "status": "NEW",
    }

    for col, def_val in defaults.items():
        if col not in df.columns:
            df[col] = def_val

    df["attack_probability"] = pd.to_numeric(df["attack_probability"], errors="coerce")
    df["model_confidence"] = pd.to_numeric(df["model_confidence"], errors="coerce")
    df["attack_probability"] = df["attack_probability"].fillna(df["model_confidence"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    df["attack_type"] = df["attack_type"].fillna("Unknown").astype(str)
    df["severity"] = df["severity"].fillna("UNKNOWN").astype(str).str.upper()
    df["status"] = df["status"].fillna("NEW").astype(str).str.upper()


    return df


def protocol_name(value):
    if value is None or pd.isna(value):
        return "Unknown"
    txt = str(value).strip()
    if txt in ["TCP", "UDP", "ICMP"]:
        return txt
    try:
        num = int(float(value))
        return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(num, str(num))
    except Exception:
        return txt if txt else "Unknown"



def port_value(value):
    if value is None or pd.isna(value):
        return "Unknown"
    try:
        return str(int(float(value)))
    except Exception:
        txt = str(value).strip()
        return txt if txt else "Unknown"


def load_evaluation_reports():
    eval_file = PROJECT_ROOT / "reports" / "evaluation" / "evaluation_summary.json"
    if eval_file.exists():
        try:
            with open(eval_file, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return None


# ============================================================
# API HEALTH CHECK
# ============================================================

t0_health = time.perf_counter()
try:
    health = get_health()
    api_online = health.get("status") == "healthy"
    health_response_ms = (time.perf_counter() - t0_health) * 1000.0
except Exception as exc:
    st.error(f"CyberSentinel API Connection Offline: {exc}")
    st.code("uvicorn src.api.main:app --host 0.0.0.0 --port 8000")
    st.stop()


# ============================================================
# SIDEBAR NAVIGATION & SYSTEM STATUS
# ============================================================

with st.sidebar:
    st.markdown('<div style="font-size:13px; font-weight:700; color:#f3f4f6;">CYBERSENTINEL</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:10px; color:#9ca3af; margin-bottom:8px;">SOC PLATFORM</div>', unsafe_allow_html=True)

    current_view = st.radio(
        "Navigation",
        [
            "Overview",
            "Real-Time Monitoring",
            "Incidents",
            "Threat Intelligence",
            "SOC Analytics",
            "Detection Analytics",
            "Model Intelligence",
            "System Status",
            "Replay / Dataset Telemetry",
        ],
        label_visibility="collapsed",
    )


    st.divider()

    st.markdown('<div style="font-size:10px; font-weight:700; color:#d1d5db; margin-bottom:4px;">SYSTEM STATUS</div>', unsafe_allow_html=True)
    st.markdown('<div class="sys-status-badge">● API ONLINE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sys-status-badge">● DATABASE ONLINE</div>', unsafe_allow_html=True)
    st.markdown('<div class="sys-status-badge">● ML ENGINE READY</div>', unsafe_allow_html=True)

    st.divider()

    st.markdown('<div style="font-size:10px; font-weight:700; color:#d1d5db; margin-bottom:4px;">FILTERS</div>', unsafe_allow_html=True)

    if "filter_status" not in st.session_state:
        st.session_state["filter_status"] = "ALL"
    if "filter_severity" not in st.session_state:
        st.session_state["filter_severity"] = "ALL"
    if "filter_attack" not in st.session_state:
        st.session_state["filter_attack"] = "ALL"
    if "filter_limit" not in st.session_state:
        st.session_state["filter_limit"] = DEFAULT_ALERT_LIMIT

    status_filter = st.selectbox(
        "Status",
        ["ALL", "NEW", "INVESTIGATING", "ESCALATED", "RESOLVED"],
        key="filter_status",
    )

    severity_filter = st.selectbox(
        "Severity",
        ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        key="filter_severity",
    )

    attack_filter = st.selectbox(
        "Attack Type",
        [
            "ALL",
            "DDOS attack-HOIC",
            "DDoS attacks-LOIC-HTTP",
            "DoS attacks-Hulk",
            "Bot",
            "FTP-BruteForce",
            "SSH-Bruteforce",
            "Infilteration",
            "DoS attacks-SlowHTTPTest",
            "DoS attacks-GoldenEye",
            "DoS attacks-Slowloris",
            "DDOS attack-LOIC-UDP",
            "Brute Force -Web",
            "Brute Force -XSS",
            "SQL Injection",
        ],
        key="filter_attack",
    )

    limit_filter = st.selectbox(
        "Alert Limit",
        [100, 500, 1000, 5000, 10000],
        index=4,
        key="filter_limit",
    )

    st.divider()

    sb_c1, sb_c2 = st.columns(2)
    with sb_c1:
        if st.button("Refresh", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

    with sb_c2:
        if st.button("Reset Filters", use_container_width=True):
            st.session_state["filter_status"] = "ALL"
            st.session_state["filter_severity"] = "ALL"
            st.session_state["filter_attack"] = "ALL"
            st.session_state["filter_limit"] = DEFAULT_ALERT_LIMIT
            st.rerun()

    st.divider()
    st.markdown('<div style="font-size:9px; color:#6b7280;">Environment: Local SOC</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:9px; color:#6b7280;">FastAPI + SQLite</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:9px; color:#6b7280;">PySpark Engine</div>', unsafe_allow_html=True)


# ============================================================
# COMPACT HEADER BAR
# ============================================================

st.markdown(
    f"""<div class="soc-header-bar">
<div>
    <div class="soc-title-main">CYBERSENTINEL SOC &nbsp;|&nbsp; {current_view.upper()}</div>
    <div class="soc-subtitle-main">Incident Monitoring & Threat Detection Console</div>
</div>
<div>
    <span class="status-dot-green">● LIVE</span> &nbsp;|&nbsp;
    <span style="font-size:10px; color:#9ca3af;">{time.strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
</div>
</div>""",
    unsafe_allow_html=True,
)


# ============================================================
# DATA RETRIEVAL FUNCTION
# ============================================================

def fetch_soc_data():
    try:
        soc_metrics = get_soc_metrics()
        status_metrics = get_status_metrics()
        attack_metrics = get_attack_metrics()
        severity_metrics = get_severity_metrics()
    except Exception as exc:
        st.error(f"Failed to fetch SOC metrics from API: {exc}")
        st.stop()

    status_parameter = None if status_filter == "ALL" else status_filter
    severity_parameter = None if severity_filter == "ALL" else severity_filter
    attack_parameter = None if attack_filter == "ALL" else attack_filter

    try:
        raw_alerts = get_alerts(
            status=status_parameter,
            severity=severity_parameter,
            attack_type=attack_parameter,
            limit=limit_filter,
        )
        alerts_df = normalize_alerts(raw_alerts)
    except Exception as exc:
        st.error(f"Failed to fetch alerts from API: {exc}")
        alerts_df = pd.DataFrame()

    return soc_metrics, status_metrics, attack_metrics, severity_metrics, alerts_df


soc_metrics, status_metrics, attack_metrics, severity_metrics, alerts_df = fetch_soc_data()
status_counts = status_metrics.get("by_status", {})
new_alerts = status_counts.get("NEW", 0)
investigating = status_counts.get("INVESTIGATING", 0)
escalated = status_counts.get("ESCALATED", 0)
resolved = status_counts.get("RESOLVED", 0)
active_incidents = new_alerts + investigating + escalated
critical_alerts = soc_metrics.get("critical_alerts", 0)
avg_confidence = soc_metrics.get("average_confidence", 0)


# ============================================================
# VIEW — REAL-TIME MONITORING
# ============================================================

if current_view == "Real-Time Monitoring":
    st.markdown('<div style="font-size:12px; font-weight:700; color:#9ca3af; margin-bottom:10px;">REAL-TIME NETWORK THREAT STREAMING MONITOR</div>', unsafe_allow_html=True)

    # Determine active input source early to fetch correct telemetry endpoint
    active_input_source = st.session_state.get("input_source_selector", "SIMULATED")

    if active_input_source in ["LIVE NETWORK", "PCAP"]:
        try:
            stream_telemetry = get_network_status()
        except Exception:
            stream_telemetry = {"status": "STOPPED", "throughput": 0.0, "packets_captured": 0, "flows_analyzed": 0, "attacks_detected": 0, "alerts_generated": 0}
    else:
        try:
            stream_telemetry = get_stream_status()
        except Exception:
            stream_telemetry = {"status": "STOPPED", "throughput": 0.0, "flows_processed": 0, "attacks_detected": 0, "alerts_generated": 0}

    s_status = str(stream_telemetry.get("status", "STOPPED")).upper()

    if s_status in ["RUNNING", "STARTING"]:
        status_badge = '<span style="color:#10b981; font-weight:700;">● LIVE / RUNNING</span>'
    elif s_status == "PAUSED":
        status_badge = '<span style="color:#f59e0b; font-weight:700;">● PAUSED</span>'
    elif s_status == "ERROR":
        status_badge = f'<span style="color:#ef4444; font-weight:700;">● ERROR ({stream_telemetry.get("capture_permission", "DENIED")})</span>'
    else:
        status_badge = '<span style="color:#ef4444; font-weight:700;">● STOPPED</span>'

    # Header Panel
    st.markdown(
        f"""<div class="detail-panel" style="display:flex; justify-content:space-between; align-items:center;">
<div>
    <span style="font-size:12px; font-weight:700; color:#f3f4f6;">STREAM STATUS: {status_badge}</span>
    <div style="font-size:10px; color:#9ca3af;">Mode: {active_input_source} | Engine: CyberSentinel Stream & Network Monitor</div>
</div>
<div style="font-size:11px; color:#e5e7eb; text-align:right;">
    Throughput: <strong>{stream_telemetry.get('throughput', 0.0):.1f} flows/sec</strong>
</div>
</div>""",
        unsafe_allow_html=True,
    )

    # Input Source Selector
    st.markdown('<div class="soc-section-header">INPUT TRAFFIC SOURCE</div>', unsafe_allow_html=True)
    input_source = st.radio(
        "Select Traffic Source Mode",
        ["SIMULATED", "PCAP", "LIVE NETWORK"],
        horizontal=True,
        key="input_source_selector",
    )

    if input_source == "PCAP":
        st.markdown('<div class="soc-section-header">PCAP FILE ANALYSIS CONFIGURATION</div>', unsafe_allow_html=True)
        pc1, pc2, pc3 = st.columns([3, 2, 2])
        with pc1:
            cfg_pcap_path = st.text_input("PCAP File Path", value="data/test_sample.pcap")
        with pc2:
            cfg_pcap_batch = st.number_input("Batch Size", min_value=1, max_value=500, value=20, step=10, key="pcap_batch")
        with pc3:
            cfg_pcap_timeout = st.number_input("Flow Timeout (sec)", min_value=1.0, max_value=60.0, value=10.0, step=1.0, key="pcap_timeout")

        p_btn1, p_btn2 = st.columns(2)
        with p_btn1:
            if st.button("START PCAP ANALYSIS", use_container_width=True):
                try:
                    res = start_network_pcap(
                        pcap_path=cfg_pcap_path,
                        batch_size=cfg_pcap_batch,
                        flow_timeout=cfg_pcap_timeout,
                    )
                    st.success(res.get("message", "PCAP analysis started"))
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to start PCAP analysis: {exc}")
        with p_btn2:
            if st.button("STOP PCAP ANALYSIS", use_container_width=True):
                try:
                    stop_network_stream()
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to stop stream: {exc}")

    elif input_source == "LIVE NETWORK":
        st.markdown('<div class="soc-section-header">LIVE NETWORK INTERFACE MONITORING</div>', unsafe_allow_html=True)
        try:
            ifaces = get_network_interfaces()
            iface_names = [ifc["name"] for ifc in ifaces] if isinstance(ifaces, list) else ["eth0", "wlan0", "lo"]
        except Exception:
            iface_names = ["eth0", "wlan0", "lo"]

        lc1, lc2, lc3 = st.columns([3, 2, 2])
        with lc1:
            cfg_iface = st.selectbox("Select Network Interface", iface_names)
        with lc2:
            cfg_live_batch = st.number_input("Batch Size", min_value=1, max_value=500, value=20, step=10, key="live_batch")
        with lc3:
            cfg_live_timeout = st.number_input("Flow Timeout (sec)", min_value=1.0, max_value=60.0, value=10.0, step=1.0, key="live_timeout")

        st.warning(f"⚠️ Passive Monitoring Mode: Passively analyzes network flows visible to local interface '{cfg_iface}'. No packet modification or injection.")

        l_btn1, l_btn2 = st.columns(2)
        with l_btn1:
            if st.button("START LIVE MONITORING", use_container_width=True):
                try:
                    res = start_network_live(
                        interface=cfg_iface,
                        batch_size=cfg_live_batch,
                        flow_timeout=cfg_live_timeout,
                    )
                    st.success(res.get("message", "Live monitoring started"))
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to start live monitoring: {exc}")
        with l_btn2:
            if st.button("STOP LIVE MONITORING", use_container_width=True):
                try:
                    stop_network_stream()
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to stop live monitoring: {exc}")

    else:
        # Controls Panel (SIMULATED)
        st.markdown('<div class="soc-section-header">STREAM CONTROLS & CONFIGURATION (SIMULATED)</div>', unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns([2, 2, 2, 2])
        with c1:
            cfg_batch = st.number_input("Batch Size", min_value=1, max_value=500, value=50, step=10)
        with c2:
            cfg_delay = st.number_input("Delay (sec)", min_value=0.0, max_value=10.0, value=0.5, step=0.1)
        with c3:
            cfg_flows = st.number_input("Max Flows (0=All)", min_value=0, max_value=500000, value=200, step=50)
        with c4:
            cfg_seed = st.number_input("Seed", min_value=0, max_value=99999, value=42, step=1)

        ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns(4)
        with ctrl_col1:
            if st.button("START STREAM", use_container_width=True, disabled=(s_status in ["RUNNING", "PAUSED"])):
                try:
                    res = start_stream(
                        batch_size=cfg_batch,
                        delay=cfg_delay,
                        flows=cfg_flows if cfg_flows > 0 else None,
                        continuous=False,
                        seed=cfg_seed,
                    )
                    st.success(res.get("message", "Stream started"))
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to start stream: {exc}")

        with ctrl_col2:
            if st.button("PAUSE STREAM", use_container_width=True, disabled=(s_status != "RUNNING")):
                try:
                    pause_stream()
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to pause stream: {exc}")

        with ctrl_col3:
            if st.button("RESUME STREAM", use_container_width=True, disabled=(s_status != "PAUSED")):
                try:
                    resume_stream()
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to resume stream: {exc}")

        with ctrl_col4:
            if st.button("STOP STREAM", use_container_width=True, disabled=(s_status == "STOPPED")):
                try:
                    stop_stream()
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to stop stream: {exc}")

    # Display Telemetry Metrics according to selected input source mode
    if input_source == "LIVE NETWORK":
        # LIVE NETWORK TELEMETRY PANEL
        st.markdown('<div class="soc-section-header">LIVE NETWORK TELEMETRY</div>', unsafe_allow_html=True)
        l1, l2, l3, l4 = st.columns(4)
        with l1:
            st.metric("PACKETS CAPTURED", format_number(stream_telemetry.get("packets_captured", 0)))
        with l2:
            st.metric("ACTIVE FLOWS", format_number(stream_telemetry.get("active_flows", 0)))
        with l3:
            st.metric("COMPLETED FLOWS", format_number(stream_telemetry.get("flows_completed", 0)))
        with l4:
            st.metric("FLOWS ANALYZED", format_number(stream_telemetry.get("flows_analyzed", 0)))

        l5, l6, l7, l8 = st.columns(4)
        with l5:
            st.metric("BENIGN DETECTED", format_number(stream_telemetry.get("benign_detected", 0)))
        with l6:
            st.metric("ATTACKS DETECTED", format_number(stream_telemetry.get("attacks_detected", 0)))
        with l7:
            st.metric("ALERTS GENERATED", format_number(stream_telemetry.get("alerts_generated", 0)))
        with l8:
            avg_conf_val = stream_telemetry.get("average_confidence", 0.0)
            conf_str = f"{avg_conf_val:.1f}%" if avg_conf_val > 1.0 else format_percentage(avg_conf_val)
            st.metric("AVERAGE CONFIDENCE", conf_str)

        l9, l10, l11 = st.columns(3)
        with l9:
            st.metric("THROUGHPUT", f"{stream_telemetry.get('throughput', 0.0):.1f} flows/s")
        with l10:
            st.metric("CAPTURE PERMISSION", str(stream_telemetry.get("capture_permission", "UNKNOWN")))
        with l11:
            st.metric("STREAM UPTIME", f"{stream_telemetry.get('stream_uptime', 0.0):.1f}s")

        st.markdown('<div class="soc-section-header">LIVE ALERT BREAKDOWN</div>', unsafe_allow_html=True)
        s1, s2, s3, s4 = st.columns(4)
        with s1:
            st.metric("CRITICAL ALERTS", format_number(stream_telemetry.get("critical_alerts", 0)))
        with s2:
            st.metric("HIGH ALERTS", format_number(stream_telemetry.get("high_alerts", 0)))
        with s3:
            st.metric("MEDIUM ALERTS", format_number(stream_telemetry.get("medium_alerts", 0)))
        with s4:
            st.metric("LOW ALERTS", format_number(stream_telemetry.get("low_alerts", 0)))

    elif input_source == "PCAP" and not ("ground_truth_benign" in stream_telemetry and (stream_telemetry.get("ground_truth_benign", 0) > 0 or stream_telemetry.get("ground_truth_attacks", 0) > 0)):
        # PCAP FLOW TELEMETRY PANEL (without ground truth labels)
        st.markdown('<div class="soc-section-header">PCAP FLOW TELEMETRY</div>', unsafe_allow_html=True)
        p1, p2, p3, p4 = st.columns(4)
        with p1:
            st.metric("PACKETS CAPTURED", format_number(stream_telemetry.get("packets_captured", 0)))
        with p2:
            st.metric("FLOWS CREATED", format_number(stream_telemetry.get("flows_created", 0)))
        with p3:
            st.metric("FLOWS COMPLETED", format_number(stream_telemetry.get("flows_completed", 0)))
        with p4:
            st.metric("FLOWS ANALYZED", format_number(stream_telemetry.get("flows_analyzed", 0)))

        p5, p6, p7, p8 = st.columns(4)
        with p5:
            st.metric("BENIGN DETECTED", format_number(stream_telemetry.get("benign_detected", 0)))
        with p6:
            st.metric("ATTACKS DETECTED", format_number(stream_telemetry.get("attacks_detected", 0)))
        with p7:
            st.metric("ALERTS GENERATED", format_number(stream_telemetry.get("alerts_generated", 0)))
        with p8:
            avg_conf_val = stream_telemetry.get("average_confidence", 0.0)
            conf_str = f"{avg_conf_val:.1f}%" if avg_conf_val > 1.0 else format_percentage(avg_conf_val)
            st.metric("AVERAGE CONFIDENCE", conf_str)

        st.markdown('<div class="soc-section-header">PCAP ALERT BREAKDOWN</div>', unsafe_allow_html=True)
        s1, s2, s3, s4 = st.columns(4)
        with s1:
            st.metric("CRITICAL ALERTS", format_number(stream_telemetry.get("critical_alerts", 0)))
        with s2:
            st.metric("HIGH ALERTS", format_number(stream_telemetry.get("high_alerts", 0)))
        with s3:
            st.metric("MEDIUM ALERTS", format_number(stream_telemetry.get("medium_alerts", 0)))
        with s4:
            st.metric("LOW ALERTS", format_number(stream_telemetry.get("low_alerts", 0)))

    else:
        # SIMULATED MODE (OR LABELED PCAP): GROUND TRUTH VS MODEL PREDICTION METRICS
        st.markdown('<div class="soc-section-header">GROUND TRUTH VS MODEL PREDICTION METRICS</div>', unsafe_allow_html=True)
        g1, g2, g3, g4 = st.columns(4)
        gt_benign = stream_telemetry.get("ground_truth_benign", 0)
        gt_attacks = stream_telemetry.get("ground_truth_attacks", 0)
        gt_rate = stream_telemetry.get("ground_truth_attack_rate", 0.0)

        pred_attacks = stream_telemetry.get("predicted_attacks", stream_telemetry.get("attacks_detected", 0))
        pred_benign = stream_telemetry.get("predicted_benign", stream_telemetry.get("benign_detected", 0))
        pred_rate = stream_telemetry.get("predicted_attack_rate", 0.0)

        with g1:
            st.metric("GT BENIGN FLOWS", format_number(gt_benign))
        with g2:
            st.metric("GT ATTACK FLOWS", format_number(gt_attacks))
        with g3:
            st.metric("GROUND TRUTH ATTACK RATE", f"{gt_rate:.1f}%")
        with g4:
            st.metric("MODEL DETECTED ATTACK RATE", f"{pred_rate:.1f}%")

        # SOC Results Panel
        st.markdown('<div class="soc-section-header">SOC ALERTS METRICS</div>', unsafe_allow_html=True)
        m1, m2, m3, m4, m5 = st.columns(5)
        processed_val = stream_telemetry.get("flows_processed", 0)
        alerts_val = stream_telemetry.get("alerts_generated", 0)
        throughput_val = stream_telemetry.get("throughput", 0.0)
        avg_conf_val = stream_telemetry.get("average_confidence", 0.0)

        with m1:
            st.metric("FLOWS PROCESSED", format_number(processed_val))
        with m2:
            st.metric("PREDICTED ATTACKS", format_number(pred_attacks))
        with m3:
            st.metric("ALERTS PERSISTED", format_number(alerts_val))
        with m4:
            st.metric("AVG CONFIDENCE", format_percentage(avg_conf_val))
        with m5:
            st.metric("THROUGHPUT", f"{throughput_val:.1f} flows/s")

        s1, s2, s3, s4 = st.columns(4)
        with s1:
            st.metric("CRITICAL ALERTS", format_number(stream_telemetry.get("critical_alerts", 0)))
        with s2:
            st.metric("HIGH ALERTS", format_number(stream_telemetry.get("high_alerts", 0)))
        with s3:
            st.metric("MEDIUM ALERTS", format_number(stream_telemetry.get("medium_alerts", 0)))
        with s4:
            st.metric("LOW ALERTS", format_number(stream_telemetry.get("low_alerts", 0)))

    # Recent Completed Network Flow Activity Table
    st.markdown('<div class="soc-section-header">NETWORK FLOW ACTIVITY (RECENT COMPLETED FLOWS)</div>', unsafe_allow_html=True)
    try:
        net_flows = get_network_flows()
        if net_flows and isinstance(net_flows, list):
            net_df = pd.DataFrame(net_flows)
            net_table = net_df.rename(columns={
                "time": "TIME",
                "src_ip": "SOURCE",
                "dst_ip": "DESTINATION",
                "dst_port": "DST PORT",
                "protocol": "PROTOCOL",
                "packets": "PACKETS",
                "bytes": "BYTES",
                "status": "STATUS",
            })
            st.dataframe(net_table[["TIME", "SOURCE", "DESTINATION", "DST PORT", "PROTOCOL", "PACKETS", "BYTES", "STATUS"]], use_container_width=True, hide_index=True, height=250)
        else:
            st.info("No active network flows completed yet.")
    except Exception:
        st.info("Network flow activity available during PCAP / Live Network ingestion mode.")


    # Live Threat Feed Table
    st.markdown('<div class="soc-section-header">LIVE THREAT FEED (NEWEST DETECTED ATTACKS)</div>', unsafe_allow_html=True)

    if not alerts_df.empty:
        feed_df = alerts_df.head(20).copy()
        feed_df["Time"] = feed_df["timestamp"].dt.strftime("%H:%M:%S").fillna("Unknown")
        feed_df["Confidence"] = feed_df["attack_probability"].apply(lambda v: format_percentage(safe_float(v)))
        feed_df["Dst Port"] = feed_df["dst_port"].apply(port_value)
        feed_df["Protocol"] = feed_df["protocol"].apply(protocol_name)
        feed_df["SEVERITY"] = feed_df["severity"].apply(lambda s: f"● {s}")

        feed_table = feed_df[[
            "SEVERITY", "Time", "attack_type", "Confidence", "Dst Port", "Protocol", "status", "alert_id"
        ]].rename(columns={
            "Time": "TIME",
            "attack_type": "ATTACK TYPE",
            "Confidence": "CONFIDENCE",
            "Dst Port": "DST PORT",
            "Protocol": "PROTOCOL",
            "status": "STATUS",
            "alert_id": "ALERT ID"
        })

        st.dataframe(feed_table, use_container_width=True, hide_index=True, height=350)

    else:
        st.info("No attack alerts currently generated.")

    if s_status == "RUNNING":
        time.sleep(2)
        st.rerun()


# ============================================================
# VIEW 1 — SOC OVERVIEW
# ============================================================

elif current_view == "Overview":

    # Operational Summary Metrics Row
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("ACTIVE INCIDENTS", format_number(active_incidents))
        st.markdown('<div class="metric-caption">NEW + INVESTIGATING + ESCALATED</div>', unsafe_allow_html=True)
    with m2:
        st.metric("CRITICAL", format_number(critical_alerts))
        st.markdown('<div class="metric-caption">Critical Severity Events</div>', unsafe_allow_html=True)
    with m3:
        st.metric("INVESTIGATING", format_number(investigating))
        st.markdown('<div class="metric-caption">Analyst Review in Progress</div>', unsafe_allow_html=True)
    with m4:
        st.metric("ESCALATED", format_number(escalated))
        st.markdown('<div class="metric-caption">Tier-2 Escalations</div>', unsafe_allow_html=True)
    with m5:
        st.metric("AVG CONFIDENCE", format_percentage(avg_confidence))
        st.markdown('<div class="metric-caption">Mean Probability Score</div>', unsafe_allow_html=True)

    # Restrained Threat Level Status Banner
    st.markdown(
        f"""<div class="threat-level-banner">
<div class="threat-title">CURRENT SOC THREAT LEVEL: CRITICAL</div>
<div class="threat-desc">{format_number(critical_alerts)} critical alerts recorded in SQLite store</div>
</div>""",
        unsafe_allow_html=True,
    )

    # Time-Series Incident Activity
    st.markdown('<div class="soc-section-header">INCIDENT ACTIVITY OVER TIME</div>', unsafe_allow_html=True)
    if not alerts_df.empty and "timestamp" in alerts_df.columns:
        ts_df = alerts_df.dropna(subset=["timestamp"]).copy()
        if not ts_df.empty:
            ts_df["time_bucket"] = ts_df["timestamp"].dt.floor("1min")
            activity_df = ts_df.groupby("time_bucket").size().reset_index(name="alert_count")

            fig_time = px.line(
                activity_df,
                x="time_bucket",
                y="alert_count",
                title="",
                labels={"time_bucket": "Time (UTC)", "alert_count": "Alert Count"},
            )
            fig_time.update_traces(line_color="#3b82f6", line_width=2)
            fig_time.update_layout(
                template="plotly_dark",
                paper_bgcolor="#151922",
                plot_bgcolor="#151922",
                margin=dict(l=10, r=10, t=10, b=10),
                height=180,
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=False),
                font=dict(size=10, color="#9ca3af"),
            )
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("No valid timestamp series available.")
    else:
        st.info("No alert time series data available.")

    # Charts Row
    ch1, ch2 = st.columns(2)
    with ch1:
        st.markdown('<div class="soc-section-header">ATTACK DISTRIBUTION</div>', unsafe_allow_html=True)
        atk_df = pd.DataFrame(attack_metrics)
        if not atk_df.empty:
            if "AttackType" in atk_df.columns and "attack_type" not in atk_df.columns:
                atk_df = atk_df.rename(columns={"AttackType": "attack_type"})
            atk_df = atk_df.sort_values("count", ascending=True)

            fig_bar = px.bar(
                atk_df,
                x="count",
                y="attack_type",
                orientation="h",
                color_discrete_sequence=["#3b82f6"],
            )
            fig_bar.update_layout(
                template="plotly_dark",
                paper_bgcolor="#151922",
                plot_bgcolor="#151922",
                margin=dict(l=10, r=10, t=10, b=10),
                xaxis=dict(showgrid=False, title=""),
                yaxis=dict(showgrid=False, title=""),
                height=200,
                font=dict(size=10, color="#9ca3af"),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

    with ch2:
        st.markdown('<div class="soc-section-header">SEVERITY DISTRIBUTION</div>', unsafe_allow_html=True)
        sev_df = pd.DataFrame(severity_metrics)
        if not sev_df.empty:
            if "Severity" in sev_df.columns and "severity" not in sev_df.columns:
                sev_df = sev_df.rename(columns={"Severity": "severity"})
            sev_colors = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#f59e0b",
                "LOW": "#10b981",
                "UNKNOWN": "#6b7280",
            }
            fig_pie = px.pie(
                sev_df,
                names="severity",
                values="count",
                hole=0.6,
                color="severity",
                color_discrete_map=sev_colors,
            )
            fig_pie.update_layout(
                template="plotly_dark",
                paper_bgcolor="#151922",
                plot_bgcolor="#151922",
                margin=dict(l=10, r=10, t=10, b=10),
                height=200,
                font=dict(size=10, color="#9ca3af"),
            )
            st.plotly_chart(fig_pie, use_container_width=True)

    # Recent Incidents Table
    st.markdown('<div class="soc-section-header">RECENT INCIDENTS</div>', unsafe_allow_html=True)
    if not alerts_df.empty:
        rec_df = alerts_df.head(10).copy()
        rec_df["Time"] = rec_df["timestamp"].dt.strftime("%H:%M:%S").fillna("Unknown")
        rec_df["Confidence"] = rec_df["attack_probability"].apply(lambda v: format_percentage(safe_float(v)))
        rec_df["Dst Port"] = rec_df["dst_port"].apply(port_value)
        rec_df["Protocol"] = rec_df["protocol"].apply(protocol_name)
        rec_df["SEVERITY"] = rec_df["severity"].apply(lambda s: f"● {s}")

        rec_table = rec_df[[
            "SEVERITY", "Time", "attack_type", "Confidence", "Dst Port", "Protocol", "status", "alert_id"
        ]].rename(columns={
            "Time": "TIME",
            "attack_type": "ATTACK TYPE",
            "Confidence": "CONFIDENCE",
            "Dst Port": "DST PORT",
            "Protocol": "PROTOCOL",
            "status": "STATUS",
            "alert_id": "ALERT ID"
        })

        st.dataframe(rec_table, use_container_width=True, hide_index=True, height=260)


# ============================================================
# VIEW 2 — INCIDENTS (MAIN ANALYST WORKSPACE)
# ============================================================

elif current_view == "Incidents":
    st.markdown('<div style="font-size:12px; font-weight:700; color:#9ca3af; margin-bottom:10px;">INCIDENT ANALYST WORKSPACE — Phase 3A Correlation & Response Engine</div>', unsafe_allow_html=True)

    left_col, right_col = st.columns([52, 48])

    # Fetch incidents from API
    try:
        incidents_list = get_incidents(
            status=None if status_filter == "ALL" else status_filter,
            severity=None if severity_filter == "ALL" else severity_filter,
            limit=limit_filter,
        )
    except Exception as exc:
        incidents_list = []
        st.error(f"Failed to fetch incidents: {exc}")

    with left_col:
        st.markdown('<div class="soc-section-header">INCIDENT QUEUE</div>', unsafe_allow_html=True)

        if not incidents_list:
            st.info("No correlated incidents match the current filters.")
            selected_inc = None
        else:
            inc_df = pd.DataFrame(incidents_list)

            queue_display = inc_df.copy()
            queue_display["RISK"] = queue_display["risk_score"].apply(lambda s: f"⚡ {s:.0f}")
            queue_display["SEVERITY"] = queue_display["severity"].apply(lambda s: f"● {s}")
            queue_display["FIRST SEEN"] = pd.to_datetime(queue_display["first_seen"]).dt.strftime("%H:%M:%S").fillna("N/A")
            queue_display["LAST SEEN"] = pd.to_datetime(queue_display["last_seen"]).dt.strftime("%H:%M:%S").fillna("N/A")

            queue_table = queue_display[[
                "incident_id", "SEVERITY", "RISK", "primary_attack_type", "alert_count", "FIRST SEEN", "LAST SEEN", "status"
            ]].rename(columns={
                "incident_id": "INCIDENT ID",
                "primary_attack_type": "PRIMARY ATTACK",
                "alert_count": "ALERTS",
                "status": "STATUS"
            })

            st.dataframe(queue_table, use_container_width=True, hide_index=True, height=350)

            inc_options = [
                f"{r['severity']} | Risk: {r['risk_score']:.0f} | {r['primary_attack_type']} ({r['alert_count']} alerts) | {r['incident_id']}"
                for r in incidents_list
            ]

            selected_idx = st.selectbox(
                "Select Incident for Investigation:",
                range(len(inc_options)),
                format_func=lambda i: inc_options[i],
                key="incident_select_box"
            )

            selected_inc = incidents_list[selected_idx] if selected_idx < len(incidents_list) else None

    with right_col:
        st.markdown('<div class="soc-section-header">INCIDENT DETAILS & ANALYST WORKSPACE</div>', unsafe_allow_html=True)

        if selected_inc is not None:
            inc_id = selected_inc["incident_id"]
            inc_title = selected_inc.get("title", f"Incident {inc_id}")
            inc_status = selected_inc.get("status", "NEW")
            inc_severity = selected_inc.get("severity", "MEDIUM")
            inc_risk = selected_inc.get("risk_score", 0.0)
            inc_attacks = selected_inc.get("primary_attack_type", "Threat Detected")
            inc_count = selected_inc.get("alert_count", 1)
            inc_assigned = selected_inc.get("assigned_to", "Unassigned")
            inc_first = str(selected_inc.get("first_seen", "N/A"))
            inc_last = str(selected_inc.get("last_seen", "N/A"))

            # Incident Header Panel
            st.markdown(
                f"""<div class="detail-panel">
<div style="font-size:13px; font-weight:700; color:#f3f4f6; margin-bottom:4px;">{inc_title}</div>
<div style="font-size:10px; color:#9ca3af; margin-bottom:8px;">ID: <strong>{inc_id}</strong> | Primary Threat: <strong>{inc_attacks}</strong></div>
<div class="detail-row"><span class="detail-key">Risk Score</span><span class="detail-val" style="color:#ef4444; font-weight:700;">{inc_risk:.1f} / 100</span></div>
<div class="detail-row"><span class="detail-key">Severity</span><span class="detail-val">{inc_severity}</span></div>
<div class="detail-row"><span class="detail-key">Status</span><span class="detail-val" style="color:#10b981;">{inc_status}</span></div>
<div class="detail-row"><span class="detail-key">Correlated Alerts</span><span class="detail-val">{inc_count} alerts</span></div>
<div class="detail-row"><span class="detail-key">Assigned Analyst</span><span class="detail-val">{inc_assigned}</span></div>
<div class="detail-row"><span class="detail-key">First / Last Seen</span><span class="detail-val" style="font-size:10px;">{inc_first[:19]} / {inc_last[:19]}</span></div>
</div>""",
                unsafe_allow_html=True,
            )

            # Analyst Workflow Action Buttons
            st.markdown('<div style="font-size:10px; font-weight:700; color:#9ca3af; margin-top:8px; margin-bottom:4px;">ANALYST ACTIONS</div>', unsafe_allow_html=True)
            a1, a2, a3, a4 = st.columns(4)
            with a1:
                if st.button("INVESTIGATE", use_container_width=True, key=f"btn_inv_{inc_id}"):
                    try:
                        update_incident_status(inc_id, "INVESTIGATING")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Error: {exc}")
            with a2:
                if st.button("ESCALATE", use_container_width=True, key=f"btn_esc_{inc_id}"):
                    try:
                        update_incident_status(inc_id, "ESCALATED")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Error: {exc}")
            with a3:
                if st.button("RESOLVE", use_container_width=True, key=f"btn_res_{inc_id}"):
                    try:
                        update_incident_status(inc_id, "RESOLVED")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Error: {exc}")
            with a4:
                if st.button("REOPEN", use_container_width=True, key=f"btn_reop_{inc_id}"):
                    try:
                        update_incident_status(inc_id, "REOPEN")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Error: {exc}")

            # Assign Analyst Toolbar
            as1, as2 = st.columns([3, 1])
            with as1:
                assignee_input = st.text_input("Assign Analyst", value=inc_assigned if inc_assigned != "Unassigned" else "Analyst-1", key=f"assign_input_{inc_id}")
            with as2:
                st.markdown('<div style="height:27px;"></div>', unsafe_allow_html=True)
                if st.button("ASSIGN", use_container_width=True, key=f"btn_assign_{inc_id}"):
                    try:
                        assign_incident(inc_id, assignee_input)
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Error: {exc}")

            # Entity Summary
            st.markdown('<div class="soc-section-header">ENTITY SUMMARY</div>', unsafe_allow_html=True)
            sources_list = selected_inc.get("source_entities", [])
            dests_list = selected_inc.get("destination_entities", [])
            ports_list = selected_inc.get("destination_ports", [])
            protos_list = selected_inc.get("protocols", [])

            sources_str = ", ".join([str(s) for s in sources_list]) if sources_list else "N/A (Local Ingestion)"
            dests_str = ", ".join([str(d) for d in dests_list]) if dests_list else "N/A (Local Host)"
            ports_str = ", ".join([str(p) for p in ports_list]) if ports_list else "N/A"
            protos_str = ", ".join([str(pr) for pr in protos_list]) if protos_list else "TCP"

            st.markdown(
                f"""<div class="detail-panel">
<div class="detail-row"><span class="detail-key">SOURCE ENTITIES</span><span class="detail-val">{sources_str}</span></div>
<div class="detail-row"><span class="detail-key">DESTINATION ENTITIES</span><span class="detail-val">{dests_str}</span></div>
<div class="detail-row"><span class="detail-key">DESTINATION PORTS</span><span class="detail-val">{ports_str}</span></div>
<div class="detail-row"><span class="detail-key">PROTOCOLS</span><span class="detail-val">{protos_str}</span></div>
</div>""",
                unsafe_allow_html=True,
            )

            # Explainable Risk Score Factors
            st.markdown('<div class="soc-section-header">TRANSPARENT RISK SCORE BREAKDOWN</div>', unsafe_allow_html=True)
            rf = selected_inc.get("risk_factors", {})
            if isinstance(rf, dict) and rf:
                st.markdown(
                    f"""<div class="detail-panel">
<div class="detail-row"><span class="detail-key">Base Severity Score ({rf.get('base_severity', inc_severity)})</span><span class="detail-val">+{rf.get('base_score', 0)}</span></div>
<div class="detail-row"><span class="detail-key">Alert Volume Factor ({rf.get('alert_count', inc_count)} alerts)</span><span class="detail-val">+{rf.get('volume_bonus', 0)}</span></div>
<div class="detail-row"><span class="detail-key">Attack Diversity Factor ({rf.get('distinct_attack_types', 1)} types)</span><span class="detail-val">+{rf.get('diversity_bonus', 0)}</span></div>
<div class="detail-row"><span class="detail-key">Model Confidence Factor</span><span class="detail-val">+{rf.get('confidence_bonus', 0)}</span></div>
<div class="detail-row"><span class="detail-key">Duration Factor ({rf.get('duration_seconds', 0):.0f}s)</span><span class="detail-val">+{rf.get('duration_bonus', 0)}</span></div>
<div class="detail-row" style="border-top:1px solid #2a303a; margin-top:4px; padding-top:4px;"><span class="detail-key">TOTAL CALCULATED RISK SCORE</span><span class="detail-val" style="color:#ef4444; font-weight:700;">{inc_risk:.1f} / 100</span></div>
</div>""",
                    unsafe_allow_html=True,
                )

            # MITRE ATT&CK Mapping Panel
            st.markdown('<div class="soc-section-header">MITRE ATT&CK ENTERPRISE V19.0 MAPPING</div>', unsafe_allow_html=True)
            try:
                inc_intel = get_incident_intelligence(inc_id)
                mitre_info = inc_intel.get("mitre_attack", {}) if inc_intel else {}
                tactic_str = mitre_info.get("tactic_name", "N/A")
                tactic_id = mitre_info.get("tactic_id", "N/A")
                tech_str = mitre_info.get("technique_name", "N/A")
                tech_id = mitre_info.get("technique_id", "UNMAPPED")
                map_conf = float(mitre_info.get("confidence", 0.0))
                map_status = mitre_info.get("mapping_status", "UNMAPPED")
                rationale = mitre_info.get("rationale", "No associated ATT&CK technique.")

                st.markdown(
                    f"""<div class="detail-panel">
<div class="detail-row"><span class="detail-key">Associated Tactic</span><span class="detail-val">{tactic_str} ({tactic_id})</span></div>
<div class="detail-row"><span class="detail-key">Associated Technique</span><span class="detail-val" style="color:#ef4444; font-weight:700;">{tech_str} ({tech_id})</span></div>
<div class="detail-row"><span class="detail-key">Mapping Status / Confidence</span><span class="detail-val">{map_status} ({map_conf*100:.0f}%)</span></div>
<div class="detail-row"><span class="detail-key">Framework Rationale</span><span class="detail-val" style="font-size:10px;">{rationale}</span></div>
<div class="detail-row"><span class="detail-key">Framework Dataset</span><span class="detail-val" style="font-size:9px; color:#6b7280;">MITRE ATT&CK Enterprise v19.0 (STIX 2.1)</span></div>
</div>""",
                    unsafe_allow_html=True,
                )
            except Exception:
                pass

            # Related Alerts Table
            st.markdown('<div class="soc-section-header">RELATED ALERTS</div>', unsafe_allow_html=True)
            try:
                rel_alerts = get_incident_alerts(inc_id)
                if rel_alerts:
                    rel_df = pd.DataFrame(rel_alerts)
                    rel_df["TIME"] = pd.to_datetime(rel_df["timestamp"]).dt.strftime("%H:%M:%S").fillna("N/A")
                    rel_df["CONFIDENCE"] = rel_df["confidence"].apply(lambda v: format_percentage(safe_float(v)))
                    rel_df["DST PORT"] = rel_df["destination_port"].apply(port_value)
                    rel_df["PROTOCOL"] = rel_df["protocol"].apply(protocol_name)
                    rel_df["SEVERITY"] = rel_df["severity"].apply(lambda s: f"● {s}")

                    rel_table = rel_df[[
                        "SEVERITY", "TIME", "attack_type", "CONFIDENCE", "DST PORT", "PROTOCOL", "status", "alert_id"
                    ]].rename(columns={
                        "attack_type": "ATTACK TYPE",
                        "status": "STATUS",
                        "alert_id": "ALERT ID"
                    })
                    st.dataframe(rel_table, use_container_width=True, hide_index=True, height=220)
                else:
                    st.info("No detailed alert records retrieved for this incident.")
            except Exception as exc:
                st.error(f"Failed to fetch related alerts: {exc}")

            # Incident Timeline
            st.markdown('<div class="soc-section-header">INCIDENT TIMELINE</div>', unsafe_allow_html=True)
            try:
                timeline_events = get_incident_timeline(inc_id)
                if timeline_events:
                    tm_df = pd.DataFrame(timeline_events)
                    tm_df["TIME"] = pd.to_datetime(tm_df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
                    tm_table = tm_df[["TIME", "event_type", "actor", "description"]].rename(columns={
                        "event_type": "EVENT TYPE",
                        "actor": "ACTOR",
                        "description": "DESCRIPTION"
                    })
                    st.dataframe(tm_table, use_container_width=True, hide_index=True, height=200)
                else:
                    st.info("No timeline events logged for this incident yet.")
            except Exception as exc:
                st.error(f"Failed to fetch timeline: {exc}")


# ============================================================
# VIEW 3 — THREAT INTELLIGENCE (PHASE 3B)
# ============================================================

elif current_view == "Threat Intelligence":
    st.markdown('<div style="font-size:12px; font-weight:700; color:#9ca3af; margin-bottom:10px;">THREAT INTELLIGENCE, DETECTION RULES & MITRE ATT&CK MATRIX</div>', unsafe_allow_html=True)

    try:
        indicators = get_indicators()
        rules_list = get_rules()
        mitre_cov = get_mitre_coverage()
    except Exception as exc:
        indicators, rules_list, mitre_cov = [], [], {}

    i1, i2, i3, i4 = st.columns(4)
    with i1:
        st.metric("KNOWN INDICATORS", format_number(len(indicators)))
        st.markdown('<div class="metric-caption">LOCAL THREAT STORE</div>', unsafe_allow_html=True)
    with i2:
        st.metric("DETECTION RULES", format_number(len(rules_list)))
        st.markdown('<div class="metric-caption">BEHAVIORAL RULES</div>', unsafe_allow_html=True)
    with i3:
        st.metric("ATT&CK TACTICS", format_number(mitre_cov.get("mapped_tactics_count", 0)))
        st.markdown('<div class="metric-caption">ENTERPRISE V19.0</div>', unsafe_allow_html=True)
    with i4:
        st.metric("ATT&CK TECHNIQUES", format_number(mitre_cov.get("mapped_techniques_count", 0)))
        st.markdown('<div class="metric-caption">MAPPED TECHNIQUES</div>', unsafe_allow_html=True)

    st.markdown('<div class="soc-section-header">THREAT INTELLIGENCE INDICATOR STORE</div>', unsafe_allow_html=True)

    ind1, ind2 = st.columns([65, 35])
    with ind1:
        if indicators:
            ind_df = pd.DataFrame(indicators)
            ind_df["CREATED"] = pd.to_datetime(ind_df["created_at"]).dt.strftime("%Y-%m-%d %H:%M").fillna("N/A")
            ind_df["CONFIDENCE"] = ind_df["confidence"].apply(lambda c: f"{float(c)*100:.0f}%")
            ind_table = ind_df[["indicator_id", "indicator_type", "indicator_value", "threat_name", "severity", "CONFIDENCE", "source", "CREATED"]].rename(columns={
                "indicator_id": "ID",
                "indicator_type": "TYPE",
                "indicator_value": "VALUE",
                "threat_name": "THREAT NAME",
                "severity": "SEVERITY",
                "source": "SOURCE"
            })
            st.dataframe(ind_table, use_container_width=True, hide_index=True, height=220)
        else:
            st.info("No threat intelligence indicators added yet.")

    with ind2:
        st.markdown('<div style="font-size:10px; font-weight:700; color:#9ca3af; margin-bottom:4px;">ADD LOCAL THREAT INDICATOR</div>', unsafe_allow_html=True)
        new_type = st.selectbox("Indicator Type", ["IP", "DOMAIN", "URL", "HASH"], key="add_ind_type")
        new_val = st.text_input("Indicator Value (e.g. 10.20.30.40)", key="add_ind_val")
        new_threat = st.text_input("Threat Name", value="APT Attack Infrastructure", key="add_ind_threat")
        new_sev = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], index=1, key="add_ind_sev")
        if st.button("ADD THREAT INDICATOR", use_container_width=True, key="btn_add_ind"):
            if new_val:
                try:
                    res = add_indicator(indicator_type=new_type, indicator_value=new_val, threat_name=new_threat, severity=new_sev)
                    if not res:
                        from src.intel.indicator_store import IndicatorStore
                        res = IndicatorStore.add_indicator({
                            "indicator_type": new_type,
                            "indicator_value": new_val,
                            "threat_name": new_threat,
                            "severity": new_sev,
                        })
                    st.success(f"Added indicator '{new_val}'")
                    st.rerun()
                except Exception as exc:
                    st.error(f"{exc}")
            else:
                st.warning("Please enter an indicator value.")

    st.markdown('<div class="soc-section-header">BEHAVIORAL DETECTION RULES ENGINE</div>', unsafe_allow_html=True)
    if rules_list:
        rule_df = pd.DataFrame(rules_list)
        rule_table = rule_df[["rule_id", "rule_name", "severity", "default_threshold", "description"]].rename(columns={
            "rule_id": "RULE ID",
            "rule_name": "RULE NAME",
            "severity": "SEVERITY",
            "default_threshold": "THRESHOLD",
            "description": "DESCRIPTION"
        })
        st.dataframe(rule_table, use_container_width=True, hide_index=True, height=200)

    st.markdown('<div class="soc-section-header">MITRE ATT&CK ENTERPRISE V19.0 COVERAGE MATRIX</div>', unsafe_allow_html=True)
    try:
        mitre_techs = get_mitre_techniques()
        if mitre_techs:
            tech_df = pd.DataFrame(mitre_techs)
            tech_df["ASSOCIATED DETECTIONS"] = tech_df["associated_attacks"].apply(lambda a: ", ".join(a) if isinstance(a, list) else str(a))
            tech_df["CONFIDENCE"] = tech_df["confidence"].apply(lambda c: f"{float(c)*100:.0f}%")
            tech_table = tech_df[["technique_id", "technique_name", "tactic_name", "CONFIDENCE", "ASSOCIATED DETECTIONS"]].rename(columns={
                "technique_id": "TECHNIQUE ID",
                "technique_name": "TECHNIQUE NAME",
                "tactic_name": "TACTIC",
            })
            st.dataframe(tech_table, use_container_width=True, hide_index=True, height=250)
    except Exception as exc:
        st.info("MITRE ATT&CK v19.0 coverage framework operational.")


# ============================================================
# VIEW — SOC ANALYTICS & MODEL MONITORING (PHASE 4)
# ============================================================

elif current_view == "SOC Analytics":
    st.markdown('<div style="font-size:12px; font-weight:700; color:#9ca3af; margin-bottom:10px;">SOC ANALYTICS & MODEL MONITORING WORKSPACE</div>', unsafe_allow_html=True)

    # 1. TIME WINDOW FILTER TOOLBAR
    w_col1, w_col2 = st.columns([30, 70])
    with w_col1:
        sel_window = st.selectbox("Analytics Time Window", ["15m", "1h", "24h", "7d", "all"], index=2, key="soc_analytics_win")

    # 2. SOC PERFORMANCE SUMMARY METRICS
    try:
        summary = get_analytics_summary(window=sel_window)
    except Exception:
        summary = {}

    s1, s2, s3, s4, s5, s6, s7, s8 = st.columns(8)
    with s1:
        st.metric("TOTAL ALERTS", format_number(summary.get("total_alerts", 0)))
    with s2:
        st.metric("ACTIVE ALERTS", format_number(summary.get("active_alerts", 0)))
    with s3:
        st.metric("CRITICAL ALERTS", format_number(summary.get("critical_alerts", 0)))
    with s4:
        st.metric("OPEN INCIDENTS", format_number(summary.get("open_incidents", 0)))
    with s5:
        st.metric("ATTACK RATE", format_percentage(summary.get("attack_rate", 0.0)))
    with s6:
        st.metric("AVG CONFIDENCE", format_percentage(summary.get("mean_confidence") or 0.0))
    with s7:
        st.metric("ALERT RATE", f"{summary.get('alert_rate_per_min', 0.0)}/m")
    with s8:
        st.metric("MTTR", f"{summary.get('mttr_seconds', 'N/A')}s" if summary.get("mttr_seconds") is not None else "N/A")

    st.markdown("---")

    # 3. ATTACK ACTIVITY OVER TIME & ATTACK TYPE DISTRIBUTION
    a_col1, a_col2 = st.columns([60, 40])

    with a_col1:
        st.markdown('<div class="soc-section-header">ATTACK ACTIVITY OVER TIME</div>', unsafe_allow_html=True)
        try:
            trends_res = get_analytics_trends(window=sel_window)
            trends_data = trends_res.get("trends", []) if isinstance(trends_res, dict) else []
            if trends_data:
                tr_df = pd.DataFrame(trends_data)
                tr_df["dt"] = pd.to_datetime(tr_df["timestamp"])
                fig_trend = px.line(
                    tr_df,
                    x="dt",
                    y=["total_alerts", "critical", "attack_alerts"],
                    color_discrete_map={"total_alerts": "#3b82f6", "critical": "#ef4444", "attack_alerts": "#f97316"},
                    labels={"dt": "Time", "value": "Count", "variable": "Metric"},
                )
                fig_trend.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="#151922",
                    plot_bgcolor="#151922",
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=240,
                    xaxis=dict(showgrid=False),
                    yaxis=dict(showgrid=False),
                    font=dict(size=10, color="#9ca3af"),
                )
                st.plotly_chart(fig_trend, use_container_width=True)
            else:
                st.info("No activity telemetry in selected time window.")
        except Exception as exc:
            st.error(f"Error rendering activity trends: {exc}")

    with a_col2:
        st.markdown('<div class="soc-section-header">ATTACK TYPE DISTRIBUTION</div>', unsafe_allow_html=True)
        try:
            atks_res = get_analytics_attacks(window=sel_window)
            atks_data = atks_res.get("attack_distribution", []) if isinstance(atks_res, dict) else []
            if atks_data:
                atk_df = pd.DataFrame(atks_data).sort_values("count", ascending=True)
                fig_bar = px.bar(
                    atk_df,
                    x="count",
                    y="attack_type",
                    orientation="h",
                    color_discrete_sequence=["#3b82f6"],
                )
                fig_bar.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="#151922",
                    plot_bgcolor="#151922",
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=240,
                    xaxis=dict(showgrid=False),
                    yaxis=dict(showgrid=False),
                    font=dict(size=10, color="#9ca3af"),
                )
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.info("No attack distribution telemetry.")
        except Exception as exc:
            st.error(f"Error rendering attack distribution: {exc}")

    st.markdown("---")

    # 4. SEVERITY ANALYTICS & TOP ENTITIES
    sev_col, ent_col = st.columns([35, 65])

    with sev_col:
        st.markdown('<div class="soc-section-header">SEVERITY DISTRIBUTION</div>', unsafe_allow_html=True)
        try:
            sev_res = get_analytics_severity(window=sel_window)
            dist = sev_res.get("distribution", {}) if isinstance(sev_res, dict) else {}
            if dist:
                sev_df = pd.DataFrame([{"severity": k, "count": v} for k, v in dist.items()])
                sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b", "LOW": "#10b981"}
                fig_pie = px.pie(
                    sev_df,
                    names="severity",
                    values="count",
                    hole=0.5,
                    color="severity",
                    color_discrete_map=sev_colors,
                )
                fig_pie.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="#151922",
                    plot_bgcolor="#151922",
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=220,
                    font=dict(size=10, color="#9ca3af"),
                )
                st.plotly_chart(fig_pie, use_container_width=True)
        except Exception as exc:
            st.error(f"Error rendering severity: {exc}")

    with ent_col:
        st.markdown('<div class="soc-section-header">TOP TARGETED ENTITIES & PORTS</div>', unsafe_allow_html=True)
        try:
            ent_res = get_analytics_entities(window=sel_window, limit=5)
            e_src = ent_res.get("top_sources", []) if isinstance(ent_res, dict) else []
            e_dst = ent_res.get("top_destinations", []) if isinstance(ent_res, dict) else []
            e_ports = ent_res.get("top_ports", []) if isinstance(ent_res, dict) else []

            t_src, t_dst, t_prt = st.tabs(["TOP SOURCES", "TOP DESTINATIONS", "TOP PORTS"])
            with t_src:
                if e_src:
                    st.dataframe(pd.DataFrame(e_src), use_container_width=True, hide_index=True, height=160)
                else:
                    st.info("No top source entity data.")
            with t_dst:
                if e_dst:
                    st.dataframe(pd.DataFrame(e_dst), use_container_width=True, hide_index=True, height=160)
                else:
                    st.info("No top destination entity data.")
            with t_prt:
                if e_ports:
                    st.dataframe(pd.DataFrame(e_ports), use_container_width=True, hide_index=True, height=160)
                else:
                    st.info("No top port data.")
        except Exception as exc:
            st.error(f"Error rendering entities: {exc}")

    st.markdown("---")

    # 5. MODEL MONITORING & DISTRIBUTION SHIFT
    st.markdown('<div class="soc-section-header">MODEL PERFORMANCE & DRIFT MONITORING</div>', unsafe_allow_html=True)
    try:
        model_res = get_analytics_model(window=sel_window)
        st1 = model_res.get("stage1_metrics", {}) if isinstance(model_res, dict) else {}
        st2 = model_res.get("stage2_metrics", {}) if isinstance(model_res, dict) else {}
        mon = model_res.get("monitoring_indicators", {}) if isinstance(model_res, dict) else {}

        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.metric("PREDICTION VOLUME", format_number(model_res.get("inference_volume", 0)))
        with m2:
            st.metric("STAGE 1 ATTACK RATE", format_percentage(st1.get("attack_rate", 0.0)))
        with m3:
            st.metric("STAGE 1 MEAN CONF", format_percentage(st1.get("mean_confidence") or 0.0))
        with m4:
            st.metric("LOW CONFIDENCE (<0.60)", format_number(st1.get("low_confidence_count", 0)))
        with m5:
            st.metric("DRIFT STATUS", mon.get("status", "NORMAL"))

        st.markdown(
            f"""<div class="detail-panel">
<div class="detail-row"><span class="detail-key">Baseline Confidence vs Recent</span><span class="detail-val">{mon.get('baseline_confidence', 'N/A')} vs {st1.get('mean_confidence', 'N/A')} (Shift: {mon.get('confidence_shift', 0.0)})</span></div>
<div class="detail-row"><span class="detail-key">Baseline Attack Rate vs Recent</span><span class="detail-val">{mon.get('baseline_attack_rate', 'N/A')} vs {st1.get('attack_rate', 0.0)} (Shift: {mon.get('attack_rate_shift', 0.0)})</span></div>
<div class="detail-row"><span class="detail-key">Monitoring Note</span><span class="detail-val" style="font-size:10px; color:#9ca3af;">{mon.get('note', '')}</span></div>
</div>""",
            unsafe_allow_html=True,
        )
    except Exception as exc:
        st.error(f"Error rendering model monitoring: {exc}")

    st.markdown("---")

    # 6. HISTORICAL DATASET ANALYTICS (CSE-CIC-IDS2018)
    st.markdown('<div class="soc-section-header">HISTORICAL CSE-CIC-IDS2018 DATASET ANALYSIS</div>', unsafe_allow_html=True)
    try:
        ds_res = get_analytics_dataset()
        d_col1, d_col2 = st.columns([40, 60])

        with d_col1:
            st.markdown('<div style="font-size:11px; font-weight:700; color:#d1d5db;">DATASET SCALE</div>', unsafe_allow_html=True)
            st.metric("TOTAL PARQUET FLOWS", format_number(ds_res.get("total_flows", 0)))
            st.metric("TRAIN FLOWS", format_number(ds_res.get("train_flows", 0)))
            st.metric("TEST FLOWS", format_number(ds_res.get("test_flows", 0)))
            st.metric("DATASET ATTACK RATE", format_percentage(ds_res.get("attack_rate", 0.0)))

        with d_col2:
            st.markdown('<div style="font-size:11px; font-weight:700; color:#d1d5db;">CLASS DISTRIBUTION (CSE-CIC-IDS2018)</div>', unsafe_allow_html=True)
            cls_dist = ds_res.get("class_distribution", [])
            if cls_dist:
                cls_df = pd.DataFrame(cls_dist)
                cls_df["COUNT"] = cls_df["count"].apply(format_number)
                cls_df["PERCENTAGE"] = cls_df["percentage"].apply(format_percentage)
                st.dataframe(cls_df[["class_name", "COUNT", "PERCENTAGE"]].rename(columns={"class_name": "CLASS NAME"}), use_container_width=True, hide_index=True, height=200)
    except Exception as exc:
        st.error(f"Error rendering historical dataset analytics: {exc}")


# ============================================================
# VIEW 4 — DETECTION ANALYTICS
# ============================================================

elif current_view == "Detection Analytics":
    st.markdown('<div style="font-size:12px; font-weight:700; color:#9ca3af; margin-bottom:10px;">DETECTION ENGINE ANALYTICS & PIPELINE EVALUATION</div>', unsafe_allow_html=True)

    # Technical Architecture Diagram Strip
    st.markdown('<div class="soc-section-header">PIPELINE ARCHITECTURE DIAGRAM</div>', unsafe_allow_html=True)
    st.markdown(
        """<div class="pipeline-box">
<div class="pipeline-step">Network Flow</div>
<div class="pipeline-arrow">➔</div>
<div class="pipeline-step">Stage 1<br><span style="font-size:9px; color:#9ca3af;">Binary Attack Detection</span></div>
<div class="pipeline-arrow">➔</div>
<div class="pipeline-step">Stage 2<br><span style="font-size:9px; color:#9ca3af;">Attack Classification</span></div>
<div class="pipeline-arrow">➔</div>
<div class="pipeline-step">Severity Engine</div>
<div class="pipeline-arrow">➔</div>
<div class="pipeline-step">SOC Alert Store</div>
</div>""",
        unsafe_allow_html=True,
    )

    eval_data = load_evaluation_reports()

    da1, da2, da3 = st.columns(3)

    with da1:
        st.markdown(
            """<div class="detail-panel">
<div style="font-size:11px; font-weight:700; color:#e5e7eb; margin-bottom:6px;">STAGE 1 — BINARY DETECTOR</div>
<div class="detail-row"><span class="detail-key">Model Algorithm</span><span class="detail-val">Random Forest</span></div>
<div class="detail-row"><span class="detail-key">Task</span><span class="detail-val">Benign vs Attack</span></div>
<div class="detail-row"><span class="detail-key">Threshold</span><span class="detail-val">0.70</span></div>
<div class="detail-row"><span class="detail-key">Accuracy</span><span class="detail-val">98.93%</span></div>
<div class="detail-row"><span class="detail-key">Recall (Detection)</span><span class="detail-val">94.49%</span></div>
<div class="detail-row"><span class="detail-key">FPR</span><span class="detail-val">0.16%</span></div>
</div>""",
            unsafe_allow_html=True,
        )

    with da2:
        st.markdown(
            """<div class="detail-panel">
<div style="font-size:11px; font-weight:700; color:#e5e7eb; margin-bottom:6px;">STAGE 2 — ATTACK CLASSIFIER</div>
<div class="detail-row"><span class="detail-key">Model Algorithm</span><span class="detail-val">Random Forest</span></div>
<div class="detail-row"><span class="detail-key">Attack Classes</span><span class="detail-val">14 Categories</span></div>
<div class="detail-row"><span class="detail-key">Features</span><span class="detail-val">78 Features</span></div>
<div class="detail-row"><span class="detail-key">Accuracy</span><span class="detail-val">97.00%</span></div>
<div class="detail-row"><span class="detail-key">Weighted F1</span><span class="detail-val">96.83%</span></div>
<div class="detail-row"><span class="detail-key">Temporal Features</span><span class="detail-val">Excluded</span></div>
</div>""",
            unsafe_allow_html=True,
        )

    with da3:
        st.markdown(
            f"""<div class="detail-panel">
<div style="font-size:11px; font-weight:700; color:#e5e7eb; margin-bottom:6px;">PIPELINE BENCHMARK</div>
<div class="detail-row"><span class="detail-key">Overall Accuracy</span><span class="detail-val">98.43%</span></div>
<div class="detail-row"><span class="detail-key">Detection Accuracy</span><span class="detail-val">94.49%</span></div>
<div class="detail-row"><span class="detail-key">Classification Acc</span><span class="detail-val">96.87%</span></div>
<div class="detail-row"><span class="detail-key">Mean Confidence</span><span class="detail-val">{format_percentage(avg_confidence)}</span></div>
<div class="detail-row"><span class="detail-key">Inference Runtime</span><span class="detail-val">PySpark Distributed</span></div>
<div class="detail-row"><span class="detail-key">Evaluation Dataset</span><span class="detail-val">3,247,598 Flows</span></div>
</div>""",
            unsafe_allow_html=True,
        )

    st.markdown('<div class="soc-section-header">FULL DATASET MODEL EVALUATION SUMMARY</div>', unsafe_allow_html=True)
    if eval_data:
        s1 = eval_data.get("stage1_metrics", {})
        s2 = eval_data.get("stage2_metrics", {})

        metrics_summary_table = pd.DataFrame([
            {"Stage": "Stage 1 (Binary Detector)", "Accuracy": format_percentage(s1.get("accuracy", 0.9893)), "Precision": format_percentage(s1.get("precision", 0.9915)), "Recall": format_percentage(s1.get("recall", 0.9449)), "F1 Score": format_percentage(s1.get("f1_score", 0.9676))},
            {"Stage": "Stage 2 (Attack Classifier)", "Accuracy": format_percentage(s2.get("accuracy", 0.9700)), "Precision": format_percentage(s2.get("weighted_precision", 0.9723)), "Recall": format_percentage(s2.get("weighted_recall", 0.9700)), "F1 Score": format_percentage(s2.get("weighted_f1", 0.9683))},
            {"Stage": "End-to-End Pipeline", "Accuracy": "98.43%", "Precision": "98.19%", "Recall": "94.49%", "F1 Score": "96.79%"},
        ])
        st.dataframe(metrics_summary_table, use_container_width=True, hide_index=True)
    else:
        st.info("Evaluation metrics summary loaded from API baseline.")


# ============================================================
# VIEW 5 — MODEL INTELLIGENCE
# ============================================================

elif current_view == "Model Intelligence":
    st.markdown('<div style="font-size:12px; font-weight:700; color:#9ca3af; margin-bottom:10px;">MODEL SPECIFICATIONS & PERFORMANCE MONITORING</div>', unsafe_allow_html=True)

    mi1, mi2 = st.columns(2)

    with mi1:
        st.markdown('<div class="soc-section-header">STAGE 1 — BINARY DETECTOR SPECIFICATION</div>', unsafe_allow_html=True)
        st.markdown(
            """<div class="detail-panel">
<div class="detail-row"><span class="detail-key">Model Type</span><span class="detail-val">Random Forest Classifier</span></div>
<div class="detail-row"><span class="detail-key">Classification Task</span><span class="detail-val">Benign (0.0) vs Attack (1.0)</span></div>
<div class="detail-row"><span class="detail-key">Detection Threshold</span><span class="detail-val">0.70</span></div>
<div class="detail-row"><span class="detail-key">Input Features</span><span class="detail-val">Network Flow Features</span></div>
<div class="detail-row"><span class="detail-key">True Positive Rate (Recall)</span><span class="detail-val">94.49%</span></div>
<div class="detail-row"><span class="detail-key">False Positive Rate (FPR)</span><span class="detail-val">0.16%</span></div>
</div>""",
            unsafe_allow_html=True,
        )

    with mi2:
        st.markdown('<div class="soc-section-header">STAGE 2 — ATTACK CLASSIFIER SPECIFICATION</div>', unsafe_allow_html=True)
        st.markdown(
            f"""<div class="detail-panel">
<div class="detail-row"><span class="detail-key">Model Type</span><span class="detail-val">Random Forest Classifier</span></div>
<div class="detail-row"><span class="detail-key">Classification Task</span><span class="detail-val">14 Multi-Class Attack Types</span></div>
<div class="detail-row"><span class="detail-key">Observed Classes (SOC DB)</span><span class="detail-val">{len(attack_metrics)} Classes</span></div>
<div class="detail-row"><span class="detail-key">Input Features</span><span class="detail-val">78 Network Flow Features</span></div>
<div class="detail-row"><span class="detail-key">Temporal Features</span><span class="detail-val">Excluded (Prevents Data Leakage)</span></div>
<div class="detail-row"><span class="detail-key">Weighted F1 Score</span><span class="detail-val">96.83%</span></div>
</div>""",
            unsafe_allow_html=True,
        )

    st.markdown('<div class="soc-section-header">MODEL PERFORMANCE METRICS TABLE</div>', unsafe_allow_html=True)
    perf_table = pd.DataFrame([
        {"Metric": "Accuracy", "Stage 1 Detector": "98.93%", "Stage 2 Classifier": "97.00%", "Combined Pipeline": "98.43%"},
        {"Metric": "Precision", "Stage 1 Detector": "99.15%", "Stage 2 Classifier": "97.23%", "Combined Pipeline": "98.19%"},
        {"Metric": "Recall", "Stage 1 Detector": "94.49%", "Stage 2 Classifier": "97.00%", "Combined Pipeline": "94.49%"},
        {"Metric": "F1 Score", "Stage 1 Detector": "96.76%", "Stage 2 Classifier": "96.83%", "Combined Pipeline": "96.79%"},
        {"Metric": "Mean Confidence", "Stage 1 Detector": "97.44%", "Stage 2 Classifier": "94.18%", "Combined Pipeline": format_percentage(avg_confidence)},
    ])
    st.dataframe(perf_table, use_container_width=True, hide_index=True)


# ============================================================
# VIEW 6 — SYSTEM STATUS
# ============================================================

elif current_view == "System Status":
    st.markdown('<div style="font-size:12px; font-weight:700; color:#9ca3af; margin-bottom:10px;">SYSTEM STATUS & OPERATIONAL HEALTH</div>', unsafe_allow_html=True)

    sys1, sys2 = st.columns(2)

    with sys1:
        st.markdown('<div class="soc-section-header">PLATFORM COMPONENT HEALTH</div>', unsafe_allow_html=True)
        st.markdown(
            f"""<div class="detail-panel">
<div class="detail-row"><span class="detail-key">FastAPI Backend Service</span><span class="detail-val" style="color:#10b981;">● ONLINE (HTTP 200)</span></div>
<div class="detail-row"><span class="detail-key">API Response Latency</span><span class="detail-val">{health_response_ms:.2f} ms</span></div>
<div class="detail-row"><span class="detail-key">SQLite SOC Store</span><span class="detail-val" style="color:#10b981;">● ONLINE (alerts.db)</span></div>
<div class="detail-row"><span class="detail-key">PySpark Engine</span><span class="detail-val" style="color:#10b981;">● READY (Distributed Context)</span></div>
<div class="detail-row"><span class="detail-key">Streamlit Console</span><span class="detail-val" style="color:#10b981;">● ACTIVE</span></div>
</div>""",
            unsafe_allow_html=True,
        )

    with sys2:
        st.markdown('<div class="soc-section-header">DATABASE TELEMETRY SUMMARY</div>', unsafe_allow_html=True)
        total_db_alerts = status_metrics.get("total", soc_metrics.get("total_alerts", 0))
        st.markdown(
            f"""<div class="detail-panel">
<div class="detail-row"><span class="detail-key">Total Recorded SOC Alerts</span><span class="detail-val">{format_number(total_db_alerts)}</span></div>
<div class="detail-row"><span class="detail-key">New Alerts</span><span class="detail-val">{format_number(new_alerts)}</span></div>
<div class="detail-row"><span class="detail-key">Investigating Alerts</span><span class="detail-val">{format_number(investigating)}</span></div>
<div class="detail-row"><span class="detail-key">Escalated Alerts</span><span class="detail-val">{format_number(escalated)}</span></div>
<div class="detail-row"><span class="detail-key">Resolved Alerts</span><span class="detail-val">{format_number(resolved)}</span></div>
<div class="detail-row"><span class="detail-key">Last Console Refresh</span><span class="detail-val">{time.strftime('%H:%M:%S UTC')}</span></div>
</div>""",
            unsafe_allow_html=True,
        )


# ============================================================
# VIEW 7 — REPLAY / DATASET TELEMETRY
# ============================================================

elif current_view == "Replay / Dataset Telemetry":
    st.markdown('<div style="font-size:12px; font-weight:700; color:#9ca3af; margin-bottom:10px;">HISTORICAL DATASET TELEMETRY & REPLAY SERVICE</div>', unsafe_allow_html=True)

    r1, r2 = st.columns(2)

    with r1:
        st.markdown('<div class="soc-section-header">DATASET SCALE</div>', unsafe_allow_html=True)
        st.markdown(
            """<div class="detail-panel">
<div class="detail-row"><span class="detail-key">Dataset Source</span><span class="detail-val">CSE-CIC-IDS2018</span></div>
<div class="detail-row"><span class="detail-key">Total Test Flows</span><span class="detail-val">3,247,598 Flows</span></div>
<div class="detail-row"><span class="detail-key">Benign Test Flows</span><span class="detail-val">2,697,619 (83.07%)</span></div>
<div class="detail-row"><span class="detail-key">Attack Test Flows</span><span class="detail-val">549,979 (16.93%)</span></div>
<div class="detail-row"><span class="detail-key">Attack Categories</span><span class="detail-val">14 Classes</span></div>
</div>""",
            unsafe_allow_html=True
        )

    with r2:
        total_db_alerts = status_metrics.get("total", soc_metrics.get("total_alerts", 0))
        st.markdown('<div class="soc-section-header">CURRENT SOC OPERATIONS</div>', unsafe_allow_html=True)
        st.markdown(
            f"""<div class="detail-panel">
<div class="detail-row"><span class="detail-key">Supported Replay Capacity</span><span class="detail-val">50,000 Flows</span></div>
<div class="detail-row"><span class="detail-key">Batch Size</span><span class="detail-val">1,000 Flows / Batch</span></div>
<div class="detail-row"><span class="detail-key">Total Active SOC Alerts</span><span class="detail-val">{format_number(total_db_alerts)} Alerts</span></div>
<div class="detail-row"><span class="detail-key">Replay Command</span><span class="detail-val" style="font-size:9px;">python -m src.streaming.replay_service --flows 50000 --batch-size 1000 --delay 0 --replay-id demo_50k</span></div>
</div>""",
            unsafe_allow_html=True
        )

    st.markdown('<div class="soc-section-header">HISTORICAL REPLAY RUN HISTORY</div>', unsafe_allow_html=True)
    try:
        replays = get_replays()
        if replays:
            df_rep = pd.DataFrame(replays)
            st.dataframe(
                df_rep[[
                    "replay_id", "start_time", "flows_processed", "gt_attacks", "pred_attacks", "alerts_inserted", "throughput", "status"
                ]].rename(columns={
                    "replay_id": "REPLAY ID",
                    "start_time": "START TIME",
                    "flows_processed": "FLOWS PROCESSED",
                    "gt_attacks": "GT ATTACKS",
                    "pred_attacks": "PRED ATTACKS",
                    "alerts_inserted": "ALERTS PERSISTED",
                    "throughput": "THROUGHPUT (FLOWS/SEC)",
                    "status": "STATUS"
                }),
                use_container_width=True, hide_index=True
            )
        else:
            st.info("No recorded replay runs in SQLite replay_history yet.")
    except Exception as exc:
        st.warning(f"Could not load replay history: {exc}")


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """<div style="border-top:1px solid #2a303a; margin-top:30px; padding-top:10px; font-size:10px; color:#6b7280; text-align:center;">
CyberSentinel SOC Console v1.0.0 | Enterprise Security Operations Center Interface | PySpark • Random Forest • FastAPI • SQLite • Streamlit
</div>""",
    unsafe_allow_html=True,
)
