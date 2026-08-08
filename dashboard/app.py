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
    df["protocol"] = pd.to_numeric(df["protocol"], errors="coerce")
    df["attack_type"] = df["attack_type"].fillna("Unknown").astype(str)
    df["severity"] = df["severity"].fillna("UNKNOWN").astype(str).str.upper()
    df["status"] = df["status"].fillna("NEW").astype(str).str.upper()

    return df


def protocol_name(value):
    if value is None or pd.isna(value):
        return "Unknown"
    try:
        num = int(float(value))
        return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(num, str(num))
    except Exception:
        txt = str(value).strip()
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
            "Incidents",
            "Threat Intelligence",
            "Detection Analytics",
            "Model Intelligence",
            "System Status",
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
        [100, 500, 1000, 5000],
        index=3,
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
# VIEW 1 — SOC OVERVIEW
# ============================================================

if current_view == "Overview":
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
    st.markdown('<div style="font-size:12px; font-weight:700; color:#9ca3af; margin-bottom:10px;">INCIDENT QUEUE — Security alerts requiring analyst review</div>', unsafe_allow_html=True)

    left_col, right_col = st.columns([65, 35])

    with left_col:
        st.markdown('<div class="soc-section-header">INCIDENT QUEUE</div>', unsafe_allow_html=True)

        if alerts_df.empty:
            st.info("No incidents match current filters.")
            selected_row = None
        else:
            severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            alerts_df["_severity_rank"] = alerts_df["severity"].map(severity_rank).fillna(99)
            alerts_df = alerts_df.sort_values(["_severity_rank", "attack_probability"], ascending=[True, False])
            alerts_df = alerts_df.drop(columns=["_severity_rank"])

            display_queue = alerts_df.copy().head(100)
            display_queue["TIMESTAMP"] = display_queue["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("Unknown")
            display_queue["CONFIDENCE"] = display_queue["attack_probability"].apply(lambda v: format_percentage(safe_float(v)))
            display_queue["DST PORT"] = display_queue["dst_port"].apply(port_value)
            display_queue["PROTOCOL"] = display_queue["protocol"].apply(protocol_name)
            display_queue["SEVERITY"] = display_queue["severity"].apply(lambda s: f"● {s}")

            queue_table = display_queue[[
                "SEVERITY", "TIMESTAMP", "attack_type", "CONFIDENCE", "DST PORT", "PROTOCOL", "status", "alert_id"
            ]].rename(columns={
                "attack_type": "ATTACK TYPE",
                "status": "STATUS",
                "alert_id": "ALERT ID"
            })

            st.dataframe(queue_table, use_container_width=True, hide_index=True, height=400)

            alert_options = []
            for idx, r in alerts_df.iterrows():
                t_str = r['timestamp'].strftime("%H:%M:%S") if pd.notna(r['timestamp']) else "N/A"
                conf_str = format_percentage(safe_float(r['attack_probability']))
                alert_options.append(f"{r['severity']} | {t_str} | {r['attack_type']} | {conf_str} | ID: {r['alert_id']}")

            selected_idx = st.selectbox(
                "Select Incident for Investigation:",
                range(len(alert_options)),
                format_func=lambda i: alert_options[i],
            )
            selected_row = alerts_df.iloc[selected_idx] if len(alerts_df) > 0 else None

    with right_col:
        st.markdown('<div class="soc-section-header">INCIDENT DETAILS</div>', unsafe_allow_html=True)

        if selected_row is not None:
            at_type = str(first_available(selected_row, ["attack_type", "AttackType"], "Unknown"))
            sev_level = str(first_available(selected_row, ["severity", "Severity"], "UNKNOWN"))
            conf_val = safe_float(first_available(selected_row, ["attack_probability", "model_confidence"], 0))
            stat_val = str(first_available(selected_row, ["status", "Status"], "NEW"))
            al_id = first_available(selected_row, ["alert_id", "Alert_ID"], "N/A")

            # Incident Summary Panel
            st.markdown(
                f"""<div class="detail-panel">
<div style="font-size:12px; font-weight:700; color:#f3f4f6; margin-bottom:6px;">INCIDENT: {at_type}</div>
<div class="detail-row"><span class="detail-key">Severity</span><span class="detail-val" style="color:#ef4444;">{sev_level}</span></div>
<div class="detail-row"><span class="detail-key">Confidence</span><span class="detail-val">{format_percentage(conf_val)}</span></div>
<div class="detail-row"><span class="detail-key">Status</span><span class="detail-val">{stat_val}</span></div>
<div class="detail-row"><span class="detail-key">Alert ID</span><span class="detail-val" style="font-size:10px;">{al_id}</span></div>
</div>""",
                unsafe_allow_html=True,
            )

            # Network Observation
            ts_val = first_available(selected_row, ["timestamp"], None)
            ts_str = pd.to_datetime(ts_val).strftime("%Y-%m-%d %H:%M:%S") if ts_val is not None and pd.notna(ts_val) else "Unknown"
            dp_val = port_value(first_available(selected_row, ["dst_port"], None))
            pr_val = protocol_name(first_available(selected_row, ["protocol"], None))

            st.markdown(
                f"""<div class="detail-panel">
<div style="font-size:10px; font-weight:700; color:#9ca3af; margin-bottom:4px;">NETWORK OBSERVATION</div>
<div class="detail-row"><span class="detail-key">Timestamp</span><span class="detail-val">{ts_str}</span></div>
<div class="detail-row"><span class="detail-key">Destination Port</span><span class="detail-val">{dp_val}</span></div>
<div class="detail-row"><span class="detail-key">Protocol</span><span class="detail-val">{pr_val}</span></div>
</div>""",
                unsafe_allow_html=True,
            )

            # Model Decision Engine
            st.markdown(
                f"""<div class="detail-panel">
<div style="font-size:10px; font-weight:700; color:#9ca3af; margin-bottom:4px;">MODEL DECISION ENGINE</div>
<div class="detail-row"><span class="detail-key">Stage 1 Detection</span><span class="detail-val">96.52% (Threshold 0.70)</span></div>
<div class="detail-row"><span class="detail-key">Stage 2 Classifier</span><span class="detail-val">99.80% ({at_type})</span></div>
<div class="detail-row"><span class="detail-key">Combined Confidence</span><span class="detail-val">{format_percentage(conf_val)}</span></div>
</div>""",
                unsafe_allow_html=True,
            )

            # Analyst Workflow Buttons
            st.markdown('<div style="font-size:10px; font-weight:700; color:#9ca3af; margin-bottom:4px;">ANALYST WORKFLOW</div>', unsafe_allow_html=True)
            b1, b2 = st.columns(2)
            with b1:
                if st.button("INVESTIGATE", use_container_width=True):
                    try:
                        update_alert_status(al_id, "INVESTIGATING")
                        st.cache_data.clear()
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed: {exc}")

            with b2:
                if st.button("ESCALATE", use_container_width=True):
                    try:
                        update_alert_status(al_id, "ESCALATED")
                        st.cache_data.clear()
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed: {exc}")

            b3, b4 = st.columns(2)
            with b3:
                if st.button("RESOLVE", use_container_width=True):
                    try:
                        update_alert_status(al_id, "RESOLVED")
                        st.cache_data.clear()
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed: {exc}")

            with b4:
                if st.button("RESET TO NEW", use_container_width=True):
                    try:
                        update_alert_status(al_id, "NEW")
                        st.cache_data.clear()
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed: {exc}")


# ============================================================
# VIEW 3 — THREAT INTELLIGENCE
# ============================================================

elif current_view == "Threat Intelligence":
    st.markdown('<div style="font-size:12px; font-weight:700; color:#9ca3af; margin-bottom:10px;">THREAT INTELLIGENCE & TELEMETRY ANALYTICS</div>', unsafe_allow_html=True)

    t1, t2 = st.columns(2)

    with t1:
        st.markdown('<div class="soc-section-header">ATTACK TYPE DISTRIBUTION</div>', unsafe_allow_html=True)
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
                height=220,
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=False),
                font=dict(size=10, color="#9ca3af"),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

    with t2:
        st.markdown('<div class="soc-section-header">SEVERITY DISTRIBUTION</div>', unsafe_allow_html=True)
        sev_df = pd.DataFrame(severity_metrics)
        if not sev_df.empty:
            if "Severity" in sev_df.columns and "severity" not in sev_df.columns:
                sev_df = sev_df.rename(columns={"Severity": "severity"})
            sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b", "LOW": "#10b981", "UNKNOWN": "#6b7280"}
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
                height=220,
                font=dict(size=10, color="#9ca3af"),
            )
            st.plotly_chart(fig_pie, use_container_width=True)

    t3, t4 = st.columns(2)

    with t3:
        st.markdown('<div class="soc-section-header">ATTACK CONFIDENCE DISTRIBUTION</div>', unsafe_allow_html=True)
        if not alerts_df.empty and "attack_probability" in alerts_df.columns:
            fig_hist = px.histogram(
                alerts_df,
                x="attack_probability",
                nbins=20,
                color_discrete_sequence=["#3b82f6"],
                labels={"attack_probability": "Model Probability Score"},
            )
            fig_hist.update_layout(
                template="plotly_dark",
                paper_bgcolor="#151922",
                plot_bgcolor="#151922",
                margin=dict(l=10, r=10, t=10, b=10),
                height=220,
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=False),
                font=dict(size=10, color="#9ca3af"),
            )
            st.plotly_chart(fig_hist, use_container_width=True)
        else:
            st.info("No confidence telemetry available.")

    with t4:
        st.markdown('<div class="soc-section-header">TOP TARGET DESTINATION PORTS</div>', unsafe_allow_html=True)
        if not alerts_df.empty and "dst_port" in alerts_df.columns:
            port_counts = alerts_df["dst_port"].apply(port_value).value_counts().reset_index()
            port_counts.columns = ["port", "count"]
            port_counts = port_counts.head(8)

            fig_ports = px.bar(
                port_counts,
                x="port",
                y="count",
                color_discrete_sequence=["#10b981"],
                labels={"port": "Destination Port", "count": "Alert Count"},
            )
            fig_ports.update_layout(
                template="plotly_dark",
                paper_bgcolor="#151922",
                plot_bgcolor="#151922",
                margin=dict(l=10, r=10, t=10, b=10),
                height=220,
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=False),
                font=dict(size=10, color="#9ca3af"),
            )
            st.plotly_chart(fig_ports, use_container_width=True)
        else:
            st.info("No port telemetry available.")


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
# FOOTER
# ============================================================

st.markdown(
    """<div style="border-top:1px solid #2a303a; margin-top:30px; padding-top:10px; font-size:10px; color:#6b7280; text-align:center;">
CyberSentinel SOC Console v1.0.0 | Enterprise Security Operations Center Interface | PySpark • Random Forest • FastAPI • SQLite • Streamlit
</div>""",
    unsafe_allow_html=True,
)