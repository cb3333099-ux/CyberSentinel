import sys
from pathlib import Path

# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# IMPORTS
# ============================================================

import pandas as pd
import plotly.express as px
import streamlit as st

from src.api.client import (
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
    page_title="CyberSentinel SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# GLOBAL CSS
# ============================================================

st.markdown(
    """
<style>

.stApp {
    background-color: #0b0f14;
    color: #e6edf3;
}

[data-testid="stSidebar"] {
    background-color: #080c11;
    border-right: 1px solid #202833;
}

[data-testid="stSidebar"] * {
    color: #d7e0e8;
}

/* ------------------------------------------------------------
   Header
   ------------------------------------------------------------ */

.soc-header {
    background: linear-gradient(
        135deg,
        #111827 0%,
        #0f172a 55%,
        #0b1220 100%
    );

    border: 1px solid #263241;
    border-radius: 12px;

    padding: 22px 26px;

    margin-bottom: 22px;
}

.soc-title {
    color: #f8fafc;
    font-size: 30px;
    font-weight: 800;
    line-height: 1.2;
}

.soc-subtitle {
    color: #94a3b8;
    font-size: 14px;
    margin-top: 6px;
}

.live-status {
    color: #4ade80;
    font-size: 12px;
    font-weight: 700;
    margin-top: 10px;
}

/* ------------------------------------------------------------
   Section headings
   ------------------------------------------------------------ */

.section-heading {
    color: #f1f5f9;
    font-size: 20px;
    font-weight: 700;

    margin-top: 25px;
    margin-bottom: 13px;
}

/* ------------------------------------------------------------
   Native Streamlit metrics
   ------------------------------------------------------------ */

[data-testid="stMetric"] {
    background-color: #111827;

    border: 1px solid #263241;
    border-radius: 10px;

    padding: 15px 16px;

    min-height: 92px;
}

[data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
    font-size: 11px !important;
}

[data-testid="stMetricValue"] {
    color: #f8fafc !important;
    font-size: 25px !important;
    font-weight: 750 !important;
}

[data-testid="stMetricDelta"] {
    display: none !important;
}

/* ------------------------------------------------------------
   Captions under metrics
   ------------------------------------------------------------ */

.metric-caption {
    color: #64748b;
    font-size: 11px;
    margin-top: -8px;
    margin-bottom: 4px;
}

/* ------------------------------------------------------------
   Tables
   ------------------------------------------------------------ */

[data-testid="stDataFrame"] {
    border: 1px solid #263241;
    border-radius: 8px;
}

/* ------------------------------------------------------------
   Buttons
   ------------------------------------------------------------ */

.stButton > button {
    border: 1px solid #364152;
    background-color: #111827;
    color: #e2e8f0;
    border-radius: 7px;
}

.stButton > button:hover {
    border-color: #64748b;
    color: #ffffff;
}

/* ------------------------------------------------------------
   Footer
   ------------------------------------------------------------ */

.footer {
    border-top: 1px solid #263241;

    margin-top: 35px;
    padding-top: 16px;

    color: #64748b;

    text-align: center;

    font-size: 11px;
}

</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# HELPERS
# ============================================================

def safe_float(value, default=0.0):
    try:

        if value is None:
            return default

        if pd.isna(value):
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
    """
    Handles both:
        0.9613 -> 96.13%
        96.13  -> 96.13%
    """

    try:

        value = float(value)

        if value > 1:
            return f"{value:.2f}%"

        return f"{value * 100:.2f}%"

    except Exception:

        return "0.00%"


def first_available(row, names, default=None):
    """
    Return the first available/non-null field
    from a list of possible API/database field names.
    """

    for name in names:

        if name not in row.index:
            continue

        value = row[name]

        if value is None:
            continue

        try:

            if pd.isna(value):
                continue

        except Exception:
            pass

        return value

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

    # --------------------------------------------------------
    # Normalize possible API field names
    # --------------------------------------------------------

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

        if (
            old_name in df.columns
            and new_name not in df.columns
        ):

            df = df.rename(
                columns={
                    old_name: new_name
                }
            )

    # --------------------------------------------------------
    # Ensure expected columns exist
    # --------------------------------------------------------

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

    for column, default in defaults.items():

        if column not in df.columns:
            df[column] = default

    # --------------------------------------------------------
    # Use model_confidence if attack_probability is absent
    # --------------------------------------------------------

    df["attack_probability"] = pd.to_numeric(
        df["attack_probability"],
        errors="coerce",
    )

    df["model_confidence"] = pd.to_numeric(
        df["model_confidence"],
        errors="coerce",
    )

    df["attack_probability"] = (
        df["attack_probability"]
        .fillna(df["model_confidence"])
    )

    # --------------------------------------------------------
    # Data types
    # --------------------------------------------------------

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
    )

    df["dst_port"] = pd.to_numeric(
        df["dst_port"],
        errors="coerce",
    )

    df["protocol"] = pd.to_numeric(
        df["protocol"],
        errors="coerce",
    )

    df["attack_type"] = (
        df["attack_type"]
        .fillna("Unknown")
        .astype(str)
    )

    df["severity"] = (
        df["severity"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
    )

    df["status"] = (
        df["status"]
        .fillna("NEW")
        .astype(str)
        .str.upper()
    )

    return df


def protocol_name(value):

    if value is None:
        return "Unknown"

    try:

        if pd.isna(value):
            return "Unknown"

    except Exception:
        pass

    try:

        number = int(float(value))

        protocol_map = {
            6: "TCP",
            17: "UDP",
            1: "ICMP",
        }

        return protocol_map.get(
            number,
            str(number),
        )

    except Exception:

        text = str(value).strip()

        if not text:
            return "Unknown"

        return text


def port_value(value):

    if value is None:
        return "Unknown"

    try:

        if pd.isna(value):
            return "Unknown"

    except Exception:
        pass

    try:

        return str(int(float(value)))

    except Exception:

        text = str(value).strip()

        if not text:
            return "Unknown"

        return text


# ============================================================
# API HEALTH
# ============================================================

try:

    health = get_health()

    api_online = (
        health.get("status")
        == "healthy"
    )

except Exception as exc:

    st.error(
        f"CyberSentinel API is unavailable: {exc}"
    )

    st.info(
        "Start the API in another terminal:"
    )

    st.code(
        "uvicorn src.api.main:app "
        "--host 0.0.0.0 --port 8000"
    )

    st.stop()


# ============================================================
# HEADER
# ============================================================

# Keep the HTML compact so Streamlit does not interpret
# individual blocks as Markdown code.

st.markdown(
    """
<div class="soc-header"><div class="soc-title">🛡️ CyberSentinel</div><div class="soc-subtitle">AI-Powered Network Threat Intelligence &amp; Detection</div><div class="live-status">● SOC API ONLINE &nbsp;|&nbsp; Two-Stage ML Detection Pipeline</div></div>
""",
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title(
        "🛡️ CyberSentinel"
    )

    st.caption(
        "Security Operations Center"
    )

    st.divider()

    st.subheader(
        "Alert Filters"
    )

    status_filter = st.selectbox(
        "Status",
        [
            "ALL",
            "NEW",
            "INVESTIGATING",
            "ESCALATED",
            "RESOLVED",
        ],
    )

    severity_filter = st.selectbox(
        "Severity",
        [
            "ALL",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
        ],
    )

    attack_filter = st.selectbox(
        "Attack Type",
        [
            "ALL",
            "Brute Force -Web",
            "Brute Force -XSS",
            "SQL Injection",
        ],
    )

    st.divider()

    st.subheader(
        "System"
    )

    st.caption(
        "Detection threshold: 0.70"
    )

    st.caption(
        "Stage 1: Attack Detection"
    )

    st.caption(
        "Stage 2: Attack Classification"
    )

    st.caption(
        "Backend: FastAPI + SQLite"
    )

    st.caption(
        "Analytics: PySpark"
    )

    st.divider()

    if st.button(
        "🔄 Refresh Dashboard",
        use_container_width=True,
    ):

        st.cache_data.clear()

        st.rerun()


# ============================================================
# LOAD SOC METRICS
# ============================================================

try:

    soc_metrics = get_soc_metrics()

    status_metrics = get_status_metrics()

    attack_metrics = get_attack_metrics()

    severity_metrics = get_severity_metrics()

except Exception as exc:

    st.error(
        f"Failed to load SOC metrics: {exc}"
    )

    st.stop()


# ============================================================
# STATUS COUNTS
# ============================================================

status_counts = status_metrics.get(
    "by_status",
    {},
)

total_alerts = status_metrics.get(
    "total",
    soc_metrics.get(
        "total_alerts",
        0,
    ),
)

new_alerts = status_counts.get(
    "NEW",
    0,
)

investigating = status_counts.get(
    "INVESTIGATING",
    0,
)

escalated = status_counts.get(
    "ESCALATED",
    0,
)

resolved = status_counts.get(
    "RESOLVED",
    0,
)


# ============================================================
# SOC OVERVIEW
# ============================================================

st.markdown(
    '<div class="section-heading">SOC Overview</div>',
    unsafe_allow_html=True,
)

c1, c2, c3, c4, c5 = st.columns(5)


with c1:

    st.metric(
        "Active Alerts",
        format_number(
            total_alerts
        ),
    )

    st.markdown(
        '<div class="metric-caption">'
        'Total alerts in SOC'
        '</div>',
        unsafe_allow_html=True,
    )


with c2:

    st.metric(
        "Critical Alerts",
        format_number(
            soc_metrics.get(
                "critical_alerts",
                0,
            )
        ),
    )

    st.markdown(
        '<div class="metric-caption">'
        'Immediate attention required'
        '</div>',
        unsafe_allow_html=True,
    )


with c3:

    st.metric(
        "Investigating",
        format_number(
            investigating
        ),
    )

    st.markdown(
        '<div class="metric-caption">'
        'Analyst investigation'
        '</div>',
        unsafe_allow_html=True,
    )


with c4:

    st.metric(
        "Escalated",
        format_number(
            escalated
        ),
    )

    st.markdown(
        '<div class="metric-caption">'
        'Requires escalation'
        '</div>',
        unsafe_allow_html=True,
    )


with c5:

    st.metric(
        "Average Confidence",
        format_percentage(
            soc_metrics.get(
                "average_confidence",
                0,
            )
        ),
    )

    st.markdown(
        '<div class="metric-caption">'
        'Model confidence'
        '</div>',
        unsafe_allow_html=True,
    )


# ============================================================
# ALERT WORKFLOW
# ============================================================

st.markdown(
    '<div class="section-heading">Alert Workflow</div>',
    unsafe_allow_html=True,
)

w1, w2, w3, w4 = st.columns(4)


with w1:

    st.metric(
        "🆕 NEW",
        format_number(
            new_alerts
        ),
    )

    st.markdown(
        '<div class="metric-caption">'
        'Current alerts awaiting investigation'
        '</div>',
        unsafe_allow_html=True,
    )


with w2:

    st.metric(
        "🔎 INVESTIGATING",
        format_number(
            investigating
        ),
    )

    st.markdown(
        '<div class="metric-caption">'
        'Alerts under analyst investigation'
        '</div>',
        unsafe_allow_html=True,
    )


with w3:

    st.metric(
        "⚠️ ESCALATED",
        format_number(
            escalated
        ),
    )

    st.markdown(
        '<div class="metric-caption">'
        'Alerts requiring escalation'
        '</div>',
        unsafe_allow_html=True,
    )


with w4:

    st.metric(
        "✅ RESOLVED",
        format_number(
            resolved
        ),
    )

    st.markdown(
        '<div class="metric-caption">'
        'Resolved security alerts'
        '</div>',
        unsafe_allow_html=True,
    )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

st.markdown(
    '<div class="section-heading">Threat Intelligence</div>',
    unsafe_allow_html=True,
)

left_chart, right_chart = st.columns(2)


# ============================================================
# ATTACK DISTRIBUTION
# ============================================================

with left_chart:

    attack_df = pd.DataFrame(
        attack_metrics
    )

    if not attack_df.empty:

        if (
            "attack_type"
            not in attack_df.columns
        ):

            for candidate in [
                "AttackType",
                "Attack_Type",
            ]:

                if candidate in attack_df.columns:

                    attack_df = attack_df.rename(
                        columns={
                            candidate:
                                "attack_type"
                        }
                    )

                    break

        fig = px.bar(
            attack_df,
            x="attack_type",
            y="count",
            title="Alerts by Attack Type",
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#11161d",
            plot_bgcolor="#11161d",
            margin=dict(
                l=30,
                r=20,
                t=55,
                b=30,
            ),
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    else:

        st.info(
            "No attack distribution data."
        )


# ============================================================
# SEVERITY DISTRIBUTION
# ============================================================

with right_chart:

    severity_df = pd.DataFrame(
        severity_metrics
    )

    if not severity_df.empty:

        if (
            "severity"
            not in severity_df.columns
        ):

            if "Severity" in severity_df.columns:

                severity_df = severity_df.rename(
                    columns={
                        "Severity":
                            "severity"
                    }
                )

        fig = px.pie(
            severity_df,
            names="severity",
            values="count",
            hole=0.55,
            title="Alerts by Severity",
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#11161d",
            plot_bgcolor="#11161d",
            margin=dict(
                l=20,
                r=20,
                t=55,
                b=20,
            ),
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    else:

        st.info(
            "No severity distribution data."
        )


# ============================================================
# FILTER PARAMETERS
# ============================================================

status_parameter = (
    None
    if status_filter == "ALL"
    else status_filter
)

severity_parameter = (
    None
    if severity_filter == "ALL"
    else severity_filter
)

attack_parameter = (
    None
    if attack_filter == "ALL"
    else attack_filter
)


# ============================================================
# LOAD ALERTS
# ============================================================

try:

    raw_alerts = get_alerts(
        status=status_parameter,
        severity=severity_parameter,
        attack_type=attack_parameter,
        limit=1000,
    )

    alerts_df = normalize_alerts(
        raw_alerts
    )

except Exception as exc:

    st.error(
        f"Failed to load alerts: {exc}"
    )

    alerts_df = pd.DataFrame()


# ============================================================
# ALERT INVESTIGATION
# ============================================================

st.markdown(
    '<div class="section-heading">Alert Investigation</div>',
    unsafe_allow_html=True,
)

st.caption(
    "Select an alert to investigate its threat "
    "characteristics and update its SOC workflow state."
)


if alerts_df.empty:

    st.info(
        "No alerts match the selected filters."
    )

else:

    # --------------------------------------------------------
    # Sort alerts
    # --------------------------------------------------------

    severity_rank = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "UNKNOWN": 4,
    }

    alerts_df["_severity_rank"] = (
        alerts_df["severity"]
        .map(severity_rank)
        .fillna(99)
    )

    alerts_df = alerts_df.sort_values(
        [
            "_severity_rank",
            "attack_probability",
        ],
        ascending=[
            True,
            False,
        ],
    )

    alerts_df = alerts_df.drop(
        columns=[
            "_severity_rank"
        ]
    )

    # --------------------------------------------------------
    # Alert selector
    # --------------------------------------------------------

    options = []

    option_indices = []

    for index, row in alerts_df.iterrows():

        timestamp = row.get(
            "timestamp"
        )

        if pd.notna(timestamp):

            timestamp_text = timestamp.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        else:

            timestamp_text = "Unknown"

        probability = safe_float(
            row.get(
                "attack_probability"
            )
        )

        options.append(
            f"{row.get('alert_id', index)}"
            f" — {timestamp_text}"
            f" — {row.get('attack_type', 'Unknown')}"
            f" — {row.get('severity', 'UNKNOWN')}"
            f" — {format_percentage(probability)}"
            f" — {row.get('status', 'NEW')}"
        )

        option_indices.append(
            index
        )

    selected_position = st.selectbox(
        "Select an alert",
        range(len(options)),
        format_func=lambda x:
            options[x],
    )

    selected_index = option_indices[
        selected_position
    ]

    selected = alerts_df.loc[
        selected_index
    ]


    # ========================================================
    # SELECTED THREAT
    # ========================================================

    st.markdown(
        "### Selected Threat"
    )

    d1, d2, d3, d4 = st.columns(4)


    attack_type = str(
        first_available(
            selected,
            [
                "attack_type",
                "AttackType",
                "Attack_Type",
            ],
            "Unknown",
        )
    )


    severity = str(
        first_available(
            selected,
            [
                "severity",
                "Severity",
            ],
            "UNKNOWN",
        )
    )


    confidence_value = first_available(
        selected,
        [
            "attack_probability",
            "model_confidence",
            "confidence",
            "probability",
        ],
        0,
    )

    confidence = safe_float(
        confidence_value
    )


    status = str(
        first_available(
            selected,
            [
                "status",
                "Status",
            ],
            "NEW",
        )
    )


    with d1:

        st.metric(
            "Attack Type",
            attack_type,
        )


    with d2:

        st.metric(
            "Severity",
            severity,
        )


    with d3:

        st.metric(
            "Model Confidence",
            format_percentage(
                confidence
            ),
        )


    with d4:

        st.metric(
            "Status",
            status,
        )


    # ========================================================
    # NETWORK DETAILS
    # ========================================================

    network_col, assessment_col = st.columns(2)


    with network_col:

        st.markdown(
            "#### Network Details"
        )

        timestamp = first_available(
            selected,
            [
                "timestamp",
                "Timestamp",
            ],
            None,
        )

        if timestamp is not None:

            try:

                timestamp = pd.to_datetime(
                    timestamp
                ).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

            except Exception:

                timestamp = str(
                    timestamp
                )

        else:

            timestamp = "Unknown"


        destination_port = first_available(
            selected,
            [
                "dst_port",
                "Dst_Port",
                "destination_port",
                "Destination_Port",
            ],
            None,
        )


        protocol = first_available(
            selected,
            [
                "protocol",
                "Protocol",
            ],
            None,
        )


        st.json(
            {
                "Timestamp":
                    timestamp,

                "Destination Port":
                    port_value(
                        destination_port
                    ),

                "Protocol":
                    protocol_name(
                        protocol
                    ),
            }
        )


    # ========================================================
    # THREAT ASSESSMENT
    # ========================================================

    with assessment_col:

        st.markdown(
            "#### Threat Assessment"
        )

        st.json(
            {
                "Attack Type":
                    attack_type,

                "Severity":
                    severity,

                "Model Confidence":
                    format_percentage(
                        confidence
                    ),

                "Current Status":
                    status,
            }
        )


    # ========================================================
    # SOC ACTIONS
    # ========================================================

    st.markdown(
        "### SOC Actions"
    )

    a1, a2, a3, a4 = st.columns(4)


    alert_id = first_available(
        selected,
        [
            "alert_id",
            "Alert_ID",
            "id",
        ],
        None,
    )


    with a1:

        if st.button(
            "🔎 Investigate",
            use_container_width=True,
        ):

            try:

                update_alert_status(
                    alert_id,
                    "INVESTIGATING",
                )

                st.success(
                    "Alert moved to INVESTIGATING."
                )

                st.cache_data.clear()

                st.rerun()

            except Exception as exc:

                st.error(
                    f"Investigation failed: {exc}"
                )


    with a2:

        if st.button(
            "⚠️ Escalate",
            use_container_width=True,
        ):

            try:

                update_alert_status(
                    alert_id,
                    "ESCALATED",
                )

                st.warning(
                    "Alert escalated."
                )

                st.cache_data.clear()

                st.rerun()

            except Exception as exc:

                st.error(
                    f"Escalation failed: {exc}"
                )


    with a3:

        if st.button(
            "✅ Resolve",
            use_container_width=True,
        ):

            try:

                update_alert_status(
                    alert_id,
                    "RESOLVED",
                )

                st.success(
                    "Alert resolved."
                )

                st.cache_data.clear()

                st.rerun()

            except Exception as exc:

                st.error(
                    f"Resolution failed: {exc}"
                )


    with a4:

        if st.button(
            "↩️ Reset to NEW",
            use_container_width=True,
        ):

            try:

                update_alert_status(
                    alert_id,
                    "NEW",
                )

                st.info(
                    "Alert reset to NEW."
                )

                st.cache_data.clear()

                st.rerun()

            except Exception as exc:

                st.error(
                    f"Reset failed: {exc}"
                )


# ============================================================
# SOC ALERT QUEUE
# ============================================================

st.markdown(
    '<div class="section-heading">SOC Alert Queue</div>',
    unsafe_allow_html=True,
)


if alerts_df.empty:

    st.info(
        "No alerts available."
    )

else:

    queue_df = alerts_df.copy()

    queue_df = queue_df.head(100)

    queue_columns = [
        "alert_id",
        "timestamp",
        "attack_type",
        "severity",
        "attack_probability",
        "dst_port",
        "protocol",
        "status",
    ]

    queue_columns = [
        column
        for column in queue_columns
        if column in queue_df.columns
    ]

    queue_df = queue_df[
        queue_columns
    ]

    queue_df = queue_df.rename(
        columns={
            "alert_id":
                "Alert ID",

            "timestamp":
                "Timestamp",

            "attack_type":
                "Attack Type",

            "severity":
                "Severity",

            "attack_probability":
                "Confidence",

            "dst_port":
                "Dst Port",

            "protocol":
                "Protocol",

            "status":
                "Status",
        }
    )


    if "Timestamp" in queue_df.columns:

        queue_df["Timestamp"] = (
            pd.to_datetime(
                queue_df["Timestamp"],
                errors="coerce",
            )
            .dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )


    if "Confidence" in queue_df.columns:

        queue_df["Confidence"] = (
            queue_df["Confidence"]
            .apply(
                lambda value:
                    format_percentage(
                        safe_float(
                            value
                        )
                    )
            )
        )


    if "Dst Port" in queue_df.columns:

        queue_df["Dst Port"] = (
            queue_df["Dst Port"]
            .apply(
                port_value
            )
        )


    if "Protocol" in queue_df.columns:

        queue_df["Protocol"] = (
            queue_df["Protocol"]
            .apply(
                protocol_name
            )
        )


    st.dataframe(
        queue_df,
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# THREAT INTELLIGENCE SUMMARY
# ============================================================

st.markdown(
    '<div class="section-heading">'
    'Threat Intelligence Summary'
    '</div>',
    unsafe_allow_html=True,
)

summary_left, summary_right = st.columns(2)


with summary_left:

    st.markdown(
        "### Attack Distribution"
    )

    attack_summary = pd.DataFrame(
        attack_metrics
    )

    if not attack_summary.empty:

        st.dataframe(
            attack_summary,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            "No attack distribution available."
        )


with summary_right:

    st.markdown(
        "### Severity Distribution"
    )

    severity_summary = pd.DataFrame(
        severity_metrics
    )

    if not severity_summary.empty:

        st.dataframe(
            severity_summary,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            "No severity distribution available."
        )


# ============================================================
# MODEL INTELLIGENCE
# ============================================================

st.markdown(
    '<div class="section-heading">'
    'Model Intelligence'
    '</div>',
    unsafe_allow_html=True,
)

m1, m2, m3, m4 = st.columns(4)


with m1:

    st.metric(
        "Detection Threshold",
        "0.70",
    )


with m2:

    st.metric(
        "ML Features",
        "81",
    )


with m3:

    st.metric(
        "Attack Classes",
        format_number(
            soc_metrics.get(
                "attack_types",
                3,
            )
        ),
    )


with m4:

    st.metric(
        "Average Confidence",
        format_percentage(
            soc_metrics.get(
                "average_confidence",
                0,
            )
        ),
    )


st.caption(
    "CyberSentinel uses a two-stage machine-learning "
    "architecture. Stage 1 detects suspicious network "
    "flows, while Stage 2 classifies detected attacks "
    "into Brute Force -Web, Brute Force -XSS, and "
    "SQL Injection."
)


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
<div class="footer">CyberSentinel • AI-Powered Network Threat Detection &nbsp;|&nbsp; PySpark • Random Forest • FastAPI • SQLite • Streamlit</div>
""",
    unsafe_allow_html=True,
)