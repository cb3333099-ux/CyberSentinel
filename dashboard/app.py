from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


# ============================================================
# CONFIGURATION
# ============================================================

ALERT_PATH = Path(
    "/home/charay/cybersentinel-data/"
    "inference/cybersentinel_alerts"
)

DETECTION_THRESHOLD = 0.70


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberSentinel SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CUSTOM STYLING
# ============================================================

st.markdown(
    """
    <style>

    .main {
        background-color: #0b1120;
    }

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
    }

    .metric-card {
        background: #111827;
        border: 1px solid #263244;
        border-radius: 12px;
        padding: 18px;
        min-height: 115px;
    }

    .metric-title {
        color: #94a3b8;
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }

    .metric-value {
        color: #f8fafc;
        font-size: 1.85rem;
        font-weight: 800;
        margin-top: 8px;
    }

    .metric-subtitle {
        color: #64748b;
        font-size: 0.72rem;
        margin-top: 4px;
    }

    .online {
        color: #22c55e;
        font-weight: 700;
    }

    .section-box {
        background: #111827;
        border: 1px solid #263244;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 15px;
    }

    .threat-title {
        color: #f8fafc;
        font-size: 1.15rem;
        font-weight: 700;
    }

    .threat-label {
        color: #64748b;
        font-size: 0.75rem;
        text-transform: uppercase;
        font-weight: 700;
        margin-bottom: 4px;
    }

    .threat-value {
        color: #e2e8f0;
        font-size: 0.95rem;
        font-weight: 600;
        margin-bottom: 14px;
        line-height: 1.5;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# HEADER
# ============================================================

st.markdown("# 🛡️ CyberSentinel")

st.markdown(
    "### AI-Powered Network Threat Intelligence & Detection"
)

st.markdown(
    '<span class="online">● SYSTEM ONLINE</span>'
    " &nbsp;&nbsp;|&nbsp;&nbsp; "
    "Two-Stage ML Detection Pipeline",
    unsafe_allow_html=True,
)

st.divider()


# ============================================================
# LOAD ALERT DATA
# ============================================================

@st.cache_data
def load_alerts():

    if not ALERT_PATH.exists():
        return pd.DataFrame()

    try:
        return pd.read_parquet(ALERT_PATH)

    except Exception as exc:
        st.error(
            f"Unable to load alert data: {exc}"
        )
        return pd.DataFrame()


alerts = load_alerts()


# ============================================================
# EMPTY DATA CHECK
# ============================================================

if alerts.empty:

    st.warning(
        "No CyberSentinel alert data found."
    )

    st.code(
        "python src/ml/inference.py",
        language="bash",
    )

    st.stop()


# ============================================================
# DATA PREPARATION
# ============================================================

alerts["Timestamp"] = pd.to_datetime(
    alerts["Timestamp"],
    errors="coerce",
)

alerts["attack_probability"] = pd.to_numeric(
    alerts["attack_probability"],
    errors="coerce",
)

alerts["Dst_Port"] = pd.to_numeric(
    alerts["Dst_Port"],
    errors="coerce",
)

alerts["Protocol"] = pd.to_numeric(
    alerts["Protocol"],
    errors="coerce",
)

alerts["severity"] = (
    alerts["severity"]
    .fillna("UNKNOWN")
    .astype(str)
)

alerts["attack_type"] = (
    alerts["attack_type"]
    .fillna("Unknown")
    .astype(str)
)


# ============================================================
# PROTOCOL MAPPING
# ============================================================

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


# ============================================================
# SIDEBAR FILTERS
# ============================================================

st.sidebar.title(
    "Threat Operations"
)

st.sidebar.caption(
    "Configure the active threat-intelligence view."
)


severity_options = sorted(
    alerts["severity"].unique()
)

selected_severity = st.sidebar.multiselect(
    "Severity",
    severity_options,
    default=severity_options,
)


attack_options = sorted(
    alerts["attack_type"].unique()
)

selected_attacks = st.sidebar.multiselect(
    "Attack Type",
    attack_options,
    default=attack_options,
)


min_probability = st.sidebar.slider(
    "Minimum Model Confidence",
    0.0,
    1.0,
    0.70,
    0.05,
)


filtered = alerts[
    alerts["severity"].isin(
        selected_severity
    )
    &
    alerts["attack_type"].isin(
        selected_attacks
    )
    &
    (
        alerts["attack_probability"]
        >= min_probability
    )
].copy()


# ============================================================
# CORE METRICS
# ============================================================

total_alerts = len(filtered)

critical_count = int(
    (filtered["severity"] == "CRITICAL").sum()
)

high_count = int(
    (filtered["severity"] == "HIGH").sum()
)

attack_type_count = int(
    filtered["attack_type"].nunique()
)

avg_confidence = (
    float(
        filtered["attack_probability"].mean()
    )
    if not filtered.empty
    else 0.0
)


# ============================================================
# OPERATIONAL RISK INDEX
# ============================================================

if total_alerts > 0:

    critical_ratio = (
        critical_count / total_alerts
    )

    high_ratio = (
        high_count / total_alerts
    )

    medium_ratio = (
        1
        - critical_ratio
        - high_ratio
    )

    risk_index = (
        critical_ratio * 100
        + high_ratio * 65
        + max(medium_ratio, 0) * 35
    )

    risk_index = min(
        100,
        max(0, risk_index),
    )

else:

    risk_index = 0


# ============================================================
# TOP THREAT
# ============================================================

if not filtered.empty:

    attack_counts_raw = (
        filtered["attack_type"]
        .value_counts()
    )

    top_attack = attack_counts_raw.idxmax()

    top_attack_count = int(
        attack_counts_raw.max()
    )

else:

    top_attack = "None"
    top_attack_count = 0


# ============================================================
# TOP TARGETED PORT
# ============================================================

if not filtered.empty:

    port_counts_raw = (
        filtered["Dst_Port"]
        .value_counts()
    )

    top_port = int(
        port_counts_raw.idxmax()
    )

    top_port_count = int(
        port_counts_raw.max()
    )

else:

    top_port = "-"
    top_port_count = 0


# ============================================================
# KPI ROW
# ============================================================

c1, c2, c3, c4, c5 = st.columns(5)


with c1:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">
                Active Alerts
            </div>
            <div class="metric-value">
                {total_alerts:,}
            </div>
            <div class="metric-subtitle">
                Current filtered feed
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with c2:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">
                Operational Risk
            </div>
            <div class="metric-value">
                {risk_index:.0f}/100
            </div>
            <div class="metric-subtitle">
                Severity-weighted index
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with c3:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">
                Critical Alerts
            </div>
            <div class="metric-value">
                {critical_count:,}
            </div>
            <div class="metric-subtitle">
                Immediate investigation
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with c4:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">
                Top Threat
            </div>
            <div class="metric-value"
                 style="font-size:1.15rem;">
                {top_attack}
            </div>
            <div class="metric-subtitle">
                {top_attack_count:,} detected alerts
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


with c5:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">
                Avg Model Confidence
            </div>
            <div class="metric-value">
                {avg_confidence:.1%}
            </div>
            <div class="metric-subtitle">
                Stage 1 detection score
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


st.markdown("")


# ============================================================
# THREAT OPERATIONS
# ============================================================

st.subheader(
    "Threat Operations"
)

left, right = st.columns(2)


# ============================================================
# ATTACK DISTRIBUTION
# ============================================================

with left:

    st.markdown(
        "#### Attack Distribution"
    )

    attack_counts = (
        filtered["attack_type"]
        .value_counts()
        .reset_index()
    )

    attack_counts.columns = [
        "Attack Type",
        "Alerts",
    ]

    fig_attack = px.bar(
        attack_counts,
        x="Attack Type",
        y="Alerts",
        text="Alerts",
    )

    fig_attack.update_layout(
        template="plotly_dark",
        height=390,
        margin=dict(
            l=20,
            r=20,
            t=20,
            b=20,
        ),
        xaxis_title=None,
    )

    fig_attack.update_traces(
        textposition="outside"
    )

    st.plotly_chart(
        fig_attack,
        use_container_width=True,
    )


# ============================================================
# SEVERITY DISTRIBUTION
# ============================================================

with right:

    st.markdown(
        "#### Severity Distribution"
    )

    severity_counts = (
        filtered["severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = [
        "Severity",
        "Alerts",
    ]

    fig_severity = px.pie(
        severity_counts,
        names="Severity",
        values="Alerts",
        hole=0.58,
    )

    fig_severity.update_layout(
        template="plotly_dark",
        height=390,
        margin=dict(
            l=20,
            r=20,
            t=20,
            b=20,
        ),
    )

    st.plotly_chart(
        fig_severity,
        use_container_width=True,
    )


# ============================================================
# THREAT TIMELINE
# ============================================================

st.subheader(
    "Threat Activity Timeline"
)

if not filtered.empty:

    timeline = (
        filtered
        .dropna(subset=["Timestamp"])
        .assign(
            Hour=lambda x:
                x["Timestamp"].dt.floor("h")
        )
        .groupby(
            ["Hour", "severity"]
        )
        .size()
        .reset_index(
            name="Alerts"
        )
    )

    fig_timeline = px.line(
        timeline,
        x="Hour",
        y="Alerts",
        color="severity",
        markers=True,
    )

    fig_timeline.update_layout(
        template="plotly_dark",
        height=400,
        margin=dict(
            l=20,
            r=20,
            t=20,
            b=20,
        ),
        xaxis_title="Time",
        yaxis_title="Alerts",
    )

    st.plotly_chart(
        fig_timeline,
        use_container_width=True,
    )


# ============================================================
# TARGETED PORTS + PROTOCOLS
# ============================================================

left, right = st.columns(2)


with left:

    st.markdown(
        "#### Most Targeted Ports"
    )

    port_counts = (
        filtered["Dst_Port"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    port_counts.columns = [
        "Destination Port",
        "Alerts",
    ]

    port_counts[
        "Destination Port"
    ] = (
        port_counts[
            "Destination Port"
        ]
        .astype(int)
        .astype(str)
    )

    fig_ports = px.bar(
        port_counts,
        x="Alerts",
        y="Destination Port",
        orientation="h",
        text="Alerts",
    )

    fig_ports.update_layout(
        template="plotly_dark",
        height=400,
        margin=dict(
            l=20,
            r=20,
            t=20,
            b=20,
        ),
        yaxis=dict(
            categoryorder="total ascending"
        ),
    )

    st.plotly_chart(
        fig_ports,
        use_container_width=True,
    )


with right:

    st.markdown(
        "#### Protocol Distribution"
    )

    protocol_data = filtered.copy()

    protocol_data["Protocol Name"] = (
        protocol_data["Protocol"]
        .map(PROTOCOL_MAP)
        .fillna("Other")
    )

    protocol_counts = (
        protocol_data[
            "Protocol Name"
        ]
        .value_counts()
        .reset_index()
    )

    protocol_counts.columns = [
        "Protocol",
        "Alerts",
    ]

    fig_protocol = px.pie(
        protocol_counts,
        names="Protocol",
        values="Alerts",
        hole=0.55,
    )

    fig_protocol.update_layout(
        template="plotly_dark",
        height=400,
        margin=dict(
            l=20,
            r=20,
            t=20,
            b=20,
        ),
    )

    st.plotly_chart(
        fig_protocol,
        use_container_width=True,
    )


# ============================================================
# ALERT INVESTIGATION
# ============================================================

st.subheader(
    "Alert Investigation"
)

if filtered.empty:

    st.info(
        "No alerts match the current filters."
    )

else:

    investigation_df = (
        filtered
        .sort_values(
            "attack_probability",
            ascending=False,
        )
        .reset_index(drop=True)
    )

    investigation_labels = []

    for i, row in investigation_df.head(100).iterrows():

        timestamp = row["Timestamp"]

        if pd.notna(timestamp):

            timestamp_text = timestamp.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        else:

            timestamp_text = "Unknown"

        investigation_labels.append(
            f"{i} | "
            f"{timestamp_text} | "
            f"{row['attack_type']} | "
            f"{row['severity']} | "
            f"{row['attack_probability']:.2%}"
        )

    selected_label = st.selectbox(
        "Select an alert to investigate",
        investigation_labels,
    )

    selected_index = int(
        selected_label.split("|")[0].strip()
    )

    selected = investigation_df.iloc[
        selected_index
    ]


    # --------------------------------------------------------
    # SELECTED THREAT
    # --------------------------------------------------------

    st.markdown(
        """
        <div class="section-box">
            <div class="threat-title">
                Selected Threat
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


    d1, d2, d3, d4 = st.columns(4)


    with d1:

        st.markdown(
            '<div class="threat-label">'
            'Attack Type'
            '</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            f'<div class="threat-value">'
            f'{selected["attack_type"]}'
            f'</div>',
            unsafe_allow_html=True,
        )


    with d2:

        st.markdown(
            '<div class="threat-label">'
            'Severity'
            '</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            f'<div class="threat-value">'
            f'{selected["severity"]}'
            f'</div>',
            unsafe_allow_html=True,
        )


    with d3:

        st.markdown(
            '<div class="threat-label">'
            'Model Confidence'
            '</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            f'<div class="threat-value">'
            f'{selected["attack_probability"]:.2%}'
            f'</div>',
            unsafe_allow_html=True,
        )


    with d4:

        st.markdown(
            '<div class="threat-label">'
            'Destination Port'
            '</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            f'<div class="threat-value">'
            f'{int(selected["Dst_Port"])}'
            f'</div>',
            unsafe_allow_html=True,
        )


    e1, e2, e3, e4 = st.columns(4)


    with e1:

        st.markdown(
            '<div class="threat-label">'
            'Timestamp'
            '</div>',
            unsafe_allow_html=True,
        )

        st.write(
            selected["Timestamp"]
        )


    with e2:

        st.markdown(
            '<div class="threat-label">'
            'Protocol'
            '</div>',
            unsafe_allow_html=True,
        )

        protocol = PROTOCOL_MAP.get(
            int(selected["Protocol"]),
            "Other",
        )

        st.write(protocol)


    with e3:

        st.markdown(
            '<div class="threat-label">'
            'Flow Duration'
            '</div>',
            unsafe_allow_html=True,
        )

        flow_duration = selected.get(
            "Flow_Duration",
            0,
        )

        st.write(
            f"{float(flow_duration):,.0f}"
        )


    with e4:

        st.markdown(
            '<div class="threat-label">'
            'Alert Source'
            '</div>',
            unsafe_allow_html=True,
        )

        st.write(
            "CyberSentinel ML Detector"
        )


# ============================================================
# THREAT ASSESSMENT & RESPONSE
# ============================================================

st.subheader(
    "Threat Assessment & Response"
)

if not filtered.empty:

    response_left, response_right = st.columns(
        [1.4, 1]
    )


    # --------------------------------------------------------
    # AUTOMATED THREAT ASSESSMENT
    # --------------------------------------------------------

    with response_left:

        st.markdown(
            """
            <div class="section-box">
                <div class="threat-title">
                    Automated Threat Assessment
                </div>
            """,
            unsafe_allow_html=True,
        )

        selected_attack = selected["attack_type"]
        selected_port = int(selected["Dst_Port"])
        selected_severity = selected["severity"]
        selected_probability = float(
            selected["attack_probability"]
        )


        if selected_attack == "Brute Force -Web":

            assessment = (
                "Repeated web-service activity is "
                "consistent with a brute-force attack "
                "pattern targeting an HTTP service."
            )

            recommendation = (
                "Investigate the originating traffic, "
                "review authentication activity, and "
                "consider rate limiting or access controls."
            )


        elif selected_attack == "Brute Force -XSS":

            assessment = (
                "Traffic exhibits characteristics "
                "associated with cross-site scripting "
                "activity combined with brute-force behavior."
            )

            recommendation = (
                "Inspect HTTP request patterns and "
                "review application-layer security controls."
            )


        elif selected_attack == "SQL Injection":

            assessment = (
                "The detected traffic is classified as "
                "SQL injection activity targeting an "
                "application service."
            )

            recommendation = (
                "Inspect application logs and database "
                "requests and validate input sanitization."
            )


        else:

            assessment = (
                "The model identified suspicious network "
                "activity requiring analyst investigation."
            )

            recommendation = (
                "Review the associated network flow and "
                "host activity."
            )


        st.markdown(
            '<div class="threat-label">'
            'Attack Pattern'
            '</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            f'<div class="threat-value">'
            f'{assessment}'
            f'</div>',
            unsafe_allow_html=True,
        )


        st.markdown(
            '<div class="threat-label">'
            'Recommended Action'
            '</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            f'<div class="threat-value">'
            f'{recommendation}'
            f'</div>',
            unsafe_allow_html=True,
        )


        st.markdown(
            '</div>',
            unsafe_allow_html=True,
        )


    # --------------------------------------------------------
    # RESPONSE STATUS
    # --------------------------------------------------------

    with response_right:

        st.markdown(
            """
            <div class="section-box">
                <div class="threat-title">
                    Response Status
                </div>
            """,
            unsafe_allow_html=True,
        )

        st.write(
            f"**Severity:** {selected_severity}"
        )

        st.write(
            f"**Confidence:** "
            f"{selected_probability:.2%}"
        )

        st.write(
            f"**Destination:** "
            f"Port {selected_port}"
        )

        st.write(
            "**Detection Pipeline:** "
            "Stage 1 → Stage 2"
        )

        st.markdown(
            "</div>",
            unsafe_allow_html=True,
        )


        action_col1, action_col2 = st.columns(2)


        with action_col1:

            if st.button(
                "✓ Mark Investigated",
                use_container_width=True,
            ):

                st.success(
                    "Alert marked as investigated."
                )


        with action_col2:

            if st.button(
                "⚠ Escalate",
                use_container_width=True,
            ):

                st.warning(
                    "Alert escalated for further review."
                )


else:

    st.info(
        "Select an alert to activate threat assessment."
    )


# ============================================================
# MODEL INTELLIGENCE
# ============================================================

st.subheader(
    "Model Intelligence"
)

m1, m2, m3, m4 = st.columns(4)


with m1:

    st.metric(
        "Detection Model",
        "Random Forest",
    )


with m2:

    st.metric(
        "Detection Threshold",
        f"{DETECTION_THRESHOLD:.2f}",
    )


with m3:

    st.metric(
        "ML Features",
        "81",
    )


with m4:

    st.metric(
        "Attack Classes",
        "3",
    )


st.caption(
    "CyberSentinel uses a two-stage machine-learning "
    "pipeline: Stage 1 detects suspicious network flows "
    "and Stage 2 classifies detected attacks as "
    "Brute Force -Web, Brute Force -XSS, or SQL Injection."
)


# ============================================================
# THREAT ALERT FEED
# ============================================================

st.subheader(
    "Threat Alert Feed"
)

display_columns = [
    "Timestamp",
    "Dst_Port",
    "Protocol",
    "attack_probability",
    "attack_type",
    "severity",
]

table = filtered[
    display_columns
].copy()


# Convert protocol numbers into readable names.

table["Protocol"] = (
    table["Protocol"]
    .map(PROTOCOL_MAP)
    .fillna("Other")
)


# Format probability.

table["attack_probability"] = (
    table["attack_probability"]
    .map(
        lambda x:
        f"{x:.2%}"
    )
)


# Format destination port.

table["Dst_Port"] = (
    table["Dst_Port"]
    .apply(
        lambda x:
        int(x)
        if pd.notna(x)
        else "-"
    )
)


table = table.sort_values(
    "Timestamp",
    ascending=False,
)


st.dataframe(
    table,
    use_container_width=True,
    height=450,
    hide_index=True,
)


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "CyberSentinel • AI-powered network threat "
    "detection and intelligence platform"
)
