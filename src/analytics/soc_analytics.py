import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from src.soc.alert_store import get_connection, initialize_database


def parse_window(window: str = "24h") -> Tuple[str, float]:
    """
    Parse time window string ('15m', '1h', '24h', '7d', 'all') into ISO UTC cutoff and total minutes.
    """
    win_lower = str(window).lower().strip()
    now_dt = datetime.now(timezone.utc)

    if win_lower == "15m":
        cutoff_dt = now_dt - timedelta(minutes=15)
        total_mins = 15.0
    elif win_lower == "1h":
        cutoff_dt = now_dt - timedelta(hours=1)
        total_mins = 60.0
    elif win_lower == "24h":
        cutoff_dt = now_dt - timedelta(hours=24)
        total_mins = 1440.0
    elif win_lower == "7d":
        cutoff_dt = now_dt - timedelta(days=7)
        total_mins = 10080.0
    else:  # 'all'
        cutoff_dt = datetime(1970, 1, 1, tzinfo=timezone.utc)
        total_mins = (now_dt - cutoff_dt).total_seconds() / 60.0

    return cutoff_dt.isoformat(), total_mins


def get_summary_metrics(window: str = "24h") -> Dict[str, Any]:
    """
    Calculate high-level SOC summary performance metrics for a specified time window.
    """
    initialize_database()
    cutoff_iso, total_mins = parse_window(window)
    conn = get_connection()
    cursor = conn.cursor()

    # Alerts count
    cursor.execute("SELECT COUNT(*), SUM(CASE WHEN status = 'NEW' THEN 1 ELSE 0 END) FROM alerts WHERE created_at >= ?", (cutoff_iso,))
    row_alerts = cursor.fetchone()
    total_alerts = row_alerts[0] if row_alerts else 0
    active_alerts = row_alerts[1] if row_alerts and row_alerts[1] is not None else 0

    # Severity Breakdown
    cursor.execute(
        """
        SELECT
            SUM(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 ELSE 0 END),
            SUM(CASE WHEN UPPER(severity) = 'HIGH' THEN 1 ELSE 0 END),
            SUM(CASE WHEN UPPER(severity) = 'MEDIUM' THEN 1 ELSE 0 END),
            SUM(CASE WHEN UPPER(severity) = 'LOW' THEN 1 ELSE 0 END),
            SUM(CASE WHEN UPPER(attack_type) != 'BENIGN' THEN 1 ELSE 0 END),
            AVG(CASE WHEN UPPER(attack_type) != 'BENIGN' THEN confidence ELSE NULL END)
        FROM alerts
        WHERE created_at >= ?
        """,
        (cutoff_iso,),
    )
    row_sev = cursor.fetchone()
    crit_count = row_sev[0] if row_sev and row_sev[0] is not None else 0
    high_count = row_sev[1] if row_sev and row_sev[1] is not None else 0
    med_count = row_sev[2] if row_sev and row_sev[2] is not None else 0
    low_count = row_sev[3] if row_sev and row_sev[3] is not None else 0
    attack_alerts = row_sev[4] if row_sev and row_sev[4] is not None else 0
    avg_conf = float(row_sev[5]) if row_sev and row_sev[5] is not None else None

    # Incidents metrics
    cursor.execute(
        """
        SELECT
            SUM(CASE WHEN UPPER(status) IN ('NEW', 'INVESTIGATING', 'ESCALATED') THEN 1 ELSE 0 END),
            SUM(CASE WHEN UPPER(status) = 'RESOLVED' THEN 1 ELSE 0 END)
        FROM incidents
        WHERE created_at >= ?
        """,
        (cutoff_iso,),
    )
    row_inc = cursor.fetchone()
    open_inc = row_inc[0] if row_inc and row_inc[0] is not None else 0
    res_inc = row_inc[1] if row_inc and row_inc[1] is not None else 0

    # MTTR Calculation for RESOLVED incidents
    cursor.execute(
        """
        SELECT first_seen, updated_at
        FROM incidents
        WHERE UPPER(status) = 'RESOLVED' AND created_at >= ?
        """,
        (cutoff_iso,),
    )
    resolved_rows = cursor.fetchall()
    mttr_seconds = None
    if resolved_rows:
        durations = []
        for r in resolved_rows:
            try:
                dt1 = pd.to_datetime(r[0]).timestamp()
                dt2 = pd.to_datetime(r[1]).timestamp()
                diff = abs(dt2 - dt1)
                durations.append(diff)
            except Exception:
                pass
        if durations:
            mttr_seconds = round(sum(durations) / len(durations), 1)

    conn.close()

    alert_rate = round(total_alerts / max(1.0, total_mins), 2)
    incident_rate = round((open_inc + res_inc) / max(1.0, total_mins), 2)
    total_incidents = open_inc + res_inc
    alert_to_incident_ratio = round(total_alerts / max(1, total_incidents), 2) if total_incidents > 0 else None
    attack_rate = round(attack_alerts / max(1, total_alerts), 4) if total_alerts > 0 else 0.0

    return {
        "window": window,
        "total_alerts": total_alerts,
        "active_alerts": active_alerts,
        "critical_alerts": crit_count,
        "high_alerts": high_count,
        "medium_alerts": med_count,
        "low_alerts": low_count,
        "open_incidents": open_inc,
        "resolved_incidents": res_inc,
        "mean_confidence": round(avg_conf, 4) if avg_conf is not None else None,
        "alert_rate_per_min": alert_rate,
        "incident_rate_per_min": incident_rate,
        "alert_to_incident_ratio": alert_to_incident_ratio,
        "attack_rate": attack_rate,
        "mttr_seconds": mttr_seconds,
    }


def get_attack_activity_trends(window: str = "24h") -> List[Dict[str, Any]]:
    """
    Generate time-series trend metrics bucketed by time interval.
    """
    initialize_database()
    cutoff_iso, _ = parse_window(window)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            timestamp,
            severity,
            attack_type
        FROM alerts
        WHERE created_at >= ?
        ORDER BY timestamp ASC
        """,
        (cutoff_iso,),
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return []

    df = pd.DataFrame(rows, columns=["timestamp", "severity", "attack_type"])
    df["dt"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["dt"])

    if window in ("15m", "1h"):
        freq = "1min"
    elif window == "24h":
        freq = "1h"
    else:
        freq = "1D"

    df["bucket"] = df["dt"].dt.floor(freq)
    grouped = df.groupby("bucket")

    result = []
    for bucket, group in grouped:
        crit = int((group["severity"].str.upper() == "CRITICAL").sum())
        high = int((group["severity"].str.upper() == "HIGH").sum())
        med = int((group["severity"].str.upper() == "MEDIUM").sum())
        low = int((group["severity"].str.upper() == "LOW").sum())
        attacks = int((group["attack_type"].str.upper() != "BENIGN").sum())

        result.append({
            "timestamp": bucket.isoformat(),
            "total_alerts": len(group),
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "attack_alerts": attacks,
        })

    return result


def get_attack_distribution(window: str = "24h") -> List[Dict[str, Any]]:
    """
    Get alert count and percentage distribution by attack type.
    """
    initialize_database()
    cutoff_iso, _ = parse_window(window)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            attack_type,
            COUNT(*) as count,
            AVG(confidence) as avg_conf
        FROM alerts
        WHERE created_at >= ?
        GROUP BY attack_type
        ORDER BY count DESC
        """,
        (cutoff_iso,),
    )
    rows = cursor.fetchall()
    conn.close()

    total = sum(r[1] for r in rows) if rows else 0
    result = []
    for r in rows:
        cnt = r[1]
        pct = round(cnt / total, 4) if total > 0 else 0.0
        result.append({
            "attack_type": r[0],
            "count": cnt,
            "percentage": pct,
            "mean_confidence": round(float(r[2]), 4) if r[2] is not None else None,
        })

    return result


def get_severity_analytics(window: str = "24h") -> Dict[str, Any]:
    """
    Get severity distribution breakdown and time-series trends.
    """
    initialize_database()
    cutoff_iso, _ = parse_window(window)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT severity, COUNT(*)
        FROM alerts
        WHERE created_at >= ?
        GROUP BY severity
        """,
        (cutoff_iso,),
    )
    rows = cursor.fetchall()
    conn.close()

    distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in rows:
        sev_upper = str(r[0]).upper()
        if sev_upper in distribution:
            distribution[sev_upper] = r[1]

    trends = get_attack_activity_trends(window)
    return {
        "window": window,
        "distribution": distribution,
        "trends": trends,
    }


def get_top_entities(window: str = "24h", limit: int = 10) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get top source IPs, destination IPs, and destination ports by alert count.
    """
    initialize_database()
    cutoff_iso, _ = parse_window(window)
    conn = get_connection()
    cursor = conn.cursor()

    # Top Source IPs
    cursor.execute(
        """
        SELECT
            source_ip,
            COUNT(*) as alert_count,
            SUM(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
        FROM alerts
        WHERE created_at >= ? AND source_ip IS NOT NULL AND source_ip != ''
        GROUP BY source_ip
        ORDER BY alert_count DESC
        LIMIT ?
        """,
        (cutoff_iso, limit),
    )
    sources = [
        {
            "entity": r[0],
            "alert_count": r[1],
            "critical_count": r[2] or 0,
            "first_seen": r[3],
            "last_seen": r[4],
        }
        for r in cursor.fetchall()
    ]

    # Top Destination IPs
    cursor.execute(
        """
        SELECT
            destination_ip,
            COUNT(*) as alert_count,
            SUM(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
        FROM alerts
        WHERE created_at >= ? AND destination_ip IS NOT NULL AND destination_ip != ''
        GROUP BY destination_ip
        ORDER BY alert_count DESC
        LIMIT ?
        """,
        (cutoff_iso, limit),
    )
    destinations = [
        {
            "entity": r[0],
            "alert_count": r[1],
            "critical_count": r[2] or 0,
            "first_seen": r[3],
            "last_seen": r[4],
        }
        for r in cursor.fetchall()
    ]

    # Top Destination Ports
    cursor.execute(
        """
        SELECT
            destination_port,
            COUNT(*) as alert_count,
            SUM(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
        FROM alerts
        WHERE created_at >= ? AND destination_port IS NOT NULL
        GROUP BY destination_port
        ORDER BY alert_count DESC
        LIMIT ?
        """,
        (cutoff_iso, limit),
    )
    ports = [
        {
            "entity": str(r[0]),
            "alert_count": r[1],
            "critical_count": r[2] or 0,
            "first_seen": r[3],
            "last_seen": r[4],
        }
        for r in cursor.fetchall()
    ]

    conn.close()
    return {
        "top_sources": sources,
        "top_destinations": destinations,
        "top_ports": ports,
    }


def get_protocol_analytics(window: str = "24h") -> List[Dict[str, Any]]:
    """
    Get protocol breakdown (TCP, UDP, ICMP, OTHER) with counts and percentages.
    """
    initialize_database()
    cutoff_iso, _ = parse_window(window)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT protocol, COUNT(*)
        FROM alerts
        WHERE created_at >= ?
        GROUP BY protocol
        """,
        (cutoff_iso,),
    )
    rows = cursor.fetchall()
    conn.close()

    total = sum(r[1] for r in rows) if rows else 0
    proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}

    for r in rows:
        p = str(r[0]).upper() if r[0] else "OTHER"
        if p in proto_counts:
            proto_counts[p] += r[1]
        else:
            proto_counts["OTHER"] += r[1]

    result = []
    for proto, cnt in proto_counts.items():
        pct = round(cnt / total, 4) if total > 0 else 0.0
        result.append({
            "protocol": proto,
            "count": cnt,
            "percentage": pct,
        })

    return result


def get_incident_analytics(window: str = "24h") -> Dict[str, Any]:
    """
    Analyze Phase 3A SOC incidents for the time window.
    """
    initialize_database()
    cutoff_iso, _ = parse_window(window)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            status,
            severity,
            alert_count,
            first_seen,
            last_seen,
            updated_at
        FROM incidents
        WHERE created_at >= ?
        """,
        (cutoff_iso,),
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return {
            "window": window,
            "total_incidents": 0,
            "open_incidents": 0,
            "investigating_incidents": 0,
            "escalated_incidents": 0,
            "resolved_incidents": 0,
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "avg_alerts_per_incident": 0.0,
            "mttr_seconds": None,
        }

    status_counts = {"NEW": 0, "INVESTIGATING": 0, "ESCALATED": 0, "RESOLVED": 0}
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_alerts_in_incidents = 0
    resolved_durations = []

    for r in rows:
        st_upper = str(r[0]).upper()
        if st_upper in status_counts:
            status_counts[st_upper] += 1

        sv_upper = str(r[1]).upper()
        if sv_upper in sev_counts:
            sev_counts[sv_upper] += 1

        total_alerts_in_incidents += r[2] if r[2] else 0

        if st_upper == "RESOLVED":
            try:
                dt1 = pd.to_datetime(r[3]).timestamp()
                dt2 = pd.to_datetime(r[5]).timestamp()
                resolved_durations.append(abs(dt2 - dt1))
            except Exception:
                pass

    total_incidents = len(rows)
    avg_alerts = round(total_alerts_in_incidents / max(1, total_incidents), 1)
    mttr = round(sum(resolved_durations) / len(resolved_durations), 1) if resolved_durations else None

    return {
        "window": window,
        "total_incidents": total_incidents,
        "open_incidents": status_counts["NEW"],
        "investigating_incidents": status_counts["INVESTIGATING"],
        "escalated_incidents": status_counts["ESCALATED"],
        "resolved_incidents": status_counts["RESOLVED"],
        "severity_distribution": sev_counts,
        "avg_alerts_per_incident": avg_alerts,
        "mttr_seconds": mttr,
    }
