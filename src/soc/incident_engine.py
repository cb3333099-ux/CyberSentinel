import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from src.soc.alert_store import get_connection, initialize_database


# ============================================================
# RISK SCORE CALCULATION
# ============================================================

SEVERITY_BASE_SCORES = {
    "CRITICAL": 80.0,
    "HIGH": 60.0,
    "MEDIUM": 40.0,
    "LOW": 20.0,
    "UNKNOWN": 10.0,
}


def calculate_risk_score(
    highest_severity: str,
    alert_count: int,
    confidence: float,
    attack_types: List[str],
    duration_seconds: float = 0.0,
) -> Tuple[float, Dict[str, Any]]:
    """
    Calculate an explainable, transparent risk score (0-100) for an incident.

    Returns:
        (risk_score, risk_factors_dict)
    """
    sev_upper = str(highest_severity).upper()
    base_score = SEVERITY_BASE_SCORES.get(sev_upper, 10.0)

    # Volume factor: +3 points per additional alert beyond the first (capped at +20)
    volume_bonus = min(20.0, max(0, alert_count - 1) * 3.0)

    # Attack diversity factor: +5 points per distinct attack type beyond the first (capped at +15)
    distinct_attacks = len(set(attack_types)) if attack_types else 1
    diversity_bonus = min(15.0, max(0, distinct_attacks - 1) * 5.0)

    # Confidence factor: up to +10 points for high model confidence
    conf_val = float(confidence) if confidence is not None else 0.0
    if conf_val > 1.0:
        conf_val /= 100.0
    confidence_bonus = round(conf_val * 10.0, 2)

    # Duration / Sustained activity factor: +5 points if activity spans > 60 seconds
    duration_bonus = 5.0 if duration_seconds >= 60.0 else 0.0

    raw_score = base_score + volume_bonus + diversity_bonus + confidence_bonus + duration_bonus
    clamped_score = round(min(100.0, max(0.0, raw_score)), 1)

    factors = {
        "base_severity": sev_upper,
        "base_score": base_score,
        "alert_count": alert_count,
        "volume_bonus": volume_bonus,
        "distinct_attack_types": distinct_attacks,
        "diversity_bonus": diversity_bonus,
        "confidence": conf_val,
        "confidence_bonus": confidence_bonus,
        "duration_seconds": duration_seconds,
        "duration_bonus": duration_bonus,
        "calculated_risk_score": clamped_score,
    }

    return clamped_score, factors


# ============================================================
# INCIDENT CORRELATION ENGINE
# ============================================================

class IncidentEngine:
    """
    SOC Incident Correlation Engine for CyberSentinel (Phase 3A).

    Groups related threat alerts into high-level SOC incidents based on
    time-window correlation (default: 5 min), source IP, destination IP,
    port, protocol, and attack type.
    """

    @staticmethod
    def correlate_alert(alert_dict: Dict[str, Any], time_window_seconds: int = 300) -> str:
        """
        Correlate an incoming attack alert dictionary into an active incident or create a new incident.

        Returns:
            incident_id (str)
        """
        initialize_database()
        conn = get_connection()
        cursor = conn.cursor()

        alert_id = str(alert_dict.get("alert_id", ""))
        alert_ts_str = str(alert_dict.get("timestamp") or alert_dict.get("created_at") or datetime.now(timezone.utc).isoformat())

        src_ip = alert_dict.get("source_ip") or alert_dict.get("src_ip") or alert_dict.get("Src_IP")
        dst_ip = alert_dict.get("destination_ip") or alert_dict.get("dst_ip") or alert_dict.get("Dst_IP")
        dst_port = alert_dict.get("destination_port") or alert_dict.get("dst_port") or alert_dict.get("Dst_Port")
        protocol = str(alert_dict.get("protocol") or alert_dict.get("Protocol") or "TCP")
        attack_type = str(alert_dict.get("attack_type") or alert_dict.get("attack_label") or "Threat Detected")
        severity = str(alert_dict.get("severity") or "MEDIUM").upper()
        confidence = float(alert_dict.get("confidence") or alert_dict.get("attack_probability") or 0.0)

        if pd.notna(dst_port) and dst_port is not None:
            try:
                dst_port = int(float(dst_port))
            except (ValueError, TypeError):
                dst_port = None
        else:
            dst_port = None

        # Convert alert_ts to unix timestamp for distance calculation
        try:
            alert_dt = pd.to_datetime(alert_ts_str)
            alert_unix = alert_dt.timestamp()
        except Exception:
            alert_unix = time.time()
            alert_ts_str = datetime.now(timezone.utc).isoformat()

        # Query active incidents (NEW, INVESTIGATING, ESCALATED)
        cursor.execute(
            """
            SELECT incident_id, title, status, severity, risk_score, risk_factors,
                   created_at, updated_at, first_seen, last_seen, alert_count,
                   primary_attack_type, source_entities, destination_entities,
                   destination_ports, protocols, assigned_to, summary
            FROM incidents
            WHERE status IN ('NEW', 'INVESTIGATING', 'ESCALATED')
            ORDER BY last_seen DESC
            """
        )
        active_incidents = [dict(r) for r in cursor.fetchall()]

        matching_incident: Optional[Dict[str, Any]] = None

        for inc in active_incidents:
            try:
                inc_last_unix = pd.to_datetime(inc["last_seen"]).timestamp()
            except Exception:
                inc_last_unix = alert_unix

            # Time window check (default 5 min = 300s)
            time_diff = abs(alert_unix - inc_last_unix)
            if time_diff > time_window_seconds:
                continue

            # Load entity sets
            sources = json.loads(inc["source_entities"]) if inc.get("source_entities") else []
            destinations = json.loads(inc["destination_entities"]) if inc.get("destination_entities") else []
            ports = json.loads(inc["destination_ports"]) if inc.get("destination_ports") else []
            protos = json.loads(inc["protocols"]) if inc.get("protocols") else []
            inc_attack = inc["primary_attack_type"]

            # CRITICAL DISCOVERY RULE:
            # If source IP is explicitly provided for BOTH the alert and the incident,
            # but they do NOT match, DO NOT merge them into the same incident!
            if src_ip and sources and str(src_ip) not in sources:
                continue

            # Deterministic Matching Rules:
            rule1 = bool(src_ip and src_ip in sources and (attack_type == inc_attack or (dst_ip and dst_ip in destinations) or (dst_port and dst_port in ports)))
            rule2 = bool(dst_ip and dst_ip in destinations and (attack_type == inc_attack or (dst_port and dst_port in ports)))
            rule3 = bool(attack_type == inc_attack and dst_port and dst_port in ports)

            if rule1 or rule2 or rule3:
                matching_incident = inc
                break

        now_iso = datetime.now(timezone.utc).isoformat()

        if matching_incident:
            incident_id = matching_incident["incident_id"]

            # Update entity sets
            sources = json.loads(matching_incident["source_entities"]) if matching_incident.get("source_entities") else []
            destinations = json.loads(matching_incident["destination_entities"]) if matching_incident.get("destination_entities") else []
            ports = json.loads(matching_incident["destination_ports"]) if matching_incident.get("destination_ports") else []
            protos = json.loads(matching_incident["protocols"]) if matching_incident.get("protocols") else []

            if src_ip and str(src_ip) not in sources: sources.append(str(src_ip))
            if dst_ip and str(dst_ip) not in destinations: destinations.append(str(dst_ip))
            if dst_port is not None and dst_port not in ports: ports.append(dst_port)
            if protocol and str(protocol) not in protos: protos.append(str(protocol))

            new_alert_count = matching_incident["alert_count"] + 1

            # Escalate severity if new alert is higher priority
            sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
            cur_sev = matching_incident["severity"]
            new_sev = cur_sev if sev_rank.get(cur_sev, 0) >= sev_rank.get(severity, 0) else severity

            first_seen_str = matching_incident["first_seen"]
            try:
                dur_sec = abs(pd.to_datetime(alert_ts_str).timestamp() - pd.to_datetime(first_seen_str).timestamp())
            except Exception:
                dur_sec = 0.0

            # Collect attack types linked to incident
            cursor.execute(
                """
                SELECT DISTINCT a.attack_type
                FROM alerts a
                JOIN incident_alerts ia ON a.alert_id = ia.alert_id
                WHERE ia.incident_id = ?
                """,
                (incident_id,)
            )
            existing_attacks = [r[0] for r in cursor.fetchall()]
            if attack_type not in existing_attacks:
                existing_attacks.append(attack_type)

            new_risk_score, risk_factors = calculate_risk_score(
                highest_severity=new_sev,
                alert_count=new_alert_count,
                confidence=confidence,
                attack_types=existing_attacks,
                duration_seconds=dur_sec,
            )

            # Ensure alert exists in alerts table
            cursor.execute("SELECT alert_id FROM alerts WHERE alert_id = ?", (alert_id,))
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT INTO alerts (
                        alert_id, timestamp, attack_type, severity, confidence,
                        destination_port, protocol, status, incident_id, source_ip, destination_ip, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_id, alert_ts_str, attack_type, severity, confidence,
                        dst_port, protocol, "NEW", incident_id, str(src_ip) if src_ip else None, str(dst_ip) if dst_ip else None, now_iso, now_iso
                    )
                )

            # Update incident record
            cursor.execute(
                """
                UPDATE incidents
                SET updated_at = ?,
                    last_seen = ?,
                    alert_count = ?,
                    severity = ?,
                    risk_score = ?,
                    risk_factors = ?,
                    source_entities = ?,
                    destination_entities = ?,
                    destination_ports = ?,
                    protocols = ?,
                    summary = ?
                WHERE incident_id = ?
                """,
                (
                    now_iso,
                    alert_ts_str,
                    new_alert_count,
                    new_sev,
                    new_risk_score,
                    json.dumps(risk_factors),
                    json.dumps(sources),
                    json.dumps(destinations),
                    json.dumps(ports),
                    json.dumps(protos),
                    f"Incident correlated {new_alert_count} alerts covering {len(existing_attacks)} attack types.",
                    incident_id,
                ),
            )

            # Link alert to incident
            cursor.execute(
                "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, added_at) VALUES (?, ?, ?)",
                (incident_id, alert_id, now_iso),
            )
            cursor.execute("UPDATE alerts SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id))

            # Record timeline event
            event_id = f"EVT-{hashlib.md5(f'{incident_id}{alert_id}{now_iso}'.encode()).hexdigest()[:10]}"
            cursor.execute(
                """
                INSERT INTO incident_timeline (event_id, incident_id, timestamp, event_type, actor, description, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    incident_id,
                    now_iso,
                    "ALERT_CORRELATED",
                    "SYSTEM",
                    f"Correlated alert {alert_id} ({attack_type}) to incident {incident_id}.",
                    json.dumps({"alert_id": alert_id, "attack_type": attack_type, "severity": severity}),
                ),
            )

            conn.commit()
            conn.close()
            return incident_id

        else:
            # Create NEW Incident
            date_prefix = datetime.now(timezone.utc).strftime("%Y%m%d")
            rand_suffix = hashlib.md5(f"{alert_id}{now_iso}".encode()).hexdigest()[:6].upper()
            incident_id = f"INC-{date_prefix}-{rand_suffix}"

            sources = [str(src_ip)] if src_ip else []
            destinations = [str(dst_ip)] if dst_ip else []
            ports = [dst_port] if dst_port is not None else []
            protos = [str(protocol)] if protocol else []

            risk_score, risk_factors = calculate_risk_score(
                highest_severity=severity,
                alert_count=1,
                confidence=confidence,
                attack_types=[attack_type],
                duration_seconds=0.0,
            )

            title = f"{severity} Incident: {attack_type}"
            if dst_port:
                title += f" on Port {dst_port}"

            summary = f"Security Incident created for {attack_type} alert on interface/port {dst_port or 'N/A'}."

            # Ensure alert exists in alerts table
            cursor.execute("SELECT alert_id FROM alerts WHERE alert_id = ?", (alert_id,))
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT INTO alerts (
                        alert_id, timestamp, attack_type, severity, confidence,
                        destination_port, protocol, status, incident_id, source_ip, destination_ip, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_id, alert_ts_str, attack_type, severity, confidence,
                        dst_port, protocol, "NEW", incident_id, str(src_ip) if src_ip else None, str(dst_ip) if dst_ip else None, now_iso, now_iso
                    )
                )

            cursor.execute(
                """
                INSERT INTO incidents (
                    incident_id, title, status, severity, risk_score, risk_factors,
                    created_at, updated_at, first_seen, last_seen, alert_count,
                    primary_attack_type, source_entities, destination_entities,
                    destination_ports, protocols, assigned_to, summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    title,
                    "NEW",
                    severity,
                    risk_score,
                    json.dumps(risk_factors),
                    now_iso,
                    now_iso,
                    alert_ts_str,
                    alert_ts_str,
                    1,
                    attack_type,
                    json.dumps(sources),
                    json.dumps(destinations),
                    json.dumps(ports),
                    json.dumps(protos),
                    "Unassigned",
                    summary,
                ),
            )

            # Link alert to incident
            cursor.execute(
                "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, added_at) VALUES (?, ?, ?)",
                (incident_id, alert_id, now_iso),
            )
            cursor.execute("UPDATE alerts SET incident_id = ? WHERE alert_id = ?", (incident_id, alert_id))

            # Record initial timeline event
            event_id = f"EVT-{hashlib.md5(f'{incident_id}CREATED{now_iso}'.encode()).hexdigest()[:10]}"
            cursor.execute(
                """
                INSERT INTO incident_timeline (event_id, incident_id, timestamp, event_type, actor, description, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    incident_id,
                    now_iso,
                    "INCIDENT_CREATED",
                    "SYSTEM",
                    f"Incident created from alert {alert_id} ({attack_type}).",
                    json.dumps({"alert_id": alert_id, "attack_type": attack_type, "severity": severity, "risk_score": risk_score}),
                ),
            )

            conn.commit()
            conn.close()
            return incident_id


# ============================================================
# INCIDENT MANAGEMENT & QUERY FUNCTIONS
# ============================================================

def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """
    Retrieve incident records filtered by status and severity.
    """
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM incidents"
    params: List[Any] = []
    where_clauses: List[str] = []

    if status:
        where_clauses.append("UPPER(status) = ?")
        params.append(status.upper())

    if severity:
        where_clauses.append("UPPER(severity) = ?")
        params.append(severity.upper())

    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)

    query += " ORDER BY risk_score DESC, last_seen DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    for r in rows:
        r["source_entities"] = json.loads(r["source_entities"]) if r.get("source_entities") else []
        r["destination_entities"] = json.loads(r["destination_entities"]) if r.get("destination_entities") else []
        r["destination_ports"] = json.loads(r["destination_ports"]) if r.get("destination_ports") else []
        r["protocols"] = json.loads(r["protocols"]) if r.get("protocols") else []
        r["risk_factors"] = json.loads(r["risk_factors"]) if r.get("risk_factors") else {}

    return rows


def get_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single incident by ID.
    """
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    inc = dict(row)
    inc["source_entities"] = json.loads(inc["source_entities"]) if inc.get("source_entities") else []
    inc["destination_entities"] = json.loads(inc["destination_entities"]) if inc.get("destination_entities") else []
    inc["destination_ports"] = json.loads(inc["destination_ports"]) if inc.get("destination_ports") else []
    inc["protocols"] = json.loads(inc["protocols"]) if inc.get("protocols") else []
    inc["risk_factors"] = json.loads(inc["risk_factors"]) if inc.get("risk_factors") else {}

    return inc


def update_incident_status(incident_id: str, new_status: str, actor: str = "ANALYST") -> Optional[Dict[str, Any]]:
    """
    Update incident status (NEW, INVESTIGATING, ESCALATED, RESOLVED, REOPEN) and record timeline event.
    """
    status_upper = new_status.upper()
    valid_statuses = {"NEW", "INVESTIGATING", "ESCALATED", "RESOLVED", "REOPEN"}
    if status_upper not in valid_statuses:
        raise ValueError(f"Invalid incident status '{new_status}'. Allowed: {sorted(valid_statuses)}")

    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT status FROM incidents WHERE incident_id = ?", (incident_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return None

    old_status = existing[0]
    now_iso = datetime.now(timezone.utc).isoformat()
    target_status = "NEW" if status_upper == "REOPEN" else status_upper

    cursor.execute(
        "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
        (target_status, now_iso, incident_id),
    )

    event_id = f"EVT-{hashlib.md5(f'{incident_id}{status_upper}{now_iso}'.encode()).hexdigest()[:10]}"
    cursor.execute(
        """
        INSERT INTO incident_timeline (event_id, incident_id, timestamp, event_type, actor, description, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            incident_id,
            now_iso,
            "STATUS_CHANGED",
            actor,
            f"Analyst {actor} changed status from {old_status} to {target_status}.",
            json.dumps({"old_status": old_status, "new_status": target_status}),
        ),
    )

    conn.commit()
    conn.close()
    return get_incident(incident_id)


def assign_incident(incident_id: str, assigned_to: str, actor: str = "ANALYST") -> Optional[Dict[str, Any]]:
    """
    Assign an incident to an analyst and record timeline event.
    """
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    now_iso = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        "UPDATE incidents SET assigned_to = ?, updated_at = ? WHERE incident_id = ?",
        (assigned_to, now_iso, incident_id),
    )

    event_id = f"EVT-{hashlib.md5(f'{incident_id}{assigned_to}{now_iso}'.encode()).hexdigest()[:10]}"
    cursor.execute(
        """
        INSERT INTO incident_timeline (event_id, incident_id, timestamp, event_type, actor, description, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            incident_id,
            now_iso,
            "ASSIGNED",
            actor,
            f"Incident assigned to {assigned_to}.",
            json.dumps({"assigned_to": assigned_to}),
        ),
    )

    conn.commit()
    conn.close()
    return get_incident(incident_id)


def get_incident_alerts(incident_id: str) -> List[Dict[str, Any]]:
    """
    Retrieve all alert records linked to a specific incident.
    """
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT a.*
        FROM alerts a
        JOIN incident_alerts ia ON a.alert_id = ia.alert_id
        WHERE ia.incident_id = ?
        ORDER BY a.created_at DESC
        """,
        (incident_id,),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    for r in rows:
        for k, v in list(r.items()):
            if pd.isna(v):
                r[k] = None

    return rows


def get_incident_timeline(incident_id: str) -> List[Dict[str, Any]]:
    """
    Retrieve chronological event timeline for an incident.
    """
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM incident_timeline
        WHERE incident_id = ?
        ORDER BY timestamp ASC
        """,
        (incident_id,),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    for r in rows:
        r["details"] = json.loads(r["details"]) if r.get("details") else {}

    return rows
