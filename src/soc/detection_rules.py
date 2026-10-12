import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.soc.alert_store import get_connection, initialize_database


# Configurable Rule Engine Thresholds
DEFAULT_CONFIG = {
    "correlation_window_seconds": 300,
    "ssh_alert_threshold": 3,
    "ftp_alert_threshold": 3,
    "dos_alert_threshold": 5,
    "critical_alert_threshold": 3,
}

ALLOWLISTED_FIELDS = {
    "attack_type",
    "severity",
    "source_ip",
    "src_ip",
    "destination_ip",
    "dst_ip",
    "destination_port",
    "dst_port",
    "protocol",
    "confidence",
    "model_confidence",
    "attack_probability",
}

ALLOWLISTED_OPERATORS = {
    "equals",
    "==",
    "eq",
    "not_equals",
    "!=",
    "neq",
    "contains",
    "not_contains",
    "starts_with",
    "ends_with",
    "greater_than",
    ">",
    "gt",
    "greater_than_or_equal",
    ">=",
    "gte",
    "less_than",
    "<",
    "lt",
    "less_than_or_equal",
    "<=",
    "lte",
    "in_list",
}

ALLOWLISTED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

RULE_DEFINITIONS = [
    {
        "rule_id": "RULE-001",
        "rule_name": "Repeated SSH Activity",
        "description": "Triggers when multiple SSH-Bruteforce alerts originate from the same source IP within the correlation window.",
        "severity": "HIGH",
        "threshold_param": "ssh_alert_threshold",
        "default_threshold": 3,
        "threshold_value": 3.0,
        "enabled": True,
        "rule_type": "THRESHOLD",
        "window_seconds": 300,
        "conditions": [{"field": "attack_type", "operator": "contains", "value": "SSH"}],
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "mitre_tactic_id": "TA0006",
        "mitre_tactic_name": "Credential Access",
    },
    {
        "rule_id": "RULE-002",
        "rule_name": "Repeated FTP Brute-Force Activity",
        "description": "Triggers when multiple FTP-BruteForce alerts originate from the same source IP within the correlation window.",
        "severity": "HIGH",
        "threshold_param": "ftp_alert_threshold",
        "default_threshold": 3,
        "threshold_value": 3.0,
        "enabled": True,
        "rule_type": "THRESHOLD",
        "window_seconds": 300,
        "conditions": [{"field": "attack_type", "operator": "contains", "value": "FTP"}],
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "mitre_tactic_id": "TA0006",
        "mitre_tactic_name": "Credential Access",
    },
    {
        "rule_id": "RULE-003",
        "rule_name": "High-Volume DoS/DDoS Activity",
        "description": "Triggers when high-volume DoS or DDoS attack flows surpass the volumetric stream threshold.",
        "severity": "CRITICAL",
        "threshold_param": "dos_alert_threshold",
        "default_threshold": 5,
        "threshold_value": 5.0,
        "enabled": True,
        "rule_type": "THRESHOLD",
        "window_seconds": 300,
        "conditions": [{"field": "attack_type", "operator": "contains", "value": "DOS"}],
        "mitre_technique_id": "T1498",
        "mitre_technique_name": "Network Denial of Service",
        "mitre_tactic_id": "TA0040",
        "mitre_tactic_name": "Impact",
    },
    {
        "rule_id": "RULE-004",
        "rule_name": "Repeated Critical Alerts from Same Source",
        "description": "Triggers when multiple CRITICAL severity alerts are detected from the same source entity.",
        "severity": "CRITICAL",
        "threshold_param": "critical_alert_threshold",
        "default_threshold": 3,
        "threshold_value": 3.0,
        "enabled": True,
        "rule_type": "THRESHOLD",
        "window_seconds": 300,
        "conditions": [{"field": "severity", "operator": "equals", "value": "CRITICAL"}],
        "mitre_technique_id": "T1190",
        "mitre_technique_name": "Exploit Public-Facing Application",
        "mitre_tactic_id": "TA0001",
        "mitre_tactic_name": "Initial Access",
    },
    {
        "rule_id": "RULE-005",
        "rule_name": "Known Malicious Indicator Match",
        "description": "Triggers when network traffic entities match a known malicious indicator in local threat intelligence.",
        "severity": "CRITICAL",
        "threshold_param": "intel_match",
        "default_threshold": 1,
        "threshold_value": 1.0,
        "enabled": True,
        "rule_type": "INTEL_MATCH",
        "window_seconds": 300,
        "conditions": [],
        "mitre_technique_id": "T1071",
        "mitre_technique_name": "Application Layer Protocol",
        "mitre_tactic_id": "TA0011",
        "mitre_tactic_name": "Command and Control",
    },
]


# ============================================================
# STRUCTURED CONDITION EVALUATION ENGINE (SAFE, NO ARBITRARY CODE)
# ============================================================

def _normalize_alert_field(alert: Dict[str, Any], field: str) -> Any:
    field_lower = field.lower()
    if field_lower in {"source_ip", "src_ip"}:
        return alert.get("source_ip") or alert.get("src_ip")
    if field_lower in {"destination_ip", "dst_ip"}:
        return alert.get("destination_ip") or alert.get("dst_ip")
    if field_lower in {"destination_port", "dst_port"}:
        val = alert.get("destination_port") or alert.get("dst_port")
        try:
            return int(float(val)) if val is not None else None
        except Exception:
            return None
    if field_lower in {"confidence", "model_confidence", "attack_probability"}:
        val = alert.get("confidence") or alert.get("model_confidence") or alert.get("attack_probability")
        try:
            return float(val) if val is not None else None
        except Exception:
            return None
    return alert.get(field)


def evaluate_single_condition(alert: Dict[str, Any], condition: Dict[str, Any]) -> Tuple[bool, str]:
    if not isinstance(condition, dict):
        return False, "Invalid condition format"
    field = str(condition.get("field", "")).strip().lower()
    op = str(condition.get("operator", "")).strip().lower()
    expected = condition.get("value")

    if field not in ALLOWLISTED_FIELDS:
        return False, f"Field '{field}' is not in allowlisted fields"
    if op not in ALLOWLISTED_OPERATORS:
        return False, f"Operator '{op}' is not in allowlisted operators"

    actual = _normalize_alert_field(alert, field)
    if actual is None:
        return False, f"Field '{field}' was missing in alert"

    # Numeric comparisons
    if op in {"greater_than", ">", "gt", "greater_than_or_equal", ">=", "gte", "less_than", "<", "lt", "less_than_or_equal", "<=", "lte"}:
        try:
            act_num = float(actual)
            exp_num = float(expected)
        except (ValueError, TypeError):
            return False, f"Non-numeric comparison between actual '{actual}' and expected '{expected}'"

        if op in {"greater_than", ">", "gt"}:
            matched = act_num > exp_num
            return matched, f"{field} ({act_num}) > {exp_num}"
        if op in {"greater_than_or_equal", ">=", "gte"}:
            matched = act_num >= exp_num
            return matched, f"{field} ({act_num}) >= {exp_num}"
        if op in {"less_than", "<", "lt"}:
            matched = act_num < exp_num
            return matched, f"{field} ({act_num}) < {exp_num}"
        if op in {"less_than_or_equal", "<=", "lte"}:
            matched = act_num <= exp_num
            return matched, f"{field} ({act_num}) <= {exp_num}"

    # String comparisons
    act_str = str(actual).strip()
    exp_str = str(expected).strip() if expected is not None else ""

    if op in {"equals", "==", "eq"}:
        matched = act_str.upper() == exp_str.upper()
        return matched, f"{field} ('{act_str}') == '{exp_str}'"
    if op in {"not_equals", "!=", "neq"}:
        matched = act_str.upper() != exp_str.upper()
        return matched, f"{field} ('{act_str}') != '{exp_str}'"
    if op == "contains":
        matched = exp_str.upper() in act_str.upper()
        return matched, f"{field} ('{act_str}') contains '{exp_str}'"
    if op == "not_contains":
        matched = exp_str.upper() not in act_str.upper()
        return matched, f"{field} ('{act_str}') does not contain '{exp_str}'"
    if op == "starts_with":
        matched = act_str.upper().startswith(exp_str.upper())
        return matched, f"{field} ('{act_str}') starts with '{exp_str}'"
    if op == "ends_with":
        matched = act_str.upper().endswith(exp_str.upper())
        return matched, f"{field} ('{act_str}') ends with '{exp_str}'"
    if op == "in_list":
        if isinstance(expected, list):
            candidates = [str(c).strip().upper() for c in expected]
        else:
            candidates = [c.strip().upper() for c in str(expected).split(",") if c.strip()]
        matched = act_str.upper() in candidates
        return matched, f"{field} ('{act_str}') in [{', '.join(candidates)}]"

    return False, f"Unhandled operator '{op}'"


def evaluate_rule_conditions(alert: Dict[str, Any], conditions: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    if not conditions:
        return True, ["No conditions specified; matches by default"]
    explanations = []
    for cond in conditions:
        matched, expl = evaluate_single_condition(alert, cond)
        explanations.append(expl)
        if not matched:
            return False, explanations
    return True, explanations


# ============================================================
# VALIDATION
# ============================================================

def validate_rule_data(rule_data: Dict[str, Any], is_new: bool = True) -> None:
    if not isinstance(rule_data, dict):
        raise ValueError("Rule data must be a dictionary")

    rule_id = str(rule_data.get("rule_id", "")).strip().upper()
    if is_new:
        if not rule_id:
            raise ValueError("rule_id is required")
        if not re.match(r"^[A-Z0-9_\-]{3,64}$", rule_id):
            raise ValueError("rule_id must be 3-64 characters and contain only letters, numbers, hyphens, and underscores")

    rule_name = str(rule_data.get("rule_name", "")).strip()
    if is_new or "rule_name" in rule_data:
        if not rule_name:
            raise ValueError("rule_name is required")
        if len(rule_name) > 200:
            raise ValueError("rule_name must be 200 characters or fewer")

    description = str(rule_data.get("description", "")).strip()
    if is_new or "description" in rule_data:
        if not description:
            raise ValueError("description is required")
        if len(description) > 2000:
            raise ValueError("description must be 2000 characters or fewer")

    severity = str(rule_data.get("severity", "MEDIUM")).strip().upper()
    if severity not in ALLOWLISTED_SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(list(ALLOWLISTED_SEVERITIES))}")

    if "threshold_value" in rule_data and rule_data["threshold_value"] is not None:
        try:
            val = float(rule_data["threshold_value"])
            if val < 1.0 or val > 10000.0:
                raise ValueError("threshold_value must be between 1.0 and 10000.0")
        except (ValueError, TypeError) as exc:
            raise ValueError("threshold_value must be a valid number between 1.0 and 10000.0") from exc

    if "window_seconds" in rule_data and rule_data["window_seconds"] is not None:
        try:
            win = int(rule_data["window_seconds"])
            if win < 10 or win > 86400:
                raise ValueError("window_seconds must be between 10 and 86400 seconds")
        except (ValueError, TypeError) as exc:
            raise ValueError("window_seconds must be a valid integer between 10 and 86400") from exc

    conditions = rule_data.get("conditions")
    if conditions is not None:
        if not isinstance(conditions, list):
            raise ValueError("conditions must be a list of condition objects")
        for idx, cond in enumerate(conditions):
            if not isinstance(cond, dict):
                raise ValueError(f"Condition at index {idx} must be a dictionary")
            field = str(cond.get("field", "")).strip().lower()
            op = str(cond.get("operator", "")).strip().lower()
            if field not in ALLOWLISTED_FIELDS:
                raise ValueError(f"Invalid field '{field}' in condition {idx}. Allowed: {sorted(list(ALLOWLISTED_FIELDS))}")
            if op not in ALLOWLISTED_OPERATORS:
                raise ValueError(f"Invalid operator '{op}' in condition {idx}. Allowed: {sorted(list(ALLOWLISTED_OPERATORS))}")
            if "value" not in cond or cond["value"] is None:
                raise ValueError(f"Missing 'value' in condition {idx}")


# ============================================================
# PERSISTENCE & CRUD OPERATIONS
# ============================================================

def _format_rule_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["enabled"] = bool(d.get("enabled", 1))
    d["threshold_value"] = float(d.get("threshold_value", 1.0))
    d["window_seconds"] = int(d.get("window_seconds", 300))
    d["default_threshold"] = int(d["threshold_value"])
    try:
        d["conditions"] = json.loads(d.get("conditions") or "[]")
    except Exception:
        d["conditions"] = []

    # Map MITRE ATT&CK metadata
    tech_id = d.get("mitre_technique_id")
    if tech_id:
        d["mitre_attack"] = {
            "technique_id": tech_id,
            "technique_name": d.get("mitre_technique_name") or "Technique",
            "tactic_id": d.get("mitre_tactic_id") or "TA0001",
            "tactic_name": d.get("mitre_tactic_name") or "Tactic",
            "mapping_status": "MAPPED",
        }
    else:
        d["mitre_attack"] = {
            "technique_id": None,
            "technique_name": None,
            "tactic_id": None,
            "tactic_name": None,
            "mapping_status": "UNMAPPED",
        }
    return d


def list_rules() -> List[Dict[str, Any]]:
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM detection_rules ORDER BY rule_id ASC")
        rows = cursor.fetchall()
        if rows:
            return [_format_rule_dict(r) for r in rows]
    except Exception:
        pass
    finally:
        conn.close()

    # Fallback to in-memory definitions if DB table is unpopulated
    return [dict(r) for r in RULE_DEFINITIONS]


def get_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    rule_id_clean = str(rule_id or "").strip().upper()
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM detection_rules WHERE UPPER(rule_id) = ?", (rule_id_clean,))
        row = cursor.fetchone()
        if row:
            return _format_rule_dict(row)
    except Exception:
        pass
    finally:
        conn.close()

    for r in RULE_DEFINITIONS:
        if r["rule_id"].upper() == rule_id_clean:
            return dict(r)
    return None


def record_rule_audit(rule_id: str, action: str, analyst: str = "ANALYST", details: Optional[Dict[str, Any]] = None) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    audit_id = f"AUD-{hashlib.sha256(f'{rule_id}:{action}:{now_iso}'.encode()).hexdigest()[:12].upper()}"
    details_str = json.dumps(details or {})
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO detection_rule_audit (audit_id, rule_id, action, analyst, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (audit_id, rule_id, action, analyst, details_str, now_iso),
        )
        conn.commit()
    finally:
        conn.close()


def get_rule_audit(rule_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        if rule_id:
            cursor.execute(
                "SELECT * FROM detection_rule_audit WHERE UPPER(rule_id) = ? ORDER BY timestamp DESC LIMIT ?",
                (str(rule_id).strip().upper(), limit),
            )
        else:
            cursor.execute("SELECT * FROM detection_rule_audit ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        results = []
        for r in rows:
            item = dict(r)
            try:
                item["details"] = json.loads(item.get("details") or "{}")
            except Exception:
                item["details"] = {}
            results.append(item)
        return results
    finally:
        conn.close()


def create_rule(rule_data: Dict[str, Any], analyst: str = "ANALYST") -> Dict[str, Any]:
    validate_rule_data(rule_data, is_new=True)
    rule_id = str(rule_data["rule_id"]).strip().upper()
    existing = get_rule(rule_id)
    if existing:
        raise ValueError(f"Rule with ID '{rule_id}' already exists")

    from src.intel.mitre_attack import MitreAttackEngine
    tech_id = rule_data.get("mitre_technique_id")
    tech_name = rule_data.get("mitre_technique_name")
    tac_id = rule_data.get("mitre_tactic_id")
    tac_name = rule_data.get("mitre_tactic_name")

    if tech_id and (not tech_name or not tac_name):
        techniques = MitreAttackEngine.list_techniques()
        for t in techniques:
            if t["technique_id"].upper() == str(tech_id).upper():
                tech_name = t["technique_name"]
                tac_id = t["tactic_id"]
                tac_name = t["tactic_name"]
                break

    now_iso = datetime.now(timezone.utc).isoformat()
    cond_str = json.dumps(rule_data.get("conditions") or [])

    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO detection_rules (
                rule_id, rule_name, description, severity, enabled, rule_type,
                threshold_param, threshold_value, window_seconds, conditions,
                mitre_technique_id, mitre_technique_name, mitre_tactic_id, mitre_tactic_name,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule_id,
                rule_data["rule_name"],
                rule_data["description"],
                rule_data.get("severity", "MEDIUM").upper(),
                1 if rule_data.get("enabled", True) else 0,
                rule_data.get("rule_type", "CUSTOM").upper(),
                rule_data.get("threshold_param") or f"{rule_id.lower()}_threshold",
                float(rule_data.get("threshold_value", 1.0)),
                int(rule_data.get("window_seconds", 300)),
                cond_str,
                tech_id,
                tech_name,
                tac_id,
                tac_name,
                now_iso,
                now_iso,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    record_rule_audit(
        rule_id=rule_id,
        action="CREATED",
        analyst=analyst,
        details={"rule_name": rule_data["rule_name"], "severity": rule_data.get("severity")},
    )
    return get_rule(rule_id)  # type: ignore


def update_rule(rule_id: str, updates: Dict[str, Any], analyst: str = "ANALYST") -> Optional[Dict[str, Any]]:
    rule_id_clean = str(rule_id).strip().upper()
    existing = get_rule(rule_id_clean)
    if not existing:
        return None

    validate_rule_data(updates, is_new=False)
    now_iso = datetime.now(timezone.utc).isoformat()

    rule_name = updates.get("rule_name", existing["rule_name"])
    description = updates.get("description", existing["description"])
    severity = updates.get("severity", existing["severity"]).upper()
    threshold_value = float(updates.get("threshold_value", existing["threshold_value"]))
    window_seconds = int(updates.get("window_seconds", existing["window_seconds"]))
    conditions = updates.get("conditions", existing.get("conditions", []))
    cond_str = json.dumps(conditions)

    tech_id = updates.get("mitre_technique_id", existing.get("mitre_technique_id"))
    tech_name = updates.get("mitre_technique_name", existing.get("mitre_technique_name"))
    tac_id = updates.get("mitre_tactic_id", existing.get("mitre_tactic_id"))
    tac_name = updates.get("mitre_tactic_name", existing.get("mitre_tactic_name"))

    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE detection_rules
            SET rule_name = ?, description = ?, severity = ?, threshold_value = ?,
                window_seconds = ?, conditions = ?, mitre_technique_id = ?,
                mitre_technique_name = ?, mitre_tactic_id = ?, mitre_tactic_name = ?,
                updated_at = ?
            WHERE UPPER(rule_id) = ?
            """,
            (
                rule_name,
                description,
                severity,
                threshold_value,
                window_seconds,
                cond_str,
                tech_id,
                tech_name,
                tac_id,
                tac_name,
                now_iso,
                rule_id_clean,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    record_rule_audit(
        rule_id=rule_id_clean,
        action="UPDATED",
        analyst=analyst,
        details={"updated_fields": list(updates.keys())},
    )
    return get_rule(rule_id_clean)


def set_rule_status(rule_id: str, enabled: bool, analyst: str = "ANALYST") -> Optional[Dict[str, Any]]:
    rule_id_clean = str(rule_id).strip().upper()
    existing = get_rule(rule_id_clean)
    if not existing:
        return None

    now_iso = datetime.now(timezone.utc).isoformat()
    val = 1 if enabled else 0

    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE detection_rules SET enabled = ?, updated_at = ? WHERE UPPER(rule_id) = ?",
            (val, now_iso, rule_id_clean),
        )
        conn.commit()
    finally:
        conn.close()

    record_rule_audit(
        rule_id=rule_id_clean,
        action="ENABLED" if enabled else "DISABLED",
        analyst=analyst,
        details={"previous_state": existing.get("enabled"), "new_state": enabled},
    )
    return get_rule(rule_id_clean)


def duplicate_rule(source_rule_id: str, new_rule_id: str, new_rule_name: str, analyst: str = "ANALYST") -> Optional[Dict[str, Any]]:
    src = get_rule(source_rule_id)
    if not src:
        return None

    new_rule_data = {
        "rule_id": new_rule_id,
        "rule_name": new_rule_name,
        "description": f"Duplicated from {src['rule_id']}: {src['description']}",
        "severity": src["severity"],
        "enabled": True,
        "rule_type": "CUSTOM" if src.get("rule_type") == "THRESHOLD" else src.get("rule_type", "CUSTOM"),
        "threshold_value": src.get("threshold_value", 1.0),
        "threshold_param": f"{new_rule_id.lower()}_threshold",
        "window_seconds": src.get("window_seconds", 300),
        "conditions": src.get("conditions", []),
        "mitre_technique_id": src.get("mitre_technique_id"),
        "mitre_technique_name": src.get("mitre_technique_name"),
        "mitre_tactic_id": src.get("mitre_tactic_id"),
        "mitre_tactic_name": src.get("mitre_tactic_name"),
    }
    created = create_rule(new_rule_data, analyst=analyst)
    record_rule_audit(
        rule_id=new_rule_data["rule_id"],
        action="DUPLICATED",
        analyst=analyst,
        details={"duplicated_from": source_rule_id},
    )
    return created


# ============================================================
# BOUNDED OFFLINE PREVIEW & SANDBOX ENGINE
# ============================================================

REFERENCE_OFFLINE_SAMPLES = [
    {
        "alert_id": "PREVIEW-SSH-01",
        "timestamp": "2026-10-12T09:00:00Z",
        "attack_type": "SSH-Bruteforce",
        "severity": "HIGH",
        "confidence": 0.95,
        "source_ip": "192.0.2.45",
        "destination_ip": "10.0.0.12",
        "destination_port": 22,
        "protocol": "TCP",
    },
    {
        "alert_id": "PREVIEW-SSH-02",
        "timestamp": "2026-10-12T09:01:00Z",
        "attack_type": "SSH-Bruteforce",
        "severity": "HIGH",
        "confidence": 0.98,
        "source_ip": "192.0.2.45",
        "destination_ip": "10.0.0.12",
        "destination_port": 22,
        "protocol": "TCP",
    },
    {
        "alert_id": "PREVIEW-SSH-03",
        "timestamp": "2026-10-12T09:02:00Z",
        "attack_type": "SSH-Bruteforce",
        "severity": "HIGH",
        "confidence": 0.99,
        "source_ip": "192.0.2.45",
        "destination_ip": "10.0.0.12",
        "destination_port": 22,
        "protocol": "TCP",
    },
    {
        "alert_id": "PREVIEW-FTP-01",
        "timestamp": "2026-10-12T09:03:00Z",
        "attack_type": "FTP-BruteForce",
        "severity": "HIGH",
        "confidence": 0.92,
        "source_ip": "198.51.100.18",
        "destination_ip": "10.0.0.15",
        "destination_port": 21,
        "protocol": "TCP",
    },
    {
        "alert_id": "PREVIEW-DOS-01",
        "timestamp": "2026-10-12T09:04:00Z",
        "attack_type": "DoS attacks-Hulk",
        "severity": "CRITICAL",
        "confidence": 0.96,
        "source_ip": "203.0.113.100",
        "destination_ip": "10.0.0.5",
        "destination_port": 80,
        "protocol": "TCP",
    },
    {
        "alert_id": "PREVIEW-DOS-02",
        "timestamp": "2026-10-12T09:04:15Z",
        "attack_type": "DDOS attack-HOIC",
        "severity": "CRITICAL",
        "confidence": 0.97,
        "source_ip": "203.0.113.101",
        "destination_ip": "10.0.0.5",
        "destination_port": 80,
        "protocol": "TCP",
    },
    {
        "alert_id": "PREVIEW-SQLI-01",
        "timestamp": "2026-10-12T09:05:00Z",
        "attack_type": "SQL Injection",
        "severity": "CRITICAL",
        "confidence": 0.89,
        "source_ip": "198.51.100.77",
        "destination_ip": "10.0.0.8",
        "destination_port": 443,
        "protocol": "TCP",
    },
    {
        "alert_id": "PREVIEW-BOT-01",
        "timestamp": "2026-10-12T09:06:00Z",
        "attack_type": "Bot",
        "severity": "HIGH",
        "confidence": 0.85,
        "source_ip": "198.51.100.88",
        "destination_ip": "10.0.0.22",
        "destination_port": 8080,
        "protocol": "TCP",
    },
    {
        "alert_id": "PREVIEW-NORM-01",
        "timestamp": "2026-10-12T09:07:00Z",
        "attack_type": "Benign",
        "severity": "LOW",
        "confidence": 0.10,
        "source_ip": "10.0.0.200",
        "destination_ip": "10.0.0.1",
        "destination_port": 53,
        "protocol": "UDP",
    },
]


def get_preview_sample_candidates(limit: int = 50) -> List[Dict[str, Any]]:
    samples: List[Dict[str, Any]] = []
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT alert_id, timestamp, attack_type, severity, confidence, source_ip, destination_ip, destination_port, protocol
            FROM alerts
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        for r in cursor.fetchall():
            samples.append(dict(r))
    except Exception:
        pass
    finally:
        conn.close()

    # If fewer than 5 alerts exist in the DB, append reference test vectors
    if len(samples) < 5:
        existing_ids = {s.get("alert_id") for s in samples}
        for ref in REFERENCE_OFFLINE_SAMPLES:
            if ref["alert_id"] not in existing_ids:
                samples.append(dict(ref))

    return samples[:limit]


def preview_rule_execution(
    rule_dict: Dict[str, Any],
    sample_alerts: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Safely execute a rule draft or modified threshold against bounded offline sample flows.
    This strictly performs read-only, in-memory evaluation and DOES NOT create alerts or alter database state.
    """
    validate_rule_data(rule_dict, is_new=False)
    if sample_alerts is None:
        sample_alerts = get_preview_sample_candidates(limit=50)

    matched_samples = []
    conditions = rule_dict.get("conditions") or []
    rule_type = rule_dict.get("rule_type", "THRESHOLD")
    threshold = float(rule_dict.get("threshold_value") or 1.0)
    rule_id = rule_dict.get("rule_id", "PREVIEW-RULE")
    rule_name = rule_dict.get("rule_name", "Preview Rule")

    # Evaluate against samples
    for sample in sample_alerts:
        matched = False
        reasons: List[str] = []

        # Check conditions
        if conditions:
            cond_matched, cond_reasons = evaluate_rule_conditions(sample, conditions)
            if cond_matched:
                matched = True
                reasons = cond_reasons
        else:
            # Fallback for built-in rule definitions in preview
            atk = str(sample.get("attack_type", "")).upper()
            sev = str(sample.get("severity", "")).upper()
            if rule_id == "RULE-001" and "SSH" in atk:
                matched = True
                reasons.append(f"Attack type matches SSH activity ('{sample.get('attack_type')}')")
            elif rule_id == "RULE-002" and "FTP" in atk:
                matched = True
                reasons.append(f"Attack type matches FTP activity ('{sample.get('attack_type')}')")
            elif rule_id == "RULE-003" and "DOS" in atk:
                matched = True
                reasons.append(f"Attack type matches DoS/DDoS flow ('{sample.get('attack_type')}')")
            elif rule_id == "RULE-004" and sev == "CRITICAL":
                matched = True
                reasons.append(f"Severity is CRITICAL ('{sample.get('severity')}')")
            elif rule_id == "RULE-005":
                matched = True
                reasons.append("Threat intelligence indicator matching enabled")

        if matched:
            matched_samples.append({
                "alert_id": sample.get("alert_id") or "SAMPLE-FLOW",
                "timestamp": sample.get("timestamp") or sample.get("created_at"),
                "attack_type": sample.get("attack_type"),
                "severity": sample.get("severity"),
                "source_ip": sample.get("source_ip") or sample.get("src_ip"),
                "destination_port": sample.get("destination_port") or sample.get("dst_port"),
                "confidence": sample.get("confidence"),
                "reason": "; ".join(reasons),
                "matched": True,
            })

    total_evaluated = len(sample_alerts)
    match_count = len(matched_samples)
    match_pct = round((match_count / max(total_evaluated, 1)) * 100.0, 1)

    return {
        "preview": True,
        "is_offline_preview": True,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "threshold_value": threshold,
        "total_samples_evaluated": total_evaluated,
        "match_count": match_count,
        "match_percentage": match_pct,
        "matches": matched_samples,
        "summary": f"{match_count} of {total_evaluated} sample telemetry records matched ({match_pct}%). Preview mode did not alter production alerts or incidents.",
    }


# ============================================================
# DETERMINISTIC DETECTION RULE ENGINE
# ============================================================

class DetectionRuleEngine:
    """
    Deterministic Detection Rule Engine for CyberSentinel.
    Evaluates enabled behavioral, threshold, and custom threat rules against network telemetry.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.custom_config = dict(config) if config else {}
        self.config = dict(DEFAULT_CONFIG)
        if config:
            self.config.update(config)

    def evaluate_rules(
        self,
        alert_dict: Dict[str, Any],
        recent_alerts: Optional[List[Dict[str, Any]]] = None,
        intel_match: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Evaluate all active detection rules for an incoming alert dictionary.

        Returns:
            List of matched RuleMatch dictionary objects.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        src_ip = alert_dict.get("source_ip") or alert_dict.get("src_ip")
        attack_type = str(alert_dict.get("attack_type", ""))
        severity = str(alert_dict.get("severity", "MEDIUM")).upper()

        if recent_alerts is None:
            recent_alerts = []

        # Load currently configured rules (respecting enable/disable states and custom thresholds)
        all_rules = list_rules()
        rule_map = {r["rule_id"].upper(): r for r in all_rules}

        r1 = rule_map.get("RULE-001")
        window_sec = int(self.custom_config.get("correlation_window_seconds") or (r1.get("window_seconds") if r1 else 300) or 300)

        # Filter recent alerts within correlation window
        valid_alerts = []
        for r in recent_alerts:
            ts_val = r.get("timestamp") or r.get("created_at")
            if ts_val:
                try:
                    alert_dt = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
                    diff = abs((datetime.now(timezone.utc) - alert_dt).total_seconds())
                    if diff <= window_sec:
                        valid_alerts.append(r)
                except Exception:
                    valid_alerts.append(r)
            else:
                valid_alerts.append(r)

        matched_rules = []

        # --- Rule 1: Repeated SSH Activity ---
        if r1 is None or r1.get("enabled", True):
            ssh_thresh = self.custom_config.get("ssh_alert_threshold") or (r1.get("threshold_value") if r1 else 3) or 3
            ssh_thresh = int(float(ssh_thresh))
            if "SSH" in attack_type.upper():
                ssh_count = 1 + sum(
                    1 for a in valid_alerts
                    if "SSH" in str(a.get("attack_type", "")).upper() and (not src_ip or a.get("source_ip") == src_ip)
                )
                if ssh_count >= ssh_thresh:
                    matched_rules.append({
                        "rule_id": "RULE-001",
                        "rule_name": r1.get("rule_name", "Repeated SSH Activity") if r1 else "Repeated SSH Activity",
                        "matched": True,
                        "severity": r1.get("severity", "HIGH") if r1 else "HIGH",
                        "reason": f"Detected {ssh_count} SSH brute-force alerts from source '{src_ip or 'Local'}' (Threshold: {ssh_thresh}).",
                        "evidence": {"ssh_count": ssh_count, "threshold": ssh_thresh, "source_ip": src_ip},
                        "timestamp": now_iso,
                    })

        # --- Rule 2: Repeated FTP Brute-Force Activity ---
        r2 = rule_map.get("RULE-002")
        if r2 is None or r2.get("enabled", True):
            ftp_thresh = self.custom_config.get("ftp_alert_threshold") or (r2.get("threshold_value") if r2 else 3) or 3
            ftp_thresh = int(float(ftp_thresh))
            if "FTP" in attack_type.upper():
                ftp_count = 1 + sum(
                    1 for a in valid_alerts
                    if "FTP" in str(a.get("attack_type", "")).upper() and (not src_ip or a.get("source_ip") == src_ip)
                )
                if ftp_count >= ftp_thresh:
                    matched_rules.append({
                        "rule_id": "RULE-002",
                        "rule_name": r2.get("rule_name", "Repeated FTP Brute-Force Activity") if r2 else "Repeated FTP Brute-Force Activity",
                        "matched": True,
                        "severity": r2.get("severity", "HIGH") if r2 else "HIGH",
                        "reason": f"Detected {ftp_count} FTP brute-force alerts from source '{src_ip or 'Local'}' (Threshold: {ftp_thresh}).",
                        "evidence": {"ftp_count": ftp_count, "threshold": ftp_thresh, "source_ip": src_ip},
                        "timestamp": now_iso,
                    })

        # --- Rule 3: High-Volume DoS/DDoS Activity ---
        r3 = rule_map.get("RULE-003")
        if r3 is None or r3.get("enabled", True):
            dos_thresh = self.custom_config.get("dos_alert_threshold") or (r3.get("threshold_value") if r3 else 5) or 5
            dos_thresh = int(float(dos_thresh))
            if "DOS" in attack_type.upper():
                dos_count = 1 + sum(
                    1 for a in valid_alerts
                    if "DOS" in str(a.get("attack_type", "")).upper()
                )
                if dos_count >= dos_thresh:
                    matched_rules.append({
                        "rule_id": "RULE-003",
                        "rule_name": r3.get("rule_name", "High-Volume DoS/DDoS Activity") if r3 else "High-Volume DoS/DDoS Activity",
                        "matched": True,
                        "severity": r3.get("severity", "CRITICAL") if r3 else "CRITICAL",
                        "reason": f"Detected high-volume DoS/DDoS stream ({dos_count} flows) exceeding threshold ({dos_thresh}).",
                        "evidence": {"dos_count": dos_count, "threshold": dos_thresh},
                        "timestamp": now_iso,
                    })

        # --- Rule 4: Repeated Critical Alerts ---
        r4 = rule_map.get("RULE-004")
        if r4 is None or r4.get("enabled", True):
            crit_thresh = self.custom_config.get("critical_alert_threshold") or (r4.get("threshold_value") if r4 else 3) or 3
            crit_thresh = int(float(crit_thresh))
            if severity == "CRITICAL":
                crit_count = 1 + sum(
                    1 for a in valid_alerts
                    if str(a.get("severity", "")).upper() == "CRITICAL" and (not src_ip or a.get("source_ip") == src_ip)
                )
                if crit_count >= crit_thresh:
                    matched_rules.append({
                        "rule_id": "RULE-004",
                        "rule_name": r4.get("rule_name", "Repeated Critical Alerts from Same Source") if r4 else "Repeated Critical Alerts from Same Source",
                        "matched": True,
                        "severity": r4.get("severity", "CRITICAL") if r4 else "CRITICAL",
                        "reason": f"Accumulated {crit_count} CRITICAL severity alerts for source '{src_ip or 'Local'}' (Threshold: {crit_thresh}).",
                        "evidence": {"critical_count": crit_count, "threshold": crit_thresh, "source_ip": src_ip},
                        "timestamp": now_iso,
                    })

        # --- Rule 5: Known Malicious Indicator Match ---
        r5 = rule_map.get("RULE-005")
        if r5 is None or r5.get("enabled", True):
            if intel_match:
                threat_name = intel_match.get("threat_name", "Known Threat")
                ind_val = intel_match.get("indicator_value", src_ip)
                matched_rules.append({
                    "rule_id": "RULE-005",
                    "rule_name": r5.get("rule_name", "Known Malicious Indicator Match") if r5 else "Known Malicious Indicator Match",
                    "matched": True,
                    "severity": intel_match.get("severity", r5.get("severity", "CRITICAL") if r5 else "CRITICAL"),
                    "reason": f"Entity '{ind_val}' matched threat intelligence indicator '{threat_name}' ({intel_match.get('source', 'Threat Intel')}).",
                    "evidence": {
                        "indicator_value": ind_val,
                        "threat_name": threat_name,
                        "intel_confidence": intel_match.get("confidence", 0.90),
                        "intel_source": intel_match.get("source", "LOCAL_SOC"),
                    },
                    "timestamp": now_iso,
                })

        # --- Custom & Condition-Based Rules (Phase 7) ---
        for rule in all_rules:
            r_id = rule["rule_id"].upper()
            if r_id in {"RULE-001", "RULE-002", "RULE-003", "RULE-004", "RULE-005"}:
                continue  # Handled above
            if not rule.get("enabled", True):
                continue  # Disabled rule

            conditions = rule.get("conditions") or []
            if not conditions:
                continue

            matches_current, explanations = evaluate_rule_conditions(alert_dict, conditions)
            if not matches_current:
                continue

            threshold = int(float(rule.get("threshold_value", 1.0)))
            rule_win = int(rule.get("window_seconds", 300))

            # Filter valid alerts within this rule's specific window
            matching_recent = 0
            for r in recent_alerts:
                ts_val = r.get("timestamp") or r.get("created_at")
                if ts_val:
                    try:
                        alert_dt = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
                        diff = abs((datetime.now(timezone.utc) - alert_dt).total_seconds())
                        if diff > rule_win:
                            continue
                    except Exception:
                        pass
                m_hist, _ = evaluate_rule_conditions(r, conditions)
                if m_hist:
                    matching_recent += 1

            total_count = 1 + matching_recent
            if total_count >= threshold:
                matched_rules.append({
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["rule_name"],
                    "matched": True,
                    "severity": rule.get("severity", "HIGH"),
                    "reason": f"Custom rule condition matched ({'; '.join(explanations)}) with {total_count} occurrences (Threshold: {threshold}).",
                    "evidence": {
                        "occurrences": total_count,
                        "threshold": threshold,
                        "conditions": conditions,
                        "window_seconds": rule_win,
                    },
                    "timestamp": now_iso,
                })

        return matched_rules
