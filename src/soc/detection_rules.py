import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.soc.alert_store import get_connection, initialize_database


# Configurable Rule Engine Thresholds
DEFAULT_CONFIG = {
    "correlation_window_seconds": 300,
    "ssh_alert_threshold": 3,
    "ftp_alert_threshold": 3,
    "dos_alert_threshold": 5,
    "critical_alert_threshold": 3,
}

RULE_DEFINITIONS = [
    {
        "rule_id": "RULE-001",
        "rule_name": "Repeated SSH Activity",
        "description": "Triggers when multiple SSH-Bruteforce alerts originate from the same source IP within the correlation window.",
        "severity": "HIGH",
        "threshold_param": "ssh_alert_threshold",
        "default_threshold": 3,
    },
    {
        "rule_id": "RULE-002",
        "rule_name": "Repeated FTP Brute-Force Activity",
        "description": "Triggers when multiple FTP-BruteForce alerts originate from the same source IP within the correlation window.",
        "severity": "HIGH",
        "threshold_param": "ftp_alert_threshold",
        "default_threshold": 3,
    },
    {
        "rule_id": "RULE-003",
        "rule_name": "High-Volume DoS/DDoS Activity",
        "description": "Triggers when high-volume DoS or DDoS attack flows surpass the volumetric stream threshold.",
        "severity": "CRITICAL",
        "threshold_param": "dos_alert_threshold",
        "default_threshold": 5,
    },
    {
        "rule_id": "RULE-004",
        "rule_name": "Repeated Critical Alerts from Same Source",
        "description": "Triggers when multiple CRITICAL severity alerts are detected from the same source entity.",
        "severity": "CRITICAL",
        "threshold_param": "critical_alert_threshold",
        "default_threshold": 3,
    },
    {
        "rule_id": "RULE-005",
        "rule_name": "Known Malicious Indicator Match",
        "description": "Triggers when network traffic entities match a known malicious indicator in local threat intelligence.",
        "severity": "CRITICAL",
        "threshold_param": "intel_match",
        "default_threshold": 1,
    },
]


class DetectionRuleEngine:
    """
    Deterministic Detection Rule Engine for CyberSentinel (Phase 3B).
    Evaluates behavioral threat rules against network telemetry and threat intelligence.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
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
        Evaluate all detection rules for an incoming alert dictionary.

        Returns:
            List of matched RuleMatch dictionary objects.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        src_ip = alert_dict.get("source_ip") or alert_dict.get("src_ip")
        attack_type = str(alert_dict.get("attack_type", ""))
        severity = str(alert_dict.get("severity", "MEDIUM")).upper()

        if recent_alerts is None:
            recent_alerts = []

        # Filter recent alerts within correlation window
        window_sec = self.config.get("correlation_window_seconds", 300)
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

        # Rule 1: Repeated SSH Activity
        ssh_thresh = self.config.get("ssh_alert_threshold", 3)
        if "SSH" in attack_type.upper():
            ssh_count = 1 + sum(1 for a in valid_alerts if "SSH" in str(a.get("attack_type", "")).upper() and (not src_ip or a.get("source_ip") == src_ip))
            if ssh_count >= ssh_thresh:
                matched_rules.append({
                    "rule_id": "RULE-001",
                    "rule_name": "Repeated SSH Activity",
                    "matched": True,
                    "severity": "HIGH",
                    "reason": f"Detected {ssh_count} SSH brute-force alerts from source '{src_ip or 'Local'}' (Threshold: {ssh_thresh}).",
                    "evidence": {"ssh_count": ssh_count, "threshold": ssh_thresh, "source_ip": src_ip},
                    "timestamp": now_iso,
                })

        # Rule 2: Repeated FTP Brute-Force Activity
        ftp_thresh = self.config.get("ftp_alert_threshold", 3)
        if "FTP" in attack_type.upper():
            ftp_count = 1 + sum(1 for a in valid_alerts if "FTP" in str(a.get("attack_type", "")).upper() and (not src_ip or a.get("source_ip") == src_ip))
            if ftp_count >= ftp_thresh:
                matched_rules.append({
                    "rule_id": "RULE-002",
                    "rule_name": "Repeated FTP Brute-Force Activity",
                    "matched": True,
                    "severity": "HIGH",
                    "reason": f"Detected {ftp_count} FTP brute-force alerts from source '{src_ip or 'Local'}' (Threshold: {ftp_thresh}).",
                    "evidence": {"ftp_count": ftp_count, "threshold": ftp_thresh, "source_ip": src_ip},
                    "timestamp": now_iso,
                })

        # Rule 3: High-Volume DoS/DDoS Activity
        dos_thresh = self.config.get("dos_alert_threshold", 5)
        if "DOS" in attack_type.upper():
            dos_count = 1 + sum(1 for a in valid_alerts if "DOS" in str(a.get("attack_type", "")).upper())
            if dos_count >= dos_thresh:
                matched_rules.append({
                    "rule_id": "RULE-003",
                    "rule_name": "High-Volume DoS/DDoS Activity",
                    "matched": True,
                    "severity": "CRITICAL",
                    "reason": f"Detected high-volume DoS/DDoS stream ({dos_count} flows) exceeding threshold ({dos_thresh}).",
                    "evidence": {"dos_count": dos_count, "threshold": dos_thresh},
                    "timestamp": now_iso,
                })

        # Rule 4: Repeated Critical Alerts
        crit_thresh = self.config.get("critical_alert_threshold", 3)
        if severity == "CRITICAL":
            crit_count = 1 + sum(1 for a in valid_alerts if str(a.get("severity", "")).upper() == "CRITICAL" and (not src_ip or a.get("source_ip") == src_ip))
            if crit_count >= crit_thresh:
                matched_rules.append({
                    "rule_id": "RULE-004",
                    "rule_name": "Repeated Critical Alerts from Same Source",
                    "matched": True,
                    "severity": "CRITICAL",
                    "reason": f"Accumulated {crit_count} CRITICAL severity alerts for source '{src_ip or 'Local'}' (Threshold: {crit_thresh}).",
                    "evidence": {"critical_count": crit_count, "threshold": crit_thresh, "source_ip": src_ip},
                    "timestamp": now_iso,
                })

        # Rule 5: Known Malicious Indicator Match
        if intel_match:
            threat_name = intel_match.get("threat_name", "Known Threat")
            ind_val = intel_match.get("indicator_value", src_ip)
            matched_rules.append({
                "rule_id": "RULE-005",
                "rule_name": "Known Malicious Indicator Match",
                "matched": True,
                "severity": intel_match.get("severity", "CRITICAL"),
                "reason": f"Entity '{ind_val}' matched threat intelligence indicator '{threat_name}' ({intel_match.get('source', 'Threat Intel')}).",
                "evidence": {
                    "indicator_value": ind_val,
                    "threat_name": threat_name,
                    "intel_confidence": intel_match.get("confidence", 0.90),
                    "intel_source": intel_match.get("source", "LOCAL_SOC"),
                },
                "timestamp": now_iso,
            })

        return matched_rules


def get_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    for r in RULE_DEFINITIONS:
        if r["rule_id"].upper() == rule_id.upper():
            return dict(r)
    return None


def list_rules() -> List[Dict[str, Any]]:
    return [dict(r) for r in RULE_DEFINITIONS]
