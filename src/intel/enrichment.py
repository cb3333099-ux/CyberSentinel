from typing import Any, Dict, List, Optional

import pandas as pd
from src.intel.indicator_store import IndicatorStore
from src.intel.mitre_attack import MitreAttackEngine
from src.soc.detection_rules import DetectionRuleEngine


def enrich_alert(alert_dict: Dict[str, Any], recent_alerts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Enrich an alert dictionary with Threat Intelligence, Detection Rules, and MITRE ATT&CK mapping.

    Keeps ML confidence and Threat Intel confidence strictly separate.
    """
    enriched = dict(alert_dict)

    # 1. Preserve ML metrics
    ml_confidence = float(alert_dict.get("confidence") or alert_dict.get("attack_probability") or 0.0)
    ml_severity = str(alert_dict.get("severity") or "MEDIUM").upper()

    enriched["model_confidence"] = ml_confidence
    enriched["model_severity"] = ml_severity

    # 2. Extract Entities & Match Threat Intelligence
    src_ip = alert_dict.get("source_ip") or alert_dict.get("src_ip")
    dst_ip = alert_dict.get("destination_ip") or alert_dict.get("dst_ip")

    intel_match = None
    if src_ip:
        intel_match = IndicatorStore.match_indicator(str(src_ip), entity_type="IP")
    if not intel_match and dst_ip:
        intel_match = IndicatorStore.match_indicator(str(dst_ip), entity_type="IP")

    if intel_match:
        enriched["intel_match"] = True
        enriched["intel_threat_name"] = intel_match.get("threat_name", "Known Threat")
        enriched["intel_confidence"] = float(intel_match.get("confidence", 0.90))
        enriched["intel_severity"] = str(intel_match.get("severity", "HIGH")).upper()
        enriched["intel_source"] = intel_match.get("source", "LOCAL_SOC")
    else:
        enriched["intel_match"] = False
        enriched["intel_threat_name"] = None
        enriched["intel_confidence"] = None
        enriched["intel_severity"] = None
        enriched["intel_source"] = None

    # 3. Evaluate Detection Rules
    rule_engine = DetectionRuleEngine()
    matched_rules = rule_engine.evaluate_rules(alert_dict, recent_alerts=recent_alerts, intel_match=intel_match)
    enriched["rules_triggered"] = matched_rules
    enriched["rules_triggered_count"] = len(matched_rules)

    # 4. Map MITRE ATT&CK Framework
    attack_type = str(alert_dict.get("attack_type") or alert_dict.get("attack_label") or "Threat Detected")
    rule_ids = [r["rule_id"] for r in matched_rules]
    mitre_data = MitreAttackEngine.get_mitre_mapping(attack_type, rule_ids=rule_ids)
    enriched["mitre_attack"] = mitre_data

    return enriched


def enrich_incident(incident_dict: Dict[str, Any], correlated_alerts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Enrich an incident dictionary with aggregated Threat Intelligence, Rule matches, and MITRE ATT&CK data.
    """
    enriched = dict(incident_dict)

    if correlated_alerts is None:
        correlated_alerts = []

    intel_matches = []
    rules_triggered = []
    threat_names = set()
    intel_sources = set()

    for a in correlated_alerts:
        e_alert = enrich_alert(a)
        if e_alert.get("intel_match"):
            intel_matches.append(e_alert)
            if e_alert.get("intel_threat_name"):
                threat_names.add(e_alert["intel_threat_name"])
            if e_alert.get("intel_source"):
                intel_sources.add(e_alert["intel_source"])
        if e_alert.get("rules_triggered"):
            rules_triggered.extend(e_alert["rules_triggered"])

    enriched["intel_match_count"] = len(intel_matches)
    enriched["threat_names"] = sorted(list(threat_names))
    enriched["intel_sources"] = sorted(list(intel_sources))
    enriched["intel_severity"] = "HIGH" if intel_matches else "NONE"
    enriched["intel_confidence"] = max([m.get("intel_confidence", 0.0) for m in intel_matches], default=0.0)
    enriched["rules_triggered_count"] = len(rules_triggered)

    # MITRE ATT&CK Mapping for Incident
    primary_attack = incident_dict.get("primary_attack_type", "Threat Detected")
    enriched["mitre_attack"] = MitreAttackEngine.get_mitre_mapping(primary_attack)

    return enriched
