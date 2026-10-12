import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.soc.alert_store import get_connection, initialize_database
from src.soc.detection_rules import (
    DetectionRuleEngine,
    create_rule,
    duplicate_rule,
    get_preview_sample_candidates,
    get_rule,
    get_rule_audit,
    list_rules,
    preview_rule_execution,
    set_rule_status,
    update_rule,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_test_rules():
    initialize_database()
    conn = get_connection()
    # Clean up custom/created test rules and test audits, but leave the 5 default rules intact
    conn.execute("DELETE FROM detection_rule_audit")
    conn.execute("DELETE FROM detection_rules WHERE rule_id LIKE 'TEST-%' OR rule_id LIKE 'RULE-006%' OR rule_id LIKE '%-CLONE'")
    # Ensure default rules are enabled and have standard thresholds
    conn.execute("UPDATE detection_rules SET enabled = 1 WHERE rule_id LIKE 'RULE-00%'")
    conn.commit()
    conn.close()
    yield


def test_01_default_rules_registered_and_enabled():
    rules = list_rules()
    assert len(rules) >= 5
    rule_ids = {r["rule_id"] for r in rules}
    assert {"RULE-001", "RULE-002", "RULE-003", "RULE-004", "RULE-005"}.issubset(rule_ids)

    r1 = get_rule("RULE-001")
    assert r1 is not None
    assert r1["rule_name"] == "Repeated SSH Activity"
    assert r1["severity"] == "HIGH"
    assert r1["enabled"] is True
    assert r1["threshold_value"] == 3.0
    assert r1["mitre_attack"]["technique_id"] == "T1110"


def test_02_create_rule_and_validation():
    # Valid creation
    new_rule = {
        "rule_id": "TEST-RULE-SQLI",
        "rule_name": "Repeated SQL Injection Flows",
        "description": "Triggers when SQL injection payloads are detected across web services.",
        "severity": "CRITICAL",
        "rule_type": "CUSTOM",
        "threshold_value": 2.0,
        "window_seconds": 180,
        "enabled": True,
        "conditions": [{"field": "attack_type", "operator": "contains", "value": "SQL"}],
        "mitre_technique_id": "T1190",
    }
    created = create_rule(new_rule, analyst="SecOps-Analyst-1")
    assert created is not None
    assert created["rule_id"] == "TEST-RULE-SQLI"
    assert created["threshold_value"] == 2.0
    assert created["window_seconds"] == 180
    assert created["mitre_attack"]["technique_id"] == "T1190"

    # Reject duplicate rule_id
    with pytest.raises(ValueError, match="already exists"):
        create_rule(new_rule)

    # Reject invalid rule_id syntax
    with pytest.raises(ValueError, match="rule_id must be 3-64 characters"):
        create_rule({"rule_id": "!!BAD!!", "rule_name": "Test", "description": "Test", "severity": "HIGH"})

    # Reject invalid severity
    with pytest.raises(ValueError, match="severity must be one of"):
        create_rule({"rule_id": "TEST-SEV", "rule_name": "Test", "description": "Test", "severity": "EXTREME"})

    # Reject unallowlisted condition field
    with pytest.raises(ValueError, match="Invalid field 'malicious_code'"):
        create_rule({
            "rule_id": "TEST-BAD-FIELD",
            "rule_name": "Test",
            "description": "Test",
            "severity": "HIGH",
            "conditions": [{"field": "malicious_code", "operator": "equals", "value": "test"}],
        })

    # Reject unallowlisted operator
    with pytest.raises(ValueError, match="Invalid operator 'eval'"):
        create_rule({
            "rule_id": "TEST-BAD-OP",
            "rule_name": "Test",
            "description": "Test",
            "severity": "HIGH",
            "conditions": [{"field": "attack_type", "operator": "eval", "value": "test"}],
        })


def test_03_enable_disable_affects_detection_engine():
    alert = {
        "alert_id": "test_ssh_alert",
        "attack_type": "SSH-Bruteforce",
        "severity": "HIGH",
        "source_ip": "198.51.100.22",
    }
    recent = [
        {"attack_type": "SSH-Bruteforce", "source_ip": "198.51.100.22", "timestamp": datetime.now(timezone.utc).isoformat()},
        {"attack_type": "SSH-Bruteforce", "source_ip": "198.51.100.22", "timestamp": datetime.now(timezone.utc).isoformat()},
    ]

    # Enabled: Should match RULE-001 (threshold 3)
    engine = DetectionRuleEngine()
    matches = engine.evaluate_rules(alert, recent_alerts=recent)
    assert any(m["rule_id"] == "RULE-001" for m in matches)

    # Disable RULE-001
    disabled_rule = set_rule_status("RULE-001", enabled=False, analyst="Lead-Analyst")
    assert disabled_rule["enabled"] is False

    # Disabled: DetectionRuleEngine must NOT match RULE-001
    matches_after_disable = engine.evaluate_rules(alert, recent_alerts=recent)
    assert not any(m["rule_id"] == "RULE-001" for m in matches_after_disable)

    # Re-enable RULE-001
    set_rule_status("RULE-001", enabled=True, analyst="Lead-Analyst")
    matches_after_enable = engine.evaluate_rules(alert, recent_alerts=recent)
    assert any(m["rule_id"] == "RULE-001" for m in matches_after_enable)


def test_04_threshold_adjustment_and_evaluation():
    alert = {
        "alert_id": "test_ssh_thresh",
        "attack_type": "SSH-Bruteforce",
        "severity": "HIGH",
        "source_ip": "10.0.0.55",
    }
    recent = [
        {"attack_type": "SSH-Bruteforce", "source_ip": "10.0.0.55", "timestamp": datetime.now(timezone.utc).isoformat()},
        {"attack_type": "SSH-Bruteforce", "source_ip": "10.0.0.55", "timestamp": datetime.now(timezone.utc).isoformat()},
    ]

    # Baseline threshold is 3 -> matches
    engine = DetectionRuleEngine()
    assert any(m["rule_id"] == "RULE-001" for m in engine.evaluate_rules(alert, recent_alerts=recent))

    # Increase threshold to 10
    update_rule("RULE-001", {"threshold_value": 10.0}, analyst="Tuning-Analyst")
    r1 = get_rule("RULE-001")
    assert r1["threshold_value"] == 10.0

    # With threshold 10, 3 occurrences should NOT trigger
    matches_tuned = engine.evaluate_rules(alert, recent_alerts=recent)
    assert not any(m["rule_id"] == "RULE-001" for m in matches_tuned)


def test_05_rule_duplication():
    duplicated = duplicate_rule("RULE-001", "TEST-RULE-001-CLONE", "SSH Brute-Force Stricter Clone", analyst="Analyst-B")
    assert duplicated is not None
    assert duplicated["rule_id"] == "TEST-RULE-001-CLONE"
    assert duplicated["rule_name"] == "SSH Brute-Force Stricter Clone"
    assert duplicated["mitre_attack"]["technique_id"] == "T1110"


def test_06_offline_preview_sandbox_isolation():
    # Preview must safely return match results without inserting alerts or changing incidents
    conn = get_connection()
    c_alerts_before = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
    c_incidents_before = conn.execute("SELECT count(*) FROM incidents").fetchone()[0]
    conn.close()

    rule_dict = {
        "rule_id": "TEST-PREVIEW-SSH",
        "rule_name": "Preview SSH Rule",
        "severity": "HIGH",
        "threshold_value": 1.0,
        "conditions": [{"field": "attack_type", "operator": "contains", "value": "SSH"}],
    }
    samples = get_preview_sample_candidates(limit=25)
    assert len(samples) > 0

    preview = preview_rule_execution(rule_dict, sample_alerts=samples)
    assert preview["preview"] is True
    assert preview["is_offline_preview"] is True
    assert preview["total_samples_evaluated"] == len(samples)
    assert preview["match_count"] >= 1
    assert preview["matches"][0]["matched"] is True
    assert "attack_type" in preview["matches"][0]["reason"]

    # Verify database state remained completely untouched
    conn = get_connection()
    c_alerts_after = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
    c_incidents_after = conn.execute("SELECT count(*) FROM incidents").fetchone()[0]
    conn.close()

    assert c_alerts_after == c_alerts_before
    assert c_incidents_after == c_incidents_before


def test_07_audit_trail_logging():
    rule_data = {
        "rule_id": "TEST-AUDIT-01",
        "rule_name": "Audit Tracked Rule",
        "description": "Rule to test audit logging",
        "severity": "MEDIUM",
        "threshold_value": 2.0,
        "conditions": [{"field": "attack_type", "operator": "equals", "value": "Bot"}],
    }
    create_rule(rule_data, analyst="Auditor-Alice")
    update_rule("TEST-AUDIT-01", {"severity": "HIGH"}, analyst="Auditor-Bob")
    set_rule_status("TEST-AUDIT-01", enabled=False, analyst="Auditor-Charlie")

    history = get_rule_audit("TEST-AUDIT-01")
    assert len(history) == 3
    actions = [h["action"] for h in history]
    analysts = [h["analyst"] for h in history]

    assert actions == ["DISABLED", "UPDATED", "CREATED"]
    assert analysts == ["Auditor-Charlie", "Auditor-Bob", "Auditor-Alice"]


def test_08_api_endpoints_and_error_handling():
    # 1. GET /api/rules
    resp = client.get("/api/rules")
    assert resp.status_code == 200
    assert resp.json()["count"] >= 5

    # 2. POST /api/rules (Create)
    resp = client.post(
        "/api/rules",
        json={
            "rule_id": "TEST-API-01",
            "rule_name": "API Created Rule",
            "description": "Created via FastAPI",
            "severity": "HIGH",
            "threshold_value": 3.0,
            "window_seconds": 300,
            "conditions": [{"field": "attack_type", "operator": "contains", "value": "DoS"}],
            "actor": "API-Analyst",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["rule"]["rule_id"] == "TEST-API-01"

    # 3. GET /api/rules/{rule_id}
    resp = client.get("/api/rules/TEST-API-01")
    assert resp.status_code == 200
    assert resp.json()["rule"]["rule_name"] == "API Created Rule"

    # 4. PUT /api/rules/{rule_id} (Update)
    resp = client.put(
        "/api/rules/TEST-API-01",
        json={"rule_name": "API Updated Name", "threshold_value": 5.0, "actor": "API-Tuner"},
    )
    assert resp.status_code == 200
    assert resp.json()["rule"]["threshold_value"] == 5.0

    # 5. POST /api/rules/{rule_id}/status (Disable)
    resp = client.post("/api/rules/TEST-API-01/status", json={"enabled": False, "actor": "API-Admin"})
    assert resp.status_code == 200
    assert resp.json()["rule"]["enabled"] is False

    # 6. POST /api/rules/{rule_id}/duplicate
    resp = client.post(
        "/api/rules/TEST-API-01/duplicate",
        json={"new_rule_id": "TEST-API-01-CLONE", "new_rule_name": "API Cloned Rule", "actor": "API-Cloner"},
    )
    assert resp.status_code == 200
    assert resp.json()["rule"]["rule_id"] == "TEST-API-01-CLONE"

    # 7. POST /api/rules/preview (Preview endpoint)
    resp = client.post(
        "/api/rules/preview",
        json={
            "rule": {
                "rule_id": "PREVIEW-TEST",
                "rule_name": "Preview Test",
                "severity": "HIGH",
                "conditions": [{"field": "attack_type", "operator": "contains", "value": "SSH"}],
            }
        },
    )
    assert resp.status_code == 200
    assert resp.json()["preview"] is True
    assert resp.json()["match_count"] >= 1

    # 8. GET /api/rules/preview-samples
    resp = client.get("/api/rules/preview-samples?limit=10")
    assert resp.status_code == 200
    assert resp.json()["count"] > 0

    # 9. GET /api/rules/{rule_id}/audit
    resp = client.get("/api/rules/TEST-API-01/audit")
    assert resp.status_code == 200
    assert resp.json()["count"] >= 3

    # 10. Error cases: 404 for missing rule
    assert client.get("/api/rules/RULE-NONEXISTENT").status_code == 404
    assert client.get("/api/rules/RULE-NONEXISTENT/audit").status_code == 404
    assert client.post("/api/rules/RULE-NONEXISTENT/status", json={"enabled": True}).status_code == 404

    # 11. Error cases: 400 for bad condition field in preview
    resp = client.post(
        "/api/rules/preview",
        json={
            "rule": {
                "rule_id": "BAD-PREVIEW",
                "rule_name": "Bad Preview",
                "conditions": [{"field": "unsafe_field", "operator": "equals", "value": "x"}],
            }
        },
    )
    assert resp.status_code == 400
