import time
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.soc.alert_store import get_connection, initialize_database, sync_alerts
from src.soc.incident_engine import (
    IncidentEngine,
    assign_incident,
    calculate_risk_score,
    get_incident,
    get_incident_alerts,
    get_incident_timeline,
    get_incidents,
    update_incident_status,
)


@pytest.fixture(autouse=True)
def setup_db():
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM incident_timeline")
    cursor.execute("DELETE FROM incident_alerts")
    cursor.execute("DELETE FROM incidents")
    cursor.execute("DELETE FROM alerts WHERE alert_id LIKE 'test_%'")
    conn.commit()
    conn.close()
    yield


client = TestClient(app)


class TestCyberSentinelIncidentsPhase3A:
    """
    Phase 3A Incident Correlation & Analyst Workspace Test Suite.
    """

    def test_01_new_incident_creation(self):
        alert_dict = {
            "alert_id": "test_alert_01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "SSH-Bruteforce",
            "severity": "HIGH",
            "confidence": 0.95,
            "destination_port": 22,
            "protocol": "TCP",
            "source_ip": "10.0.0.5",
            "destination_ip": "192.168.1.10",
        }

        inc_id = IncidentEngine.correlate_alert(alert_dict)
        assert inc_id is not None
        assert inc_id.startswith("INC-")

        inc = get_incident(inc_id)
        assert inc is not None
        assert inc["primary_attack_type"] == "SSH-Bruteforce"
        assert inc["severity"] == "HIGH"
        assert inc["alert_count"] == 1
        assert inc["risk_score"] >= 60.0
        assert "10.0.0.5" in inc["source_entities"]

    def test_02_alert_correlation_same_source(self):
        ts_now = datetime.now(timezone.utc).isoformat()

        alert_1 = {
            "alert_id": "test_corr_01",
            "timestamp": ts_now,
            "attack_type": "SSH-Bruteforce",
            "severity": "HIGH",
            "confidence": 0.90,
            "destination_port": 22,
            "protocol": "TCP",
            "source_ip": "10.0.0.50",
            "destination_ip": "192.168.1.100",
        }

        alert_2 = {
            "alert_id": "test_corr_02",
            "timestamp": ts_now,
            "attack_type": "SSH-Bruteforce",
            "severity": "HIGH",
            "confidence": 0.98,
            "destination_port": 22,
            "protocol": "TCP",
            "source_ip": "10.0.0.50",
            "destination_ip": "192.168.1.100",
        }

        inc_id_1 = IncidentEngine.correlate_alert(alert_1)
        inc_id_2 = IncidentEngine.correlate_alert(alert_2)

        assert inc_id_1 == inc_id_2

        inc = get_incident(inc_id_1)
        assert inc["alert_count"] == 2
        assert len(inc["source_entities"]) == 1
        assert inc["source_entities"][0] == "10.0.0.50"

    def test_03_separate_source_separation(self):
        ts_now = datetime.now(timezone.utc).isoformat()

        alert_source_a = {
            "alert_id": "test_sep_01",
            "timestamp": ts_now,
            "attack_type": "SSH-Bruteforce",
            "severity": "HIGH",
            "confidence": 0.90,
            "destination_port": 22,
            "protocol": "TCP",
            "source_ip": "10.0.0.88",
            "destination_ip": "192.168.1.10",
        }

        alert_source_b = {
            "alert_id": "test_sep_02",
            "timestamp": ts_now,
            "attack_type": "DDoS attacks-LOIC-HTTP",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "destination_port": 80,
            "protocol": "TCP",
            "source_ip": "10.0.0.99",
            "destination_ip": "192.168.1.20",
        }

        inc_id_a = IncidentEngine.correlate_alert(alert_source_a)
        inc_id_b = IncidentEngine.correlate_alert(alert_source_b)

        assert inc_id_a != inc_id_b

        inc_a = get_incident(inc_id_a)
        inc_b = get_incident(inc_id_b)

        assert inc_a["source_entities"] == ["10.0.0.88"]
        assert inc_b["source_entities"] == ["10.0.0.99"]

    def test_04_time_window_separation(self):
        # Alert A at t=0
        t_0 = datetime.now(timezone.utc) - timedelta(minutes=10)
        alert_old = {
            "alert_id": "test_time_01",
            "timestamp": t_0.isoformat(),
            "attack_type": "DoS attacks-Hulk",
            "severity": "HIGH",
            "confidence": 0.90,
            "destination_port": 80,
            "protocol": "TCP",
            "source_ip": "172.16.0.5",
            "destination_ip": "10.0.0.1",
        }

        inc_id_old = IncidentEngine.correlate_alert(alert_old, time_window_seconds=300)

        # Alert B at t=10 min (> 5 min time window)
        t_new = datetime.now(timezone.utc)
        alert_new = {
            "alert_id": "test_time_02",
            "timestamp": t_new.isoformat(),
            "attack_type": "DoS attacks-Hulk",
            "severity": "HIGH",
            "confidence": 0.92,
            "destination_port": 80,
            "protocol": "TCP",
            "source_ip": "172.16.0.5",
            "destination_ip": "10.0.0.1",
        }

        inc_id_new = IncidentEngine.correlate_alert(alert_new, time_window_seconds=300)

        assert inc_id_old != inc_id_new

    def test_05_risk_score_calculation(self):
        # Critical base = 80.0
        score_1, factors_1 = calculate_risk_score(
            highest_severity="CRITICAL",
            alert_count=1,
            confidence=0.9,
            attack_types=["DDOS attack-HOIC"],
            duration_seconds=0.0,
        )
        assert score_1 >= 80.0
        assert score_1 <= 100.0
        assert factors_1["base_score"] == 80.0

        # Multi-alert + multi-attack escalation
        score_2, factors_2 = calculate_risk_score(
            highest_severity="HIGH",
            alert_count=5,
            confidence=0.95,
            attack_types=["SSH-Bruteforce", "FTP-BruteForce"],
            duration_seconds=120.0,
        )
        # Base 60 + Volume (4*3=12) + Diversity (1*5=5) + Conf (9.5) + Duration (5) = ~91.5
        assert score_2 > 85.0
        assert score_2 <= 100.0
        assert factors_2["volume_bonus"] == 12.0
        assert factors_2["diversity_bonus"] == 5.0

    def test_06_related_alerts_retrieval(self):
        ts_now = datetime.now(timezone.utc).isoformat()
        alert_1 = {
            "alert_id": "test_rel_01",
            "timestamp": ts_now,
            "attack_type": "Bot",
            "severity": "MEDIUM",
            "confidence": 0.85,
            "destination_port": 8080,
            "protocol": "TCP",
            "source_ip": "192.168.1.50",
        }
        alert_2 = {
            "alert_id": "test_rel_02",
            "timestamp": ts_now,
            "attack_type": "Bot",
            "severity": "HIGH",
            "confidence": 0.95,
            "destination_port": 8080,
            "protocol": "TCP",
            "source_ip": "192.168.1.50",
        }

        # Sync through alert store
        df = pd.DataFrame([alert_1, alert_2])
        sync_alerts(df)

        incidents = get_incidents()
        matching_inc = [inc for inc in incidents if "192.168.1.50" in inc["source_entities"]]
        assert len(matching_inc) > 0

        inc_id = matching_inc[0]["incident_id"]
        rel_alerts = get_incident_alerts(inc_id)
        assert len(rel_alerts) >= 2

    def test_07_incident_status_update(self):
        alert_dict = {
            "alert_id": "test_stat_01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "Infilteration",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "destination_port": 443,
            "protocol": "TCP",
            "source_ip": "10.10.10.10",
        }
        inc_id = IncidentEngine.correlate_alert(alert_dict)

        # Status transitions
        updated_1 = update_incident_status(inc_id, "INVESTIGATING", actor="Analyst-John")
        assert updated_1["status"] == "INVESTIGATING"

        updated_2 = update_incident_status(inc_id, "ESCALATED", actor="SOC-Lead")
        assert updated_2["status"] == "ESCALATED"

        updated_3 = update_incident_status(inc_id, "RESOLVED", actor="SOC-Lead")
        assert updated_3["status"] == "RESOLVED"

        updated_4 = update_incident_status(inc_id, "REOPEN", actor="Analyst-John")
        assert updated_4["status"] == "NEW"

    def test_08_timeline_persistence(self):
        alert_dict = {
            "alert_id": "test_tm_01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "SQL Injection",
            "severity": "HIGH",
            "confidence": 0.92,
            "destination_port": 80,
            "protocol": "TCP",
            "source_ip": "192.168.2.20",
        }
        inc_id = IncidentEngine.correlate_alert(alert_dict)

        assign_incident(inc_id, "Analyst-Alice", actor="Admin")
        update_incident_status(inc_id, "INVESTIGATING", actor="Analyst-Alice")

        timeline = get_incident_timeline(inc_id)
        assert len(timeline) >= 3

        event_types = [e["event_type"] for e in timeline]
        assert "INCIDENT_CREATED" in event_types
        assert "ASSIGNED" in event_types
        assert "STATUS_CHANGED" in event_types

    def test_09_entity_aggregation(self):
        ts_now = datetime.now(timezone.utc).isoformat()
        alert_1 = {
            "alert_id": "test_ent_01",
            "timestamp": ts_now,
            "attack_type": "Brute Force -Web",
            "severity": "MEDIUM",
            "confidence": 0.80,
            "destination_port": 80,
            "protocol": "TCP",
            "source_ip": "10.0.0.100",
            "destination_ip": "192.168.1.1",
        }
        alert_2 = {
            "alert_id": "test_ent_02",
            "timestamp": ts_now,
            "attack_type": "Brute Force -Web",
            "severity": "HIGH",
            "confidence": 0.88,
            "destination_port": 443,
            "protocol": "TCP",
            "source_ip": "10.0.0.100",
            "destination_ip": "192.168.1.2",
        }

        inc_id_1 = IncidentEngine.correlate_alert(alert_1)
        inc_id_2 = IncidentEngine.correlate_alert(alert_2)

        assert inc_id_1 == inc_id_2

        inc = get_incident(inc_id_1)
        assert inc["source_entities"] == ["10.0.0.100"]
        assert sorted(inc["destination_entities"]) == ["192.168.1.1", "192.168.1.2"]
        assert sorted(inc["destination_ports"]) == [80, 443]

    def test_10_api_incidents_endpoints(self):
        # Create incident
        alert_dict = {
            "alert_id": "test_api_inc_01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "DoS attacks-Slowloris",
            "severity": "HIGH",
            "confidence": 0.94,
            "destination_port": 80,
            "protocol": "TCP",
            "source_ip": "10.20.30.40",
        }
        inc_id = IncidentEngine.correlate_alert(alert_dict)

        # 1. GET /api/incidents
        resp = client.get("/api/incidents")
        assert resp.status_code == 200
        data = resp.json()
        assert "incidents" in data
        assert data["count"] > 0

        # 2. GET /api/incidents/{incident_id}
        resp = client.get(f"/api/incidents/{inc_id}")
        assert resp.status_code == 200
        inc_data = resp.json().get("incident")
        assert inc_data["incident_id"] == inc_id

        # 3. POST /api/incidents/{incident_id}/status
        resp = client.post(f"/api/incidents/{inc_id}/status", json={"status": "INVESTIGATING", "actor": "TestAnalyst"})
        assert resp.status_code == 200
        assert resp.json()["incident"]["status"] == "INVESTIGATING"

        # 4. POST /api/incidents/{incident_id}/assign
        resp = client.post(f"/api/incidents/{inc_id}/assign", json={"assigned_to": "Analyst-Bob", "actor": "Lead"})
        assert resp.status_code == 200
        assert resp.json()["incident"]["assigned_to"] == "Analyst-Bob"

        # 5. GET /api/incidents/{incident_id}/alerts
        resp = client.get(f"/api/incidents/{inc_id}/alerts")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

        # 6. GET /api/incidents/{incident_id}/timeline
        resp = client.get(f"/api/incidents/{inc_id}/timeline")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    def test_11_existing_alert_workflow_intact(self):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        assert "alerts" in resp.json()

        resp_metrics = client.get("/api/metrics")
        assert resp_metrics.status_code == 200

        resp_status = client.get("/api/metrics/status")
        assert resp_status.status_code == 200
