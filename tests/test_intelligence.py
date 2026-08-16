import os
import sys
import unittest
from datetime import datetime, timezone

import pandas as pd
import pytest
from fastapi.testclient import TestClient

# Add workspace root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.api.main import app
from src.intel.enrichment import enrich_alert, enrich_incident
from src.intel.indicator_store import IndicatorStore
from src.intel.mitre_attack import ATTACK_VERSION, MitreAttackEngine
from src.soc.alert_store import get_connection, initialize_database
from src.soc.detection_rules import DetectionRuleEngine, get_rule, list_rules

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM threat_intel_indicators")
    cursor.execute("DELETE FROM detection_rule_matches")
    cursor.execute("DELETE FROM incident_timeline")
    cursor.execute("DELETE FROM incident_alerts")
    cursor.execute("DELETE FROM incidents")
    cursor.execute("DELETE FROM alerts WHERE alert_id LIKE 'test_%'")
    conn.commit()
    conn.close()
    yield


class TestCyberSentinelIntelligencePhase3B:

    def test_01_indicator_creation(self):
        ind = IndicatorStore.add_indicator({
            "indicator_type": "IP",
            "indicator_value": "198.51.100.55",
            "threat_name": "APT29 Command Node",
            "confidence": 0.95,
            "severity": "CRITICAL",
            "source": "STIX_FEED",
            "description": "Known C2 Server",
        })
        assert ind is not None
        assert ind["indicator_value"] == "198.51.100.55"
        assert ind["threat_name"] == "APT29 Command Node"
        assert ind["severity"] == "CRITICAL"
        assert ind["confidence"] == 0.95

    def test_02_indicator_lookup(self):
        IndicatorStore.add_indicator({
            "indicator_type": "DOMAIN",
            "indicator_value": "malicious-c2.org",
            "threat_name": "BadDomain",
            "confidence": 0.90,
            "severity": "HIGH",
        })
        found = IndicatorStore.search_indicator("malicious-c2.org")
        assert found is not None
        assert found["indicator_type"] == "DOMAIN"
        assert found["threat_name"] == "BadDomain"

    def test_03_indicator_matching(self):
        IndicatorStore.add_indicator({
            "indicator_type": "IP",
            "indicator_value": "203.0.113.88",
            "threat_name": "Lazarus IP",
            "severity": "CRITICAL",
        })
        match = IndicatorStore.match_indicator("203.0.113.88", entity_type="IP")
        assert match is not None
        assert match["threat_name"] == "Lazarus IP"

    def test_04_no_match_behavior(self):
        match = IndicatorStore.match_indicator("1.1.1.1", entity_type="IP")
        assert match is None

    def test_05_alert_enrichment(self):
        IndicatorStore.add_indicator({
            "indicator_type": "IP",
            "indicator_value": "10.50.60.70",
            "threat_name": "Scraper Bot",
            "severity": "HIGH",
        })
        alert = {
            "alert_id": "test_intel_01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "SSH-Bruteforce",
            "severity": "HIGH",
            "confidence": 0.92,
            "source_ip": "10.50.60.70",
            "destination_port": 22,
        }
        enriched = enrich_alert(alert)
        assert enriched["intel_match"] is True
        assert enriched["intel_threat_name"] == "Scraper Bot"
        assert enriched["model_confidence"] == 0.92  # Preserved
        assert enriched["mitre_attack"]["technique_id"] == "T1110"

    def test_06_incident_enrichment(self):
        alert_1 = {
            "alert_id": "test_inc_intel_01",
            "attack_type": "SSH-Bruteforce",
            "source_ip": "198.51.100.99",
            "confidence": 0.95,
            "severity": "HIGH",
        }
        IndicatorStore.add_indicator({
            "indicator_type": "IP",
            "indicator_value": "198.51.100.99",
            "threat_name": "Brute Force Botnet",
        })
        inc = {
            "incident_id": "INC-TEST-01",
            "primary_attack_type": "SSH-Bruteforce",
            "severity": "HIGH",
            "risk_score": 75.0,
        }
        enriched = enrich_incident(inc, correlated_alerts=[alert_1])
        assert enriched["intel_match_count"] == 1
        assert "Brute Force Botnet" in enriched["threat_names"]
        assert enriched["mitre_attack"]["technique_id"] == "T1110"

    def test_07_rule_evaluation(self):
        alert = {
            "alert_id": "test_rule_01",
            "attack_type": "SSH-Bruteforce",
            "severity": "HIGH",
            "source_ip": "10.0.0.99",
        }
        recent = [
            {"attack_type": "SSH-Bruteforce", "source_ip": "10.0.0.99", "timestamp": datetime.now(timezone.utc).isoformat()},
            {"attack_type": "SSH-Bruteforce", "source_ip": "10.0.0.99", "timestamp": datetime.now(timezone.utc).isoformat()},
        ]
        engine = DetectionRuleEngine()
        matches = engine.evaluate_rules(alert, recent_alerts=recent)
        rule_ids = [m["rule_id"] for m in matches]
        assert "RULE-001" in rule_ids

    def test_08_rule_threshold_behavior(self):
        alert = {
            "alert_id": "test_rule_thresh",
            "attack_type": "SSH-Bruteforce",
            "source_ip": "10.0.0.1",
        }
        # Thresh 5
        engine = DetectionRuleEngine(config={"ssh_alert_threshold": 5})
        matches = engine.evaluate_rules(alert, recent_alerts=[])
        assert len(matches) == 0

    def test_09_mitre_mapping_lookup(self):
        mapping = MitreAttackEngine.get_mitre_mapping("SSH-Bruteforce")
        assert mapping["technique_id"] == "T1110"
        assert mapping["tactic_name"] == "Credential Access"
        assert mapping["mapping_status"] == "MAPPED"

    def test_10_unknown_unmapped_behavior(self):
        mapping = MitreAttackEngine.get_mitre_mapping("Unknown Custom Attack")
        assert mapping["technique_id"] is None
        assert mapping["mapping_status"] == "UNMAPPED"

    def test_11_attack_version_reporting(self):
        cov = MitreAttackEngine.get_coverage()
        assert cov["attack_version"] == "19.0"
        assert "MITRE ATT&CK Enterprise v19.0" in cov["dataset_source"]

    def test_12_risk_score_enrichment(self):
        from src.soc.incident_engine import calculate_risk_score
        score, factors = calculate_risk_score(
            highest_severity="HIGH",
            alert_count=3,
            confidence=0.95,
            attack_types=["SSH-Bruteforce"],
            duration_seconds=120.0,
        )
        assert score > 60.0
        assert factors["volume_bonus"] == 6.0
        assert factors["duration_bonus"] == 5.0

    def test_13_api_endpoints(self):
        # 1. POST /api/intel/indicators
        resp = client.post(
            "/api/intel/indicators",
            json={
                "indicator_type": "IP",
                "indicator_value": "198.51.100.200",
                "threat_name": "API Test Threat",
                "severity": "HIGH",
            },
        )
        assert resp.status_code == 200
        ind_id = resp.json()["indicator"]["indicator_id"]

        # 2. GET /api/intel/indicators
        resp = client.get("/api/intel/indicators")
        assert resp.status_code == 200
        assert resp.json()["count"] > 0

        # 3. GET /api/rules
        resp = client.get("/api/rules")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 5

        # 4. GET /api/mitre/coverage
        resp = client.get("/api/mitre/coverage")
        assert resp.status_code == 200
        assert resp.json()["attack_version"] == "19.0"

        # 5. DELETE /api/intel/indicators/{id}
        resp = client.delete(f"/api/intel/indicators/{ind_id}")
        assert resp.status_code == 200

    def test_14_existing_incidents_suite(self):
        # Ensure Phase 3A incident correlation works with Phase 3B modules loaded
        from src.soc.incident_engine import IncidentEngine
        inc_id = IncidentEngine.correlate_alert({
            "alert_id": "test_integ_01",
            "attack_type": "DoS attacks-Hulk",
            "severity": "HIGH",
            "confidence": 0.90,
            "destination_port": 80,
            "protocol": "TCP",
            "source_ip": "10.0.0.77",
        })
        assert inc_id is not None
        assert inc_id.startswith("INC-")

    def test_15_existing_network_suite(self):
        # Verify network module definitions intact
        from src.network.packet_capture import PacketCapture
        cap = PacketCapture()
        assert cap.packets_captured == 0

    def test_16_existing_streaming_suite(self):
        # Verify stream manager definitions intact
        from src.streaming.stream_manager import StreamManager
        sm = StreamManager()
        status = sm.get_status()
        assert status["status"] == "STOPPED"

    def test_17_indicator_validation_rejection_invalid_ip(self):
        # Must reject 102.202.290.1 because 290 is not a valid IPv4 octet
        with pytest.raises(ValueError, match="Invalid IP address format"):
            IndicatorStore.add_indicator({
                "indicator_type": "IP",
                "indicator_value": "102.202.290.1",
                "threat_name": "Invalid IP Test",
            })

    def test_18_indicator_validation_rejection_invalid_domain(self):
        # Must reject domain syntax without top-level domain
        with pytest.raises(ValueError, match="Invalid domain syntax"):
            IndicatorStore.add_indicator({
                "indicator_type": "DOMAIN",
                "indicator_value": "invalid_domain_name",
                "threat_name": "Invalid Domain Test",
            })

    def test_19_indicator_validation_success_private_ip(self):
        # Add valid documentation test IP 192.0.2.100
        ind = IndicatorStore.add_indicator({
            "indicator_type": "IP",
            "indicator_value": "192.0.2.100",
            "threat_name": "Documentation Test IP",
            "severity": "HIGH",
        })
        assert ind is not None
        indicators = IndicatorStore.list_indicators()
        assert len(indicators) == 1
        assert indicators[0]["indicator_value"] == "192.0.2.100"
