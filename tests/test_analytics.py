import os
import sys
from datetime import datetime, timezone

import pandas as pd
import pytest
from fastapi.testclient import TestClient

# Add workspace root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.analytics.dataset_analytics import get_historical_dataset_analytics
from src.analytics.model_monitor import get_model_monitoring_metrics
from src.analytics.soc_analytics import (
    get_attack_activity_trends,
    get_attack_distribution,
    get_incident_analytics,
    get_protocol_analytics,
    get_severity_analytics,
    get_summary_metrics,
    get_top_entities,
)
from src.api.main import app
from src.soc.alert_store import get_connection, initialize_database, sync_alerts

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


class TestCyberSentinelAnalyticsPhase4:

    def test_01_summary_metrics(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        df = pd.DataFrame([
            {"alert_id": "test_an_01", "timestamp": now_iso, "attack_type": "SSH-Bruteforce", "severity": "HIGH", "confidence": 0.95, "source_ip": "10.0.0.1", "destination_port": 22, "protocol": "TCP"},
            {"alert_id": "test_an_02", "timestamp": now_iso, "attack_type": "BENIGN", "severity": "LOW", "confidence": 0.10, "source_ip": "10.0.0.2", "destination_port": 80, "protocol": "TCP"},
        ])
        sync_alerts(df)

        metrics = get_summary_metrics("24h")
        assert metrics["total_alerts"] >= 2
        assert metrics["critical_alerts"] >= 0
        assert metrics["attack_rate"] > 0.0

    def test_02_time_window_filtering(self):
        m_15m = get_summary_metrics("15m")
        m_1h = get_summary_metrics("1h")
        m_24h = get_summary_metrics("24h")
        m_7d = get_summary_metrics("7d")
        m_all = get_summary_metrics("all")

        assert m_15m["window"] == "15m"
        assert m_1h["window"] == "1h"
        assert m_24h["window"] == "24h"
        assert m_7d["window"] == "7d"
        assert m_all["window"] == "all"

    def test_03_attack_trends(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        df = pd.DataFrame([
            {"alert_id": "test_trend_01", "timestamp": now_iso, "attack_type": "DoS attacks-Hulk", "severity": "CRITICAL", "confidence": 0.98},
        ])
        sync_alerts(df)

        trends = get_attack_activity_trends("24h")
        assert isinstance(trends, list)
        if trends:
            assert "timestamp" in trends[0]
            assert "total_alerts" in trends[0]

    def test_04_attack_distribution(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        df = pd.DataFrame([
            {"alert_id": "test_dist_01", "timestamp": now_iso, "attack_type": "Bot", "severity": "MEDIUM", "confidence": 0.85},
        ])
        sync_alerts(df)

        dist = get_attack_distribution("24h")
        assert isinstance(dist, list)
        if dist:
            assert "attack_type" in dist[0]
            assert "percentage" in dist[0]

    def test_05_severity_distribution(self):
        sev_res = get_severity_analytics("24h")
        assert "distribution" in sev_res
        assert "CRITICAL" in sev_res["distribution"]
        assert "HIGH" in sev_res["distribution"]

    def test_06_entity_analytics(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        df = pd.DataFrame([
            {"alert_id": "test_ent_01", "timestamp": now_iso, "attack_type": "FTP-BruteForce", "severity": "CRITICAL", "confidence": 0.99, "source_ip": "192.168.1.100", "destination_ip": "10.0.0.5", "destination_port": 21},
        ])
        sync_alerts(df)

        entities = get_top_entities("24h", limit=5)
        assert "top_sources" in entities
        assert "top_destinations" in entities
        assert "top_ports" in entities

    def test_07_protocol_analytics(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        df = pd.DataFrame([
            {"alert_id": "test_proto_01", "timestamp": now_iso, "attack_type": "Bot", "severity": "LOW", "confidence": 0.50, "protocol": "UDP"},
        ])
        sync_alerts(df)

        proto = get_protocol_analytics("24h")
        assert isinstance(proto, list)
        udp_item = next((p for p in proto if p["protocol"] == "UDP"), None)
        assert udp_item is not None

    def test_08_incident_analytics(self):
        inc_res = get_incident_analytics("24h")
        assert "open_incidents" in inc_res
        assert "resolved_incidents" in inc_res
        assert "severity_distribution" in inc_res

    def test_09_model_monitoring(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        df = pd.DataFrame([
            {"alert_id": "test_mon_01", "timestamp": now_iso, "attack_type": "SSH-Bruteforce", "severity": "HIGH", "confidence": 0.95},
            {"alert_id": "test_mon_02", "timestamp": now_iso, "attack_type": "BENIGN", "severity": "LOW", "confidence": 0.40},
        ])
        sync_alerts(df)

        mon = get_model_monitoring_metrics("24h")
        assert "stage1_metrics" in mon
        assert "stage2_metrics" in mon
        assert "monitoring_indicators" in mon
        assert mon["stage1_metrics"]["low_confidence_count"] >= 1

    def test_10_dataset_analytics(self):
        ds = get_historical_dataset_analytics()
        assert ds["total_flows"] > 0
        assert ds["train_flows"] > 0
        assert "class_distribution" in ds

    def test_11_empty_data_behavior(self):
        # Empty window check
        metrics = get_summary_metrics("15m")
        assert metrics["total_alerts"] == 0
        assert metrics["mean_confidence"] is None
        assert metrics["mttr_seconds"] is None

    def test_12_api_endpoints(self):
        endpoints = [
            "/api/analytics/summary",
            "/api/analytics/trends",
            "/api/analytics/attacks",
            "/api/analytics/severity",
            "/api/analytics/entities",
            "/api/analytics/protocols",
            "/api/analytics/incidents",
            "/api/analytics/model",
            "/api/analytics/dataset",
        ]
        for ep in endpoints:
            resp = client.get(ep)
            assert resp.status_code == 200

    def test_13_pyspark_aggregation_path(self):
        ds = get_historical_dataset_analytics("data/processed/ml-full")
        assert ds is not None
        assert "total_flows" in ds
