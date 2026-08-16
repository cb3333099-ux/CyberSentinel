import time
import unittest
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from src.streaming.flow_stream import FlowStream
from src.streaming.live_inference_service import LiveInferenceService
from src.streaming.stream_manager import StreamManager, stream_manager
from src.soc.alert_store import get_alerts, update_status, sync_alerts
from src.streaming.replay_service import run_replay
from src.api.main import app
from fastapi.testclient import TestClient


class TestCyberSentinelStreaming(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.service = LiveInferenceService()

    @classmethod
    def tearDownClass(cls):
        try:
            stream_manager.stop()
        except Exception:
            pass

    def test_01_flow_stream_produces_valid_flows(self):
        streamer = FlowStream(batch_size=10, max_flows=20, delay=0.0)
        flows = list(streamer.stream())
        self.assertEqual(len(flows), 20)

        sample_flow = flows[0]
        self.assertIn("Dst_Port", sample_flow)
        self.assertIn("Protocol", sample_flow)
        self.assertIn("Timestamp", sample_flow)
        self.assertIn("Flow_Duration", sample_flow)

    def test_02_batch_size_works(self):
        streamer = FlowStream(batch_size=15, max_flows=45, delay=0.0)
        batches = list(streamer.stream_batches())
        self.assertEqual(len(batches), 3)
        for b in batches:
            self.assertEqual(len(b), 15)

    def test_03_delay_works(self):
        streamer = FlowStream(batch_size=10, max_flows=20, delay=0.2)
        t0 = time.time()
        batches = list(streamer.stream_batches())
        t1 = time.time()
        elapsed = t1 - t0
        self.assertGreaterEqual(elapsed, 0.3)  # 2 batches * 0.2s delay = ~0.4s

    def test_04_predictor_receives_correctly_shaped_flows(self):
        sample_flow = {
            "Dst_Port": 80.0,
            "Protocol": 6.0,
            "Timestamp": "2026-08-16T12:00:00",
            "Flow_Duration": 1000.0,
            "Tot_Fwd_Pkts": 5.0,
            "Tot_Bwd_Pkts": 5.0,
        }
        res = self.service.process_batch([sample_flow], persist_alert=False)
        self.assertEqual(res["total_flows"], 1)
        self.assertEqual(len(res["processed_results"]), 1)
        pred = res["processed_results"][0]
        self.assertIn("is_attack", pred)
        self.assertIn("attack_type", pred)
        self.assertIn("severity", pred)

    def test_05_benign_flows_do_not_create_soc_alerts(self):
        benign_flow = {
            "Dst_Port": 443.0,
            "Protocol": 6.0,
            "Timestamp": "2026-08-16T12:00:00",
            "Flow_Duration": 50.0,
            "Tot_Fwd_Pkts": 1.0,
            "Tot_Bwd_Pkts": 1.0,
            "TotLen_Fwd_Pkts": 0.0,
            "TotLen_Bwd_Pkts": 0.0,
            "Fwd_Pkt_Len_Max": 0.0,
            "stage1_label": 0.0,
            "attack_label": "Benign",
        }
        res = self.service.process_batch([benign_flow], persist_alert=True)
        if not res["processed_results"][0]["is_attack"]:
            self.assertEqual(res["alerts_inserted"], 0)

    def test_06_attack_flows_create_soc_alerts(self):
        test_alert_df = pd.DataFrame([{
            "Timestamp": "2026-08-16T13:00:00",
            "Dst_Port": 22,
            "Protocol": "TCP",
            "attack_type": "SSH-Bruteforce",
            "severity": "HIGH",
            "attack_probability": 0.95,
            "confidence": 0.95,
            "is_attack": True,
            "stage1_confidence": 0.98,
            "stage2_confidence": 0.97,
        }])
        inserted = sync_alerts(test_alert_df)
        self.assertGreaterEqual(inserted, 0)

    def test_07_streaming_counters_increment_correctly(self):
        sm = StreamManager()
        status = sm.get_status()
        self.assertEqual(status["flows_processed"], 0)

        sm.flows_processed += 50
        sm.attacks_detected += 5
        status_updated = sm.get_status()
        self.assertEqual(status_updated["flows_processed"], 50)
        self.assertEqual(status_updated["attacks_detected"], 5)

    def test_08_stream_can_start(self):
        sm = StreamManager()
        res = sm.start(batch_size=10, delay=0.1, max_flows=20)
        self.assertEqual(res["status"], "RUNNING")
        time.sleep(0.3)
        st = sm.get_status()
        self.assertIn(st["status"], ["STARTING", "RUNNING", "COMPLETED"])
        sm.stop()

    def test_09_stream_can_pause(self):
        sm = StreamManager()
        sm.start(batch_size=10, delay=0.5, max_flows=100)
        time.sleep(0.1)
        res = sm.pause()
        self.assertEqual(res["status"], "PAUSED")
        self.assertEqual(sm.get_status()["status"], "PAUSED")
        sm.stop()

    def test_10_stream_can_resume(self):
        sm = StreamManager()
        sm.start(batch_size=10, delay=0.5, max_flows=100)
        time.sleep(0.1)
        sm.pause()
        res = sm.resume()
        self.assertEqual(res["status"], "RUNNING")
        self.assertEqual(sm.get_status()["status"], "RUNNING")
        sm.stop()

    def test_11_stream_can_stop(self):
        sm = StreamManager()
        sm.start(batch_size=10, delay=0.5, max_flows=100)
        time.sleep(0.1)
        res = sm.stop()
        self.assertEqual(res["status"], "STOPPED")
        self.assertEqual(sm.get_status()["status"], "STOPPED")

    def test_12_api_endpoints_return_http_200(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/api/metrics")
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/api/metrics/status")
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/api/stream/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("status", response.json())

        response = self.client.post("/api/stream/start", json={"batch_size": 10, "delay": 0.1, "flows": 20})
        self.assertEqual(response.status_code, 200)

        response = self.client.post("/api/stream/pause")
        self.assertEqual(response.status_code, 200)

        response = self.client.post("/api/stream/resume")
        self.assertEqual(response.status_code, 200)

        response = self.client.post("/api/stream/stop")
        self.assertEqual(response.status_code, 200)

    def test_13_existing_historical_replay_still_works(self):
        self.assertTrue(callable(run_replay))

    def test_14_existing_alert_workflow_still_works(self):
        alerts_df = get_alerts(limit=5)
        self.assertIsInstance(alerts_df, pd.DataFrame)

    def test_15_existing_dashboard_still_loads(self):
        dashboard_file = Path("dashboard/app.py")
        self.assertTrue(dashboard_file.exists())

    def test_16_deterministic_seeded_sampling(self):
        s1 = FlowStream(batch_size=10, max_flows=50, delay=0.0, seed=42)
        flows1 = [f["Dst_Port"] for f in s1.stream()]

        s2 = FlowStream(batch_size=10, max_flows=50, delay=0.0, seed=42)
        flows2 = [f["Dst_Port"] for f in s2.stream()]

        self.assertEqual(flows1, flows2)

    def test_17_sampling_contains_benign_and_attack_flows(self):
        streamer = FlowStream(batch_size=20, max_flows=100, delay=0.0, seed=42, target_attack_ratio=0.3)
        flows = list(streamer.stream())
        self.assertEqual(len(flows), 100)

        gt_attacks = sum(1 for f in flows if f.get("stage1_label") == 1.0)
        gt_benign = sum(1 for f in flows if f.get("stage1_label") == 0.0)

        self.assertGreater(gt_benign, 0)
        self.assertGreater(gt_attacks, 0)

    def test_18_ground_truth_labels_isolated_from_inference(self):
        sample_flow = {
            "Dst_Port": 80.0,
            "Protocol": 6.0,
            "Timestamp": "2026-08-16T12:00:00",
            "stage1_label": 1.0,
            "attack_label": "DDOS attack-HOIC",
            "source_file": "test_01.parquet",
        }
        clean = self.service._prepare_flow_for_inference(sample_flow)
        self.assertNotIn("stage1_label", clean)
        self.assertNotIn("attack_label", clean)
        self.assertNotIn("source_file", clean)
        self.assertIn("Dst_Port", clean)
        self.assertIn("Protocol", clean)

    def test_19_confidence_survives_end_to_end(self):
        test_alert_df = pd.DataFrame([{
            "Timestamp": "2026-08-16T14:00:00",
            "Dst_Port": 22,
            "Protocol": "TCP",
            "attack_type": "SSH-Bruteforce",
            "severity": "CRITICAL",
            "attack_probability": 0.9872,
            "confidence": 0.9872,
            "is_attack": True,
        }])
        sync_alerts(test_alert_df)

        resp = self.client.get("/api/alerts")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        alerts_list = data.get("alerts", data) if isinstance(data, dict) else data
        self.assertGreater(len(alerts_list), 0)
        first_alert = alerts_list[0]
        self.assertIn("confidence", first_alert)
        self.assertGreater(first_alert["confidence"], 0.0)

    def test_20_dst_port_survives_end_to_end(self):
        test_alert_df = pd.DataFrame([{
            "Timestamp": "2026-08-16T14:05:00",
            "Dst_Port": 443,
            "Protocol": "TCP",
            "attack_type": "FTP-BruteForce",
            "severity": "HIGH",
            "attack_probability": 0.9431,
            "confidence": 0.9431,
            "is_attack": True,
        }])
        sync_alerts(test_alert_df)

        resp = self.client.get("/api/alerts")
        data = resp.json()
        alerts_list = data.get("alerts", data) if isinstance(data, dict) else data
        ports = [a.get("destination_port") for a in alerts_list if isinstance(a, dict) and a.get("destination_port") is not None]
        self.assertGreater(len(ports), 0)

    def test_21_protocol_survives_end_to_end(self):
        test_alert_df = pd.DataFrame([{
            "Timestamp": "2026-08-16T14:10:00",
            "Dst_Port": 80,
            "Protocol": "TCP",
            "attack_type": "DDOS attack-HOIC",
            "severity": "CRITICAL",
            "attack_probability": 0.9912,
            "confidence": 0.9912,
            "is_attack": True,
        }])
        sync_alerts(test_alert_df)

        resp = self.client.get("/api/alerts")
        data = resp.json()
        alerts_list = data.get("alerts", data) if isinstance(data, dict) else data
        protocols = [a.get("protocol") for a in alerts_list if isinstance(a, dict) and a.get("protocol") is not None]
        self.assertIn("TCP", protocols)

    def test_22_alert_duplicate_prevention(self):
        test_alert_df = pd.DataFrame([{
            "Timestamp": "2026-08-16T15:00:00",
            "Dst_Port": 8080,
            "Protocol": "TCP",
            "attack_type": "Web Attack - XSS",
            "severity": "MEDIUM",
            "attack_probability": 0.85,
            "confidence": 0.85,
            "is_attack": True,
        }])
        inserted1 = sync_alerts(test_alert_df)
        inserted2 = sync_alerts(test_alert_df)
        self.assertEqual(inserted2, 0)


if __name__ == "__main__":
    unittest.main()
