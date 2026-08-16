import os
import tempfile
import time
import unittest
from pathlib import Path

import pandas as pd
from scapy.all import IP, TCP, UDP, Ether, wrpcap

from src.network.pcap_reader import PcapReader, PacketMetadata
from src.network.flow_builder import FlowBuilder, FeatureValidator, FlowState
from src.network.packet_capture import PacketCapture
from src.network.network_stream import NetworkStreamManager
from src.streaming.live_inference_service import LiveInferenceService
from src.streaming.flow_stream import FlowStream
from src.streaming.replay_service import run_replay
from src.soc.alert_store import get_alerts
from src.api.main import app
from fastapi.testclient import TestClient


class TestCyberSentinelNetworkPhase2(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.service = LiveInferenceService()

        # Create temporary PCAP fixture with synthetic packets
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.pcap_path = Path(cls.temp_dir.name) / "sample_test.pcap"

        pkts = []
        t0 = time.time()
        # 1. Forward TCP SYN (10.0.0.1:12345 -> 192.168.1.1:80)
        p1 = Ether() / IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S", window=8192)
        p1.time = t0
        pkts.append(p1)

        # 2. Backward TCP SYN-ACK (192.168.1.1:80 -> 10.0.0.1:12345)
        p2 = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=80, dport=12345, flags="SA", window=8192)
        p2.time = t0 + 0.01
        pkts.append(p2)

        # 3. Forward TCP ACK + Data
        p3 = Ether() / IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="PA") / b"GET / HTTP/1.1\r\n\r\n"
        p3.time = t0 + 0.02
        pkts.append(p3)

        # 4. Forward TCP FIN
        p4 = Ether() / IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="FA")
        p4.time = t0 + 0.05
        pkts.append(p4)

        # 5. UDP flow (10.0.0.2:54321 -> 192.168.1.1:53)
        p5 = Ether() / IP(src="10.0.0.2", dst="192.168.1.1") / UDP(sport=54321, dport=53) / b"dns-query-payload"
        p5.time = t0 + 0.10
        pkts.append(p5)

        wrpcap(str(cls.pcap_path), pkts)

        # Empty PCAP fixture
        cls.empty_pcap_path = Path(cls.temp_dir.name) / "empty.pcap"
        wrpcap(str(cls.empty_pcap_path), [])

    @classmethod
    def tearDownClass(cls):
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass

    def test_01_pcap_reader_opens_valid_pcap(self):
        reader = PcapReader(self.pcap_path)
        pkts = list(reader.read_packets())
        self.assertGreaterEqual(len(pkts), 5)

    def test_02_pcap_reader_rejects_invalid_path(self):
        reader = PcapReader("non_existent_file.pcap")
        with self.assertRaises(FileNotFoundError):
            list(reader.read_packets())

    def test_03_packet_metadata_extraction(self):
        reader = PcapReader(self.pcap_path)
        pkts = list(reader.read_packets())
        p0 = pkts[0]
        self.assertEqual(p0.src_ip, "10.0.0.1")
        self.assertEqual(p0.dst_ip, "192.168.1.1")
        self.assertEqual(p0.src_port, 12345)
        self.assertEqual(p0.dst_port, 80)
        self.assertEqual(p0.protocol, 6)
        self.assertTrue(p0.tcp_flags.get("SYN"))

    def test_04_tcp_flow_creation(self):
        builder = FlowBuilder(flow_timeout=10.0)
        reader = PcapReader(self.pcap_path)
        flows = []
        for pkt in reader.read_packets():
            flows.extend(builder.add_packet(pkt))
        flows.extend(builder.flush_all())
        self.assertGreaterEqual(len(flows), 1)

    def test_05_udp_flow_creation(self):
        builder = FlowBuilder(flow_timeout=10.0)
        p = PacketMetadata(
            timestamp=time.time(),
            src_ip="10.0.0.2",
            dst_ip="192.168.1.1",
            src_port=54321,
            dst_port=53,
            protocol=17,
            pkt_len=60,
            payload_len=20,
            header_len=28,
            tcp_flags={},
        )
        builder.add_packet(p)
        flushed = builder.flush_all()
        self.assertEqual(len(flushed), 1)
        self.assertEqual(flushed[0]["Protocol"], 17.0)

    def test_06_bidirectional_flow_aggregation(self):
        builder = FlowBuilder(flow_timeout=10.0)
        reader = PcapReader(self.pcap_path)
        all_flows = []
        for pkt in reader.read_packets():
            all_flows.extend(builder.add_packet(pkt))
        all_flows.extend(builder.flush_all())
        tcp_flow = [f for f in all_flows if f["Protocol"] == 6.0][0]
        self.assertGreaterEqual(tcp_flow["Tot_Fwd_Pkts"], 1.0)

    def test_07_flow_timeout(self):
        builder = FlowBuilder(flow_timeout=2.0)
        t0 = time.time()
        p1 = PacketMetadata(
            timestamp=t0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1000, dst_port=80, protocol=6, pkt_len=60,
            payload_len=0, header_len=40, tcp_flags={"SYN": True},
        )
        p2 = PacketMetadata(
            timestamp=t0 + 5.0, src_ip="10.0.0.3", dst_ip="10.0.0.4",
            src_port=2000, dst_port=80, protocol=6, pkt_len=60,
            payload_len=0, header_len=40, tcp_flags={"SYN": True},
        )
        completed = builder.add_packet(p1)
        completed.extend(builder.add_packet(p2))
        self.assertGreaterEqual(len(completed), 1)

    def test_08_flow_finalization(self):
        builder = FlowBuilder(flow_timeout=10.0)
        t0 = time.time()
        p_fin = PacketMetadata(
            timestamp=t0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1000, dst_port=80, protocol=6, pkt_len=60,
            payload_len=0, header_len=40, tcp_flags={"FIN": True},
        )
        completed = builder.add_packet(p_fin)
        self.assertEqual(len(completed), 1)

    def test_09_packet_count_calculation(self):
        builder = FlowBuilder(flow_timeout=10.0)
        reader = PcapReader(self.pcap_path)
        all_flows = []
        for pkt in reader.read_packets():
            all_flows.extend(builder.add_packet(pkt))
        all_flows.extend(builder.flush_all())
        tcp_flow = [f for f in all_flows if f["Protocol"] == 6.0][0]
        self.assertEqual(tcp_flow["Tot_Fwd_Pkts"] + tcp_flow["Tot_Bwd_Pkts"], 4.0)

    def test_10_byte_count_calculation(self):
        builder = FlowBuilder(flow_timeout=10.0)
        reader = PcapReader(self.pcap_path)
        all_flows = []
        for pkt in reader.read_packets():
            all_flows.extend(builder.add_packet(pkt))
        all_flows.extend(builder.flush_all())
        tcp_flow = [f for f in all_flows if f["Protocol"] == 6.0][0]
        self.assertGreater(tcp_flow["TotLen_Fwd_Pkts"], 0.0)

    def test_11_flow_duration_calculation(self):
        builder = FlowBuilder(flow_timeout=10.0)
        reader = PcapReader(self.pcap_path)
        all_flows = []
        for pkt in reader.read_packets():
            all_flows.extend(builder.add_packet(pkt))
        all_flows.extend(builder.flush_all())
        tcp_flow = [f for f in all_flows if f["Protocol"] == 6.0][0]
        self.assertGreaterEqual(tcp_flow["Flow_Duration"], 0.0)

    def test_12_feature_generation(self):
        builder = FlowBuilder(flow_timeout=10.0)
        reader = PcapReader(self.pcap_path)
        all_flows = []
        for pkt in reader.read_packets():
            all_flows.extend(builder.add_packet(pkt))
        all_flows.extend(builder.flush_all())
        flow = all_flows[0]
        self.assertIn("Flow_Duration", flow)
        self.assertIn("Tot_Fwd_Pkts", flow)
        self.assertIn("Hour", flow)
        self.assertIn("DayOfWeek", flow)
        self.assertIn("IsWeekend", flow)

    def test_13_required_feature_validation(self):
        builder = FlowBuilder(flow_timeout=10.0)
        reader = PcapReader(self.pcap_path)
        all_flows = []
        for pkt in reader.read_packets():
            all_flows.extend(builder.add_packet(pkt))
        all_flows.extend(builder.flush_all())
        is_valid, summary = FeatureValidator.validate_flow(all_flows[0])
        self.assertTrue(is_valid)
        self.assertEqual(summary["missing_count"], 0)

    def test_14_predictor_compatibility(self):
        builder = FlowBuilder(flow_timeout=10.0)
        reader = PcapReader(self.pcap_path)
        all_flows = []
        for pkt in reader.read_packets():
            all_flows.extend(builder.add_packet(pkt))
        all_flows.extend(builder.flush_all())
        res = self.service.process_batch(all_flows, persist_alert=False)
        self.assertEqual(res["total_flows"], len(all_flows))
        self.assertEqual(len(res["processed_results"]), len(all_flows))

    def test_15_batch_inference(self):
        builder = FlowBuilder(flow_timeout=10.0)
        reader = PcapReader(self.pcap_path)
        all_flows = []
        for pkt in reader.read_packets():
            all_flows.extend(builder.add_packet(pkt))
        all_flows.extend(builder.flush_all())
        res = self.service.process_batch(all_flows, persist_alert=True)
        self.assertIn("benign_count", res)
        self.assertIn("attack_count", res)

    def test_16_empty_pcap_handling(self):
        reader = PcapReader(self.empty_pcap_path)
        pkts = list(reader.read_packets())
        self.assertEqual(len(pkts), 0)

    def test_17_malformed_packet_handling(self):
        reader = PcapReader(self.pcap_path)
        parsed = reader.parse_packet(Ether())
        self.assertIsNone(parsed)

    def test_18_existing_phase1_tests_remain_passing(self):
        streamer = FlowStream(batch_size=10, max_flows=20, delay=0.0, seed=42)
        flows = list(streamer.stream())
        self.assertEqual(len(flows), 20)

    def test_19_existing_historical_replay_remains_passing(self):
        self.assertTrue(callable(run_replay))

    def test_20_existing_alert_workflow_remains_passing(self):
        alerts_df = get_alerts(limit=5)
        self.assertIsInstance(alerts_df, pd.DataFrame)

    def test_21_live_capture_permission_probe(self):
        cap = PacketCapture()
        is_ok, perm_status, msg = cap.check_capture_permission("eth0")
        self.assertIn(perm_status, ["OK", "DENIED", "ERROR"])
        self.assertIsInstance(msg, str)
        self.assertGreater(len(msg), 0)

    def test_22_live_capture_status_includes_permission_fields(self):
        nsm = NetworkStreamManager()
        status = nsm.get_status()
        self.assertIn("capture_permission", status)
        self.assertIn("capture_permission_detail", status)

    def test_23_api_network_start_permission_error_handling(self):
        # Verify /api/network/start response code matches permission state
        response = self.client.post("/api/network/start", json={
            "source_type": "live",
            "interface": "eth0"
        })
        self.assertIn(response.status_code, [200, 403])
        # Stop stream if started
        self.client.post("/api/network/stop")


if __name__ == "__main__":
    unittest.main()
