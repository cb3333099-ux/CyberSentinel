import argparse
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.network.pcap_reader import PcapReader, PacketMetadata
from src.network.flow_builder import FlowBuilder, FeatureValidator
from src.network.packet_capture import PacketCapture
from src.streaming.live_inference_service import LiveInferenceService
from src.streaming.stream_manager import stream_manager as base_stream_manager


class NetworkStreamManager:
    """
    Unified Real Network Stream Controller for CyberSentinel (Phase 2).

    Orchestrates PCAP file reading and live network capture through FlowBuilder,
    FeatureValidator, LiveInferenceService, and SQLite alert store.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Telemetry State
        self.status = "STOPPED"  # STOPPED, STARTING, RUNNING, PAUSED, ERROR, COMPLETED
        self.input_source: str = "SIMULATED"  # SIMULATED, PCAP, LIVE NETWORK
        self.pcap_path: Optional[str] = None
        self.interface: Optional[str] = None
        self.batch_size: int = 20
        self.flow_timeout: float = 10.0
        self.capture_permission: str = "UNKNOWN"  # OK, DENIED, UNKNOWN, ERROR
        self.capture_permission_detail: Optional[str] = None

        self.packets_captured: int = 0
        self.flows_created: int = 0
        self.flows_completed: int = 0
        self.flows_analyzed: int = 0
        self.active_flows: int = 0

        self.benign_detected: int = 0
        self.attacks_detected: int = 0
        self.alerts_generated: int = 0
        self.critical_alerts: int = 0
        self.high_alerts: int = 0
        self.medium_alerts: int = 0
        self.low_alerts: int = 0

        self._confidence_sum: float = 0.0
        self._confidence_count: int = 0
        self.average_confidence: float = 0.0
        self.current_throughput: float = 0.0
        self.dropped_packets: int = 0
        self.errors: int = 0

        self.stream_start_time: Optional[float] = None
        self.last_packet_time: Optional[str] = None
        self.last_flow_time: Optional[str] = None

        self.recent_completed_flows: List[Dict[str, Any]] = []

        # Engine handles
        self._thread: Optional[threading.Thread] = None
        self._stop_requested = False
        self._pause_requested = False
        self._inference_service: Optional[LiveInferenceService] = None
        self._packet_capture: Optional[PacketCapture] = None

    def get_inference_service(self) -> LiveInferenceService:
        with self._lock:
            if self._inference_service is None:
                self._inference_service = LiveInferenceService()
            return self._inference_service

    def start_pcap_stream(
        self,
        pcap_path: str,
        batch_size: int = 20,
        flow_timeout: float = 10.0,
    ) -> Dict[str, Any]:
        """
        Start PCAP file flow analysis.
        """
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file does not exist: {pcap_path}")

        with self._lock:
            if self.status in ["RUNNING", "STARTING"]:
                return {"message": f"Stream active with status {self.status}", "status": self.status}

            self._reset_telemetry()
            self.status = "STARTING"
            self.input_source = "PCAP"
            self.pcap_path = str(pcap_path)
            self.batch_size = max(1, batch_size)
            self.flow_timeout = max(1.0, flow_timeout)
            self._stop_requested = False

        self._thread = threading.Thread(target=self._run_pcap_worker, daemon=True)
        self._thread.start()

        return {"message": f"PCAP stream started: {pcap_path}", "status": "RUNNING"}

    def start_live_stream(
        self,
        interface: str,
        batch_size: int = 20,
        flow_timeout: float = 10.0,
    ) -> Dict[str, Any]:
        """
        Start Live Network Interface monitoring.
        """
        # Pre-flight privilege check
        temp_cap = PacketCapture()
        is_ok, perm_status, msg = temp_cap.check_capture_permission(interface)
        if not is_ok:
            with self._lock:
                self.status = "ERROR"
                self.capture_permission = perm_status
                self.capture_permission_detail = msg
                self.errors += 1
            raise PermissionError(msg)

        with self._lock:
            if self.status in ["RUNNING", "STARTING"]:
                return {"message": f"Stream active with status {self.status}", "status": self.status}

            self._reset_telemetry()
            self.status = "STARTING"
            self.input_source = "LIVE NETWORK"
            self.interface = interface
            self.batch_size = max(1, batch_size)
            self.flow_timeout = max(1.0, flow_timeout)
            self.capture_permission = perm_status
            self.capture_permission_detail = msg
            self._stop_requested = False

        self._thread = threading.Thread(target=self._run_live_worker, daemon=True)
        self._thread.start()

        return {"message": f"Live monitoring started on interface: {interface}", "status": "RUNNING"}

    def stop_stream(self) -> Dict[str, Any]:
        """
        Stop active stream.
        """
        with self._lock:
            self._stop_requested = True
            if self._packet_capture:
                try:
                    self._packet_capture.stop_capture()
                except Exception:
                    pass
            self.status = "STOPPED"
        return {"message": "Network stream stopped", "status": "STOPPED"}

    def _reset_telemetry(self) -> None:
        self.packets_captured = 0
        self.flows_created = 0
        self.flows_completed = 0
        self.flows_analyzed = 0
        self.active_flows = 0

        self.benign_detected = 0
        self.attacks_detected = 0
        self.alerts_generated = 0
        self.critical_alerts = 0
        self.high_alerts = 0
        self.medium_alerts = 0
        self.low_alerts = 0

        self._confidence_sum = 0.0
        self._confidence_count = 0
        self.average_confidence = 0.0
        self.current_throughput = 0.0
        self.dropped_packets = 0
        self.errors = 0

        self.stream_start_time = time.time()
        self.last_packet_time = None
        self.last_flow_time = None
        self.recent_completed_flows.clear()

    def _process_flow_batch(
        self,
        batch_flows: List[Dict[str, Any]],
        inference_service: LiveInferenceService,
        elapsed: float,
    ) -> None:
        if not batch_flows:
            return

        valid_flows: List[Dict[str, Any]] = []
        for flow in batch_flows:
            is_valid, summary = FeatureValidator.validate_flow(flow)
            if is_valid:
                valid_flows.append(flow)
            else:
                with self._lock:
                    self.dropped_packets += 1

        if not valid_flows:
            return

        # Process valid flows through LiveInferenceService / CyberSentinelPredictor
        result = inference_service.process_batch(valid_flows, persist_alert=True)
        now_iso = datetime.now().isoformat()

        with self._lock:
            self.flows_analyzed += len(valid_flows)
            self.benign_detected += result["benign_count"]
            self.attacks_detected += result["attack_count"]
            self.alerts_generated += result["alerts_inserted"]

            sevs = result["severities"]
            self.critical_alerts += sevs.get("CRITICAL", 0)
            self.high_alerts += sevs.get("HIGH", 0)
            self.medium_alerts += sevs.get("MEDIUM", 0)
            self.low_alerts += sevs.get("LOW", 0)

            if result["attack_count"] > 0:
                self._confidence_sum += result["average_confidence"] * result["attack_count"]
                self._confidence_count += result["attack_count"]
                self.average_confidence = self._confidence_sum / self._confidence_count

            self.last_flow_time = now_iso
            self.current_throughput = (self.flows_analyzed / elapsed) if elapsed > 0 else 0.0

            # Update recent completed flows
            for flow, res in zip(valid_flows, result["processed_results"]):
                flow_summary = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "src_ip": str(flow.get("Src_IP", "127.0.0.1")),
                    "dst_ip": str(flow.get("Dst_IP", "127.0.0.1")),
                    "dst_port": int(flow.get("Dst_Port", 0)),
                    "protocol": "TCP" if flow.get("Protocol") == 6 else ("UDP" if flow.get("Protocol") == 17 else str(flow.get("Protocol"))),
                    "packets": int(flow.get("Tot_Fwd_Pkts", 0) + flow.get("Tot_Bwd_Pkts", 0)),
                    "bytes": int(flow.get("TotLen_Fwd_Pkts", 0) + flow.get("TotLen_Bwd_Pkts", 0)),
                    "is_attack": res["is_attack"],
                    "attack_type": res["attack_type"],
                    "severity": res["severity"],
                    "confidence": res["confidence"],
                    "status": "ATTACK" if res["is_attack"] else "BENIGN",
                }
                self.recent_completed_flows.insert(0, flow_summary)
            if len(self.recent_completed_flows) > 50:
                self.recent_completed_flows = self.recent_completed_flows[:50]

    def _run_pcap_worker(self) -> None:
        try:
            inference_service = self.get_inference_service()
            reader = PcapReader(self.pcap_path)
            builder = FlowBuilder(flow_timeout=self.flow_timeout)

            with self._lock:
                self.status = "RUNNING"

            batch_flows: List[Dict[str, Any]] = []

            for pkt in reader.read_packets():
                if self._stop_requested:
                    break

                now_iso = datetime.now().isoformat()
                with self._lock:
                    self.packets_captured += 1
                    self.last_packet_time = now_iso

                completed = builder.add_packet(pkt)
                with self._lock:
                    self.flows_created = builder.total_flows_created
                    self.flows_completed = builder.total_flows_completed
                    self.active_flows = len(builder.active_flows)

                if completed:
                    batch_flows.extend(completed)

                if len(batch_flows) >= self.batch_size:
                    elapsed = time.time() - (self.stream_start_time or time.time())
                    self._process_flow_batch(batch_flows, inference_service, elapsed)
                    batch_flows.clear()

            # Flush remaining active flows
            flushed = builder.flush_all()
            if flushed:
                batch_flows.extend(flushed)

            if batch_flows:
                elapsed = time.time() - (self.stream_start_time or time.time())
                self._process_flow_batch(batch_flows, inference_service, elapsed)

            with self._lock:
                if not self._stop_requested:
                    self.status = "COMPLETED"

        except Exception as exc:
            import traceback
            traceback.print_exc()
            with self._lock:
                self.status = "ERROR"
                self.errors += 1

    def _run_live_worker(self) -> None:
        try:
            builder = FlowBuilder(flow_timeout=self.flow_timeout)
            batch_flows: List[Dict[str, Any]] = []

            def pkt_callback(pkt: PacketMetadata):
                nonlocal batch_flows
                if self._stop_requested:
                    return

                now_iso = datetime.now().isoformat()
                with self._lock:
                    self.packets_captured += 1
                    self.last_packet_time = now_iso

                completed = builder.add_packet(pkt)
                with self._lock:
                    self.flows_created = builder.total_flows_created
                    self.flows_completed = builder.total_flows_completed
                    self.active_flows = len(builder.active_flows)

                if completed:
                    batch_flows.extend(completed)

            with self._lock:
                self.status = "RUNNING"

            self._packet_capture = PacketCapture()
            self._packet_capture.start_capture(self.interface, pkt_callback)

            inference_service = self.get_inference_service()

            while not self._stop_requested:
                time.sleep(0.5)

                if self._packet_capture and self._packet_capture.capture_permission == "DENIED":
                    with self._lock:
                        self.status = "ERROR"
                        self.capture_permission = "DENIED"
                        self.capture_permission_detail = self._packet_capture.permission_error_msg
                        self.errors += 1
                    break

                # Flush expired flows periodically
                expired = builder.flush_expired()
                if expired:
                    batch_flows.extend(expired)

                if len(batch_flows) >= self.batch_size:
                    elapsed = time.time() - (self.stream_start_time or time.time())
                    self._process_flow_batch(batch_flows, inference_service, elapsed)
                    batch_flows.clear()

            # Clean shutdown
            flushed = builder.flush_all()
            if flushed:
                batch_flows.extend(flushed)

            if batch_flows:
                elapsed = time.time() - (self.stream_start_time or time.time())
                self._process_flow_batch(batch_flows, inference_service, elapsed)

            with self._lock:
                if self.status != "ERROR":
                    self.status = "STOPPED"

        except Exception as exc:
            import traceback
            traceback.print_exc()
            with self._lock:
                self.status = "ERROR"
                self.errors += 1

    def get_status(self) -> Dict[str, Any]:
        """
        Return unified real network telemetry status snapshot.
        """
        with self._lock:
            uptime = (time.time() - self.stream_start_time) if self.stream_start_time else 0.0
            return {
                "status": self.status,
                "input_source": self.input_source,
                "pcap_path": self.pcap_path,
                "interface": self.interface,
                "batch_size": self.batch_size,
                "flow_timeout": self.flow_timeout,
                "capture_permission": self.capture_permission,
                "capture_permission_detail": self.capture_permission_detail,
                "packets_captured": self.packets_captured,
                "flows_created": self.flows_created,
                "flows_completed": self.flows_completed,
                "flows_analyzed": self.flows_analyzed,
                "active_flows": self.active_flows,
                "benign_detected": self.benign_detected,
                "attacks_detected": self.attacks_detected,
                "alerts_generated": self.alerts_generated,
                "critical_alerts": self.critical_alerts,
                "high_alerts": self.high_alerts,
                "medium_alerts": self.medium_alerts,
                "low_alerts": self.low_alerts,
                "average_confidence": round(self.average_confidence * (100.0 if self.average_confidence <= 1.0 else 1.0), 2),
                "throughput": round(self.current_throughput, 2),
                "dropped_packets": self.dropped_packets,
                "errors": self.errors,
                "last_packet_time": self.last_packet_time,
                "last_flow_time": self.last_flow_time,
                "stream_uptime": round(uptime, 1),
                "recent_completed_flows": self.recent_completed_flows[:20],
            }


# Singleton instance
network_stream_manager = NetworkStreamManager()


# ============================================================
# DEMONSTRATION CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel Real Network Traffic Analysis CLI (Phase 2)"
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Path to input PCAP / PCAPNG file",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Name of network interface to sniff",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available local network interfaces",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=20,
        help="Batch size for flow inference (default: 20)",
    )
    parser.add_argument(
        "--flow-timeout",
        type=float,
        default=10.0,
        help="Flow timeout in seconds (default: 10.0)",
    )

    args = parser.parse_args()

    if args.list_interfaces:
        print()
        print("==================================================")
        print("CYBERSENTINEL AVAILABLE NETWORK INTERFACES")
        print("==================================================")
        ifaces = PacketCapture.list_interfaces()
        for idx, ifc in enumerate(ifaces, 1):
            print(f"{idx:<2}. Name: {ifc['name']:<15} | IP: {ifc['ip']:<15} | Desc: {ifc['description']}")
        print("==================================================")
        return

    if args.pcap:
        print()
        print("==================================================")
        print("CYBERSENTINEL NETWORK ANALYSIS")
        print("==================================================")
        print(f"Source       : PCAP ({args.pcap})")
        print(f"Batch Size   : {args.batch_size}")
        print(f"Flow Timeout : {args.flow_timeout} sec")
        print("==================================================")
        print()

        nsm = NetworkStreamManager()
        nsm.start_pcap_stream(
            pcap_path=args.pcap,
            batch_size=args.batch_size,
            flow_timeout=args.flow_timeout,
        )

    elif args.interface:
        print()
        print("==================================================")
        print("CYBERSENTINEL LIVE NETWORK MONITOR")
        print("==================================================")
        print(f"Interface       : {args.interface}")
        print(f"Capture Status  : STARTING")
        print(f"Flow Timeout    : {args.flow_timeout} sec")
        print(f"Batch Size      : {args.batch_size}")
        print()
        print("WARNING:")
        print("This mode passively analyzes traffic visible to the selected")
        print("local interface.")
        print("==================================================")
        print()

        nsm = NetworkStreamManager()
        nsm.start_live_stream(
            interface=args.interface,
            batch_size=args.batch_size,
            flow_timeout=args.flow_timeout,
        )

    else:
        parser.print_help()
        return

    try:
        while True:
            st = nsm.get_status()
            status_text = st["status"]

            print("\033[H\033[J", end="")
            print("==================================================")
            print("CYBERSENTINEL NETWORK ANALYSIS")
            print("==================================================")
            print(f"Source          : {st['input_source']}")
            print(f"Status          : {status_text}")
            print(f"Packets Captured: {st['packets_captured']:,}")
            print(f"Flows Created   : {st['flows_created']:,}")
            print(f"Flows Analyzed  : {st['flows_analyzed']:,}")
            print()
            print("Model Results")
            print("-------------")
            print(f"Benign          : {st['benign_detected']:,}")
            print(f"Attacks         : {st['attacks_detected']:,}")
            print()
            print(f"SOC Alerts      : {st['alerts_generated']:,}")
            print()
            print(f"Critical        : {st['critical_alerts']:,}")
            print(f"High            : {st['high_alerts']:,}")
            print(f"Medium          : {st['medium_alerts']:,}")
            print(f"Low             : {st['low_alerts']:,}")
            print()
            print(f"Average Confidence : {st['average_confidence']:.2f}%")
            print(f"Throughput         : {st['throughput']:.1f} flows/sec")
            print("==================================================")

            if status_text in ["COMPLETED", "STOPPED", "ERROR"]:
                break

            time.sleep(0.5)

    except KeyboardInterrupt:
        nsm.stop_stream()
        print("\nNetwork stream stopped by user.")


if __name__ == "__main__":
    main()
