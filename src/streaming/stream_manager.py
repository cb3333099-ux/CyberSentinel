import argparse
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional

from src.streaming.flow_stream import FlowStream
from src.streaming.live_inference_service import LiveInferenceService


class StreamManager:
    """
    Real-Time Streaming State Manager for CyberSentinel.

    Manages the background execution thread for network flow streaming,
    maintains real-time telemetry metrics (distinguishing ground truth vs model predictions),
    and provides control APIs (start, stop, pause, resume, status).
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Telemetry State
        self.status = "STOPPED"  # STOPPED, STARTING, RUNNING, PAUSED, ERROR, COMPLETED
        self.source_path: str = ""
        self.batch_size: int = 50
        self.delay: float = 0.5
        self.max_flows: Optional[int] = None
        self.continuous: bool = False
        self.seed: Optional[int] = 42
        self.target_attack_ratio: float = 0.30

        self.flows_received: int = 0
        self.flows_processed: int = 0

        # Ground Truth Metrics
        self.ground_truth_flows: int = 0
        self.ground_truth_attacks: int = 0
        self.ground_truth_benign: int = 0
        self.ground_truth_attack_rate: float = 0.0

        # Model Prediction Metrics
        self.attacks_detected: int = 0
        self.benign_detected: int = 0
        self.predicted_attacks: int = 0
        self.predicted_benign: int = 0
        self.predicted_attack_rate: float = 0.0

        # SOC Alert Metrics
        self.alerts_generated: int = 0
        self.critical_alerts: int = 0
        self.high_alerts: int = 0
        self.medium_alerts: int = 0
        self.low_alerts: int = 0

        self._confidence_sum: float = 0.0
        self._confidence_count: int = 0
        self.average_confidence: float = 0.0
        self.current_throughput: float = 0.0

        self.stream_start_time: Optional[str] = None
        self.last_flow_time: Optional[str] = None
        self.last_alert_time: Optional[str] = None

        # Threading / Worker handles
        self._thread: Optional[threading.Thread] = None
        self._stop_requested = False
        self._pause_requested = False
        self._inference_service: Optional[LiveInferenceService] = None

    def _reset_telemetry(self) -> None:
        """
        Reset telemetry counters prior to starting a new stream session.
        """
        with self._lock:
            self.flows_received = 0
            self.flows_processed = 0

            self.ground_truth_flows = 0
            self.ground_truth_attacks = 0
            self.ground_truth_benign = 0
            self.ground_truth_attack_rate = 0.0

            self.attacks_detected = 0
            self.benign_detected = 0
            self.predicted_attacks = 0
            self.predicted_benign = 0
            self.predicted_attack_rate = 0.0

            self.alerts_generated = 0
            self.critical_alerts = 0
            self.high_alerts = 0
            self.medium_alerts = 0
            self.low_alerts = 0

            self._confidence_sum = 0.0
            self._confidence_count = 0
            self.average_confidence = 0.0
            self.current_throughput = 0.0

            self.stream_start_time = datetime.now().isoformat()
            self.last_flow_time = None
            self.last_alert_time = None

    def start(
        self,
        source_path: Optional[str] = None,
        batch_size: int = 50,
        delay: float = 0.5,
        max_flows: Optional[int] = None,
        continuous: bool = False,
        seed: Optional[int] = 42,
        target_attack_ratio: float = 0.30,
    ) -> Dict[str, Any]:
        """
        Start real-time stream simulation in a background thread.
        """
        with self._lock:
            if self.status in ["RUNNING", "STARTING", "PAUSED"]:
                return {
                    "message": f"Stream already active with status {self.status}",
                    "status": self.status,
                }

            self.status = "STARTING"
            self._stop_requested = False
            self._pause_requested = False

            if source_path:
                self.source_path = source_path
            self.batch_size = batch_size
            self.delay = delay
            self.max_flows = max_flows
            self.continuous = continuous
            self.seed = seed
            self.target_attack_ratio = target_attack_ratio

        self._reset_telemetry()

        self._thread = threading.Thread(
            target=self._run_worker,
            daemon=True,
        )
        self._thread.start()

        return {
            "message": "Stream simulation started",
            "status": "RUNNING",
        }

    def stop(self) -> Dict[str, Any]:
        """
        Stop active stream simulation.
        """
        with self._lock:
            if self.status == "STOPPED":
                return {"message": "Stream already stopped", "status": "STOPPED"}

            self._stop_requested = True
            self._pause_requested = False
            self.status = "STOPPED"

        return {"message": "Stream stop requested", "status": "STOPPED"}

    def pause(self) -> Dict[str, Any]:
        """
        Pause active stream simulation.
        """
        with self._lock:
            if self.status not in ["RUNNING", "STARTING"]:
                return {"message": f"Cannot pause stream in status {self.status}", "status": self.status}

            self._pause_requested = True
            self.status = "PAUSED"

        return {"message": "Stream paused", "status": "PAUSED"}

    def resume(self) -> Dict[str, Any]:
        """
        Resume paused stream simulation.
        """
        with self._lock:
            if self.status != "PAUSED":
                return {"message": f"Cannot resume stream in status {self.status}", "status": self.status}

            self._pause_requested = False
            self.status = "RUNNING"

        return {"message": "Stream resumed", "status": "RUNNING"}

    def get_inference_service(self) -> LiveInferenceService:
        """
        Get or initialize the shared LiveInferenceService instance.
        """
        with self._lock:
            if self._inference_service is None:
                self._inference_service = LiveInferenceService()
            return self._inference_service

    def _run_worker(self) -> None:
        """
        Background worker thread executing the flow stream and inference pipeline.
        """
        try:
            inference_service = self.get_inference_service()

            stream_source = self.source_path if self.source_path else FlowStream.__init__.__defaults__[0]
            flow_stream = FlowStream(
                source_path=stream_source,
                batch_size=self.batch_size,
                delay=self.delay,
                max_flows=self.max_flows,
                continuous=self.continuous,
                seed=self.seed,
                target_attack_ratio=self.target_attack_ratio,
            )

            with self._lock:
                self.status = "RUNNING"

            t0 = time.time()

            for batch in flow_stream.stream_batches():
                if self._stop_requested:
                    break

                while self._pause_requested and not self._stop_requested:
                    time.sleep(0.1)

                if self._stop_requested:
                    break

                # Process batch through ML engine and alert store
                batch_result = inference_service.process_batch(batch, persist_alert=True)

                now_iso = datetime.now().isoformat()
                elapsed = time.time() - t0

                with self._lock:
                    num_batch = len(batch)
                    self.flows_received += num_batch
                    self.flows_processed += num_batch

                    # Ground Truth Telemetry
                    self.ground_truth_flows += num_batch
                    self.ground_truth_attacks += batch_result.get("gt_attack_count", 0)
                    self.ground_truth_benign += batch_result.get("gt_benign_count", 0)
                    if self.ground_truth_flows > 0:
                        self.ground_truth_attack_rate = (self.ground_truth_attacks / self.ground_truth_flows) * 100.0

                    # Model Predictions Telemetry
                    self.benign_detected += batch_result["benign_count"]
                    self.attacks_detected += batch_result["attack_count"]
                    self.predicted_benign = self.benign_detected
                    self.predicted_attacks = self.attacks_detected
                    if self.flows_processed > 0:
                        self.predicted_attack_rate = (self.predicted_attacks / self.flows_processed) * 100.0

                    # SOC Alerts Persistence
                    self.alerts_generated += batch_result["alerts_inserted"]

                    sevs = batch_result["severities"]
                    self.critical_alerts += sevs.get("CRITICAL", 0)
                    self.high_alerts += sevs.get("HIGH", 0)
                    self.medium_alerts += sevs.get("MEDIUM", 0)
                    self.low_alerts += sevs.get("LOW", 0)

                    if batch_result["attack_count"] > 0:
                        self._confidence_sum += batch_result["average_confidence"] * batch_result["attack_count"]
                        self._confidence_count += batch_result["attack_count"]
                        self.average_confidence = self._confidence_sum / self._confidence_count
                        self.last_alert_time = now_iso

                    self.last_flow_time = now_iso
                    self.current_throughput = (self.flows_processed / elapsed) if elapsed > 0 else 0.0

            with self._lock:
                if not self._stop_requested:
                    self.status = "COMPLETED"

        except Exception as exc:
            import traceback
            traceback.print_exc()
            with self._lock:
                self.status = "ERROR"
                print(f"[StreamManager] Streaming error: {exc}")

    def get_status(self) -> Dict[str, Any]:
        """
        Return snapshot of real-time telemetry metrics.
        """
        with self._lock:
            return {
                "status": self.status,
                "current_stream_status": self.status,
                "source": self.source_path,
                "batch_size": self.batch_size,
                "delay": self.delay,
                "max_flows": self.max_flows,
                "continuous": self.continuous,
                "seed": self.seed,
                "target_attack_ratio": self.target_attack_ratio,
                "flows_received": self.flows_received,
                "flows_processed": self.flows_processed,
                # Ground Truth
                "ground_truth_flows": self.ground_truth_flows,
                "ground_truth_attacks": self.ground_truth_attacks,
                "ground_truth_benign": self.ground_truth_benign,
                "ground_truth_attack_rate": round(self.ground_truth_attack_rate, 2),
                # Model Prediction
                "attacks_detected": self.attacks_detected,
                "benign_detected": self.benign_detected,
                "predicted_attacks": self.predicted_attacks,
                "predicted_benign": self.predicted_benign,
                "predicted_attack_rate": round(self.predicted_attack_rate, 2),
                # SOC Results
                "alerts_generated": self.alerts_generated,
                "critical_alerts": self.critical_alerts,
                "high_alerts": self.high_alerts,
                "medium_alerts": self.medium_alerts,
                "low_alerts": self.low_alerts,
                "average_confidence": round(self.average_confidence * (100.0 if self.average_confidence <= 1.0 else 1.0), 2),
                "throughput": round(self.current_throughput, 2),
                "current_throughput": round(self.current_throughput, 2),
                "stream_start_time": self.stream_start_time,
                "last_flow_time": self.last_flow_time,
                "last_alert_time": self.last_alert_time,
            }


# Singleton instance
stream_manager = StreamManager()


# ============================================================
# DEMONSTRATION CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel Real-Time Stream Manager CLI"
    )
    parser.add_argument(
        "--flows",
        type=int,
        default=200,
        help="Maximum flows to stream (default: 200)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=20,
        help="Batch size for inference (default: 20)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between batches in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for representative sampling (default: 42)",
    )
    parser.add_argument(
        "--attack-ratio",
        type=float,
        default=0.30,
        help="Target ground truth attack ratio (default: 0.30)",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Stream indefinitely",
    )

    args = parser.parse_args()

    sm = StreamManager()
    sm.start(
        batch_size=args.batch_size,
        delay=args.delay,
        max_flows=args.flows,
        continuous=args.continuous,
        seed=args.seed,
        target_attack_ratio=args.attack_ratio,
    )

    try:
        while True:
            st = sm.get_status()
            status_text = st["status"]

            print("\033[H\033[J", end="")  # Clear terminal
            print("==================================================")
            print("CYBERSENTINEL REAL-TIME STREAM")
            print("==================================================")
            print()
            print(f"Flows Processed       : {st['flows_processed']:,}")
            print()
            print("Ground Truth")
            print(f"  Benign              : {st['ground_truth_benign']:,}")
            print(f"  Attacks             : {st['ground_truth_attacks']:,}")
            print(f"  Attack Rate         : {st['ground_truth_attack_rate']:.1f}%")
            print()
            print("Model Prediction")
            print(f"  Benign              : {st['predicted_benign']:,}")
            print(f"  Attacks             : {st['predicted_attacks']:,}")
            print(f"  Detection Rate      : {st['predicted_attack_rate']:.1f}%")
            print()
            print(f"SOC Alerts Generated  : {st['alerts_generated']:,}")
            print()
            print(f"Critical              : {st['critical_alerts']:,}")
            print(f"High                  : {st['high_alerts']:,}")
            print(f"Medium                : {st['medium_alerts']:,}")
            print(f"Low                   : {st['low_alerts']:,}")
            print()
            print(f"Average Confidence    : {st['average_confidence']:.2f}%")
            print(f"Throughput            : {st['throughput']:.1f} flows/sec")
            print()
            print("==================================================")

            if status_text in ["COMPLETED", "STOPPED", "ERROR"]:
                break

            time.sleep(0.5)

    except KeyboardInterrupt:
        sm.stop()
        print("\nStream stopped by user.")


if __name__ == "__main__":
    main()
