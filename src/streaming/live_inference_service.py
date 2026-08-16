from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd

from src.inference.predictor import CyberSentinelPredictor
from src.soc.alert_store import sync_alerts


class LiveInferenceService:
    """
    Live Inference Service for CyberSentinel.

    Connects streaming network flows to the existing two-stage ML engine
    using batch inference (predict_batch) and persists detected attacks into
    the SQLite SOC alert store.
    """

    def __init__(
        self,
        predictor: Optional[CyberSentinelPredictor] = None,
    ):
        self.predictor = (
            predictor
            if predictor is not None
            else CyberSentinelPredictor()
        )

    def _prepare_flow_for_inference(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove ground truth labels or extra metadata before inference.
        Retain all network features, temporal features, Dst_Port, Protocol.
        """
        clean = dict(flow)
        clean.pop("stage1_label", None)
        clean.pop("attack_label", None)
        clean.pop("source_file", None)
        return clean

    def process_batch(
        self,
        flows: List[Dict[str, Any]],
        persist_alert: bool = True,
    ) -> Dict[str, Any]:
        """
        Process a batch of network flows through CyberSentinelPredictor.

        Persists detected attack flows into SQLite alert store.
        Does NOT store benign flows in SQLite.

        Returns a dictionary containing batch statistics (ground truth vs model predictions)
        and prediction details.
        """
        if not flows:
            return {
                "total_flows": 0,
                "gt_benign_count": 0,
                "gt_attack_count": 0,
                "benign_count": 0,
                "attack_count": 0,
                "alerts_inserted": 0,
                "severities": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "average_confidence": 0.0,
                "processed_results": [],
            }

        # ----------------------------------------------------
        # Prepare flows for batch inference (stripping ground truth)
        # ----------------------------------------------------
        clean_flows = [self._prepare_flow_for_inference(f) for f in flows]

        # ----------------------------------------------------
        # Run batch prediction via CyberSentinelPredictor
        # ----------------------------------------------------
        predictions = self.predictor.predict_batch(clean_flows)

        processed_results: List[Dict[str, Any]] = []
        attack_alerts_to_persist: List[Dict[str, Any]] = []

        gt_benign_count = 0
        gt_attack_count = 0
        benign_count = 0
        attack_count = 0
        severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        confidences: List[float] = []

        for flow, pred in zip(flows, predictions):
            # Ground truth tracking for evaluation/telemetry ONLY
            stage1_label = flow.get("stage1_label")
            attack_label = flow.get("attack_label")
            if stage1_label == 1.0 or (attack_label and str(attack_label) != "Benign"):
                gt_is_attack = True
                gt_attack_count += 1
            else:
                gt_is_attack = False
                gt_benign_count += 1

            timestamp = flow.get("Timestamp")
            if not timestamp:
                timestamp = datetime.now().isoformat()

            dst_port = flow.get("Dst_Port")
            protocol = flow.get("Protocol")

            is_attack = bool(pred.get("is_attack", False))
            attack_type = str(pred.get("attack_type", "Benign"))
            severity = str(pred.get("severity", "NONE")).upper()
            confidence = float(pred.get("confidence", 0.0))

            enriched_result = {
                "Timestamp": timestamp,
                "Dst_Port": dst_port,
                "Protocol": protocol,
                "attack_type": attack_type,
                "severity": severity,
                "attack_probability": confidence,
                "confidence": confidence,
                "is_attack": is_attack,
                "gt_is_attack": gt_is_attack,
                "stage1_confidence": float(pred.get("stage1_confidence", 0.0)),
                "stage2_confidence": float(pred.get("stage2_confidence", 0.0)),
            }

            if is_attack:
                attack_count += 1
                if severity in severities:
                    severities[severity] += 1
                confidences.append(confidence)
                attack_alerts_to_persist.append(enriched_result)
            else:
                benign_count += 1

            processed_results.append(enriched_result)

        # ----------------------------------------------------
        # Persist ONLY actual attacks into SQLite SOC store
        # ----------------------------------------------------
        inserted_count = 0
        if persist_alert and attack_alerts_to_persist:
            alert_df = pd.DataFrame(attack_alerts_to_persist)
            inserted_count = sync_alerts(alert_df)

        # Update alert persistence flags in processed_results
        for res in processed_results:
            if res["is_attack"]:
                res["alert_persisted"] = inserted_count > 0
                res["alert_inserted_count"] = inserted_count
            else:
                res["alert_persisted"] = False
                res["alert_inserted_count"] = 0

        avg_conf = (sum(confidences) / len(confidences)) if confidences else 0.0

        return {
            "total_flows": len(flows),
            "gt_benign_count": gt_benign_count,
            "gt_attack_count": gt_attack_count,
            "benign_count": benign_count,
            "attack_count": attack_count,
            "alerts_inserted": inserted_count,
            "severities": severities,
            "average_confidence": avg_conf,
            "processed_results": processed_results,
        }

    def close(self) -> None:
        """
        Close predictor resources safely.
        """
        if self.predictor:
            try:
                self.predictor.close()
            except Exception:
                pass
