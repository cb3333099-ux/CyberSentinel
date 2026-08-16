import numpy as np
import pandas as pd
from typing import Any, Dict, List, Optional
from src.analytics.soc_analytics import parse_window
from src.soc.alert_store import get_connection, initialize_database


# Baseline metrics derived from model validation performance
BASELINE_METRICS = {
    "mean_confidence": 0.945,
    "attack_rate": 0.312,
    "low_confidence_rate": 0.045,
}


def get_model_monitoring_metrics(window: str = "24h") -> Dict[str, Any]:
    """
    Calculate Stage 1 and Stage 2 model monitoring metrics and distribution shift indicators.
    """
    initialize_database()
    cutoff_iso, total_mins = parse_window(window)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            attack_type,
            confidence,
            severity,
            created_at
        FROM alerts
        WHERE created_at >= ?
        """,
        (cutoff_iso,),
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return {
            "window": window,
            "inference_volume": 0,
            "prediction_throughput_per_min": 0.0,
            "stage1_metrics": {
                "prediction_volume": 0,
                "attack_rate": 0.0,
                "benign_rate": 0.0,
                "mean_confidence": None,
                "low_confidence_count": 0,
                "confidence_percentiles": {},
            },
            "stage2_metrics": {
                "classification_volume": 0,
                "mean_confidence": None,
                "attack_type_distribution": [],
            },
            "monitoring_indicators": {
                "confidence_shift": None,
                "attack_rate_shift": None,
                "status": "NORMAL",
            },
        }

    df = pd.DataFrame(rows, columns=["attack_type", "confidence", "severity", "created_at"])
    df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce").fillna(0.0)

    total_predictions = len(df)
    throughput = round(total_predictions / max(1.0, total_mins), 2)

    # Stage 1 Binary Analysis
    is_attack = df["attack_type"].str.upper() != "BENIGN"
    attack_count = int(is_attack.sum())
    benign_count = total_predictions - attack_count
    attack_rate = round(attack_count / total_predictions, 4) if total_predictions > 0 else 0.0
    benign_rate = round(benign_count / total_predictions, 4) if total_predictions > 0 else 0.0

    conf_values = df["confidence"].values
    mean_conf = round(float(np.mean(conf_values)), 4) if len(conf_values) > 0 else None
    low_conf_count = int((conf_values < 0.60).sum())

    conf_pcts = {}
    if len(conf_values) > 0:
        conf_pcts = {
            "p25": round(float(np.percentile(conf_values, 25)), 4),
            "p50": round(float(np.percentile(conf_values, 50)), 4),
            "p75": round(float(np.percentile(conf_values, 75)), 4),
            "p90": round(float(np.percentile(conf_values, 90)), 4),
            "p99": round(float(np.percentile(conf_values, 99)), 4),
        }

    # Stage 2 Multi-class Analysis (Attack predictions only)
    attack_df = df[is_attack]
    stage2_volume = len(attack_df)
    stage2_mean_conf = round(float(attack_df["confidence"].mean()), 4) if stage2_volume > 0 else None

    atk_counts = attack_df["attack_type"].value_counts().to_dict()
    atk_dist = [{"attack_type": k, "count": v} for k, v in atk_counts.items()]

    # Distribution Shift Indicators (vs Validation Baseline)
    base_conf = BASELINE_METRICS["mean_confidence"]
    base_atk_rate = BASELINE_METRICS["attack_rate"]

    conf_shift = round(mean_conf - base_conf, 4) if mean_conf is not None else None
    atk_shift = round(attack_rate - base_atk_rate, 4)

    status = "NORMAL"
    if conf_shift is not None and abs(conf_shift) > 0.15:
        status = "CONFIDENCE_SHIFT_DETECTED"
    elif abs(atk_shift) > 0.25:
        status = "ATTACK_RATE_SHIFT_DETECTED"

    return {
        "window": window,
        "inference_volume": total_predictions,
        "prediction_throughput_per_min": throughput,
        "stage1_metrics": {
            "prediction_volume": total_predictions,
            "attack_rate": attack_rate,
            "benign_rate": benign_rate,
            "mean_confidence": mean_conf,
            "low_confidence_count": low_conf_count,
            "confidence_percentiles": conf_pcts,
        },
        "stage2_metrics": {
            "classification_volume": stage2_volume,
            "mean_confidence": stage2_mean_conf,
            "attack_type_distribution": atk_dist,
        },
        "monitoring_indicators": {
            "baseline_confidence": base_conf,
            "baseline_attack_rate": base_atk_rate,
            "confidence_shift": conf_shift,
            "attack_rate_shift": atk_shift,
            "status": status,
            "note": "Monitoring indicators provided for analyst awareness; model retraining is not automatically triggered.",
        },
    }
