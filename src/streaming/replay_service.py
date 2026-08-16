"""
CyberSentinel Streaming Replay Service

Replays real CSE-CIC-IDS2018 network flows through the
CyberSentinel DetectionService to simulate a live SOC stream.

Architecture:

CSE-CIC-IDS2018 Parquet
        |
        v
Streaming Replay
        |
        v
DetectionService
        |
        +---- Stage 1: Attack Detection
        |
        +---- Stage 2: Attack Classification
        |
        +---- Severity
        |
        v
SQLite Alert Store
        |
        v
FastAPI / Dashboard
"""

import argparse
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from pyspark.sql import SparkSession
from pyspark.sql.functions import col

from src.soc.detection_service import DetectionService


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_PATH = "data/processed/ml-full/test"

DEFAULT_FLOWS = 20
DEFAULT_BATCH_SIZE = 1
DEFAULT_DELAY = 1.0


# ============================================================
# SPARK
# ============================================================

def create_spark():
    """
    Create the Spark session used to read the replay dataset.
    """

    return (
        SparkSession.builder
        .appName("CyberSentinelStreamingReplay")
        .master("local[*]")
        .getOrCreate()
    )


# ============================================================
# DATASET PREPARATION
# ============================================================

def load_replay_flows(
    spark,
    number_of_flows: int,
):
    """
    Load a representative subset of real network flows.

    The replay contains both benign and attack traffic.

    Ground-truth labels are retained only for demonstration
    and evaluation purposes and are never passed to the
    CyberSentinel predictor.
    """

    df = spark.read.parquet(
        DATASET_PATH
    )

    # --------------------------------------------------------
    # Select benign flows
    # --------------------------------------------------------

    benign_count = number_of_flows // 2

    benign = (
        df.filter(
            col("stage1_label") == 0.0
        )
        .limit(
            benign_count
        )
    )

    # --------------------------------------------------------
    # Select attack flows
    # --------------------------------------------------------

    attack_count = (
        number_of_flows
        - benign_count
    )

    attacks = (
        df.filter(
            col("stage1_label") == 1.0
        )
        .limit(
            attack_count
        )
    )

    # --------------------------------------------------------
    # Combine benign + attack flows
    # --------------------------------------------------------

    replay_df = benign.unionByName(
        attacks
    )

    return replay_df


# ============================================================
# FLOW CONVERSION
# ============================================================

def row_to_flow(row) -> Dict[str, Any]:
    """
    Convert a Spark Row into the dictionary expected by
    CyberSentinelPredictor.

    Ground-truth labels and source metadata are removed
    before inference.
    """

    data = row.asDict()

    # --------------------------------------------------------
    # Remove labels / metadata that must not enter inference
    # --------------------------------------------------------

    data.pop(
        "stage1_label",
        None,
    )

    data.pop(
        "attack_label",
        None,
    )

    data.pop(
        "source_file",
        None,
    )

    # --------------------------------------------------------
    # Preserve the original network features.
    #
    # Dst_Port and Protocol are intentionally retained.
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Generate a replay timestamp.
    #
    # The processed Parquet dataset does not contain the
    # original Timestamp field, so the streaming layer
    # assigns the current replay time.
    # --------------------------------------------------------

    data["Timestamp"] = (
        datetime.now().isoformat()
    )

    return data


# ============================================================
# GROUND TRUTH
# ============================================================

def get_ground_truth(row) -> str:
    """
    Extract the original attack label for demonstration
    purposes only.

    This value is never passed to the predictor.
    """

    value = row["attack_label"]

    if value is None:
        return "Unknown"

    return str(value)


# ============================================================
# DISPLAY
# ============================================================

def print_banner():
    """
    Print the CyberSentinel streaming banner.
    """

    print()
    print("=" * 80)
    print(
        "CYBERSENTINEL LIVE STREAMING REPLAY"
    )
    print("=" * 80)
    print()

    print(
        "Source       :",
        DATASET_PATH,
    )

    print(
        "Mode         : "
        "Real CSE-CIC-IDS2018 flow replay"
    )

    print(
        "Detection    : "
        "Two-stage Random Forest"
    )

    print(
        "Inference    : "
        "Batch inference"
    )

    print(
        "Persistence  : "
        "SQLite SOC alert store"
    )

    print()


# ============================================================
# BATCH DISPLAY
# ============================================================

def print_batch_results(
    batch_number: int,
    start_index: int,
    flows: List[Dict[str, Any]],
    ground_truth: List[str],
    results: List[Dict[str, Any]],
    inserted_counts: List[int],
):
    """
    Print the predictions generated for one replay batch.

    Network metadata such as destination port and protocol
    comes from the original inference flow.

    This is important because the predictor result contains
    model outputs, while the original flow contains network
    metadata.
    """

    print()
    print("-" * 90)
    print(
        f"BATCH {batch_number}"
    )
    print("-" * 90)

    for offset, (
        flow,
        truth,
        result,
        inserted,
    ) in enumerate(
        zip(
            flows,
            ground_truth,
            results,
            inserted_counts,
        )
    ):

        flow_number = (
            start_index
            + offset
        )

        print()
        print(
            f"FLOW {flow_number}"
        )

        print(
            f"Ground Truth     : "
            f"{truth}"
        )

        print(
            f"Destination Port : "
            f"{flow.get('Dst_Port')}"
        )

        print(
            f"Protocol         : "
            f"{flow.get('Protocol')}"
        )

        print(
            f"Prediction       : "
            f"{result.get('attack_type')}"
        )

        print(
            f"Severity         : "
            f"{result.get('severity')}"
        )

        print(
            f"Confidence       : "
            f"{result.get('confidence', 0.0):.4f}"
        )

        print(
            f"Stage-1          : "
            f"{result.get('stage1_confidence', 0.0):.4f}"
        )

        print(
            f"Stage-2          : "
            f"{result.get('stage2_confidence', 0.0):.4f}"
        )

        print(
            f"Is Attack        : "
            f"{result.get('is_attack')}"
        )

        print(
            f"Alert Persisted  : "
            f"{inserted > 0}"
        )

        print(
            f"Alerts Inserted  : "
            f"{inserted}"
        )


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    results: List[Dict[str, Any]],
    ground_truth: List[str],
    inserted_counts: List[int],
    flows_requested: int = 50000,
    processing_time: float = 0.0,
    replay_id: str = "demo_50k",
    start_time: str = "",
):
    """
    Print overall streaming replay metrics and persist summary to replay_history.
    """
    total = len(results)

    gt_attacks = sum(1 for value in ground_truth if value != "Benign")
    gt_benign = total - gt_attacks

    pred_attacks = sum(1 for result in results if result.get("is_attack") is True)
    pred_benign = total - pred_attacks

    # Confusion matrix
    tp = sum(1 for gt, r in zip(ground_truth, results) if gt != "Benign" and r.get("is_attack") is True)
    tn = sum(1 for gt, r in zip(ground_truth, results) if gt == "Benign" and r.get("is_attack") is False)
    fp = sum(1 for gt, r in zip(ground_truth, results) if gt == "Benign" and r.get("is_attack") is True)
    fn = sum(1 for gt, r in zip(ground_truth, results) if gt != "Benign" and r.get("is_attack") is False)

    stage1_acc = (tp + tn) / total if total > 0 else 0.0
    stage1_recall = tp / gt_attacks if gt_attacks > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1_score = (2 * precision * stage1_recall) / (precision + stage1_recall) if (precision + stage1_recall) > 0 else 0.0

    # Stage 2 classification accuracy (on ground truth attacks)
    attack_flows = [(gt, r) for gt, r in zip(ground_truth, results) if gt != "Benign"]
    stage2_correct = sum(1 for gt, r in attack_flows if r.get("attack_type") == gt)
    stage2_acc = stage2_correct / len(attack_flows) if attack_flows else 0.0

    alerts_inserted = sum(inserted_counts)

    severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    confidences = []
    for r in results:
        if r.get("is_attack"):
            sev = str(r.get("severity", "UNKNOWN")).upper()
            if sev in severities:
                severities[sev] += 1
            conf = float(r.get("confidence", 0.0))
            confidences.append(conf)

    avg_conf = (sum(confidences) / len(confidences)) * 100 if confidences else 0.0
    throughput = (total / processing_time) if processing_time > 0 else 0.0
    end_time = datetime.now().isoformat()

    # Persist summary to SQLite replay_history
    from src.soc.alert_store import record_replay_run
    record_replay_run({
        "replay_id": replay_id,
        "start_time": start_time if start_time else end_time,
        "end_time": end_time,
        "flows_requested": flows_requested,
        "flows_processed": total,
        "gt_benign": gt_benign,
        "gt_attacks": gt_attacks,
        "pred_benign": pred_benign,
        "pred_attacks": pred_attacks,
        "alerts_inserted": alerts_inserted,
        "throughput": throughput,
        "status": "COMPLETED"
    })

    print()
    print("=" * 70)
    print("CYBERSENTINEL HISTORICAL SOC REPLAY COMPLETED")
    print("=" * 70)
    print(f"Replay ID              : {replay_id}")
    print(f"Dataset                : CSE-CIC-IDS2018")
    print(f"Source                 : {DATASET_PATH}")
    print()
    print(f"Flows requested        : {flows_requested:,}")
    print(f"Flows processed        : {total:,}")
    print()
    print("Ground Truth")
    print("------------")
    print(f"Ground Truth Benign    : {gt_benign:,}")
    print(f"Ground Truth Attacks   : {gt_attacks:,}")
    print()
    print("Model Prediction")
    print("----------------")
    print(f"Predicted Benign       : {pred_benign:,}")
    print(f"Predicted Attacks      : {pred_attacks:,}")
    print()
    print("Stage-1")
    print("-------")
    print(f"Stage-1 Accuracy       : {stage1_acc * 100:.2f}%")
    print(f"Stage-1 Attack Recall  : {stage1_recall * 100:.2f}%")
    print(f"Precision              : {precision * 100:.2f}%")
    print(f"F1 Score               : {f1_score * 100:.2f}%")
    print()
    print("Stage-2")
    print("-------")
    print(f"Attacks Classified     : {len(attack_flows):,}")
    print(f"Classification Accuracy: {stage2_acc * 100:.2f}%")
    print()
    print("SOC Alerts")
    print("----------")
    print(f"Alerts Inserted        : {alerts_inserted:,}")
    print(f"Critical               : {severities['CRITICAL']:,}")
    print(f"High                   : {severities['HIGH']:,}")
    print(f"Medium                 : {severities['MEDIUM']:,}")
    print(f"Low                    : {severities['LOW']:,}")
    print()
    print(f"Average Confidence     : {avg_conf:.2f}%")
    print()
    print("Performance")
    print("-----------")
    print(f"Total Processing Time  : {processing_time:.2f} sec")
    print(f"Throughput             : {throughput:.1f} flows/sec")
    print("=" * 70)


# ============================================================
# STREAMING REPLAY
# ============================================================

def run_replay(
    number_of_flows: int = DEFAULT_FLOWS,
    batch_size: int = DEFAULT_BATCH_SIZE,
    delay: float = DEFAULT_DELAY,
    replay_id: Optional[str] = None,
    force: bool = False,
):
    """
    Replay real network flows through CyberSentinel using batch inference.
    """
    if not replay_id:
        replay_id = f"demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Check duplicate run safety
    from src.soc.alert_store import get_replay_run
    existing_run = get_replay_run(replay_id)
    if existing_run is not None and not force:
        print()
        print("=" * 70)
        print(f"WARNING: Replay ID '{replay_id}' has already been executed!")
        print("Use --force to re-run or specify a new --replay-id.")
        print("Replay execution skipped.")
        print("=" * 70)
        return

    print_banner()

    start_time_iso = datetime.now().isoformat()
    t_start_replay = time.perf_counter()

    spark = create_spark()

    service = None

    try:

        # ----------------------------------------------------
        # Load dataset
        # ----------------------------------------------------

        print(
            "Loading replay dataset..."
        )

        replay_df = load_replay_flows(
            spark,
            number_of_flows,
        )

        rows = replay_df.collect()

        b_cnt = number_of_flows // 2
        a_cnt = number_of_flows - b_cnt
        print(f"Flows loaded       : {len(rows):,}")
        print(f"Sampling strategy  : BALANCED ({b_cnt:,} benign + {a_cnt:,} attacks)")
        print(f"Batch size         : {batch_size:,}")

        # ----------------------------------------------------
        # Initialize CyberSentinel
        # ----------------------------------------------------

        print()
        print(
            "Initializing CyberSentinel..."
        )

        service = DetectionService()

        print()
        print(
            "Streaming started."
        )

        print(
            "Press Ctrl+C to stop."
        )

        # ----------------------------------------------------
        # Global result tracking
        # ----------------------------------------------------

        all_results = []

        all_ground_truth = []

        all_inserted_counts = []

        # ----------------------------------------------------
        # Process batches
        # ----------------------------------------------------

        batch_number = 0

        for start in range(
            0,
            len(rows),
            batch_size,
        ):

            batch_number += 1

            batch_rows = rows[
                start:
                start + batch_size
            ]

            # ------------------------------------------------
            # Convert rows to inference flows
            # ------------------------------------------------

            flows = []

            ground_truth = []

            for row in batch_rows:

                flows.append(
                    row_to_flow(row)
                )

                ground_truth.append(
                    get_ground_truth(row)
                )

            # ------------------------------------------------
            # Run batch inference
            # ------------------------------------------------

            results = service.predictor.predict_batch(
                flows
            )

            # ------------------------------------------------
            # Persist attack alerts
            #
            # We deliberately use DetectionService here so
            # persistence behavior remains centralized.
            # ------------------------------------------------

            inserted_counts = []

            processed_results = []

            for flow, result in zip(
                flows,
                results,
            ):

                # --------------------------------------------
                # Build DetectionService-compatible result
                # --------------------------------------------

                enriched_result = {
                    "Timestamp": flow.get(
                        "Timestamp",
                        datetime.now().isoformat(),
                    ),

                    "Dst_Port": flow.get(
                        "Dst_Port"
                    ),

                    "Protocol": flow.get(
                        "Protocol"
                    ),

                    "attack_type": result.get(
                        "attack_type"
                    ),

                    "severity": result.get(
                        "severity"
                    ),

                    "attack_probability": result.get(
                        "confidence",
                        0.0,
                    ),

                    "confidence": result.get(
                        "confidence",
                        0.0,
                    ),

                    "is_attack": result.get(
                        "is_attack",
                        False,
                    ),

                    "stage1_confidence": result.get(
                        "stage1_confidence",
                        0.0,
                    ),

                    "stage2_confidence": result.get(
                        "stage2_confidence",
                        0.0,
                    ),
                }

                # --------------------------------------------
                # Persist only actual attacks
                # --------------------------------------------

                if result.get(
                    "is_attack",
                    False,
                ):

                    import pandas as pd

                    alert_dataframe = pd.DataFrame(
                        [enriched_result]
                    )

                    from src.soc.alert_store import sync_alerts

                    inserted = sync_alerts(
                        alert_dataframe
                    )

                else:

                    inserted = 0

                inserted_counts.append(
                    inserted
                )

                # --------------------------------------------
                # Add persistence information to result
                # --------------------------------------------

                enriched_result[
                    "alert_persisted"
                ] = (
                    inserted > 0
                )

                enriched_result[
                    "alert_inserted_count"
                ] = inserted

                processed_results.append(
                    enriched_result
                )

            # ------------------------------------------------
            # Store global results
            # ------------------------------------------------

            all_results.extend(
                processed_results
            )

            all_ground_truth.extend(
                ground_truth
            )

            all_inserted_counts.extend(
                inserted_counts
            )

            # ------------------------------------------------
            # Display batch
            # ------------------------------------------------

            print_batch_results(
                batch_number,
                start + 1,
                flows,
                ground_truth,
                processed_results,
                inserted_counts,
            )

            # ------------------------------------------------
            # Delay between batches
            # ------------------------------------------------

            if (
                start + batch_size
                < len(rows)
                and delay > 0
            ):

                time.sleep(
                    delay
                )

        # ----------------------------------------------------
        # Finished
        # ----------------------------------------------------

        t_elapsed = time.perf_counter() - t_start_replay

        print_summary(
            all_results,
            all_ground_truth,
            all_inserted_counts,
            flows_requested=number_of_flows,
            processing_time=t_elapsed,
            replay_id=replay_id,
            start_time=start_time_iso,
        )

        print()

        print(
            "CYBERSENTINEL STREAM COMPLETED"
        )

        print()

    except KeyboardInterrupt:

        print()
        print()
        print(
            "Streaming stopped by user."
        )

    finally:

        if service is not None:
            service.close()

        spark.stop()


# ============================================================
# CLI
# ============================================================

def main():
    """
    Command-line entry point.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Replay real CSE-CIC-IDS2018 "
            "network flows through CyberSentinel."
        )
    )

    # --------------------------------------------------------
    # Number of flows
    # --------------------------------------------------------

    parser.add_argument(
        "--flows",
        type=int,
        default=DEFAULT_FLOWS,
        help=(
            "Number of flows to replay "
            f"(default: {DEFAULT_FLOWS})"
        ),
    )

    # --------------------------------------------------------
    # Batch size
    # --------------------------------------------------------

    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=(
            "Number of flows processed per "
            f"inference batch "
            f"(default: {DEFAULT_BATCH_SIZE})"
        ),
    )

    # --------------------------------------------------------
    # Delay
    # --------------------------------------------------------

    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help=(
            "Delay between batches in seconds "
            f"(default: {DEFAULT_DELAY})"
        ),
    )

    # --------------------------------------------------------
    # Replay ID & Force flag
    # --------------------------------------------------------

    parser.add_argument(
        "--replay-id",
        type=str,
        default=None,
        help="Unique identifier for this replay run (e.g. demo_50k)",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Force execution even if replay_id already exists",
    )

    parser.add_argument(
        "--reset-soc",
        action="store_true",
        help="Safely backup database and reset operational alerts table while preserving replay history",
    )

    args = parser.parse_args()

    if args.reset_soc:
        from src.soc.alert_store import backup_and_reset_soc_alerts
        res = backup_and_reset_soc_alerts(confirm=True)
        print()
        print("=" * 70)
        print("CYBERSENTINEL SOC ALERT DATABASE RESET COMPLETED")
        print("=" * 70)
        print(f"Pre-reset Operational Alerts  : {res['pre_total_alerts']:,}")
        print(f"Operational Alerts after reset: {res['post_alerts_count']}")
        print(f"Replay History Preserved      : YES ({res['post_replays_count']} historical runs)")
        print(f"Database Backup Created       : {res['backup_path']}")
        print("=" * 70)
        print()
        import sys
        sys.exit(0)

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if args.flows < 2:

        parser.error(
            "--flows must be at least 2"
        )

    if args.batch_size < 1:

        parser.error(
            "--batch-size must be at least 1"
        )

    if args.batch_size > args.flows:

        parser.error(
            "--batch-size cannot exceed --flows"
        )

    if args.delay < 0:

        parser.error(
            "--delay cannot be negative"
        )

    # --------------------------------------------------------
    # Run
    # --------------------------------------------------------

    run_replay(
        number_of_flows=args.flows,
        batch_size=args.batch_size,
        delay=args.delay,
        replay_id=args.replay_id,
        force=args.force,
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
