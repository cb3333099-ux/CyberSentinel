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
from typing import Any, Dict, List

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
):
    """
    Print overall streaming replay metrics.
    """

    total = len(results)

    # --------------------------------------------------------
    # Ground truth attack count
    # --------------------------------------------------------

    actual_attacks = sum(
        1
        for value in ground_truth
        if value != "Benign"
    )

    actual_benign = (
        total
        - actual_attacks
    )

    # --------------------------------------------------------
    # Predicted attack count
    # --------------------------------------------------------

    predicted_attacks = sum(
        1
        for result in results
        if result.get("is_attack") is True
    )

    predicted_benign = (
        total
        - predicted_attacks
    )

    # --------------------------------------------------------
    # Stage 1 accuracy
    # --------------------------------------------------------

    stage1_correct = 0

    for truth, result in zip(
        ground_truth,
        results,
    ):

        actual_attack = (
            truth != "Benign"
        )

        predicted_attack = (
            result.get(
                "is_attack",
                False,
            )
        )

        if (
            actual_attack
            == predicted_attack
        ):
            stage1_correct += 1

    stage1_accuracy = (
        stage1_correct / total
        if total
        else 0.0
    )

    # --------------------------------------------------------
    # Stage 2 accuracy
    #
    # Only evaluate flows that are actually attacks.
    # --------------------------------------------------------

    attack_flows = [
        (truth, result)
        for truth, result in zip(
            ground_truth,
            results,
        )
        if truth != "Benign"
    ]

    stage2_correct = 0

    for truth, result in attack_flows:

        if (
            result.get("attack_type")
            == truth
        ):
            stage2_correct += 1

    stage2_accuracy = (
        stage2_correct
        / len(attack_flows)
        if attack_flows
        else 0.0
    )

    # --------------------------------------------------------
    # Persistence
    # --------------------------------------------------------

    alerts_inserted = sum(
        inserted_counts
    )

    # --------------------------------------------------------
    # Print summary
    # --------------------------------------------------------

    print()
    print("=" * 90)
    print(
        "CYBERSENTINEL STREAM SUMMARY"
    )
    print("=" * 90)

    print(
        f"Flows processed       : "
        f"{total}"
    )

    print(
        f"Actual attacks        : "
        f"{actual_attacks}"
    )

    print(
        f"Actual benign         : "
        f"{actual_benign}"
    )

    print(
        f"Predicted attacks     : "
        f"{predicted_attacks}"
    )

    print(
        f"Predicted benign      : "
        f"{predicted_benign}"
    )

    print(
        f"Alerts inserted       : "
        f"{alerts_inserted}"
    )

    print(
        f"Stage-1 accuracy      : "
        f"{stage1_accuracy:.4f}"
    )

    if attack_flows:

        print(
            f"Stage-2 type accuracy : "
            f"{stage2_accuracy:.4f}"
        )

    else:

        print(
            "Stage-2 type accuracy : N/A"
        )

    print(
        "=" * 90
    )


# ============================================================
# STREAMING REPLAY
# ============================================================

def run_replay(
    number_of_flows: int = DEFAULT_FLOWS,
    batch_size: int = DEFAULT_BATCH_SIZE,
    delay: float = DEFAULT_DELAY,
):
    """
    Replay real network flows through CyberSentinel
    using batch inference.

    Example:

        python -m src.streaming.replay_service \
            --flows 6 \
            --batch-size 3 \
            --delay 1
    """

    print_banner()

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

        print(
            f"Flows loaded   : "
            f"{len(rows)}"
        )

        print(
            f"Batch size     : "
            f"{batch_size}"
        )

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

        print_summary(
            all_results,
            all_ground_truth,
            all_inserted_counts,
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

    args = parser.parse_args()

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
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
