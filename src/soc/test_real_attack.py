from pyspark.sql import SparkSession
from pyspark.sql.functions import col

from src.soc.detection_service import DetectionService


def main():

    print()
    print("=" * 80)
    print("CYBERSENTINEL REAL ATTACK → SOC ALERT TEST")
    print("=" * 80)

    spark = (
        SparkSession.builder
        .appName("CyberSentinelRealAttackTest")
        .master("local[*]")
        .getOrCreate()
    )

    # --------------------------------------------------------
    # Load the real test dataset
    # --------------------------------------------------------

    df = spark.read.parquet(
        "data/processed/ml-full/test"
    )

    # --------------------------------------------------------
    # Select one genuine DDOS attack-HOIC flow
    # --------------------------------------------------------

    attack = (
        df.filter(
            (col("stage1_label") == 1.0)
            &
            (
                col("attack_label")
                == "DDOS attack-HOIC"
            )
        )
        .limit(1)
    )

    row = attack.collect()[0].asDict()

    print()
    print("GROUND TRUTH")
    print("-" * 80)

    print(
        "Attack type :",
        row["attack_label"]
    )

    print(
        "Stage 1     :",
        row["stage1_label"]
    )

    print(
        "Source file :",
        row["source_file"]
    )

    # --------------------------------------------------------
    # Remove dataset-only columns
    # --------------------------------------------------------

    flow = {
        key: value
        for key, value in row.items()
        if key not in {
            "stage1_label",
            "attack_label",
            "source_file",
        }
    }

    spark.stop()

    # --------------------------------------------------------
    # Run CyberSentinel inference
    # --------------------------------------------------------

    print()
    print("RUNNING CYBERSENTINEL INFERENCE")
    print("-" * 80)

    service = DetectionService()

    result = service.analyze_flow(
        flow,
        persist_alert=True,
    )

    # --------------------------------------------------------
    # Display result
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("CYBERSENTINEL RESULT")
    print("=" * 80)

    for key, value in result.items():
        print(
            f"{key:<25}: {value}"
        )

    service.close()

    print()
    print("=" * 80)
    print("REAL ATTACK TEST COMPLETED")
    print("=" * 80)


if __name__ == "__main__":
    main()
