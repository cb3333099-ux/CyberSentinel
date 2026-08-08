from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col,
    input_file_name,
    lit,
    trim,
)


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(
    "/mnt/d/BDA/CyberSentinel"
)

RAW_DIR = (
    PROJECT_ROOT
    / "data"
    / "raw"
)

ADDITIONAL_RAW_DIR = (
    RAW_DIR
    / "cse-cic-ids2018-full"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cse-cic-ids2018-full"
)


# ============================================================
# CANONICAL CSE-CIC-IDS2018 ML COLUMNS
# ============================================================

CANONICAL_COLUMNS = [
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Tot",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Var",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "CWE Flag Count",
    "ECE Flag Cnt",
    "Down/Up Ratio",
    "Pkt Size Avg",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg",
    "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg",
    "Bwd Pkts/b Avg",
    "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts",
    "Subflow Fwd Byts",
    "Subflow Bwd Pkts",
    "Subflow Bwd Byts",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "Label",
]


# ============================================================
# SPARK
# ============================================================

def create_spark():

    return (
        SparkSession.builder
        .appName(
            "CyberSentinel-Full-CSE-CIC-IDS2018"
        )
        .master("local[*]")
        .config(
            "spark.driver.memory",
            "4g",
        )
        .config(
            "spark.executor.memory",
            "4g",
        )
        .config(
            "spark.sql.shuffle.partitions",
            "32",
        )
        .config(
            "spark.default.parallelism",
            "16",
        )
        .config(
            "spark.sql.files.maxPartitionBytes",
            "67108864",
        )
        .config(
            "spark.sql.adaptive.enabled",
            "true",
        )
        .config(
            "spark.sql.debug.maxToStringFields",
            "200",
        )
        .getOrCreate()
    )


# ============================================================
# DISCOVER FILES
# ============================================================

def discover_files():

    print()
    print("=" * 80)
    print(
        "CYBERSENTINEL FULL CSE-CIC-IDS2018 INGESTION"
    )
    print("=" * 80)

    files = []

    # Existing Friday file
    if RAW_DIR.exists():

        for path in RAW_DIR.glob(
            "*TrafficForML_CICFlowMeter.csv"
        ):

            files.append(path)

    # Remaining downloaded files
    if ADDITIONAL_RAW_DIR.exists():

        for path in ADDITIONAL_RAW_DIR.glob(
            "*TrafficForML_CICFlowMeter.csv"
        ):

            files.append(path)

    # Remove duplicate paths
    unique = {}

    for path in files:

        unique[str(path.resolve())] = path.resolve()

    files = sorted(
        unique.values()
    )

    if len(files) != 10:

        raise RuntimeError(
            f"Expected 10 CSE-CIC-IDS2018 CSV files, "
            f"but found {len(files)}."
        )

    print()
    print(
        f"Discovered {len(files)} CSV files:"
    )

    for index, path in enumerate(
        files,
        start=1,
    ):

        size_gb = (
            path.stat().st_size
            / (1024 ** 3)
        )

        print(
            f"{index:02d}. "
            f"{path.name} "
            f"({size_gb:.2f} GB)"
        )

    return files


# ============================================================
# NORMALIZE COLUMN NAMES
# ============================================================

def normalize_column_name(name):

    return (
        name
        .strip()
    )


# ============================================================
# READ ONE FILE
# ============================================================

def read_single_file(
    spark,
    path,
):

    print()
    print(
        "-" * 80
    )

    print(
        f"Reading: {path.name}"
    )

    # --------------------------------------------------------
    # Read without inferSchema.
    #
    # We deliberately read as strings first so that files
    # with slightly different inferred numeric types cannot
    # break the union.
    # --------------------------------------------------------

    df = (
        spark.read
        .option(
            "header",
            True,
        )
        .option(
            "inferSchema",
            False,
        )
        .option(
            "mode",
            "PERMISSIVE",
        )
        .option(
            "multiLine",
            False,
        )
        .csv(
            str(path)
        )
    )

    original_columns = [
        normalize_column_name(c)
        for c in df.columns
    ]

    df = df.toDF(
        *original_columns
    )

    print(
        f"Columns in source: "
        f"{len(df.columns)}"
    )

    # --------------------------------------------------------
    # Identify missing canonical columns
    # --------------------------------------------------------

    missing = [
        column
        for column in CANONICAL_COLUMNS
        if column not in df.columns
    ]

    if missing:

        print()
        print(
            "ERROR: Missing canonical columns:"
        )

        for column in missing:

            print(
                f"  - {column}"
            )

        raise RuntimeError(
            f"{path.name} is missing "
            f"{len(missing)} required columns."
        )

    # --------------------------------------------------------
    # Select ONLY the canonical 80 ML columns.
    #
    # This automatically removes:
    #
    # Flow ID
    # Src IP
    # Src Port
    # Dst IP
    #
    # from the Tuesday file.
    # --------------------------------------------------------

    df = df.select(
        *[
            col(column)
            for column in CANONICAL_COLUMNS
        ]
    )

    # --------------------------------------------------------
    # Add source filename.
    # --------------------------------------------------------

    df = df.withColumn(
        "source_file",
        lit(path.name),
    )

    # --------------------------------------------------------
    # Normalize label.
    # --------------------------------------------------------

    df = df.withColumn(
        "Label",
        trim(
            col("Label")
        ),
    )

    # --------------------------------------------------------
    # Count rows.
    # --------------------------------------------------------

    row_count = df.count()

    print(
        f"Rows: {row_count:,}"
    )

    # --------------------------------------------------------
    # Show labels for this file.
    # --------------------------------------------------------

    print(
        "Top labels:"
    )

    (
        df
        .groupBy("Label")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            20,
            truncate=False,
        )
    )

    return df


# ============================================================
# UNION DATASETS
# ============================================================

def combine_datasets(
    dataframes,
):

    print()
    print("=" * 80)
    print(
        "Combining all datasets..."
    )
    print("=" * 80)

    combined = dataframes[0]

    for df in dataframes[1:]:

        combined = combined.unionByName(
            df,
            allowMissingColumns=False,
        )

    print()
    print(
        "All datasets combined successfully."
    )

    print(
        f"Columns: {len(combined.columns)}"
    )

    return combined


# ============================================================
# LABEL VALIDATION
# ============================================================

def validate_labels(
    df,
):

    print()
    print("=" * 80)
    print(
        "FULL DATASET LABEL VALIDATION"
    )
    print("=" * 80)

    print()
    print(
        "Complete label distribution:"
    )

    (
        df
        .groupBy("Label")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            200,
            truncate=False,
        )
    )

    print()
    print(
        "Rows by source file:"
    )

    (
        df
        .groupBy("source_file")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            20,
            truncate=False,
        )
    )

    # --------------------------------------------------------
    # Check null / empty labels
    # --------------------------------------------------------

    null_labels = (
        df
        .where(
            col("Label").isNull()
            | (trim(col("Label")) == "")
        )
        .count()
    )

    print()
    print(
        f"Null/empty labels: "
        f"{null_labels:,}"
    )

    return null_labels


# ============================================================
# WRITE PARQUET
# ============================================================

def write_parquet(
    df,
):

    print()
    print("=" * 80)
    print(
        "Writing unified Parquet dataset..."
    )
    print("=" * 80)

    output = str(
        OUTPUT_DIR
    )

    (
        df
        .write
        .mode("overwrite")
        .option(
            "compression",
            "snappy",
        )
        .parquet(
            output
        )
    )

    print()
    print(
        "Parquet dataset written to:"
    )

    print(
        output
    )


# ============================================================
# VERIFY PARQUET
# ============================================================

def verify_parquet(
    spark,
):

    print()
    print("=" * 80)
    print(
        "VERIFYING PARQUET DATASET"
    )
    print("=" * 80)

    result = (
        spark.read
        .parquet(
            str(OUTPUT_DIR)
        )
    )

    rows = result.count()

    print()
    print(
        f"Final rows: "
        f"{rows:,}"
    )

    print(
        f"Final columns: "
        f"{len(result.columns)}"
    )

    print()
    print(
        "Final label distribution:"
    )

    (
        result
        .groupBy("Label")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            200,
            truncate=False,
        )
    )

    return rows


# ============================================================
# MAIN
# ============================================================

def main():

    spark = create_spark()

    try:

        # ----------------------------------------------------
        # 1. Discover
        # ----------------------------------------------------

        files = discover_files()

        # ----------------------------------------------------
        # 2. Read each file independently
        # ----------------------------------------------------

        dataframes = []

        for path in files:

            df = read_single_file(
                spark,
                path,
            )

            dataframes.append(
                df
            )

        # ----------------------------------------------------
        # 3. Combine
        # ----------------------------------------------------

        combined = combine_datasets(
            dataframes
        )

        # ----------------------------------------------------
        # 4. Validate
        # ----------------------------------------------------

        null_labels = validate_labels(
            combined
        )

        if null_labels > 0:

            raise RuntimeError(
                f"Found {null_labels:,} rows "
                "with missing labels."
            )

        # ----------------------------------------------------
        # 5. Count
        # ----------------------------------------------------

        print()
        print(
            "Counting final combined rows..."
        )

        total_rows = combined.count()

        print()
        print(
            f"Total combined rows: "
            f"{total_rows:,}"
        )

        # ----------------------------------------------------
        # 6. Write
        # ----------------------------------------------------

        write_parquet(
            combined
        )

        # ----------------------------------------------------
        # 7. Verify
        # ----------------------------------------------------

        final_rows = verify_parquet(
            spark
        )

        # ----------------------------------------------------
        # Final summary
        # ----------------------------------------------------

        print()
        print("=" * 80)
        print(
            "CYBERSENTINEL FULL DATASET INGESTION "
            "COMPLETED"
        )
        print("=" * 80)

        print()
        print(
            f"Source files: "
            f"{len(files)}"
        )

        print(
            f"Final rows: "
            f"{final_rows:,}"
        )

        print(
            f"Final columns: "
            f"{len(CANONICAL_COLUMNS) + 1}"
        )

        print()
        print(
            "Output:"
        )

        print(
            OUTPUT_DIR
        )

        print()
        print(
            "Global deduplication: SKIPPED"
        )

        print(
            "Reason: avoid an extremely expensive "
            "16M+ row full-width shuffle."
        )

        print()
        print("=" * 80)

    finally:

        try:

            spark.stop()

        except Exception:

            pass


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
