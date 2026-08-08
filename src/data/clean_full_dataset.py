from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col,
    count,
    lower,
    trim,
    when,
)


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(
    "/mnt/d/BDA/CyberSentinel"
)

INPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cse-cic-ids2018-full"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cse-cic-ids2018-clean"
)


# ============================================================
# SPARK SESSION
# ============================================================

def create_spark():

    return (
        SparkSession.builder
        .appName(
            "CyberSentinel-Full-Dataset-Cleaning"
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
        .getOrCreate()
    )


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset(spark):

    print()
    print("=" * 80)
    print(
        "CYBERSENTINEL FULL DATASET CLEANING"
    )
    print("=" * 80)

    print()
    print(
        "Loading unified Parquet dataset..."
    )

    df = (
        spark.read
        .parquet(
            str(INPUT_DIR)
        )
    )

    print()
    print(
        f"Input columns: {len(df.columns)}"
    )

    return df


# ============================================================
# INITIAL STATISTICS
# ============================================================

def show_initial_statistics(df):

    print()
    print("=" * 80)
    print(
        "INITIAL DATASET STATISTICS"
    )
    print("=" * 80)

    total_rows = df.count()

    print()
    print(
        f"Input rows: {total_rows:,}"
    )

    print()
    print(
        "Input label distribution:"
    )

    (
        df
        .groupBy("Label")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            100,
            truncate=False,
        )
    )

    return total_rows


# ============================================================
# REMOVE HEADER ARTIFACTS
# ============================================================

def remove_header_artifacts(df):

    print()
    print("=" * 80)
    print(
        "REMOVING HEADER ARTIFACT ROWS"
    )
    print("=" * 80)

    # --------------------------------------------------------
    # The raw dataset contains a small number of rows where
    # the literal CSV header "Label" appears in the Label
    # column.
    #
    # These are NOT attack samples.
    # --------------------------------------------------------

    artifact_count = (
        df
        .where(
            trim(
                col("Label")
            ) == "Label"
        )
        .count()
    )

    print()
    print(
        f"Header-artifact rows found: "
        f"{artifact_count:,}"
    )

    if artifact_count > 0:

        df = (
            df
            .where(
                trim(
                    col("Label")
                ) != "Label"
            )
        )

    remaining = df.count()

    print(
        f"Rows after artifact removal: "
        f"{remaining:,}"
    )

    return df, artifact_count


# ============================================================
# NORMALIZE LABELS
# ============================================================

def normalize_labels(df):

    print()
    print("=" * 80)
    print(
        "NORMALIZING ATTACK LABELS"
    )
    print("=" * 80)

    # --------------------------------------------------------
    # Remove accidental surrounding whitespace.
    # --------------------------------------------------------

    df = df.withColumn(
        "Label",
        trim(
            col("Label")
        ),
    )

    # --------------------------------------------------------
    # Normalize known spelling variations.
    #
    # The source dataset uses "Infilteration". We preserve
    # the dataset's terminology rather than silently changing
    # the actual attack name.
    # --------------------------------------------------------

    df = df.withColumn(
        "Label",
        when(
            lower(
                col("Label")
            ) == "benign",
            "Benign",
        )
        .when(
            lower(
                col("Label")
            ) == "bot",
            "Bot",
        )
        .otherwise(
            col("Label")
        ),
    )

    return df


# ============================================================
# NULL / EMPTY LABEL CHECK
# ============================================================

def validate_labels(df):

    print()
    print("=" * 80)
    print(
        "VALIDATING LABELS"
    )
    print("=" * 80)

    null_count = (
        df
        .where(
            col("Label").isNull()
            |
            (
                trim(
                    col("Label")
                ) == ""
            )
        )
        .count()
    )

    print()
    print(
        f"Null/empty labels: "
        f"{null_count:,}"
    )

    if null_count != 0:

        raise RuntimeError(
            "Dataset contains null or empty labels."
        )

    # --------------------------------------------------------
    # Distinct label count
    # --------------------------------------------------------

    distinct_labels = (
        df
        .select("Label")
        .distinct()
        .count()
    )

    print(
        f"Distinct labels: "
        f"{distinct_labels}"
    )

    print()
    print(
        "Clean label distribution:"
    )

    (
        df
        .groupBy("Label")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            100,
            truncate=False,
        )
    )

    return distinct_labels


# ============================================================
# DATASET SANITY CHECK
# ============================================================

def sanity_check(df):

    print()
    print("=" * 80)
    print(
        "DATASET SANITY CHECK"
    )
    print("=" * 80)

    total = df.count()

    # --------------------------------------------------------
    # Check that no header artifacts remain.
    # --------------------------------------------------------

    remaining_artifacts = (
        df
        .where(
            trim(
                col("Label")
            ) == "Label"
        )
        .count()
    )

    if remaining_artifacts != 0:

        raise RuntimeError(
            "Header-artifact rows still exist."
        )

    # --------------------------------------------------------
    # Check source file column.
    # --------------------------------------------------------

    if "source_file" not in df.columns:

        raise RuntimeError(
            "source_file column is missing."
        )

    # --------------------------------------------------------
    # Check expected feature columns.
    # --------------------------------------------------------

    expected_columns = [
        "Dst Port",
        "Protocol",
        "Timestamp",
        "Flow Duration",
        "Tot Fwd Pkts",
        "Tot Bwd Pkts",
        "Label",
        "source_file",
    ]

    missing = [
        column
        for column in expected_columns
        if column not in df.columns
    ]

    if missing:

        raise RuntimeError(
            "Missing expected columns: "
            + ", ".join(missing)
        )

    print()
    print(
        f"Sanity-check rows: "
        f"{total:,}"
    )

    print(
        "Header artifacts remaining: 0"
    )

    print(
        "Required columns: present"
    )

    return total


# ============================================================
# WRITE CLEAN DATASET
# ============================================================

def write_dataset(df):

    print()
    print("=" * 80)
    print(
        "WRITING CLEAN DATASET"
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
        "Clean dataset written to:"
    )

    print(
        output
    )


# ============================================================
# VERIFY OUTPUT
# ============================================================

def verify_output(spark):

    print()
    print("=" * 80)
    print(
        "VERIFYING CLEAN DATASET"
    )
    print("=" * 80)

    df = (
        spark.read
        .parquet(
            str(OUTPUT_DIR)
        )
    )

    total = df.count()

    print()
    print(
        f"Final rows: "
        f"{total:,}"
    )

    print(
        f"Final columns: "
        f"{len(df.columns)}"
    )

    print()
    print(
        "Final label distribution:"
    )

    (
        df
        .groupBy("Label")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            100,
            truncate=False,
        )
    )

    # --------------------------------------------------------
    # Final artifact check
    # --------------------------------------------------------

    artifacts = (
        df
        .where(
            trim(
                col("Label")
            ) == "Label"
        )
        .count()
    )

    if artifacts != 0:

        raise RuntimeError(
            "Verification failed: "
            "header artifacts remain."
        )

    print()
    print(
        "Verification successful."
    )

    return total


# ============================================================
# MAIN
# ============================================================

def main():

    spark = create_spark()

    try:

        # ----------------------------------------------------
        # 1. Load
        # ----------------------------------------------------

        df = load_dataset(
            spark
        )

        # ----------------------------------------------------
        # 2. Initial statistics
        # ----------------------------------------------------

        input_rows = (
            show_initial_statistics(
                df
            )
        )

        # ----------------------------------------------------
        # 3. Remove header artifacts
        # ----------------------------------------------------

        df, removed = (
            remove_header_artifacts(
                df
            )
        )

        # ----------------------------------------------------
        # 4. Normalize labels
        # ----------------------------------------------------

        df = normalize_labels(
            df
        )

        # ----------------------------------------------------
        # 5. Validate
        # ----------------------------------------------------

        distinct_labels = (
            validate_labels(
                df
            )
        )

        # ----------------------------------------------------
        # 6. Sanity check
        # ----------------------------------------------------

        clean_rows = (
            sanity_check(
                df
            )
        )

        # ----------------------------------------------------
        # 7. Write
        # ----------------------------------------------------

        write_dataset(
            df
        )

        # ----------------------------------------------------
        # 8. Verify
        # ----------------------------------------------------

        final_rows = (
            verify_output(
                spark
            )
        )

        # ----------------------------------------------------
        # Final summary
        # ----------------------------------------------------

        print()
        print("=" * 80)
        print(
            "CYBERSENTINEL DATA CLEANING "
            "COMPLETED SUCCESSFULLY"
        )
        print("=" * 80)

        print()
        print(
            f"Input rows:             "
            f"{input_rows:,}"
        )

        print(
            f"Header artifacts removed:"
            f" {removed:,}"
        )

        print(
            f"Clean rows:             "
            f"{clean_rows:,}"
        )

        print(
            f"Final rows:             "
            f"{final_rows:,}"
        )

        print(
            f"Distinct labels:        "
            f"{distinct_labels}"
        )

        print()
        print(
            "Output:"
        )

        print(
            OUTPUT_DIR
        )

        print()
        print("=" * 80)

    finally:

        spark.stop()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()