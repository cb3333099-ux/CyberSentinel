from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col,
    when,
    trim,
    to_timestamp,
    hour,
    dayofweek,
    rand,
)


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = "/mnt/d/BDA/CyberSentinel"

INPUT_PATH = (
    f"{PROJECT_ROOT}/data/processed/"
    "cse-cic-ids2018-clean"
)

OUTPUT_BASE = (
    f"{PROJECT_ROOT}/data/processed/"
    "ml-full"
)

TRAIN_PATH = f"{OUTPUT_BASE}/train"
TEST_PATH = f"{OUTPUT_BASE}/test"


# ============================================================
# ML FEATURES
# ============================================================

FEATURE_COLUMNS = [

    "Dst_Port",
    "Protocol",

    "Flow_Duration",

    "Tot_Fwd_Pkts",
    "Tot_Bwd_Pkts",

    "TotLen_Fwd_Pkts",
    "TotLen_Bwd_Pkts",

    "Fwd_Pkt_Len_Max",
    "Fwd_Pkt_Len_Min",
    "Fwd_Pkt_Len_Mean",
    "Fwd_Pkt_Len_Std",

    "Bwd_Pkt_Len_Max",
    "Bwd_Pkt_Len_Min",
    "Bwd_Pkt_Len_Mean",
    "Bwd_Pkt_Len_Std",

    "Flow_Byts_per_s",
    "Flow_Pkts_per_s",

    "Flow_IAT_Mean",
    "Flow_IAT_Std",
    "Flow_IAT_Max",
    "Flow_IAT_Min",

    "Fwd_IAT_Tot",
    "Fwd_IAT_Mean",
    "Fwd_IAT_Std",
    "Fwd_IAT_Max",
    "Fwd_IAT_Min",

    "Bwd_IAT_Tot",
    "Bwd_IAT_Mean",
    "Bwd_IAT_Std",
    "Bwd_IAT_Max",
    "Bwd_IAT_Min",

    "Fwd_PSH_Flags",
    "Bwd_PSH_Flags",
    "Fwd_URG_Flags",
    "Bwd_URG_Flags",

    "Fwd_Header_Len",
    "Bwd_Header_Len",

    "Fwd_Pkts_per_s",
    "Bwd_Pkts_per_s",

    "Pkt_Len_Min",
    "Pkt_Len_Max",
    "Pkt_Len_Mean",
    "Pkt_Len_Std",
    "Pkt_Len_Var",

    "FIN_Flag_Cnt",
    "SYN_Flag_Cnt",
    "RST_Flag_Cnt",
    "PSH_Flag_Cnt",
    "ACK_Flag_Cnt",
    "URG_Flag_Cnt",

    "CWE_Flag_Count",
    "ECE_Flag_Cnt",

    "Down_per_Up_Ratio",
    "Pkt_Size_Avg",

    "Fwd_Seg_Size_Avg",
    "Bwd_Seg_Size_Avg",

    "Fwd_Byts_per_b_Avg",
    "Fwd_Pkts_per_b_Avg",
    "Fwd_Blk_Rate_Avg",

    "Bwd_Byts_per_b_Avg",
    "Bwd_Pkts_per_b_Avg",
    "Bwd_Blk_Rate_Avg",

    "Subflow_Fwd_Pkts",
    "Subflow_Fwd_Byts",
    "Subflow_Bwd_Pkts",
    "Subflow_Bwd_Byts",

    "Init_Fwd_Win_Byts",
    "Init_Bwd_Win_Byts",

    "Fwd_Act_Data_Pkts",
    "Fwd_Seg_Size_Min",

    "Active_Mean",
    "Active_Std",
    "Active_Max",
    "Active_Min",

    "Idle_Mean",
    "Idle_Std",
    "Idle_Max",
    "Idle_Min",

    "Hour",
    "DayOfWeek",
    "IsWeekend",
]


# ============================================================
# SPARK SESSION
# ============================================================

def create_spark_session():

    spark = (
        SparkSession.builder
        .master("local[*]")
        .appName(
            "CyberSentinel-Full-Feature-Engineering"
        )
        .config(
            "spark.sql.warehouse.dir",
            f"{PROJECT_ROOT}/spark-warehouse",
        )
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
            "16",
        )
        .config(
            "spark.default.parallelism",
            "8",
        )
        .config(
            "spark.sql.adaptive.enabled",
            "true",
        )
        .config(
            "spark.sql.files.maxPartitionBytes",
            "67108864",
        )
        .config(
            "spark.sql.debug.maxToStringFields",
            "200",
        )
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    return spark


# ============================================================
# LOAD DATA
# ============================================================

def load_data(spark):

    print()
    print("=" * 80)
    print("CYBERSENTINEL FULL DATASET FEATURE ENGINEERING")
    print("=" * 80)

    print()
    print("Loading cleaned CSE-CIC-IDS2018 dataset...")

    df = (
        spark.read
        .parquet(INPUT_PATH)
    )

    print()
    print(
        f"Columns loaded: {len(df.columns)}"
    )

    return df


# ============================================================
# NORMALIZE COLUMN NAMES
# ============================================================

def normalize_column_names(df):

    print()
    print("[1/7] Normalizing CICFlowMeter column names...")

    rename_map = {

        "Dst Port": "Dst_Port",
        "Flow Duration": "Flow_Duration",

        "Tot Fwd Pkts": "Tot_Fwd_Pkts",
        "Tot Bwd Pkts": "Tot_Bwd_Pkts",

        "TotLen Fwd Pkts": "TotLen_Fwd_Pkts",
        "TotLen Bwd Pkts": "TotLen_Bwd_Pkts",

        "Fwd Pkt Len Max": "Fwd_Pkt_Len_Max",
        "Fwd Pkt Len Min": "Fwd_Pkt_Len_Min",
        "Fwd Pkt Len Mean": "Fwd_Pkt_Len_Mean",
        "Fwd Pkt Len Std": "Fwd_Pkt_Len_Std",

        "Bwd Pkt Len Max": "Bwd_Pkt_Len_Max",
        "Bwd Pkt Len Min": "Bwd_Pkt_Len_Min",
        "Bwd Pkt Len Mean": "Bwd_Pkt_Len_Mean",
        "Bwd Pkt Len Std": "Bwd_Pkt_Len_Std",

        "Flow Byts/s": "Flow_Byts_per_s",
        "Flow Pkts/s": "Flow_Pkts_per_s",

        "Flow IAT Mean": "Flow_IAT_Mean",
        "Flow IAT Std": "Flow_IAT_Std",
        "Flow IAT Max": "Flow_IAT_Max",
        "Flow IAT Min": "Flow_IAT_Min",

        "Fwd IAT Tot": "Fwd_IAT_Tot",
        "Fwd IAT Mean": "Fwd_IAT_Mean",
        "Fwd IAT Std": "Fwd_IAT_Std",
        "Fwd IAT Max": "Fwd_IAT_Max",
        "Fwd IAT Min": "Fwd_IAT_Min",

        "Bwd IAT Tot": "Bwd_IAT_Tot",
        "Bwd IAT Mean": "Bwd_IAT_Mean",
        "Bwd IAT Std": "Bwd_IAT_Std",
        "Bwd IAT Max": "Bwd_IAT_Max",
        "Bwd IAT Min": "Bwd_IAT_Min",

        "Fwd PSH Flags": "Fwd_PSH_Flags",
        "Bwd PSH Flags": "Bwd_PSH_Flags",
        "Fwd URG Flags": "Fwd_URG_Flags",
        "Bwd URG Flags": "Bwd_URG_Flags",

        "Fwd Header Len": "Fwd_Header_Len",
        "Bwd Header Len": "Bwd_Header_Len",

        "Fwd Pkts/s": "Fwd_Pkts_per_s",
        "Bwd Pkts/s": "Bwd_Pkts_per_s",

        "Pkt Len Min": "Pkt_Len_Min",
        "Pkt Len Max": "Pkt_Len_Max",
        "Pkt Len Mean": "Pkt_Len_Mean",
        "Pkt Len Std": "Pkt_Len_Std",
        "Pkt Len Var": "Pkt_Len_Var",

        "FIN Flag Cnt": "FIN_Flag_Cnt",
        "SYN Flag Cnt": "SYN_Flag_Cnt",
        "RST Flag Cnt": "RST_Flag_Cnt",
        "PSH Flag Cnt": "PSH_Flag_Cnt",
        "ACK Flag Cnt": "ACK_Flag_Cnt",
        "URG Flag Cnt": "URG_Flag_Cnt",

        "CWE Flag Count": "CWE_Flag_Count",
        "ECE Flag Cnt": "ECE_Flag_Cnt",

        "Down/Up Ratio": "Down_per_Up_Ratio",
        "Pkt Size Avg": "Pkt_Size_Avg",

        "Fwd Seg Size Avg": "Fwd_Seg_Size_Avg",
        "Bwd Seg Size Avg": "Bwd_Seg_Size_Avg",

        "Fwd Byts/b Avg": "Fwd_Byts_per_b_Avg",
        "Fwd Pkts/b Avg": "Fwd_Pkts_per_b_Avg",
        "Fwd Blk Rate Avg": "Fwd_Blk_Rate_Avg",

        "Bwd Byts/b Avg": "Bwd_Byts_per_b_Avg",
        "Bwd Pkts/b Avg": "Bwd_Pkts_per_b_Avg",
        "Bwd Blk Rate Avg": "Bwd_Blk_Rate_Avg",

        "Subflow Fwd Pkts": "Subflow_Fwd_Pkts",
        "Subflow Fwd Byts": "Subflow_Fwd_Byts",
        "Subflow Bwd Pkts": "Subflow_Bwd_Pkts",
        "Subflow Bwd Byts": "Subflow_Bwd_Byts",

        "Init Fwd Win Byts": "Init_Fwd_Win_Byts",
        "Init Bwd Win Byts": "Init_Bwd_Win_Byts",

        "Fwd Act Data Pkts": "Fwd_Act_Data_Pkts",
        "Fwd Seg Size Min": "Fwd_Seg_Size_Min",

        "Active Mean": "Active_Mean",
        "Active Std": "Active_Std",
        "Active Max": "Active_Max",
        "Active Min": "Active_Min",

        "Idle Mean": "Idle_Mean",
        "Idle Std": "Idle_Std",
        "Idle Max": "Idle_Max",
        "Idle Min": "Idle_Min",
    }

    for old_name, new_name in rename_map.items():

        if old_name in df.columns:

            df = df.withColumnRenamed(
                old_name,
                new_name,
            )

    print(
        f"Columns after normalization: "
        f"{len(df.columns)}"
    )

    return df


# ============================================================
# CREATE TEMPORAL FEATURES
# ============================================================

def create_temporal_features(df):

    print()
    print("[2/7] Creating temporal features...")

    df = df.withColumn(
        "_parsed_timestamp",
        to_timestamp(
            trim(col("Timestamp")),
            "dd/MM/yyyy HH:mm:ss",
        ),
    )

    df = df.withColumn(
        "Hour",
        hour(
            col("_parsed_timestamp")
        ).cast("double"),
    )

    df = df.withColumn(
        "DayOfWeek",
        dayofweek(
            col("_parsed_timestamp")
        ).cast("double"),
    )

    df = df.withColumn(
        "IsWeekend",
        when(
            dayofweek(
                col("_parsed_timestamp")
            ).isin(1, 7),
            1.0,
        ).otherwise(
            0.0
        ),
    )

    df = df.drop(
        "_parsed_timestamp"
    )

    print(
        "Hour / DayOfWeek / IsWeekend created."
    )

    return df


# ============================================================
# CREATE TARGETS
# ============================================================

def create_targets(df):

    print()
    print("[3/7] Creating ML targets...")

    # --------------------------------------------------------
    # Stage 1:
    #
    # 0 = Benign
    # 1 = Attack
    # --------------------------------------------------------

    df = df.withColumn(
        "stage1_label",
        when(
            trim(
                col("Label")
            ) == "Benign",
            0.0,
        ).otherwise(
            1.0
        ),
    )

    # --------------------------------------------------------
    # Stage 2:
    #
    # Preserve the original 15-class label.
    # --------------------------------------------------------

    df = df.withColumn(
        "attack_label",
        trim(
            col("Label")
        ),
    )

    print()
    print(
        "Stage-1 target distribution:"
    )

    (
        df
        .groupBy("stage1_label")
        .count()
        .orderBy("stage1_label")
        .show()
    )

    return df


# ============================================================
# PREPARE NUMERIC FEATURES
# ============================================================

def prepare_numeric_features(df):

    print()
    print("[4/7] Preparing numeric ML features...")

    missing = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in df.columns
    ]

    if missing:

        raise ValueError(
            "Missing ML feature columns:\n"
            + "\n".join(missing)
        )

    # --------------------------------------------------------
    # Every feature is converted to double.
    #
    # The original ingestion intentionally loaded CSV values
    # as strings, so explicit conversion is required here.
    # --------------------------------------------------------

    for feature in FEATURE_COLUMNS:

        numeric = col(feature).cast("double")

        df = df.withColumn(
            feature,
            when(
                numeric.isNull()
                | numeric.isNaN()
                | (numeric == float("inf"))
                | (numeric == float("-inf")),
                0.0,
            ).otherwise(
                numeric
            ),
        )

    print(
        f"Prepared {len(FEATURE_COLUMNS)} "
        "numeric ML features."
    )

    return df


# ============================================================
# SELECT FINAL ML DATASET
# ============================================================

def select_final_columns(df):

    print()
    print("[5/7] Selecting final ML columns...")

    final_columns = (
        FEATURE_COLUMNS
        + [
            "stage1_label",
            "attack_label",
            "source_file",
        ]
    )

    df = df.select(
        *final_columns
    )

    print(
        f"Final columns: "
        f"{len(df.columns)}"
    )

    print(
        "Spark feature vectors will be created "
        "during model training."
    )

    return df


# ============================================================
# MEMORY-EFFICIENT TRAIN / TEST SPLIT
# ============================================================

def split_data(df):

    print()
    print("[6/7] Creating memory-efficient train/test split...")

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Do NOT use:
    #
    #     randomSplit()
    #
    # randomSplit() can trigger a large shuffle for this
    # 16M+ row dataset.
    #
    # Instead, rand(seed) generates a deterministic random
    # value for each row and we filter on that value.
    #
    # This avoids the massive shuffle that caused the Java
    # heap failure.
    # --------------------------------------------------------

    split_seed = 42

    split_column = "_split_value"

    df = df.withColumn(
        split_column,
        rand(split_seed),
    )

    train = (
        df
        .filter(
            col(split_column) < 0.80
        )
        .drop(split_column)
    )

    test = (
        df
        .filter(
            col(split_column) >= 0.80
        )
        .drop(split_column)
    )

    print()
    print(
        "Train/test split created without global shuffle."
    )

    print(
        "Target ratio: approximately 80% / 20%"
    )

    return train, test


# ============================================================
# SAVE DATA
# ============================================================

def save_data(
    train,
    test,
):

    print()
    print("[7/7] Saving train/test datasets...")

    print()
    print(
        "Writing training dataset..."
    )

    (
        train
        .write
        .mode("overwrite")
        .option(
            "compression",
            "snappy",
        )
        .parquet(
            TRAIN_PATH
        )
    )

    print()
    print(
        "Training dataset written."
    )

    print()
    print(
        "Writing testing dataset..."
    )

    (
        test
        .write
        .mode("overwrite")
        .option(
            "compression",
            "snappy",
        )
        .parquet(
            TEST_PATH
        )
    )

    print()
    print(
        "Testing dataset written."
    )


# ============================================================
# VERIFY OUTPUT
# ============================================================

def verify_output(spark):

    print()
    print("=" * 80)
    print("VERIFYING ML DATASETS")
    print("=" * 80)

    print()
    print("Reading training dataset...")

    train = (
        spark.read
        .parquet(TRAIN_PATH)
    )

    print(
        f"Training columns: "
        f"{len(train.columns)}"
    )

    print()
    print(
        "Reading testing dataset..."
    )

    test = (
        spark.read
        .parquet(TEST_PATH)
    )

    print(
        f"Testing columns: "
        f"{len(test.columns)}"
    )

    # --------------------------------------------------------
    # Counts are performed AFTER writing.
    #
    # This avoids keeping a huge DataFrame in memory while
    # doing multiple actions during the split stage.
    # --------------------------------------------------------

    train_count = train.count()
    test_count = test.count()

    print()
    print(
        f"Training rows: {train_count:,}"
    )

    print(
        f"Testing rows:  {test_count:,}"
    )

    print()
    print(
        f"Total rows: "
        f"{train_count + test_count:,}"
    )

    print()
    print(
        "Training Stage-1 distribution:"
    )

    (
        train
        .groupBy("stage1_label")
        .count()
        .orderBy("stage1_label")
        .show()
    )

    print()
    print(
        "Testing Stage-1 distribution:"
    )

    (
        test
        .groupBy("stage1_label")
        .count()
        .orderBy("stage1_label")
        .show()
    )

    print()
    print(
        "Training attack distribution:"
    )

    (
        train
        .filter(
            col("stage1_label") == 1.0
        )
        .groupBy("attack_label")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            50,
            truncate=False,
        )
    )

    return train_count, test_count


# ============================================================
# MAIN
# ============================================================

def main():

    spark = create_spark_session()

    try:

        # ----------------------------------------------------
        # 1. Load
        # ----------------------------------------------------

        df = load_data(
            spark
        )

        # ----------------------------------------------------
        # 2. Normalize columns
        # ----------------------------------------------------

        df = normalize_column_names(
            df
        )

        # ----------------------------------------------------
        # 3. Temporal features
        # ----------------------------------------------------

        df = create_temporal_features(
            df
        )

        # ----------------------------------------------------
        # 4. Targets
        # ----------------------------------------------------

        df = create_targets(
            df
        )

        # ----------------------------------------------------
        # 5. Numeric features
        # ----------------------------------------------------

        df = prepare_numeric_features(
            df
        )

        # ----------------------------------------------------
        # 6. Final columns
        # ----------------------------------------------------

        df = select_final_columns(
            df
        )

        # ----------------------------------------------------
        # 7. Split
        # ----------------------------------------------------

        train, test = split_data(
            df
        )

        # ----------------------------------------------------
        # Save
        # ----------------------------------------------------

        save_data(
            train,
            test,
        )

        # ----------------------------------------------------
        # Verify
        # ----------------------------------------------------

        train_count, test_count = (
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
            "FULL DATASET FEATURE ENGINEERING "
            "COMPLETED SUCCESSFULLY"
        )
        print("=" * 80)

        print()
        print(
            f"Source dataset:"
        )

        print(
            INPUT_PATH
        )

        print()
        print(
            f"Training dataset:"
        )

        print(
            TRAIN_PATH
        )

        print()
        print(
            f"Testing dataset:"
        )

        print(
            TEST_PATH
        )

        print()
        print(
            f"Training rows: "
            f"{train_count:,}"
        )

        print(
            f"Testing rows: "
            f"{test_count:,}"
        )

        print(
            f"Total rows: "
            f"{train_count + test_count:,}"
        )

        print()
        print(
            f"Features: "
            f"{len(FEATURE_COLUMNS)}"
        )

        print(
            "Stage 1: Benign vs Attack"
        )

        print(
            "Stage 2: 15-class attack taxonomy"
        )

        print()
        print(
            "Global random shuffle: NOT USED"
        )

        print(
            "Spark VectorAssembler: DEFERRED TO TRAINING"
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