from pyspark.sql import SparkSession
from pyspark.sql.functions import col, when
from pyspark.ml.feature import VectorAssembler


# ============================================================
# Configuration
# ============================================================

INPUT_PATH = (
    "/home/charay/cybersentinel-data/"
    "processed/cybersentinel_flows"
)

OUTPUT_BASE = (
    "/home/charay/cybersentinel-data/"
    "ml"
)

TRAIN_PATH = f"{OUTPUT_BASE}/train"
TEST_PATH = f"{OUTPUT_BASE}/test"


# ============================================================
# Spark Session
# ============================================================

def create_spark_session():

    spark = (
        SparkSession.builder
        .master("local[*]")
        .appName("CyberSentinel-Feature-Engineering")
        .config(
            "spark.sql.warehouse.dir",
            "/home/charay/cybersentinel-data/spark-warehouse"
        )
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    return spark


# ============================================================
# Load Data
# ============================================================

def load_data(spark):

    print("\n[1/6] Loading processed Parquet data...")

    df = spark.read.parquet(INPUT_PATH)

    print(f"Rows loaded: {df.count():,}")
    print(f"Columns loaded: {len(df.columns)}")

    return df


# ============================================================
# Select ML Features
# ============================================================

def select_features(df):

    print("\n[2/6] Selecting ML features...")

    # --------------------------------------------------------
    # Features deliberately excluded:
    #
    # Timestamp  -> converted into Hour/DayOfWeek/IsWeekend
    # Label      -> attack class, used only for classification
    # IsAttack   -> target variable
    #
    # --------------------------------------------------------

    feature_columns = [
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

        # Derived temporal features
        "Hour",
        "DayOfWeek",
        "IsWeekend"
    ]

    # Make sure every requested feature exists.
    available = set(df.columns)

    missing = [
        feature
        for feature in feature_columns
        if feature not in available
    ]

    if missing:
        raise ValueError(
            "Missing feature columns:\n"
            + "\n".join(missing)
        )

    selected = df.select(
        *feature_columns,
        col("IsAttack").cast("double").alias("label")
    )

    print(f"Selected features: {len(feature_columns)}")
    print("Target column: label")

    return selected, feature_columns


# ============================================================
# Clean Numeric Features
# ============================================================

def clean_numeric_features(df, feature_columns):

    print("\n[3/6] Cleaning numeric features...")

    # Spark ML cannot work with NaN / infinite values.
    #
    # We convert NaN and +/-Infinity to NULL and then
    # replace NULL with 0.
    #
    # This keeps the feature vector valid while avoiding
    # failures inside VectorAssembler.

    cleaned = df

    for feature in feature_columns:

        cleaned = cleaned.withColumn(
            feature,
            when(
                col(feature).isNull()
                | col(feature).isNaN()
                | (col(feature) == float("inf"))
                | (col(feature) == float("-inf")),
                0.0
            ).otherwise(col(feature).cast("double"))
        )

    print("Numeric feature cleaning completed.")

    return cleaned


# ============================================================
# Assemble Feature Vector
# ============================================================

def assemble_features(df, feature_columns):

    print("\n[4/6] Building Spark ML feature vector...")

    assembler = VectorAssembler(
        inputCols=feature_columns,
        outputCol="features",
        handleInvalid="keep"
    )

    assembled = assembler.transform(df)

    final_df = assembled.select(
        "features",
        "label"
    )

    print("Feature vector created.")

    return final_df


# ============================================================
# Train / Test Split
# ============================================================

def split_data(df):

    print("\n[5/6] Creating train/test split...")

    train, test = df.randomSplit(
        [0.8, 0.2],
        seed=42
    )

    print(f"Training rows: {train.count():,}")
    print(f"Testing rows:  {test.count():,}")

    print("\nTraining label distribution:")

    train.groupBy("label").count().orderBy("label").show()

    print("Testing label distribution:")

    test.groupBy("label").count().orderBy("label").show()

    return train, test


# ============================================================
# Save Prepared Data
# ============================================================

def save_data(train, test):

    print("\n[6/6] Saving ML datasets...")

    train.write.mode("overwrite").parquet(TRAIN_PATH)

    test.write.mode("overwrite").parquet(TEST_PATH)

    print(f"Training data saved to:")
    print(TRAIN_PATH)

    print(f"\nTesting data saved to:")
    print(TEST_PATH)


# ============================================================
# Main
# ============================================================

def main():

    spark = create_spark_session()

    try:

        df = load_data(spark)

        selected, feature_columns = select_features(df)

        cleaned = clean_numeric_features(
            selected,
            feature_columns
        )

        assembled = assemble_features(
            cleaned,
            feature_columns
        )

        train, test = split_data(assembled)

        save_data(train, test)

        print("\n" + "=" * 70)
        print("CYBERSENTINEL FEATURE ENGINEERING COMPLETED")
        print("=" * 70)

    finally:

        spark.stop()


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()