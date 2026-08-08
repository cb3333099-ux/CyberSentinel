from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col,
    when,
    lit
)

from pyspark.ml.functions import vector_to_array
from pyspark.ml.classification import (
    RandomForestClassificationModel
)
from pyspark.ml.feature import VectorAssembler


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_PATH = (
    "/home/charay/cybersentinel-data/"
    "processed/cybersentinel_flows"
)

DETECTOR_MODEL_PATH = (
    "/home/charay/cybersentinel-data/"
    "models/attack_detector_rf"
)

CLASSIFIER_MODEL_PATH = (
    "/home/charay/cybersentinel-data/"
    "models/attack_classifier_rf"
)

OUTPUT_PATH = (
    "/home/charay/cybersentinel-data/"
    "inference/cybersentinel_alerts"
)

DETECTION_THRESHOLD = 0.70


# ============================================================
# FEATURES
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
        .appName("CyberSentinel-Inference")
        .config(
            "spark.sql.warehouse.dir",
            "/home/charay/cybersentinel-data/spark-warehouse"
        )
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    return spark


# ============================================================
# LOAD DATA
# ============================================================

def load_data(spark):

    print("\n[1/8] Loading processed network flows...")

    df = spark.read.parquet(INPUT_PATH)

    row_count = df.count()

    print(
        f"Rows loaded: {row_count:,}"
    )

    print(
        f"Columns loaded: {len(df.columns)}"
    )

    return df


# ============================================================
# LOAD MODELS
# ============================================================

def load_models():

    print("\n[2/8] Loading trained models...")

    detector = (
        RandomForestClassificationModel
        .load(DETECTOR_MODEL_PATH)
    )

    classifier = (
        RandomForestClassificationModel
        .load(CLASSIFIER_MODEL_PATH)
    )

    print("Attack detector loaded.")
    print("Attack classifier loaded.")

    return detector, classifier


# ============================================================
# PREPARE FEATURES
# ============================================================

def prepare_features(df):

    print("\n[3/8] Preparing inference features...")

    missing = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in df.columns
    ]

    if missing:

        raise ValueError(
            "Missing feature columns:\n"
            + "\n".join(missing)
        )

    cleaned = df

    for feature in FEATURE_COLUMNS:

        cleaned = cleaned.withColumn(
            feature,
            when(
                col(feature).isNull()
                | col(feature).isNaN()
                | (col(feature) == float("inf"))
                | (col(feature) == float("-inf")),
                0.0
            ).otherwise(
                col(feature).cast("double")
            )
        )

    assembler = VectorAssembler(
        inputCols=FEATURE_COLUMNS,
        outputCol="features",
        handleInvalid="keep"
    )

    result = assembler.transform(
        cleaned
    )

    print(
        f"Feature vector created with "
        f"{len(FEATURE_COLUMNS)} features."
    )

    return result


# ============================================================
# STAGE 1 — ATTACK DETECTION
# ============================================================

def run_attack_detection(
    detector,
    df
):

    print(
        "\n[4/8] Running Stage 1 "
        "attack detection..."
    )

    predictions = detector.transform(
        df
    )

    # Spark ML vector_to_array allows us to extract
    # probability[1] without a Python UDF.
    predictions = predictions.withColumn(
        "attack_probability",
        vector_to_array(
            col("probability")
        )[1]
    )

    predictions = predictions.withColumn(
        "is_attack",
        when(
            col("attack_probability")
            >= DETECTION_THRESHOLD,
            1
        ).otherwise(0)
    )

    print(
        f"\nStage 1 threshold: "
        f"{DETECTION_THRESHOLD}"
    )

    (
        predictions
        .groupBy("is_attack")
        .count()
        .orderBy("is_attack")
        .show()
    )

    return predictions


# ============================================================
# PREPARE FOR STAGE 2
# ============================================================

def prepare_for_classification(df):

    print(
        "\nPreparing detected attacks "
        "for Stage 2..."
    )

    # Stage 1 Random Forest creates:
    #
    # prediction
    # probability
    # rawPrediction
    #
    # Stage 2 needs to create columns with those same
    # names, so remove the Stage 1 model-output columns.
    #
    # We retain attack_probability and is_attack because
    # these are CyberSentinel-specific outputs.

    columns_to_drop = [
        "prediction",
        "probability",
        "rawPrediction"
    ]

    existing = [
        column
        for column in columns_to_drop
        if column in df.columns
    ]

    if existing:

        df = df.drop(
            *existing
        )

    return df


# ============================================================
# STAGE 2 — ATTACK CLASSIFICATION
# ============================================================

def run_attack_classification(
    classifier,
    df
):

    print(
        "\n[5/8] Running Stage 2 "
        "attack classification..."
    )

    predictions = classifier.transform(
        df
    )

    # StringIndexer mapping used during training:
    #
    # 0 -> Brute Force -Web
    # 1 -> Brute Force -XSS
    # 2 -> SQL Injection

    predictions = predictions.withColumn(
        "attack_type",
        when(
            col("prediction") == 0.0,
            "Brute Force -Web"
        )
        .when(
            col("prediction") == 1.0,
            "Brute Force -XSS"
        )
        .when(
            col("prediction") == 2.0,
            "SQL Injection"
        )
        .otherwise(
            "Unknown"
        )
    )

    return predictions


# ============================================================
# GENERATE FINAL ALERTS
# ============================================================

def generate_alerts(df):

    print(
        "\n[6/8] Generating threat alerts..."
    )

    alerts = (
        df
        .filter(
            col("is_attack") == 1
        )
        .select(
            "Timestamp",
            "Dst_Port",
            "Protocol",
            "Flow_Duration",
            "attack_probability",
            "attack_type",
            "IsAttack",
            "Label"
        )
    )

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    alerts = alerts.withColumn(
        "severity",
        when(
            col("attack_probability") >= 0.90,
            "CRITICAL"
        )
        .when(
            col("attack_probability") >= 0.80,
            "HIGH"
        )
        .otherwise(
            "MEDIUM"
        )
    )

    alerts = alerts.withColumn(
        "alert_source",
        lit(
            "CyberSentinel ML Detector"
        )
    )

    return alerts


# ============================================================
# DISPLAY SUMMARY
# ============================================================

def display_summary(
    alerts
):

    print(
        "\n[7/8] Threat intelligence summary..."
    )

    total_alerts = alerts.count()

    print(
        f"\nTotal generated alerts: "
        f"{total_alerts:,}"
    )

    print("\nAlerts by attack type:")

    (
        alerts
        .groupBy("attack_type")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            truncate=False
        )
    )

    print("\nAlerts by severity:")

    (
        alerts
        .groupBy("severity")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            truncate=False
        )
    )

    print("\nTop targeted ports:")

    (
        alerts
        .groupBy("Dst_Port")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            10,
            truncate=False
        )
    )

    print("\nSample generated alerts:")

    (
        alerts
        .select(
            "Timestamp",
            "Dst_Port",
            "Protocol",
            "attack_probability",
            "attack_type",
            "severity"
        )
        .orderBy(
            col("attack_probability").desc()
        )
        .show(
            10,
            truncate=False
        )
    )


# ============================================================
# SAVE ALERTS
# ============================================================

def save_alerts(
    alerts
):

    print(
        "\n[8/8] Saving threat alerts..."
    )

    (
        alerts
        .write
        .mode("overwrite")
        .parquet(OUTPUT_PATH)
    )

    print(
        "\nAlerts saved to:"
    )

    print(
        OUTPUT_PATH
    )


# ============================================================
# MAIN
# ============================================================

def main():

    spark = create_spark_session()

    try:

        # ----------------------------------------------------
        # 1. Load data
        # ----------------------------------------------------

        df = load_data(
            spark
        )

        # ----------------------------------------------------
        # 2. Load models
        # ----------------------------------------------------

        detector, classifier = (
            load_models()
        )

        # ----------------------------------------------------
        # 3. Prepare features
        # ----------------------------------------------------

        prepared = prepare_features(
            df
        )

        # ----------------------------------------------------
        # 4. Stage 1 detection
        # ----------------------------------------------------

        detected = run_attack_detection(
            detector,
            prepared
        )

        # ----------------------------------------------------
        # Only detected attacks continue to Stage 2.
        # ----------------------------------------------------

        attacks = (
            detected
            .filter(
                col("is_attack") == 1
            )
        )

        # ----------------------------------------------------
        # Remove Stage 1 model-output columns before
        # running the Stage 2 model.
        # ----------------------------------------------------

        attacks = prepare_for_classification(
            attacks
        )

        # ----------------------------------------------------
        # 5. Stage 2 classification
        # ----------------------------------------------------

        classified = run_attack_classification(
            classifier,
            attacks
        )

        # ----------------------------------------------------
        # 6. Generate alerts
        # ----------------------------------------------------

        alerts = generate_alerts(
            classified
        )

        # ----------------------------------------------------
        # 7. Display intelligence summary
        # ----------------------------------------------------

        display_summary(
            alerts
        )

        # ----------------------------------------------------
        # 8. Save alerts
        # ----------------------------------------------------

        save_alerts(
            alerts
        )

        print(
            "\n" + "=" * 75
        )

        print(
            "CYBERSENTINEL END-TO-END "
            "INFERENCE COMPLETED SUCCESSFULLY"
        )

        print(
            "=" * 75
        )

    finally:

        spark.stop()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()