from pyspark.sql import SparkSession
from pyspark.sql.functions import col
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import BinaryClassificationEvaluator


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = "/mnt/d/BDA/CyberSentinel"

TRAIN_PATH = f"{PROJECT_ROOT}/data/processed/ml-full/train"
TEST_PATH = f"{PROJECT_ROOT}/data/processed/ml-full/test"

MODEL_PATH = f"{PROJECT_ROOT}/models/stage1_random_forest"

# Training sample size.
# The original training dataset contains 12,985,345 rows.
SAMPLE_SIZE = 2_000_000

RANDOM_SEED = 42


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
# SPARK
# ============================================================

def create_spark():

    spark = (
        SparkSession.builder
        .master("local[*]")
        .appName("CyberSentinel-Stage1")
        .config("spark.driver.memory", "8g")
        .config("spark.executor.memory", "8g")
        .config("spark.driver.maxResultSize", "1g")
        .config("spark.sql.shuffle.partitions", "16")
        .config("spark.default.parallelism", "8")
        .config("spark.sql.adaptive.enabled", "true")
        .config(
            "spark.sql.adaptive.coalescePartitions.enabled",
            "true",
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
# LOAD
# ============================================================

def load_data(spark):

    print()
    print("=" * 80)
    print("CYBERSENTINEL STAGE-1 MODEL TRAINING")
    print("=" * 80)

    print()
    print("Loading training dataset...")

    train = (
        spark.read
        .parquet(TRAIN_PATH)
        .select(
            *FEATURE_COLUMNS,
            "stage1_label",
        )
    )

    print("Training dataset loaded.")

    print()
    print("Loading testing dataset...")

    test = (
        spark.read
        .parquet(TEST_PATH)
        .select(
            *FEATURE_COLUMNS,
            "stage1_label",
        )
    )

    print("Testing dataset loaded.")

    return train, test


# ============================================================
# STRATIFIED SAMPLE
# ============================================================

def create_stratified_sample(train):

    print()
    print("=" * 80)
    print("CREATING STRATIFIED TRAINING SAMPLE")
    print("=" * 80)

    print()
    print(
        f"Original training rows: "
        f"{train.count():,}"
    )

    # Determine the actual class proportions first.
    counts = (
        train
        .groupBy("stage1_label")
        .count()
        .collect()
    )

    total = sum(
        row["count"]
        for row in counts
    )

    fractions = {}

    for row in counts:

        label = row["stage1_label"]
        count = row["count"]

        fraction = (
            SAMPLE_SIZE * count / total
        ) / count

        fractions[label] = min(
            1.0,
            fraction,
        )

        print(
            f"Class {label:.0f}: "
            f"{count:,} rows "
            f"→ approximately "
            f"{int(count * fractions[label]):,} sampled"
        )

    sample = (
        train
        .sampleBy(
            "stage1_label",
            fractions=fractions,
            seed=RANDOM_SEED,
        )
    )

    actual = sample.count()

    print()
    print(
        f"Actual sampled rows: "
        f"{actual:,}"
    )

    print()
    print("Sample distribution:")

    (
        sample
        .groupBy("stage1_label")
        .count()
        .orderBy("stage1_label")
        .show()
    )

    return sample


# ============================================================
# FEATURES
# ============================================================

def build_features(
    train,
    test,
):

    print()
    print(
        "Building Spark ML feature vectors..."
    )

    assembler = VectorAssembler(
        inputCols=FEATURE_COLUMNS,
        outputCol="features",
        handleInvalid="keep",
    )

    train = (
        assembler
        .transform(train)
        .select(
            "features",
            col("stage1_label").alias("label"),
        )
    )

    test = (
        assembler
        .transform(test)
        .select(
            "features",
            col("stage1_label").alias("label"),
        )
    )

    print(
        "Feature vectors created."
    )

    return train, test


# ============================================================
# MODEL
# ============================================================

def create_model():

    print()
    print(
        "Creating Random Forest..."
    )

    return RandomForestClassifier(
        labelCol="label",
        featuresCol="features",
        numTrees=30,
        maxDepth=10,
        maxBins=32,
        featureSubsetStrategy="sqrt",
        subsamplingRate=0.7,
        minInstancesPerNode=5,
        seed=RANDOM_SEED,
    )


# ============================================================
# TRAIN
# ============================================================

def train_model(
    model,
    train,
):

    print()
    print("=" * 80)
    print("TRAINING STAGE-1 RANDOM FOREST")
    print("=" * 80)

    print()
    print("Task: Benign vs Attack")

    print()
    print("Training configuration:")
    print("Training sample : approximately 2M rows")
    print("Trees           : 30")
    print("Max depth       : 10")
    print("Max bins        : 32")
    print("Subsampling     : 0.70")

    print()
    print("Training model...")

    fitted = model.fit(train)

    print()
    print(
        "Stage-1 training completed."
    )

    return fitted


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(
    model,
    test,
):

    print()
    print("=" * 80)
    print("STAGE-1 MODEL EVALUATION")
    print("=" * 80)

    print()
    print(
        "Generating predictions on the "
        "FULL test dataset..."
    )

    predictions = model.transform(test)

    print()
    print("Confusion Matrix:")

    (
        predictions
        .groupBy(
            "label",
            "prediction",
        )
        .count()
        .orderBy(
            "label",
            "prediction",
        )
        .show()
    )

    total = predictions.count()

    correct = (
        predictions
        .filter(
            col("label")
            == col("prediction")
        )
        .count()
    )

    accuracy = (
        correct / total
        if total
        else 0.0
    )

    tp = (
        predictions
        .filter(
            (col("label") == 1.0)
            &
            (col("prediction") == 1.0)
        )
        .count()
    )

    fp = (
        predictions
        .filter(
            (col("label") == 0.0)
            &
            (col("prediction") == 1.0)
        )
        .count()
    )

    fn = (
        predictions
        .filter(
            (col("label") == 1.0)
            &
            (col("prediction") == 0.0)
        )
        .count()
    )

    precision = (
        tp / (tp + fp)
        if tp + fp
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn
        else 0.0
    )

    f1 = (
        2 * precision * recall
        /
        (precision + recall)
        if precision + recall
        else 0.0
    )

    evaluator = BinaryClassificationEvaluator(
        labelCol="label",
        rawPredictionCol="rawPrediction",
        metricName="areaUnderROC",
    )

    auc = evaluator.evaluate(
        predictions
    )

    print()
    print(
        f"Test rows : {total:,}"
    )

    print(
        f"Accuracy  : {accuracy:.6f}"
    )

    print(
        f"Precision : {precision:.6f}"
    )

    print(
        f"Recall    : {recall:.6f}"
    )

    print(
        f"F1 Score  : {f1:.6f}"
    )

    print(
        f"ROC-AUC   : {auc:.6f}"
    )


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

def show_feature_importance(model):

    print()
    print("=" * 80)
    print("TOP STAGE-1 FEATURES")
    print("=" * 80)

    importance = (
        model
        .featureImportances
        .toArray()
    )

    ranked = sorted(
        zip(
            FEATURE_COLUMNS,
            importance,
        ),
        key=lambda x: x[1],
        reverse=True,
    )

    print()

    for rank, (
        feature,
        score,
    ) in enumerate(
        ranked[:20],
        start=1,
    ):

        print(
            f"{rank:02d}. "
            f"{feature:<35} "
            f"{score:.6f}"
        )


# ============================================================
# SAVE
# ============================================================

def save_model(model):

    print()
    print(
        "Saving Stage-1 model..."
    )

    (
        model
        .write()
        .overwrite()
        .save(MODEL_PATH)
    )

    print()
    print(
        "Model saved to:"
    )

    print(MODEL_PATH)


# ============================================================
# MAIN
# ============================================================

def main():

    spark = create_spark()

    try:

        train, test = load_data(
            spark
        )

        # IMPORTANT:
        # Only the training set is sampled.
        # The original training Parquet remains untouched.
        train = create_stratified_sample(
            train
        )

        train, test = build_features(
            train,
            test,
        )

        model = create_model()

        fitted = train_model(
            model,
            train,
        )

        evaluate_model(
            fitted,
            test,
        )

        show_feature_importance(
            fitted
        )

        save_model(
            fitted
        )

        print()
        print("=" * 80)
        print(
            "CYBERSENTINEL STAGE-1 "
            "COMPLETED SUCCESSFULLY"
        )
        print("=" * 80)

        print()
        print(
            "Stage 1: Benign vs Attack"
        )

        print(
            "Algorithm: Random Forest"
        )

        print(
            "Training: Stratified ~2M-row sample"
        )

        print(
            "Evaluation: Full 3.25M-row test set"
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
