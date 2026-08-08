from pyspark.sql import SparkSession
from pyspark.sql.functions import col
from pyspark.ml import Pipeline
from pyspark.ml.feature import VectorAssembler, StringIndexer
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import MulticlassClassificationEvaluator


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = "/mnt/d/BDA/CyberSentinel"

TRAIN_PATH = (
    f"{PROJECT_ROOT}/data/processed/ml-full/train"
)

TEST_PATH = (
    f"{PROJECT_ROOT}/data/processed/ml-full/test"
)

MODEL_PATH = (
    f"{PROJECT_ROOT}/models/stage2_attack_classifier_no_temporal"
)

RANDOM_SEED = 42

TARGET_SAMPLE_SIZE = 1_500_000

MIN_SAMPLES_PER_CLASS = 10_000


# ============================================================
# FEATURES
# ============================================================
# IMPORTANT:
# Hour, DayOfWeek and IsWeekend are intentionally excluded.
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
]


# ============================================================
# SPARK
# ============================================================

def create_spark():

    spark = (
        SparkSession.builder
        .master("local[*]")
        .appName(
            "CyberSentinel-Stage2-NoTemporal"
        )
        .config(
            "spark.driver.memory",
            "8g",
        )
        .config(
            "spark.executor.memory",
            "8g",
        )
        .config(
            "spark.driver.maxResultSize",
            "1g",
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
    print("CYBERSENTINEL STAGE-2 — NO TEMPORAL FEATURES")
    print("=" * 80)

    print()
    print("Loading training dataset...")

    train = (
        spark.read
        .parquet(TRAIN_PATH)
        .select(
            *FEATURE_COLUMNS,
            "stage1_label",
            "attack_label",
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
            "attack_label",
        )
    )

    print("Testing dataset loaded.")

    return train, test


# ============================================================
# FILTER ATTACKS
# ============================================================

def filter_attacks(train, test):

    train_attack = (
        train
        .filter(
            col("stage1_label") == 1.0
        )
        .drop("stage1_label")
    )

    test_attack = (
        test
        .filter(
            col("stage1_label") == 1.0
        )
        .drop("stage1_label")
    )

    print()
    print(
        f"Training attack rows: "
        f"{train_attack.count():,}"
    )

    print(
        f"Testing attack rows: "
        f"{test_attack.count():,}"
    )

    print()
    print("Attack distribution:")

    (
        train_attack
        .groupBy("attack_label")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            20,
            truncate=False,
        )
    )

    return train_attack, test_attack


# ============================================================
# STRATIFIED SAMPLE
# ============================================================

def create_attack_sample(train_attack):

    print()
    print("=" * 80)
    print("CREATING STRATIFIED TRAINING SAMPLE")
    print("=" * 80)

    counts = (
        train_attack
        .groupBy("attack_label")
        .count()
        .collect()
    )

    total = sum(
        row["count"]
        for row in counts
    )

    base_fraction = (
        TARGET_SAMPLE_SIZE / total
    )

    fractions = {}

    for row in counts:

        label = row["attack_label"]
        count = row["count"]

        desired = max(
            MIN_SAMPLES_PER_CLASS,
            int(count * base_fraction),
        )

        desired = min(
            count,
            desired,
        )

        fractions[label] = (
            desired / count
        )

        print(
            f"{str(label):<30} "
            f"{count:>10,} -> "
            f"~{desired:>10,}"
        )

    sample = (
        train_attack
        .sampleBy(
            "attack_label",
            fractions=fractions,
            seed=RANDOM_SEED,
        )
    )

    actual = sample.count()

    print()
    print(
        f"Actual sample size: "
        f"{actual:,}"
    )

    print()
    print("Sample distribution:")

    (
        sample
        .groupBy("attack_label")
        .count()
        .orderBy(
            col("count").desc()
        )
        .show(
            20,
            truncate=False,
        )
    )

    return sample


# ============================================================
# PIPELINE
# ============================================================

def create_pipeline():

    assembler = VectorAssembler(
        inputCols=FEATURE_COLUMNS,
        outputCol="features",
        handleInvalid="keep",
    )

    label_indexer = StringIndexer(
        inputCol="attack_label",
        outputCol="label",
        handleInvalid="keep",
    )

    classifier = RandomForestClassifier(
        labelCol="label",
        featuresCol="features",
        numTrees=30,
        maxDepth=10,
        maxBins=32,
        featureSubsetStrategy="sqrt",
        subsamplingRate=0.7,
        minInstancesPerNode=3,
        seed=RANDOM_SEED,
    )

    return Pipeline(
        stages=[
            assembler,
            label_indexer,
            classifier,
        ]
    )


# ============================================================
# TRAIN
# ============================================================

def train_model(pipeline, train):

    print()
    print("=" * 80)
    print("TRAINING LEAKAGE-REDUCED STAGE-2 MODEL")
    print("=" * 80)

    print()
    print("Features used:", len(FEATURE_COLUMNS))

    print()
    print("Temporal features removed:")
    print("  - Hour")
    print("  - DayOfWeek")
    print("  - IsWeekend")

    print()
    print("Training Random Forest...")

    model = pipeline.fit(train)

    print()
    print("Training completed.")

    return model


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(model, test):

    print()
    print("=" * 80)
    print("EVALUATING NO-TEMPORAL STAGE-2 MODEL")
    print("=" * 80)

    predictions = model.transform(test)

    evaluators = {
        "accuracy": MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="accuracy",
        ),
        "precision": MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="weightedPrecision",
        ),
        "recall": MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="weightedRecall",
        ),
        "f1": MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="f1",
        ),
    }

    results = {}

    for name, evaluator in evaluators.items():

        results[name] = (
            evaluator.evaluate(
                predictions
            )
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

    print()

    print(
        f"Attack test rows : "
        f"{total:,}"
    )

    print(
        f"Correct          : "
        f"{correct:,}"
    )

    print(
        f"Incorrect        : "
        f"{total - correct:,}"
    )

    print()

    print(
        f"Accuracy           : "
        f"{results['accuracy']:.6f}"
    )

    print(
        f"Weighted Precision : "
        f"{results['precision']:.6f}"
    )

    print(
        f"Weighted Recall    : "
        f"{results['recall']:.6f}"
    )

    print(
        f"Weighted F1        : "
        f"{results['f1']:.6f}"
    )

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
        .show(
            100,
            truncate=False,
        )
    )

    return predictions, results


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

def show_feature_importance(model):

    print()
    print("=" * 80)
    print("TOP NON-TEMPORAL FEATURES")
    print("=" * 80)

    rf_model = model.stages[2]

    importance = (
        rf_model
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
    print("Saving model...")

    (
        model
        .write()
        .overwrite()
        .save(
            MODEL_PATH
        )
    )

    print()
    print(
        "Model saved to:"
    )

    print(
        MODEL_PATH
    )


# ============================================================
# MAIN
# ============================================================

def main():

    spark = create_spark()

    try:

        train, test = load_data(
            spark
        )

        train_attack, test_attack = (
            filter_attacks(
                train,
                test,
            )
        )

        train_sample = (
            create_attack_sample(
                train_attack
            )
        )

        pipeline = create_pipeline()

        model = train_model(
            pipeline,
            train_sample,
        )

        predictions, results = (
            evaluate_model(
                model,
                test_attack,
            )
        )

        show_feature_importance(
            model
        )

        save_model(
            model
        )

        print()
        print("=" * 80)
        print(
            "STAGE-2 NO-TEMPORAL TRAINING "
            "COMPLETED SUCCESSFULLY"
        )
        print("=" * 80)

        print()
        print(
            "Final benchmark:"
        )

        print(
            f"Accuracy : "
            f"{results['accuracy']:.6f}"
        )

        print(
            f"F1       : "
            f"{results['f1']:.6f}"
        )

        print()
        print(
            "Model:"
        )

        print(
            MODEL_PATH
        )

        print()
        print("=" * 80)

    finally:

        spark.stop()


if __name__ == "__main__":
    main()