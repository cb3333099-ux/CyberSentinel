from pyspark.sql import SparkSession
from pyspark.sql.functions import col, when
from pyspark.ml.feature import VectorAssembler, StringIndexer
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import MulticlassClassificationEvaluator


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_PATH = (
    "/home/charay/cybersentinel-data/"
    "processed/cybersentinel_flows"
)

MODEL_PATH = (
    "/home/charay/cybersentinel-data/"
    "models/attack_classifier_rf"
)


# ============================================================
# FEATURE COLUMNS
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

    # Temporal features
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
        .appName("CyberSentinel-Attack-Classifier")
        .config(
            "spark.sql.warehouse.dir",
            "/home/charay/cybersentinel-data/spark-warehouse"
        )
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    return spark


# ============================================================
# LOAD ATTACK DATA
# ============================================================

def load_attack_data(spark):

    print("\n[1/8] Loading processed network-flow data...")

    df = spark.read.parquet(INPUT_PATH)

    total_rows = df.count()

    print(f"Total rows: {total_rows:,}")

    # Only attack traffic is used for the second-stage
    # multiclass classifier.
    attacks = df.filter(
        col("IsAttack") == 1
    )

    attack_count = attacks.count()

    print(
        f"Attack rows available: "
        f"{attack_count:,}"
    )

    print("\nAttack distribution:")

    (
        attacks
        .groupBy("Label")
        .count()
        .orderBy(col("count").desc())
        .show(truncate=False)
    )

    return attacks


# ============================================================
# PREPARE FEATURES
# ============================================================

def prepare_features(df):

    print("\n[2/8] Preparing attack features...")

    available_columns = set(df.columns)

    missing_columns = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in available_columns
    ]

    if missing_columns:

        raise ValueError(
            "Missing feature columns:\n"
            + "\n".join(missing_columns)
        )

    # Preserve the original attack name using a completely
    # different column name. This avoids Spark's
    # case-insensitive collision between Label and label.
    selected = df.select(
        *FEATURE_COLUMNS,
        col("Label").alias("AttackType")
    )

    cleaned = selected

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

    print(
        f"Features prepared: "
        f"{len(FEATURE_COLUMNS)}"
    )

    return cleaned


# ============================================================
# ENCODE ATTACK LABELS
# ============================================================

def encode_labels(df):

    print("\n[3/8] Encoding attack classes...")

    indexer = StringIndexer(
        inputCol="AttackType",
        outputCol="label",
        handleInvalid="error"
    )

    indexer_model = indexer.fit(df)

    indexed = indexer_model.transform(df)

    print("\nAttack class mapping:")

    for index, attack_type in enumerate(
        indexer_model.labels
    ):

        print(
            f"{index} -> {attack_type}"
        )

    return indexed, indexer_model


# ============================================================
# BUILD FEATURE VECTOR
# ============================================================

def assemble_features(df):

    print("\n[4/8] Building feature vectors...")

    assembler = VectorAssembler(
        inputCols=FEATURE_COLUMNS,
        outputCol="features",
        handleInvalid="keep"
    )

    assembled = assembler.transform(df)

    final_df = assembled.select(
        "features",
        "label",
        "AttackType"
    )

    print("Feature vectors created.")

    return final_df


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

def split_data(df):

    print(
        "\n[5/8] Creating "
        "attack-classification split..."
    )

    train, test = df.randomSplit(
        [0.8, 0.2],
        seed=42
    )

    train_count = train.count()
    test_count = test.count()

    print(
        f"Training rows: {train_count:,}"
    )

    print(
        f"Testing rows:  {test_count:,}"
    )

    print("\nTraining class distribution:")

    (
        train
        .groupBy(
            "label",
            "AttackType"
        )
        .count()
        .orderBy("label")
        .show(truncate=False)
    )

    print("Testing class distribution:")

    (
        test
        .groupBy(
            "label",
            "AttackType"
        )
        .count()
        .orderBy("label")
        .show(truncate=False)
    )

    # --------------------------------------------------------
    # Verify every class exists in both datasets.
    # --------------------------------------------------------

    required_classes = {
        "Brute Force -Web",
        "Brute Force -XSS",
        "SQL Injection",
    }

    train_classes = {
        row["AttackType"]
        for row in (
            train
            .select("AttackType")
            .distinct()
            .collect()
        )
    }

    test_classes = {
        row["AttackType"]
        for row in (
            test
            .select("AttackType")
            .distinct()
            .collect()
        )
    }

    missing_train = required_classes - train_classes
    missing_test = required_classes - test_classes

    if missing_train:

        raise ValueError(
            "Missing attack classes in training set: "
            + str(missing_train)
        )

    if missing_test:

        raise ValueError(
            "Missing attack classes in testing set: "
            + str(missing_test)
        )

    return train, test


# ============================================================
# CLASS WEIGHTS
# ============================================================

def add_class_weights(train):

    print("\n[6/8] Calculating attack-class weights...")

    counts = (
        train
        .groupBy("label")
        .count()
        .collect()
    )

    class_counts = {
        int(row["label"]): int(row["count"])
        for row in counts
    }

    total_samples = sum(
        class_counts.values()
    )

    num_classes = len(
        class_counts
    )

    weights = {
        label:
        total_samples
        / (num_classes * count)

        for label, count
        in class_counts.items()
    }

    print("\nClass weights:")

    for label in sorted(weights):

        print(
            f"Class {label}: "
            f"{weights[label]:.4f}"
        )

    # Build weight column dynamically rather than assuming
    # a particular class ordering.
    weight_column = None

    for label, weight in weights.items():

        condition = (
            when(
                col("label") == float(label),
                float(weight)
            )
        )

        if weight_column is None:

            weight_column = condition

        else:

            weight_column = (
                weight_column
                .when(
                    col("label") == float(label),
                    float(weight)
                )
            )

    weighted = train.withColumn(
        "classWeight",
        weight_column.otherwise(1.0)
    )

    return weighted


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

def train_classifier(train):

    print(
        "\n[7/8] Training "
        "multiclass Random Forest..."
    )

    classifier = RandomForestClassifier(
        labelCol="label",
        featuresCol="features",
        weightCol="classWeight",

        numTrees=100,
        maxDepth=10,

        minInstancesPerNode=2,

        featureSubsetStrategy="sqrt",

        seed=42
    )

    model = classifier.fit(train)

    print(
        "Attack classifier training completed."
    )

    return model


# ============================================================
# EVALUATE MODEL
# ============================================================

def evaluate_model(
    model,
    test,
    indexer_model
):

    print(
        "\n[8/8] Evaluating "
        "attack classifier..."
    )

    predictions = model.transform(test)

    # --------------------------------------------------------
    # Overall metrics
    # --------------------------------------------------------

    accuracy_evaluator = (
        MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="accuracy"
        )
    )

    accuracy = (
        accuracy_evaluator.evaluate(
            predictions
        )
    )

    precision_evaluator = (
        MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="weightedPrecision"
        )
    )

    weighted_precision = (
        precision_evaluator.evaluate(
            predictions
        )
    )

    recall_evaluator = (
        MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="weightedRecall"
        )
    )

    weighted_recall = (
        recall_evaluator.evaluate(
            predictions
        )
    )

    f1_evaluator = (
        MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="f1"
        )
    )

    weighted_f1 = (
        f1_evaluator.evaluate(
            predictions
        )
    )

    # --------------------------------------------------------
    # Evaluation summary
    # --------------------------------------------------------

    print("\n" + "=" * 75)
    print(
        "CYBERSENTINEL ATTACK CLASSIFIER "
        "— EVALUATION"
    )
    print("=" * 75)

    print(
        f"\nAccuracy:            "
        f"{accuracy:.4f}"
    )

    print(
        f"Weighted Precision:  "
        f"{weighted_precision:.4f}"
    )

    print(
        f"Weighted Recall:     "
        f"{weighted_recall:.4f}"
    )

    print(
        f"Weighted F1:         "
        f"{weighted_f1:.4f}"
    )

    # --------------------------------------------------------
    # Per-class results
    # --------------------------------------------------------

    print("\nPer-class results:")

    labels = indexer_model.labels

    for class_index, attack_type in enumerate(labels):

        actual_df = predictions.filter(
            col("label") == float(class_index)
        )

        actual_count = actual_df.count()

        correct_count = (
            actual_df
            .filter(
                col("prediction")
                == col("label")
            )
            .count()
        )

        predicted_df = predictions.filter(
            col("prediction")
            == float(class_index)
        )

        predicted_count = predicted_df.count()

        true_positive = correct_count

        false_positive = (
            predicted_count
            - true_positive
        )

        false_negative = (
            actual_count
            - true_positive
        )

        recall = (
            true_positive / actual_count
            if actual_count > 0
            else 0.0
        )

        precision = (
            true_positive / predicted_count
            if predicted_count > 0
            else 0.0
        )

        if (
            precision + recall
        ) > 0:

            f1 = (
                2
                * precision
                * recall
                / (precision + recall)
            )

        else:

            f1 = 0.0

        print(
            f"\n{attack_type}"
        )

        print(
            f"  Actual samples:       "
            f"{actual_count}"
        )

        print(
            f"  Predicted samples:    "
            f"{predicted_count}"
        )

        print(
            f"  Correctly classified: "
            f"{correct_count}"
        )

        print(
            f"  Precision:             "
            f"{precision:.4f}"
        )

        print(
            f"  Recall:                "
            f"{recall:.4f}"
        )

        print(
            f"  F1-score:              "
            f"{f1:.4f}"
        )

        print(
            f"  False positives:       "
            f"{false_positive}"
        )

        print(
            f"  False negatives:       "
            f"{false_negative}"
        )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    print("\nConfusion Matrix:")

    print(
        "\nRows = Actual Class"
    )

    print(
        "Columns = Predicted Class"
    )

    print(
        "\nClass mapping:"
    )

    for index, attack_type in enumerate(labels):

        print(
            f"  {index} -> {attack_type}"
        )

    confusion = (
        predictions
        .groupBy(
            "label",
            "prediction"
        )
        .count()
        .orderBy(
            "label",
            "prediction"
        )
    )

    confusion.show(
        50,
        truncate=False
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    print(
        f"\nSaving classifier to:"
    )

    print(
        MODEL_PATH
    )

    model.write().overwrite().save(
        MODEL_PATH
    )

    print(
        "\nAttack classifier saved successfully."
    )

    print("=" * 75)


# ============================================================
# MAIN
# ============================================================

def main():

    spark = create_spark_session()

    try:

        attacks = load_attack_data(
            spark
        )

        prepared = prepare_features(
            attacks
        )

        indexed, indexer_model = encode_labels(
            prepared
        )

        assembled = assemble_features(
            indexed
        )

        train, test = split_data(
            assembled
        )

        weighted_train = add_class_weights(
            train
        )

        model = train_classifier(
            weighted_train
        )

        evaluate_model(
            model,
            test,
            indexer_model
        )

        print("\n" + "=" * 75)
        print(
            "CYBERSENTINEL ATTACK CLASSIFICATION "
            "COMPLETED SUCCESSFULLY"
        )
        print("=" * 75)

    finally:

        spark.stop()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()