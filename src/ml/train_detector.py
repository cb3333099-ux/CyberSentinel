from pyspark.sql import SparkSession
from pyspark.sql.functions import col, when
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import (
    BinaryClassificationEvaluator,
    MulticlassClassificationEvaluator
)
from pyspark.ml.functions import vector_to_array


# ============================================================
# Configuration
# ============================================================

TRAIN_PATH = (
    "/home/charay/cybersentinel-data/"
    "ml/train"
)

TEST_PATH = (
    "/home/charay/cybersentinel-data/"
    "ml/test"
)

MODEL_PATH = (
    "/home/charay/cybersentinel-data/"
    "models/attack_detector_rf"
)


# ============================================================
# Spark Session
# ============================================================

def create_spark_session():

    spark = (
        SparkSession.builder
        .master("local[*]")
        .appName("CyberSentinel-Attack-Detector")
        .config(
            "spark.sql.warehouse.dir",
            "/home/charay/cybersentinel-data/spark-warehouse"
        )
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    return spark


# ============================================================
# Load Training / Testing Data
# ============================================================

def load_data(spark):

    print("\n[1/7] Loading ML datasets...")

    train = spark.read.parquet(TRAIN_PATH)
    test = spark.read.parquet(TEST_PATH)

    print(f"Training rows: {train.count():,}")
    print(f"Testing rows:  {test.count():,}")

    return train, test


# ============================================================
# Calculate Class Weights
# ============================================================

def add_class_weights(train, test):

    print("\n[2/7] Calculating class weights...")

    counts = (
        train
        .groupBy("label")
        .count()
        .collect()
    )

    class_counts = {
        int(row["label"]): row["count"]
        for row in counts
    }

    benign_count = class_counts.get(0, 0)
    attack_count = class_counts.get(1, 0)

    if attack_count == 0:
        raise ValueError("Training dataset contains no attack samples.")

    # Weight the minority class according to the
    # imbalance in the training data.
    #
    # weight = total / (number_of_classes * class_count)

    total = benign_count + attack_count

    benign_weight = total / (2.0 * benign_count)
    attack_weight = total / (2.0 * attack_count)

    print(f"Benign samples: {benign_count:,}")
    print(f"Attack samples: {attack_count:,}")

    print(f"Benign weight: {benign_weight:.4f}")
    print(f"Attack weight: {attack_weight:.4f}")

    train_weighted = train.withColumn(
        "classWeight",
        when(
            col("label") == 1.0,
            attack_weight
        ).otherwise(
            benign_weight
        )
    )

    test_weighted = test.withColumn(
        "classWeight",
        when(
            col("label") == 1.0,
            attack_weight
        ).otherwise(
            benign_weight
        )
    )

    return train_weighted, test_weighted


# ============================================================
# Train Random Forest
# ============================================================

def train_model(train):

    print("\n[3/7] Training weighted Random Forest...")

    rf = RandomForestClassifier(
        labelCol="label",
        featuresCol="features",
        weightCol="classWeight",

        numTrees=100,
        maxDepth=12,

        minInstancesPerNode=2,

        seed=42,

        featureSubsetStrategy="sqrt"
    )

    model = rf.fit(train)

    print("Random Forest training completed.")

    return model


# ============================================================
# Generate Predictions
# ============================================================

def generate_predictions(model, test):

    print("\n[4/7] Generating test predictions...")

    predictions = model.transform(test)

    predictions = predictions.select(
        "label",
        "prediction",
        "probability",
        "rawPrediction"
    )

    print("Predictions generated.")

    return predictions


# ============================================================
# Evaluate Model
# ============================================================

def evaluate_model(predictions):

    print("\n[5/7] Evaluating detector...")

    # --------------------------------------------------------
    # Accuracy
    # --------------------------------------------------------

    accuracy_evaluator = MulticlassClassificationEvaluator(
        labelCol="label",
        predictionCol="prediction",
        metricName="accuracy"
    )

    accuracy = accuracy_evaluator.evaluate(predictions)

    # --------------------------------------------------------
    # Weighted Precision
    # --------------------------------------------------------

    precision_evaluator = MulticlassClassificationEvaluator(
        labelCol="label",
        predictionCol="prediction",
        metricName="weightedPrecision"
    )

    weighted_precision = precision_evaluator.evaluate(
        predictions
    )

    # --------------------------------------------------------
    # Weighted Recall
    # --------------------------------------------------------

    recall_evaluator = MulticlassClassificationEvaluator(
        labelCol="label",
        predictionCol="prediction",
        metricName="weightedRecall"
    )

    weighted_recall = recall_evaluator.evaluate(
        predictions
    )

    # --------------------------------------------------------
    # Weighted F1
    # --------------------------------------------------------

    f1_evaluator = MulticlassClassificationEvaluator(
        labelCol="label",
        predictionCol="prediction",
        metricName="weightedFMeasure"
    )

    weighted_f1 = f1_evaluator.evaluate(
        predictions
    )

    # --------------------------------------------------------
    # ROC-AUC
    # --------------------------------------------------------

    roc_evaluator = BinaryClassificationEvaluator(
        labelCol="label",
        rawPredictionCol="rawPrediction",
        metricName="areaUnderROC"
    )

    roc_auc = roc_evaluator.evaluate(predictions)

    # --------------------------------------------------------
    # PR-AUC
    # --------------------------------------------------------

    pr_evaluator = BinaryClassificationEvaluator(
        labelCol="label",
        rawPredictionCol="rawPrediction",
        metricName="areaUnderPR"
    )

    pr_auc = pr_evaluator.evaluate(predictions)

    # --------------------------------------------------------
    # Attack-specific metrics
    # --------------------------------------------------------

    tp = predictions.filter(
        (col("label") == 1.0)
        & (col("prediction") == 1.0)
    ).count()

    tn = predictions.filter(
        (col("label") == 0.0)
        & (col("prediction") == 0.0)
    ).count()

    fp = predictions.filter(
        (col("label") == 0.0)
        & (col("prediction") == 1.0)
    ).count()

    fn = predictions.filter(
        (col("label") == 1.0)
        & (col("prediction") == 0.0)
    ).count()

    attack_precision = (
        tp / (tp + fp)
        if (tp + fp) > 0
        else 0.0
    )

    attack_recall = (
        tp / (tp + fn)
        if (tp + fn) > 0
        else 0.0
    )

    attack_f1 = (
        2 * attack_precision * attack_recall
        / (attack_precision + attack_recall)
        if (attack_precision + attack_recall) > 0
        else 0.0
    )

    print("\n" + "=" * 70)
    print("CYBERSENTINEL ATTACK DETECTOR — EVALUATION")
    print("=" * 70)

    print(f"\nAccuracy:           {accuracy:.4f}")
    print(f"Weighted Precision: {weighted_precision:.4f}")
    print(f"Weighted Recall:    {weighted_recall:.4f}")
    print(f"Weighted F1:        {weighted_f1:.4f}")

    print(f"\nROC-AUC:            {roc_auc:.4f}")
    print(f"PR-AUC:             {pr_auc:.4f}")

    print("\nAttack-specific metrics:")
    print(f"Precision:          {attack_precision:.4f}")
    print(f"Recall:             {attack_recall:.4f}")
    print(f"F1-score:           {attack_f1:.4f}")

    print("\nConfusion Matrix:")
    print(
        f"True Negatives:    {tn:,}"
    )
    print(
        f"False Positives:   {fp:,}"
    )
    print(
        f"False Negatives:   {fn:,}"
    )
    print(
        f"True Positives:    {tp:,}"
    )

    print("=" * 70)

    return {
        "accuracy": accuracy,
        "weighted_precision": weighted_precision,
        "weighted_recall": weighted_recall,
        "weighted_f1": weighted_f1,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "attack_precision": attack_precision,
        "attack_recall": attack_recall,
        "attack_f1": attack_f1,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp
    }


# ============================================================
# Feature Importance
# ============================================================

def show_feature_importance(model):

    print("\n[6/7] Inspecting feature importance...")

    importances = model.featureImportances

    print(
        f"Number of model features: "
        f"{len(importances)}"
    )

    print("\nTop feature indices:")

    ranked = sorted(
        enumerate(importances),
        key=lambda x: x[1],
        reverse=True
    )

    for index, importance in ranked[:20]:

        print(
            f"Feature {index:>3}: "
            f"{importance:.6f}"
        )


# ============================================================
# Save Model
# ============================================================

def save_model(model):

    print("\n[7/7] Saving trained detector...")

    model.write().overwrite().save(MODEL_PATH)

    print(
        f"Model saved to:\n"
        f"{MODEL_PATH}"
    )


# ============================================================
# Main
# ============================================================

def main():

    spark = create_spark_session()

    try:

        train, test = load_data(spark)

        train, test = add_class_weights(
            train,
            test
        )

        model = train_model(train)

        predictions = generate_predictions(
            model,
            test
        )

        metrics = evaluate_model(
            predictions
        )

        show_feature_importance(
            model
        )

        save_model(
            model
        )

        print("\n" + "=" * 70)
        print(
            "CYBERSENTINEL ATTACK DETECTOR "
            "COMPLETED SUCCESSFULLY"
        )
        print("=" * 70)

    finally:

        spark.stop()


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()