from pyspark.sql import SparkSession
from pyspark.sql.functions import col, when, udf
from pyspark.sql.types import DoubleType
from pyspark.ml.classification import RandomForestClassificationModel


# ============================================================
# Configuration
# ============================================================

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
        .appName("CyberSentinel-Threshold-Analysis")
        .config(
            "spark.sql.warehouse.dir",
            "/home/charay/cybersentinel-data/spark-warehouse"
        )
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    return spark


# ============================================================
# Load Model and Test Data
# ============================================================

def load_resources(spark):

    print("\n[1/5] Loading trained detector and test data...")

    test = spark.read.parquet(TEST_PATH)

    model = RandomForestClassificationModel.load(
        MODEL_PATH
    )

    print(f"Test rows: {test.count():,}")
    print("Detector loaded successfully.")

    return model, test


# ============================================================
# Generate Attack Probabilities
# ============================================================

def generate_probabilities(model, test):

    print("\n[2/5] Generating attack probabilities...")

    predictions = model.transform(test)

    # For binary Random Forest:
    #
    # probability[0] = probability of Benign
    # probability[1] = probability of Attack

    attack_probability = udf(
        lambda vector: float(vector[1]),
        DoubleType()
    )

    predictions = predictions.withColumn(
        "attack_probability",
        attack_probability(col("probability"))
    )

    print("Attack probabilities generated.")

    return predictions


# ============================================================
# Evaluate Threshold
# ============================================================

def evaluate_threshold(df, threshold):

    classified = df.withColumn(
        "threshold_prediction",
        when(
            col("attack_probability") >= threshold,
            1.0
        ).otherwise(0.0)
    )

    tp = classified.filter(
        (col("label") == 1.0)
        & (col("threshold_prediction") == 1.0)
    ).count()

    tn = classified.filter(
        (col("label") == 0.0)
        & (col("threshold_prediction") == 0.0)
    ).count()

    fp = classified.filter(
        (col("label") == 0.0)
        & (col("threshold_prediction") == 1.0)
    ).count()

    fn = classified.filter(
        (col("label") == 1.0)
        & (col("threshold_prediction") == 0.0)
    ).count()

    precision = (
        tp / (tp + fp)
        if (tp + fp) > 0
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn) > 0
        else 0.0
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn) > 0
        else 0.0
    )

    return {
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn
    }


# ============================================================
# Run Threshold Analysis
# ============================================================

def analyze_thresholds(df):

    print("\n[3/5] Evaluating detection thresholds...")

    thresholds = [
        0.10,
        0.20,
        0.30,
        0.40,
        0.50,
        0.60,
        0.70,
        0.80,
        0.90
    ]

    results = []

    for threshold in thresholds:

        print(
            f"Evaluating threshold "
            f"{threshold:.2f}..."
        )

        result = evaluate_threshold(
            df,
            threshold
        )

        results.append(result)

    return results


# ============================================================
# Display Results
# ============================================================

def display_results(results):

    print("\n[4/5] Threshold analysis results...")

    print("\n" + "=" * 100)

    print(
        f"{'Threshold':<12}"
        f"{'Precision':<12}"
        f"{'Recall':<12}"
        f"{'F1':<12}"
        f"{'FPR':<12}"
        f"{'TP':<8}"
        f"{'FP':<8}"
        f"{'FN':<8}"
    )

    print("-" * 100)

    for result in results:

        print(
            f"{result['threshold']:<12.2f}"
            f"{result['precision']:<12.4f}"
            f"{result['recall']:<12.4f}"
            f"{result['f1']:<12.4f}"
            f"{result['false_positive_rate']:<12.6f}"
            f"{result['tp']:<8}"
            f"{result['fp']:<8}"
            f"{result['fn']:<8}"
        )

    print("=" * 100)


# ============================================================
# Select Recommended Threshold
# ============================================================

def select_threshold(results):

    print("\n[5/5] Selecting recommended threshold...")

    # Cybersecurity systems generally need strong recall,
    # but we also want to reduce false alerts.
    #
    # We therefore consider thresholds that retain at least
    # 95% attack recall and choose the one with the highest F1.

    eligible = [
        result
        for result in results
        if result["recall"] >= 0.95
    ]

    if not eligible:

        print(
            "No threshold achieved at least "
            "95% attack recall."
        )

        best = max(
            results,
            key=lambda x: x["f1"]
        )

    else:

        best = max(
            eligible,
            key=lambda x: x["f1"]
        )

    print("\n" + "=" * 70)
    print("CYBERSENTINEL RECOMMENDED DETECTION THRESHOLD")
    print("=" * 70)

    print(
        f"\nThreshold:          "
        f"{best['threshold']:.2f}"
    )

    print(
        f"Precision:          "
        f"{best['precision']:.4f}"
    )

    print(
        f"Recall:             "
        f"{best['recall']:.4f}"
    )

    print(
        f"F1-score:           "
        f"{best['f1']:.4f}"
    )

    print(
        f"False Positive Rate:"
        f" {best['false_positive_rate']:.6f}"
    )

    print(
        f"\nTrue Positives:     "
        f"{best['tp']}"
    )

    print(
        f"False Positives:    "
        f"{best['fp']}"
    )

    print(
        f"False Negatives:    "
        f"{best['fn']}"
    )

    print("\n" + "=" * 70)

    return best


# ============================================================
# Main
# ============================================================

def main():

    spark = create_spark_session()

    try:

        model, test = load_resources(
            spark
        )

        predictions = generate_probabilities(
            model,
            test
        )

        results = analyze_thresholds(
            predictions
        )

        display_results(
            results
        )

        select_threshold(
            results
        )

        print("\n" + "=" * 70)
        print(
            "CYBERSENTINEL THRESHOLD ANALYSIS "
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