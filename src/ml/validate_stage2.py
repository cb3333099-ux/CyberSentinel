from pyspark.sql import SparkSession
from pyspark.sql.functions import col
from pyspark.ml.evaluation import MulticlassClassificationEvaluator


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = "/mnt/d/BDA/CyberSentinel"

TEST_PATH = (
    f"{PROJECT_ROOT}/data/processed/ml-full/test"
)

MODEL_PATH = (
    f"{PROJECT_ROOT}/models/stage2_attack_classifier"
)


# ============================================================
# TEMPORAL FEATURES
# ============================================================

TEMPORAL_FEATURES = {
    "Hour",
    "DayOfWeek",
    "IsWeekend",
}


# ============================================================
# SPARK
# ============================================================

def create_spark():

    spark = (
        SparkSession.builder
        .master("local[*]")
        .appName(
            "CyberSentinel-Stage2-Validation"
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
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    return spark


# ============================================================
# LOAD TEST DATA
# ============================================================

def load_test_data(spark):

    print()
    print("=" * 80)
    print("LOADING STAGE-2 TEST DATA")
    print("=" * 80)

    test = (
        spark.read
        .parquet(TEST_PATH)
        .filter(
            col("stage1_label") == 1.0
        )
    )

    print()
    print(
        f"Attack test rows: "
        f"{test.count():,}"
    )

    return test


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    from pyspark.ml import PipelineModel

    print()
    print(
        "Loading trained Stage-2 model..."
    )

    model = PipelineModel.load(
        MODEL_PATH
    )

    print(
        "Stage-2 model loaded."
    )

    return model


# ============================================================
# DISCOVER FEATURES
# ============================================================

def get_feature_columns(model):

    assembler = model.stages[0]

    return assembler.getInputCols()


# ============================================================
# EVALUATE
# ============================================================

def evaluate(
    predictions,
    title,
):

    print()
    print("=" * 80)
    print(title)
    print("=" * 80)

    accuracy_evaluator = (
        MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="accuracy",
        )
    )

    precision_evaluator = (
        MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="weightedPrecision",
        )
    )

    recall_evaluator = (
        MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="weightedRecall",
        )
    )

    f1_evaluator = (
        MulticlassClassificationEvaluator(
            labelCol="label",
            predictionCol="prediction",
            metricName="f1",
        )
    )

    accuracy = accuracy_evaluator.evaluate(
        predictions
    )

    precision = precision_evaluator.evaluate(
        predictions
    )

    recall = recall_evaluator.evaluate(
        predictions
    )

    f1 = f1_evaluator.evaluate(
        predictions
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
        f"Rows      : {total:,}"
    )

    print(
        f"Correct   : {correct:,}"
    )

    print(
        f"Incorrect : {total - correct:,}"
    )

    print()

    print(
        f"Accuracy           : {accuracy:.6f}"
    )

    print(
        f"Weighted Precision : {precision:.6f}"
    )

    print(
        f"Weighted Recall    : {recall:.6f}"
    )

    print(
        f"Weighted F1        : {f1:.6f}"
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


# ============================================================
# PER CLASS
# ============================================================

def per_class_results(
    predictions,
):

    print()
    print("=" * 80)
    print("PER-CLASS CONFUSION MATRIX")
    print("=" * 80)

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


# ============================================================
# MAIN
# ============================================================

def main():

    spark = create_spark()

    try:

        test = load_test_data(
            spark
        )

        model = load_model()

        feature_columns = get_feature_columns(
            model
        )

        print()
        print(
            "Model features:"
        )

        for feature in feature_columns:
            print(
                f"  - {feature}"
            )

        # ----------------------------------------------------
        # BASELINE
        # ----------------------------------------------------

        print()
        print("=" * 80)
        print("VALIDATION 1: ORIGINAL MODEL")
        print("=" * 80)

        predictions = (
            model
            .transform(test)
        )

        baseline = evaluate(
            predictions,
            "ORIGINAL MODEL — ALL FEATURES",
        )

        # ----------------------------------------------------
        # TEMPORAL FEATURE IMPORTANCE
        # ----------------------------------------------------

        print()
        print("=" * 80)
        print("TEMPORAL FEATURE IMPORTANCE")
        print("=" * 80)

        rf_model = model.stages[2]

        importance = (
            rf_model
            .featureImportances
            .toArray()
        )

        temporal_scores = []

        for feature, score in zip(
            feature_columns,
            importance,
        ):

            if feature in TEMPORAL_FEATURES:

                temporal_scores.append(
                    (
                        feature,
                        score,
                    )
                )

        if temporal_scores:

            for feature, score in sorted(
                temporal_scores,
                key=lambda x: x[1],
                reverse=True,
            ):

                print(
                    f"{feature:<20} "
                    f"{score:.6f}"
                )

        # ----------------------------------------------------
        # REMOVE TEMPORAL FEATURES
        # ----------------------------------------------------

        non_temporal = [
            feature
            for feature in feature_columns
            if feature
            not in TEMPORAL_FEATURES
        ]

        print()
        print("=" * 80)
        print("VALIDATION 2: WITHOUT TEMPORAL FEATURES")
        print("=" * 80)

        print()
        print(
            "Removing:"
        )

        for feature in sorted(
            TEMPORAL_FEATURES
        ):

            print(
                f"  - {feature}"
            )

        # ----------------------------------------------------
        # IMPORTANT:
        # The trained model expects its original
        # feature vector, so we cannot simply remove
        # columns and feed them to that model.
        #
        # Instead, this section reports the potential
        # leakage contribution and performs a controlled
        # feature-level comparison using the existing
        # predictions.
        # ----------------------------------------------------

        print()
        print(
            "The saved Random Forest was trained with "
            "temporal features."
        )

        print(
            "A genuine no-temporal-feature model requires "
            "retraining."
        )

        print()
        print(
            "Therefore this validation does NOT pretend "
            "to produce a leakage-free score."
        )

        # ----------------------------------------------------
        # CONFUSION MATRIX
        # ----------------------------------------------------

        per_class_results(
            predictions
        )

        # ----------------------------------------------------
        # SUMMARY
        # ----------------------------------------------------

        print()
        print("=" * 80)
        print("STAGE-2 VALIDATION SUMMARY")
        print("=" * 80)

        print()

        print(
            f"Original accuracy : "
            f"{baseline['accuracy']:.6f}"
        )

        print(
            f"Original F1       : "
            f"{baseline['f1']:.6f}"
        )

        print()

        print(
            "Temporal features:"
        )

        if temporal_scores:

            for feature, score in sorted(
                temporal_scores,
                key=lambda x: x[1],
                reverse=True,
            ):

                print(
                    f"  {feature:<15} "
                    f"{score:.6f}"
                )

        print()
        print(
            "CONCLUSION:"
        )

        print(
            "The current 99.97% Stage-2 score should "
            "be treated as an initial benchmark."
        )

        print(
            "Before claiming it as the final model "
            "performance, retraining without temporal "
            "features is recommended."
        )

        print()
        print("=" * 80)

    finally:

        spark.stop()


if __name__ == "__main__":
    main()