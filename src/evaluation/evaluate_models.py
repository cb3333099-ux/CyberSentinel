import json
from pathlib import Path
import time
import pandas as pd

from pyspark.sql import SparkSession
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.functions import vector_to_array
from pyspark.sql.functions import (
    col, count as spark_count, avg as spark_avg,
    max as spark_max, min as spark_min, element_at
)

from src.inference.predictor import FEATURE_COLUMNS, STAGE1_FEATURE_COLUMNS

# ============================================================
# PATH CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_DATA_PATH = PROJECT_ROOT / "data" / "processed" / "ml-full" / "test"
STAGE1_MODEL_PATH = PROJECT_ROOT / "models" / "stage1_random_forest"
STAGE2_MODEL_PATH = PROJECT_ROOT / "models" / "stage2_attack_classifier_no_temporal"
REPORTS_DIR = PROJECT_ROOT / "reports" / "evaluation"


def create_spark_session() -> SparkSession:
    """
    Create Spark Session optimized for evaluation.
    """
    spark = (
        SparkSession.builder
        .appName("CyberSentinelModelEvaluation")
        .master("local[*]")
        .config("spark.driver.memory", "8g")
        .config("spark.sql.shuffle.partitions", "16")
        .config("spark.sql.debug.maxToStringFields", "200")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    return spark


def main():
    start_time = time.time()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("CYBERSENTINEL FULL DATASET MODEL EVALUATION PIPELINE")
    print("=" * 80)
    print(f"Test dataset path: {TEST_DATA_PATH}")

    spark = create_spark_session()

    # ------------------------------------------------------------
    # 1. LOAD TEST DATASET & MODELS
    # ------------------------------------------------------------
    print("\nLoading test dataset and models...")
    test_df = spark.read.parquet(str(TEST_DATA_PATH))
    total_test_samples = test_df.count()

    stage1_model = RandomForestClassificationModel.load(str(STAGE1_MODEL_PATH))
    stage2_pipeline = PipelineModel.load(str(STAGE2_MODEL_PATH))
    stage2_labels = list(stage2_pipeline.stages[1].labels)

    print(f"Total Test Samples: {total_test_samples:,}")
    print(f"Stage 2 Attack Classes ({len(stage2_labels)}): {stage2_labels}")

    # ------------------------------------------------------------
    # 2. CLASS DISTRIBUTION
    # ------------------------------------------------------------
    print("\nComputing test set class distribution...")
    class_dist_raw = (
        test_df.groupBy("stage1_label", "attack_label")
        .agg(spark_count("*").alias("count"))
        .collect()
    )

    benign_samples = 0
    attack_samples = 0
    attack_type_counts = {}

    for row in class_dist_raw:
        s1_lbl = row["stage1_label"]
        atk_lbl = row["attack_label"]
        cnt = row["count"]
        if s1_lbl == 0.0:
            benign_samples += cnt
        else:
            attack_samples += cnt
            attack_type_counts[atk_lbl] = attack_type_counts.get(atk_lbl, 0) + cnt

    class_dist_rows = [
        {
            "class_name": "Benign",
            "count": benign_samples,
            "percentage": (benign_samples / total_test_samples) * 100.0
        }
    ]

    for atk_name, cnt in sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True):
        class_dist_rows.append({
            "class_name": atk_name,
            "count": cnt,
            "percentage": (cnt / total_test_samples) * 100.0
        })

    class_dist_df = pd.DataFrame(class_dist_rows)
    class_dist_df.to_csv(REPORTS_DIR / "class_distribution.csv", index=False)

    # ------------------------------------------------------------
    # 3. STAGE-1 EVALUATION
    # ------------------------------------------------------------
    print("\nEvaluating Stage-1 Random Forest Model...")
    assembler1 = VectorAssembler(
        inputCols=STAGE1_FEATURE_COLUMNS,
        outputCol="features",
        handleInvalid="keep"
    )
    test_s1_df = assembler1.transform(test_df)
    s1_transformed = stage1_model.transform(test_s1_df)

    s1_scored = (
        s1_transformed
        .withColumn("s1_arr", vector_to_array("probability"))
        .withColumn("s1_conf", element_at("s1_arr", col("prediction").cast("int") + 1))
    )

    s1_summary = (
        s1_scored
        .groupBy("stage1_label", "prediction")
        .agg(
            spark_count("*").alias("count"),
            spark_avg("s1_conf").alias("avg_conf"),
            spark_min("s1_conf").alias("min_conf"),
            spark_max("s1_conf").alias("max_conf")
        )
        .collect()
    )

    tp_1 = 0
    tn_1 = 0
    fp_1 = 0
    fn_1 = 0

    s1_correct_confs = []
    s1_incorrect_confs = []
    s1_all_confs = []

    for row in s1_summary:
        actual = float(row["stage1_label"])
        pred = float(row["prediction"])
        cnt = row["count"]
        avg_c = float(row["avg_conf"])
        min_c = float(row["min_conf"])
        max_c = float(row["max_conf"])

        s1_all_confs.append((cnt, avg_c, min_c, max_c))

        if actual == 1.0 and pred == 1.0:
            tp_1 += cnt
            s1_correct_confs.append((cnt, avg_c, min_c, max_c))
        elif actual == 0.0 and pred == 0.0:
            tn_1 += cnt
            s1_correct_confs.append((cnt, avg_c, min_c, max_c))
        elif actual == 0.0 and pred == 1.0:
            fp_1 += cnt
            s1_incorrect_confs.append((cnt, avg_c, min_c, max_c))
        elif actual == 1.0 and pred == 0.0:
            fn_1 += cnt
            s1_incorrect_confs.append((cnt, avg_c, min_c, max_c))

    def weighted_conf_stats(conf_list):
        if not conf_list:
            return {"mean": 0.0, "min": 0.0, "max": 0.0}
        total_cnt = sum(c[0] for c in conf_list)
        weighted_mean = sum(c[0] * c[1] for c in conf_list) / total_cnt if total_cnt > 0 else 0.0
        overall_min = min(c[2] for c in conf_list)
        overall_max = max(c[3] for c in conf_list)
        return {"mean": float(weighted_mean), "min": float(overall_min), "max": float(overall_max)}

    s1_stats_all = weighted_conf_stats(s1_all_confs)
    s1_stats_correct = weighted_conf_stats(s1_correct_confs)
    s1_stats_incorrect = weighted_conf_stats(s1_incorrect_confs)

    acc_1 = (tp_1 + tn_1) / total_test_samples if total_test_samples > 0 else 0.0
    prec_1 = tp_1 / (tp_1 + fp_1) if (tp_1 + fp_1) > 0 else 0.0
    rec_1 = tp_1 / (tp_1 + fn_1) if (tp_1 + fn_1) > 0 else 0.0
    f1_1 = (2 * prec_1 * rec_1) / (prec_1 + rec_1) if (prec_1 + rec_1) > 0 else 0.0
    fpr_1 = fp_1 / (fp_1 + tn_1) if (fp_1 + tn_1) > 0 else 0.0
    fnr_1 = fn_1 / (tp_1 + fn_1) if (tp_1 + fn_1) > 0 else 0.0

    stage1_metrics = {
        "total_samples": total_test_samples,
        "benign_samples": benign_samples,
        "attack_samples": attack_samples,
        "accuracy": acc_1,
        "precision": prec_1,
        "recall": rec_1,
        "f1_score": f1_1,
        "true_positives": tp_1,
        "true_negatives": tn_1,
        "false_positives": fp_1,
        "false_negatives": fn_1,
        "false_positive_rate": fpr_1,
        "false_negative_rate": fnr_1,
        "confidence": {
            "overall": s1_stats_all,
            "correct": s1_stats_correct,
            "incorrect": s1_stats_incorrect
        }
    }

    with open(REPORTS_DIR / "stage1_metrics.json", "w") as f:
        json.dump(stage1_metrics, f, indent=2)

    s1_cm_df = pd.DataFrame([
        {"actual": "Benign", "predicted_benign": tn_1, "predicted_attack": fp_1},
        {"actual": "Attack", "predicted_benign": fn_1, "predicted_attack": tp_1}
    ])
    s1_cm_df.to_csv(REPORTS_DIR / "stage1_confusion_matrix.csv", index=False)

    # ------------------------------------------------------------
    # 4. STAGE-2 EVALUATION (On Actual Attack Samples)
    # ------------------------------------------------------------
    print("\nEvaluating Stage-2 Attack Classifier Model...")
    attack_test_df = test_df.filter(col("stage1_label") == 1.0)
    s2_transformed = stage2_pipeline.transform(attack_test_df)

    s2_scored = (
        s2_transformed
        .withColumn("s2_arr", vector_to_array("probability"))
        .withColumn("s2_conf", element_at("s2_arr", col("prediction").cast("int") + 1))
    )

    s2_summary = (
        s2_scored
        .groupBy("attack_label", "prediction")
        .agg(
            spark_count("*").alias("count"),
            spark_avg("s2_conf").alias("avg_conf"),
            spark_min("s2_conf").alias("min_conf"),
            spark_max("s2_conf").alias("max_conf")
        )
        .collect()
    )

    s2_cm_counts = {}
    s2_correct_confs = []
    s2_incorrect_confs = []
    s2_all_confs = []

    for row in s2_summary:
        actual_name = str(row["attack_label"])
        pred_idx = int(row["prediction"])
        pred_name = stage2_labels[pred_idx]
        cnt = int(row["count"])
        avg_c = float(row["avg_conf"])
        min_c = float(row["min_conf"])
        max_c = float(row["max_conf"])

        s2_all_confs.append((cnt, avg_c, min_c, max_c))

        if actual_name not in s2_cm_counts:
            s2_cm_counts[actual_name] = {}
        s2_cm_counts[actual_name][pred_name] = cnt

        if actual_name == pred_name:
            s2_correct_confs.append((cnt, avg_c, min_c, max_c))
        else:
            s2_incorrect_confs.append((cnt, avg_c, min_c, max_c))

    s2_stats_all = weighted_conf_stats(s2_all_confs)
    s2_stats_correct = weighted_conf_stats(s2_correct_confs)
    s2_stats_incorrect = weighted_conf_stats(s2_incorrect_confs)

    all_present_classes = sorted(list(attack_type_counts.keys()))
    s2_per_class = {}
    total_s2_correct = 0

    for cls in all_present_classes:
        supp = attack_type_counts.get(cls, 0)
        tp_c = s2_cm_counts.get(cls, {}).get(cls, 0)
        total_s2_correct += tp_c

        fp_c = sum(s2_cm_counts.get(other_act, {}).get(cls, 0) for other_act in all_present_classes if other_act != cls)
        fn_c = supp - tp_c

        p_c = tp_c / (tp_c + fp_c) if (tp_c + fp_c) > 0 else 0.0
        r_c = tp_c / (tp_c + fn_c) if (tp_c + fn_c) > 0 else 0.0
        f1_c = (2 * p_c * r_c) / (p_c + r_c) if (p_c + r_c) > 0 else 0.0

        s2_per_class[cls] = {
            "support": supp,
            "precision": p_c,
            "recall": r_c,
            "f1_score": f1_c,
            "true_positives": tp_c,
            "false_positives": fp_c,
            "false_negatives": fn_c
        }

    s2_acc = total_s2_correct / attack_samples if attack_samples > 0 else 0.0
    macro_prec = sum(v["precision"] for v in s2_per_class.values()) / len(s2_per_class) if s2_per_class else 0.0
    macro_rec = sum(v["recall"] for v in s2_per_class.values()) / len(s2_per_class) if s2_per_class else 0.0
    macro_f1 = sum(v["f1_score"] for v in s2_per_class.values()) / len(s2_per_class) if s2_per_class else 0.0

    weighted_prec = sum(v["support"] * v["precision"] for v in s2_per_class.values()) / attack_samples if attack_samples > 0 else 0.0
    weighted_rec = sum(v["support"] * v["recall"] for v in s2_per_class.values()) / attack_samples if attack_samples > 0 else 0.0
    weighted_f1 = sum(v["support"] * v["f1_score"] for v in s2_per_class.values()) / attack_samples if attack_samples > 0 else 0.0

    stage2_metrics = {
        "attack_samples": attack_samples,
        "accuracy": s2_acc,
        "macro_precision": macro_prec,
        "macro_recall": macro_rec,
        "macro_f1": macro_f1,
        "weighted_precision": weighted_prec,
        "weighted_recall": weighted_rec,
        "weighted_f1": weighted_f1,
        "per_class": s2_per_class,
        "confidence": {
            "overall": s2_stats_all,
            "correct": s2_stats_correct,
            "incorrect": s2_stats_incorrect
        }
    }

    with open(REPORTS_DIR / "stage2_metrics.json", "w") as f:
        json.dump(stage2_metrics, f, indent=2)

    # Build Stage-2 Confusion Matrix CSV
    cm_cols = sorted(list(set(all_present_classes)))
    s2_cm_rows = []
    for act_cls in cm_cols:
        row_dict = {"actual": act_cls}
        for pred_cls in cm_cols:
            row_dict[pred_cls] = s2_cm_counts.get(act_cls, {}).get(pred_cls, 0)
        s2_cm_rows.append(row_dict)

    s2_cm_df = pd.DataFrame(s2_cm_rows)
    s2_cm_df.to_csv(REPORTS_DIR / "stage2_confusion_matrix.csv", index=False)

    # ------------------------------------------------------------
    # 5. END-TO-END PIPELINE EVALUATION
    # ------------------------------------------------------------
    print("\nEvaluating End-to-End Pipeline Performance...")
    detected_attacks_df = (
        s1_transformed
        .filter((col("stage1_label") == 1.0) & (col("prediction") == 1.0))
        .drop("features", "prediction", "probability", "rawPrediction")
    )

    s2_detected_transformed = stage2_pipeline.transform(detected_attacks_df)
    s2_detected_summary = (
        s2_detected_transformed
        .groupBy("attack_label", "prediction")
        .agg(spark_count("*").alias("count"))
        .collect()
    )

    correct_classified_attacks_e2e = 0

    for row in s2_detected_summary:
        actual_name = str(row["attack_label"])
        pred_idx = int(row["prediction"])
        pred_name = stage2_labels[pred_idx]
        cnt = int(row["count"])
        if actual_name == pred_name:
            correct_classified_attacks_e2e += cnt

    overall_pipeline_accuracy = (tn_1 + correct_classified_attacks_e2e) / total_test_samples if total_test_samples > 0 else 0.0
    attack_detection_accuracy = tp_1 / attack_samples if attack_samples > 0 else 0.0
    attack_classification_on_detected = correct_classified_attacks_e2e / tp_1 if tp_1 > 0 else 0.0
    attack_classification_overall = correct_classified_attacks_e2e / attack_samples if attack_samples > 0 else 0.0

    pipeline_metrics = {
        "total_test_samples": total_test_samples,
        "overall_pipeline_accuracy": overall_pipeline_accuracy,
        "attack_detection_accuracy": attack_detection_accuracy,
        "attack_classification_on_detected": attack_classification_on_detected,
        "attack_classification_overall": attack_classification_overall,
        "correct_benign_decisions": tn_1,
        "correct_attack_detections": tp_1,
        "correct_attack_classifications": correct_classified_attacks_e2e,
        "false_alarms": fp_1,
        "missed_attacks": fn_1
    }

    # Save Confidence Analysis JSON
    confidence_analysis = {
        "stage1": {
            "overall": s1_stats_all,
            "correct": s1_stats_correct,
            "incorrect": s1_stats_incorrect
        },
        "stage2": {
            "overall": s2_stats_all,
            "correct": s2_stats_correct,
            "incorrect": s2_stats_incorrect
        }
    }

    with open(REPORTS_DIR / "confidence_analysis.json", "w") as f:
        json.dump(confidence_analysis, f, indent=2)

    # Save Evaluation Summary JSON
    evaluation_summary = {
        "dataset": str(TEST_DATA_PATH),
        "total_test_samples": total_test_samples,
        "benign_samples": benign_samples,
        "attack_samples": attack_samples,
        "stage1_metrics": stage1_metrics,
        "stage2_metrics": stage2_metrics,
        "pipeline_metrics": pipeline_metrics,
        "execution_time_seconds": time.time() - start_time
    }

    with open(REPORTS_DIR / "evaluation_summary.json", "w") as f:
        json.dump(evaluation_summary, f, indent=2)

    # ------------------------------------------------------------
    # 6. GENERATE EVALUATION REPORT TXT
    # ------------------------------------------------------------
    report_text = f"""============================================================
CYBERSENTINEL MODEL EVALUATION
============================================================

Dataset:
{TEST_DATA_PATH}

Total Test Samples : {total_test_samples:,}
Benign Samples     : {benign_samples:,}
Attack Samples     : {attack_samples:,}

------------------------------------------------------------
STAGE-1 ATTACK DETECTION
------------------------------------------------------------

Accuracy           : {acc_1:.2%}
Precision          : {prec_1:.2%}
Recall             : {rec_1:.2%}
F1 Score           : {f1_1:.2%}

True Positives     : {tp_1:,}
True Negatives     : {tn_1:,}
False Positives    : {fp_1:,}
False Negatives    : {fn_1:,}

False Positive Rate: {fpr_1:.2%}
False Negative Rate: {fnr_1:.2%}

------------------------------------------------------------
STAGE-2 ATTACK CLASSIFICATION
------------------------------------------------------------

Accuracy           : {s2_acc:.2%}
Macro Precision    : {macro_prec:.2%}
Macro Recall       : {macro_rec:.2%}
Macro F1           : {macro_f1:.2%}

Weighted Precision : {weighted_prec:.2%}
Weighted Recall    : {weighted_rec:.2%}
Weighted F1        : {weighted_f1:.2%}

------------------------------------------------------------
PER-CLASS PERFORMANCE
------------------------------------------------------------

{"Attack Type":<28} {"Precision":<11} {"Recall":<9} {"F1":<9} {"Support":<8}
"""

    for cls in sorted(all_present_classes, key=lambda x: attack_type_counts[x], reverse=True):
        p_str = f"{s2_per_class[cls]['precision']:.2%}"
        r_str = f"{s2_per_class[cls]['recall']:.2%}"
        f_str = f"{s2_per_class[cls]['f1_score']:.2%}"
        sup_str = f"{s2_per_class[cls]['support']:,}"
        report_text += f"\n{cls:<28} {p_str:<11} {r_str:<9} {f_str:<9} {sup_str:<8}"

    report_text += f"""

------------------------------------------------------------
END-TO-END PIPELINE
------------------------------------------------------------

Overall Pipeline Accuracy : {overall_pipeline_accuracy:.2%}
Attack Detection Accuracy : {attack_detection_accuracy:.2%}
Attack Classification     : {attack_classification_on_detected:.2%}

------------------------------------------------------------
CONFIDENCE
------------------------------------------------------------

Stage-1 Mean Confidence : {s1_stats_all['mean']:.2%}
Stage-2 Mean Confidence : {s2_stats_all['mean']:.2%}

============================================================
"""

    with open(REPORTS_DIR / "evaluation_report.txt", "w") as f:
        f.write(report_text)

    spark.stop()

    print("\n" + report_text)
    print(f"Evaluation report written to: {REPORTS_DIR / 'evaluation_report.txt'}")
    print(f"All reports saved to: {REPORTS_DIR}")


if __name__ == "__main__":
    main()
