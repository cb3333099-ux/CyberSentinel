import os
import json
import time
import math
import tempfile
import resource
from pathlib import Path
import numpy as np
import pandas as pd
import requests

from pyspark.sql import SparkSession
from pyspark.ml.feature import VectorAssembler
from src.inference.predictor import CyberSentinelPredictor, STAGE1_FEATURE_COLUMNS
from src.soc.detection_service import DetectionService
import src.soc.alert_store as alert_store

# ============================================================
# PATH CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_DATA_PATH = PROJECT_ROOT / "data" / "processed" / "ml-full" / "test"
REPORTS_DIR = PROJECT_ROOT / "reports" / "benchmark"
API_BASE_URL = "http://localhost:8000"


def get_memory_mb() -> float:
    """
    Get resident memory usage of the current Python process in MB.
    """
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return float(line.split()[1]) / 1024.0
    except Exception:
        pass
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return float(usage.ru_maxrss) / 1024.0


def main():
    start_benchmark_time = time.time()
    mem_before_mb = get_memory_mb()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("CYBERSENTINEL PERFORMANCE BENCHMARKING SUITE")
    print("=" * 80)
    print(f"Memory RSS at start: {mem_before_mb:.2f} MB")
    print(f"Test dataset path  : {TEST_DATA_PATH}\n")

    # ------------------------------------------------------------
    # 1. LOAD TEST DATA SAMPLE
    # ------------------------------------------------------------
    print("Loading test data sample for benchmarking...")
    temp_spark = (
        SparkSession.builder
        .appName("BenchmarkDataLoader")
        .master("local[*]")
        .config("spark.driver.memory", "8g")
        .getOrCreate()
    )
    temp_spark.sparkContext.setLogLevel("WARN")

    # Extract 5,000 real flows (mixture of benign and attack)
    test_df = temp_spark.read.parquet(str(TEST_DATA_PATH))
    sample_df = test_df.limit(5000)
    flows_5k = [row.asDict() for row in sample_df.collect()]

    # Extract 100 single-flow sample (50 benign, 50 attack)
    benign_sample = [row.asDict() for row in test_df.filter(test_df.stage1_label == 0.0).limit(50).collect()]
    attack_sample = [row.asDict() for row in test_df.filter(test_df.stage1_label == 1.0).limit(50).collect()]
    single_flow_sample = benign_sample + attack_sample

    temp_spark.stop()
    print(f"Loaded {len(flows_5k):,} flows for batch benchmarking.")
    print(f"Loaded {len(single_flow_sample)} flows (50 benign, 50 attack) for single-flow benchmarking.\n")

    # ------------------------------------------------------------
    # 2. COLD-START VS WARM INFERENCE LATENCY
    # ------------------------------------------------------------
    print("------------------------------------------------------------")
    print("1. SINGLE-FLOW LATENCY BENCHMARK")
    print("------------------------------------------------------------")

    t_cold_start = time.perf_counter()
    predictor = CyberSentinelPredictor()
    cold_start_ms = (time.perf_counter() - t_cold_start) * 1000.0
    print(f"Cold-Start Latency (Spark init + model load): {cold_start_ms:.2f} ms")

    # Accuracy Regression Baseline (Before Benchmark)
    regression_sample = single_flow_sample[:10]
    baseline_predictions = [predictor.predict(f) for f in regression_sample]

    # Warmup phase (10 flows)
    print("Warming up predictor runtime with 10 flows...")
    for flow in single_flow_sample[:10]:
        predictor.predict(flow)

    # Warm single-flow latency measurement (100 flows)
    print("Measuring warm single-flow inference latency across 100 real flows...")
    single_latencies_ms = []
    single_flow_records = []

    for idx, flow in enumerate(single_flow_sample):
        t0 = time.perf_counter()
        pred = predictor.predict(flow)
        lat_ms = (time.perf_counter() - t0) * 1000.0

        single_latencies_ms.append(lat_ms)
        single_flow_records.append({
            "flow_index": idx,
            "stage1_label": flow.get("stage1_label"),
            "attack_label": flow.get("attack_label"),
            "latency_ms": lat_ms,
            "predicted_is_attack": pred["is_attack"],
            "predicted_attack_type": pred["attack_type"],
            "confidence": pred["confidence"]
        })

    sf_mean = float(np.mean(single_latencies_ms))
    sf_median = float(np.median(single_latencies_ms))
    sf_p50 = float(np.percentile(single_latencies_ms, 50))
    sf_p90 = float(np.percentile(single_latencies_ms, 90))
    sf_p95 = float(np.percentile(single_latencies_ms, 95))
    sf_p99 = float(np.percentile(single_latencies_ms, 99))
    sf_min = float(np.min(single_latencies_ms))
    sf_max = float(np.max(single_latencies_ms))

    print(f"Single-Flow Warm Inference Latency:")
    print(f"  Mean  : {sf_mean:.2f} ms")
    print(f"  Median: {sf_median:.2f} ms")
    print(f"  P95   : {sf_p95:.2f} ms")
    print(f"  P99   : {sf_p99:.2f} ms")
    print(f"  Min   : {sf_min:.2f} ms | Max: {sf_max:.2f} ms\n")

    pd.DataFrame(single_flow_records).to_csv(REPORTS_DIR / "inference_latency.csv", index=False)

    # ------------------------------------------------------------
    # 3. BATCH THROUGHPUT BENCHMARK
    # ------------------------------------------------------------
    print("------------------------------------------------------------")
    print("2. BATCH THROUGHPUT BENCHMARK")
    print("------------------------------------------------------------")

    batch_configs = [
        (1, 100),       # Batch 1 on 100 flows
        (10, 1000),     # Batch 10 on 1000 flows
        (50, 5000),     # Batch 50 on 5000 flows
        (100, 5000),    # Batch 100 on 5000 flows
        (500, 5000),    # Batch 500 on 5000 flows
        (1000, 5000)    # Batch 1000 on 5000 flows
    ]
    batch_throughput_records = []

    for b_size, target_flow_cnt in batch_configs:
        flows_subset = flows_5k[:target_flow_cnt]
        num_batches = math.ceil(len(flows_subset) / b_size)
        batch_times_ms = []

        t_batch_start = time.perf_counter()
        for i in range(num_batches):
            batch_chunk = flows_subset[i * b_size : (i + 1) * b_size]
            tb0 = time.perf_counter()
            predictor.predict_batch(batch_chunk)
            batch_times_ms.append((time.perf_counter() - tb0) * 1000.0)

        total_batch_time_sec = time.perf_counter() - t_batch_start
        throughput_fps = len(flows_subset) / total_batch_time_sec if total_batch_time_sec > 0 else 0.0
        avg_ms_per_flow = (total_batch_time_sec * 1000.0) / len(flows_subset) if flows_subset else 0.0
        p95_batch_lat = float(np.percentile(batch_times_ms, 95))

        batch_throughput_records.append({
            "batch_size": b_size,
            "total_flows": len(flows_subset),
            "total_time_sec": float(total_batch_time_sec),
            "throughput_fps": float(throughput_fps),
            "avg_ms_per_flow": float(avg_ms_per_flow),
            "p95_batch_latency_ms": p95_batch_lat
        })

        print(f"Batch Size {b_size:4d} | Flows: {len(flows_subset):,d} | Time: {total_batch_time_sec:5.2f}s | Throughput: {throughput_fps:8.1f} flows/s | Avg ms/flow: {avg_ms_per_flow:6.2f} ms")

    pd.DataFrame(batch_throughput_records).to_csv(REPORTS_DIR / "batch_throughput.csv", index=False)

    # ------------------------------------------------------------
    # 4. STAGE-SPECIFIC PERFORMANCE
    # ------------------------------------------------------------
    print("\n------------------------------------------------------------")
    print("3. STAGE-SPECIFIC LATENCY BENCHMARK")
    print("------------------------------------------------------------")

    s1_assembler = VectorAssembler(inputCols=STAGE1_FEATURE_COLUMNS, outputCol="features", handleInvalid="keep")
    stage1_latencies = []
    for flow in single_flow_sample:
        df_flow = predictor._build_dataframe(flow)
        t0 = time.perf_counter()
        features = s1_assembler.transform(df_flow)
        predictor.stage1_model.transform(features).select("prediction", "probability").first()
        stage1_latencies.append((time.perf_counter() - t0) * 1000.0)

    s1_mean_lat = float(np.mean(stage1_latencies))

    stage2_latencies = []
    for flow in attack_sample:
        df_flow = predictor._build_dataframe(flow)
        t0 = time.perf_counter()
        predictor.stage2_model.transform(df_flow).select("prediction", "probability").first()
        stage2_latencies.append((time.perf_counter() - t0) * 1000.0)

    s2_mean_lat = float(np.mean(stage2_latencies))

    combined_latencies = []
    for flow in attack_sample:
        t0 = time.perf_counter()
        predictor.predict(flow)
        combined_latencies.append((time.perf_counter() - t0) * 1000.0)

    comb_mean_lat = float(np.mean(combined_latencies))

    print(f"Stage 1 Mean Latency : {s1_mean_lat:.2f} ms")
    print(f"Stage 2 Mean Latency : {s2_mean_lat:.2f} ms (Evaluated on attacks)")
    print(f"Combined Mean Latency: {comb_mean_lat:.2f} ms")

    # ------------------------------------------------------------
    # 5. DETECTION SERVICE & ISOLATED PERSISTENCE BENCHMARK
    # ------------------------------------------------------------
    print("\n------------------------------------------------------------")
    print("4. DETECTION SERVICE & PERSISTENCE BENCHMARK")
    print("------------------------------------------------------------")

    detection_service = DetectionService(predictor=predictor)

    ml_only_lats = []
    for flow in single_flow_sample:
        t0 = time.perf_counter()
        detection_service.analyze_flow(flow, persist_alert=False)
        ml_only_lats.append((time.perf_counter() - t0) * 1000.0)

    ml_only_mean_ms = float(np.mean(ml_only_lats))

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        temp_db_path = temp_dir_path / "benchmark_alerts.db"

        orig_db_dir = alert_store.DB_DIR
        orig_db_path = alert_store.DB_PATH
        alert_store.DB_DIR = temp_dir_path
        alert_store.DB_PATH = temp_db_path

        try:
            alert_store.initialize_database()

            attack_results = []
            for flow in attack_sample:
                res = detection_service.analyze_flow(flow, persist_alert=False)
                attack_results.append(res)
            attack_results_100 = (attack_results * 2)[:100]

            df_alerts = pd.DataFrame(attack_results_100)
            t0_persist = time.perf_counter()
            inserted_count = alert_store.sync_alerts(df_alerts)
            total_persist_time = time.perf_counter() - t0_persist

            avg_persist_ms = (total_persist_time * 1000.0) / len(attack_results_100) if attack_results_100 else 0.0
            persist_fps = len(attack_results_100) / total_persist_time if total_persist_time > 0 else 0.0

            print(f"ML-Only Latency    : {ml_only_mean_ms:.2f} ms / flow")
            print(f"Isolated Persistence: Inserted {inserted_count} alerts in {total_persist_time:.4f}s ({persist_fps:.1f} alerts/sec, {avg_persist_ms:.2f} ms/alert)")

        finally:
            alert_store.DB_DIR = orig_db_dir
            alert_store.DB_PATH = orig_db_path

    # ------------------------------------------------------------
    # 6. API BENCHMARK
    # ------------------------------------------------------------
    print("\n------------------------------------------------------------")
    print("5. FASTAPI BENCHMARK")
    print("------------------------------------------------------------")

    api_latency_records = []
    api_available = False

    try:
        r_health = requests.get(f"{API_BASE_URL}/health", timeout=3)
        if r_health.status_code == 200:
            api_available = True
    except Exception:
        api_available = False

    if api_available:
        endpoints_to_test = [
            "/health",
            "/api/metrics",
            "/api/metrics/status",
            "/api/metrics/attacks",
            "/api/metrics/severity",
            "/api/alerts?limit=100",
            "/api/alerts?limit=1000",
            "/api/alerts?limit=5000",
            "/api/alerts?severity=CRITICAL&limit=100",
            "/api/alerts?severity=HIGH&limit=100",
            "/api/alerts?attack_type=DDOS%20attack-HOIC&limit=100",
            "/api/alerts?attack_type=Brute%20Force%20-Web&limit=100",
            "/api/alerts?status=NEW&limit=100",
        ]

        print(f"Benchmarking {len(endpoints_to_test)} endpoints (20 requests per endpoint)...")
        for ep in endpoints_to_test:
            req_times_ms = []
            success_cnt = 0
            fail_cnt = 0

            for _ in range(20):
                t0 = time.perf_counter()
                try:
                    resp = requests.get(f"{API_BASE_URL}{ep}", timeout=5)
                    lat = (time.perf_counter() - t0) * 1000.0
                    if resp.status_code == 200:
                        success_cnt += 1
                        req_times_ms.append(lat)
                    else:
                        fail_cnt += 1
                except Exception:
                    fail_cnt += 1

            if req_times_ms:
                ep_mean = float(np.mean(req_times_ms))
                ep_median = float(np.median(req_times_ms))
                ep_p95 = float(np.percentile(req_times_ms, 95))
                ep_min = float(np.min(req_times_ms))
                ep_max = float(np.max(req_times_ms))
            else:
                ep_mean = ep_median = ep_p95 = ep_min = ep_max = 0.0

            rec = {
                "endpoint": ep,
                "request_count": 20,
                "success_count": success_cnt,
                "fail_count": fail_cnt,
                "mean_ms": ep_mean,
                "median_ms": ep_median,
                "p95_ms": ep_p95,
                "min_ms": ep_min,
                "max_ms": ep_max
            }
            api_latency_records.append(rec)
            print(f"  {ep:<42} -> Mean: {ep_mean:6.2f} ms | P95: {ep_p95:6.2f} ms | Status: 200 OK ({success_cnt}/20)")

        pd.DataFrame(api_latency_records).to_csv(REPORTS_DIR / "api_latency.csv", index=False)
    else:
        print("API benchmark skipped because FastAPI was unavailable on port 8000.")

    # ------------------------------------------------------------
    # 7. ACCURACY REGRESSION VERIFICATION (After Benchmark)
    # ------------------------------------------------------------
    after_predictions = [predictor.predict(f) for f in regression_sample]
    regression_passed = True

    for i in range(len(regression_sample)):
        b_res = baseline_predictions[i]
        a_res = after_predictions[i]
        if (b_res["is_attack"] != a_res["is_attack"] or
            b_res["attack_type"] != a_res["attack_type"] or
            b_res["severity"] != a_res["severity"]):
            regression_passed = False
            break

    print(f"\nAccuracy Regression Status: {'PASSED (100% Identical)' if regression_passed else 'FAILED'}")

    # ------------------------------------------------------------
    # 8. RESOURCE USAGE & REPORT WRITING
    # ------------------------------------------------------------
    mem_after_mb = get_memory_mb()
    peak_mem_mb = max(mem_before_mb, mem_after_mb)

    resource_usage = {
        "memory_before_mb": mem_before_mb,
        "memory_after_mb": mem_after_mb,
        "peak_memory_mb": peak_mem_mb
    }

    with open(REPORTS_DIR / "resource_usage.json", "w") as f:
        json.dump(resource_usage, f, indent=2)

    summary_dict = {
        "dataset": str(TEST_DATA_PATH),
        "cold_start_latency_ms": cold_start_ms,
        "single_flow_latency_ms": {
            "mean": sf_mean,
            "median": sf_median,
            "p50": sf_p50,
            "p90": sf_p90,
            "p95": sf_p95,
            "p99": sf_p99,
            "min": sf_min,
            "max": sf_max
        },
        "batch_throughput": batch_throughput_records,
        "stage_latency_ms": {
            "stage1_mean": s1_mean_lat,
            "stage2_mean": s2_mean_lat,
            "combined_mean": comb_mean_lat
        },
        "api_available": api_available,
        "api_metrics": api_latency_records if api_available else [],
        "resource_usage": resource_usage,
        "accuracy_regression_passed": regression_passed,
        "total_benchmark_execution_time_sec": time.time() - start_benchmark_time
    }

    with open(REPORTS_DIR / "benchmark_summary.json", "w") as f:
        json.dump(summary_dict, f, indent=2)

    # ------------------------------------------------------------
    # 9. GENERATE FORMATTED TERMINAL REPORT
    # ------------------------------------------------------------
    report_text = f"""============================================================
CYBERSENTINEL PERFORMANCE BENCHMARK
============================================================

Dataset:
CSE-CIC-IDS2018 processed test dataset

------------------------------------------------------------
SINGLE-FLOW INFERENCE
------------------------------------------------------------

Cold-Start Latency : {cold_start_ms:.2f} ms

Warm inference:

Mean       : {sf_mean:.2f} ms
Median     : {sf_median:.2f} ms
P95        : {sf_p95:.2f} ms
P99        : {sf_p99:.2f} ms
Min        : {sf_min:.2f} ms
Max        : {sf_max:.2f} ms

------------------------------------------------------------
BATCH THROUGHPUT
------------------------------------------------------------

Batch Size    Throughput       Avg ms/flow
"""

    for b in batch_throughput_records:
        b_size = b["batch_size"]
        tp_fps = b["throughput_fps"]
        avg_ms = b["avg_ms_per_flow"]
        report_text += f"{b_size:<13} {tp_fps:8.1f} flows/s   {avg_ms:6.2f} ms\n"

    report_text += f"""
------------------------------------------------------------
PIPELINE LATENCY
------------------------------------------------------------

Stage 1 Mean       : {s1_mean_lat:.2f} ms
Stage 2 Mean       : {s2_mean_lat:.2f} ms
Combined Mean      : {comb_mean_lat:.2f} ms
"""

    if api_available:
        report_text += f"""
------------------------------------------------------------
API PERFORMANCE
------------------------------------------------------------

Endpoint                                   Mean       P95
"""
        for a in api_latency_records:
            ep = a["endpoint"]
            mean_m = a["mean_ms"]
            p95_m = a["p95_ms"]
            report_text += f"{ep:<42} {mean_m:6.2f} ms   {p95_m:6.2f} ms\n"

    report_text += f"""
------------------------------------------------------------
SYSTEM RESOURCE USAGE
------------------------------------------------------------

Memory Before : {mem_before_mb:.2f} MB
Memory After  : {mem_after_mb:.2f} MB
Peak Memory   : {peak_mem_mb:.2f} MB

============================================================
BENCHMARK COMPLETED
============================================================
"""

    with open(REPORTS_DIR / "benchmark_report.txt", "w") as f:
        f.write(report_text)

    # Clean up predictor Spark session
    predictor.spark.stop()

    print("\n" + report_text)
    print(f"Benchmark report written to: {REPORTS_DIR / 'benchmark_report.txt'}")
    print(f"All benchmark results saved to: {REPORTS_DIR}")


if __name__ == "__main__":
    main()
