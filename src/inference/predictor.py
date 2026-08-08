from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.feature import VectorAssembler
from pyspark.sql import Row, SparkSession
from pyspark.sql.functions import col


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODELS_DIR = (
    PROJECT_ROOT
    / "models"
)

STAGE1_MODEL_PATH = (
    MODELS_DIR
    / "stage1_random_forest"
)

STAGE2_MODEL_PATH = (
    MODELS_DIR
    / "stage2_attack_classifier_no_temporal"
)


# ============================================================
# FEATURE CONFIGURATION
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
    "Fwd_Byts_per_b_Avg",
    "Fwd_Pkts_per_b_Avg",
    "Fwd_Blk_Rate_Avg",
    "Bwd_Seg_Size_Avg",
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
# STAGE-1 FEATURES
# ============================================================

# Stage 1 was trained with temporal features.
STAGE1_FEATURE_COLUMNS = (
    FEATURE_COLUMNS
    + [
        "Hour",
        "DayOfWeek",
        "IsWeekend",
    ]
)


# ============================================================
# ATTACK LABELS
# ============================================================

ATTACK_LABELS = {
    0: "DDOS attack-HOIC",
    1: "DDoS attacks-LOIC-HTTP",
    2: "DoS attacks-Hulk",
    3: "Bot",
    4: "FTP-BruteForce",
    5: "SSH-Bruteforce",
    6: "Infilteration",
    7: "DoS attacks-SlowHTTPTest",
    8: "DoS attacks-GoldenEye",
    9: "DoS attacks-Slowloris",
    10: "DDOS attack-LOIC-UDP",
    11: "Brute Force -Web",
    12: "Brute Force -XSS",
    13: "SQL Injection",
}


# ============================================================
# SEVERITY
# ============================================================

def calculate_severity(
    attack_type: str,
    confidence: float,
) -> str:
    """
    Calculate SOC severity from attack type
    and model confidence.
    """

    confidence = float(
        confidence
    )

    # --------------------------------------------------------
    # Critical attacks
    # --------------------------------------------------------

    critical_attacks = {
        "DDOS attack-HOIC",
        "DDoS attacks-LOIC-HTTP",
        "DoS attacks-Hulk",
        "DDOS attack-LOIC-UDP",
    }

    if attack_type in critical_attacks:

        if confidence >= 0.90:
            return "CRITICAL"

        if confidence >= 0.70:
            return "HIGH"

        return "MEDIUM"

    # --------------------------------------------------------
    # High-risk attacks
    # --------------------------------------------------------

    high_attacks = {
        "Bot",
        "FTP-BruteForce",
        "SSH-Bruteforce",
        "Infilteration",
        "DoS attacks-SlowHTTPTest",
        "DoS attacks-GoldenEye",
        "DoS attacks-Slowloris",
    }

    if attack_type in high_attacks:

        if confidence >= 0.90:
            return "CRITICAL"

        if confidence >= 0.70:
            return "HIGH"

        return "MEDIUM"

    # --------------------------------------------------------
    # Brute force / web attacks
    # --------------------------------------------------------

    if attack_type in {
        "Brute Force -Web",
        "Brute Force -XSS",
        "SQL Injection",
    }:

        if confidence >= 0.90:
            return "HIGH"

        if confidence >= 0.70:
            return "MEDIUM"

        return "LOW"

    # --------------------------------------------------------
    # Unknown attack
    # --------------------------------------------------------

    if confidence >= 0.90:
        return "HIGH"

    if confidence >= 0.70:
        return "MEDIUM"

    return "LOW"


# ============================================================
# SPARK
# ============================================================

def create_spark() -> SparkSession:
    """
    Create the Spark session used by CyberSentinel.
    """

    spark = (
        SparkSession.builder
        .appName(
            "CyberSentinelInference"
        )
        .master("local[*]")
        .config(
            "spark.sql.shuffle.partitions",
            "8",
        )
        .config(
            "spark.driver.memory",
            "8g",
        )
        .config(
            "spark.sql.debug.maxToStringFields",
            "200",
        )
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel(
        "WARN"
    )

    return spark


# ============================================================
# PREDICTOR
# ============================================================

class CyberSentinelPredictor:

    def __init__(
        self,
        spark: Optional[SparkSession] = None,
    ):

        self.spark = (
            spark
            if spark is not None
            else create_spark()
        )

        # ----------------------------------------------------
        # Stage 1
        # ----------------------------------------------------

        print(
            "Loading Stage-1 Random Forest model..."
        )

        self.stage1_model = (
            RandomForestClassificationModel
            .load(
                str(
                    STAGE1_MODEL_PATH
                )
            )
        )

        print(
            "Stage-1 model loaded."
        )

        # ----------------------------------------------------
        # Stage 1 VectorAssembler
        # ----------------------------------------------------

        self.stage1_assembler = (
            VectorAssembler(
                inputCols=(
                    STAGE1_FEATURE_COLUMNS
                ),
                outputCol="features",
                handleInvalid="keep",
            )
        )

        # ----------------------------------------------------
        # Stage 2
        # ----------------------------------------------------

        print(
            "Loading no-temporal Stage-2 model..."
        )

        self.stage2_model = (
            PipelineModel
            .load(
                str(
                    STAGE2_MODEL_PATH
                )
            )
        )

        print(
            "Stage-2 model loaded."
        )

    # ========================================================
    # NORMALIZE VALUE
    # ========================================================

    @staticmethod
    def _numeric(
        value: Any,
    ) -> float:

        if value is None:
            return 0.0

        try:
            return float(
                value
            )

        except (
            ValueError,
            TypeError,
        ):
            return 0.0

    # ========================================================
    # PARSE TEMPORAL FEATURES
    # ========================================================

    @staticmethod
    def _temporal_features(
        flow: Dict[str, Any],
    ):
        """
        Derive Hour, DayOfWeek and IsWeekend.

        Stage 1 uses these temporal features.
        Stage 2 does not.
        """

        hour = flow.get(
            "Hour"
        )

        day_of_week = flow.get(
            "DayOfWeek"
        )

        is_weekend = flow.get(
            "IsWeekend"
        )

        timestamp = flow.get(
            "Timestamp"
        )

        if timestamp and (
            hour is None
            or day_of_week is None
            or is_weekend is None
        ):

            parsed = None

            formats = [
                "%d/%m/%Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
            ]

            for fmt in formats:

                try:

                    parsed = (
                        datetime.strptime(
                            str(timestamp),
                            fmt,
                        )
                    )

                    break

                except ValueError:
                    continue

            if parsed is not None:

                if hour is None:
                    hour = parsed.hour

                if day_of_week is None:
                    day_of_week = (
                        parsed.weekday()
                    )

                if is_weekend is None:
                    is_weekend = (
                        1
                        if parsed.weekday() >= 5
                        else 0
                    )

        if hour is None:
            hour = 0

        if day_of_week is None:
            day_of_week = 0

        if is_weekend is None:
            is_weekend = 0

        return (
            hour,
            day_of_week,
            is_weekend,
        )

    # ========================================================
    # BUILD DATAFRAME
    # ========================================================

    def _build_dataframe(
        self,
        flow: Dict[str, Any],
    ):

        values = {}

        # ----------------------------------------------------
        # Network features
        # ----------------------------------------------------

        for feature in FEATURE_COLUMNS:

            values[feature] = (
                self._numeric(
                    flow.get(
                        feature,
                        0.0,
                    )
                )
            )

        # ----------------------------------------------------
        # Temporal features
        # ----------------------------------------------------

        (
            hour,
            day_of_week,
            is_weekend,
        ) = self._temporal_features(
            flow
        )

        values["Hour"] = (
            self._numeric(
                hour
            )
        )

        values["DayOfWeek"] = (
            self._numeric(
                day_of_week
            )
        )

        values["IsWeekend"] = (
            self._numeric(
                is_weekend
            )
        )

        return self.spark.createDataFrame(
            [
                Row(**values)
            ]
        )

    # ========================================================
    # BUILD BATCH DATAFRAME
    # ========================================================

    def _build_batch_dataframe(
        self,
        flows: List[Dict[str, Any]],
    ):
        """
        Build ONE Spark DataFrame from multiple flows.

        An internal _flow_index column preserves
        the original input order.
        """

        rows = []

        for index, flow in enumerate(
            flows
        ):

            values = {}

            # ------------------------------------------------
            # Network features
            # ------------------------------------------------

            for feature in FEATURE_COLUMNS:

                values[feature] = (
                    self._numeric(
                        flow.get(
                            feature,
                            0.0,
                        )
                    )
                )

            # ------------------------------------------------
            # Temporal features
            # ------------------------------------------------

            (
                hour,
                day_of_week,
                is_weekend,
            ) = self._temporal_features(
                flow
            )

            values["Hour"] = (
                self._numeric(
                    hour
                )
            )

            values["DayOfWeek"] = (
                self._numeric(
                    day_of_week
                )
            )

            values["IsWeekend"] = (
                self._numeric(
                    is_weekend
                )
            )

            # ------------------------------------------------
            # Internal row identifier
            # ------------------------------------------------

            values["_flow_index"] = (
                index
            )

            rows.append(
                Row(**values)
            )

        return self.spark.createDataFrame(
            rows
        )

    # ========================================================
    # PREDICT SINGLE FLOW
    # ========================================================

    def predict(
        self,
        flow: Dict[str, Any],
    ) -> Dict[str, Any]:

        df = self._build_dataframe(
            flow
        )

        # ====================================================
        # STAGE 1
        # ====================================================

        stage1_features = (
            self.stage1_assembler
            .transform(df)
        )

        stage1_result = (
            self.stage1_model
            .transform(
                stage1_features
            )
            .select(
                "prediction",
                "probability",
            )
            .first()
        )

        stage1_prediction = int(
            stage1_result[
                "prediction"
            ]
        )

        stage1_probability = (
            stage1_result[
                "probability"
            ]
        )

        # ----------------------------------------------------
        # BENIGN
        # ----------------------------------------------------

        if stage1_prediction == 0:

            confidence = float(
                stage1_probability[0]
            )

            return {
                "is_attack": False,
                "attack_type": "Benign",
                "severity": "NONE",
                "confidence": confidence,
                "stage1_confidence": confidence,
                "stage2_confidence": 0.0,
            }

        # ====================================================
        # STAGE 2
        # ====================================================

        stage2_result = (
            self.stage2_model
            .transform(df)
            .select(
                "prediction",
                "probability",
            )
            .first()
        )

        stage2_prediction = int(
            stage2_result[
                "prediction"
            ]
        )

        stage2_probability = (
            stage2_result[
                "probability"
            ]
        )

        attack_type = (
            ATTACK_LABELS.get(
                stage2_prediction,
                "Unknown",
            )
        )

        stage1_attack_confidence = (
            float(
                stage1_probability[1]
            )
        )

        stage2_confidence = (
            float(
                stage2_probability[
                    stage2_prediction
                ]
            )
        )

        # ----------------------------------------------------
        # Combined confidence
        # ----------------------------------------------------

        confidence = (
            stage1_attack_confidence
            * stage2_confidence
        )

        severity = (
            calculate_severity(
                attack_type,
                confidence,
            )
        )

        return {
            "is_attack": True,
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence,
            "stage1_confidence": (
                stage1_attack_confidence
            ),
            "stage2_confidence": (
                stage2_confidence
            ),
        }

    # ========================================================
    # PREDICT BATCH
    # ========================================================

    def predict_batch(
        self,
        flows: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Run two-stage inference on multiple flows
        using a shared Spark DataFrame.

        This avoids creating a separate Spark
        DataFrame for every individual flow.

        Input order is preserved.
        """

        if not flows:
            return []

        # ----------------------------------------------------
        # Build ONE DataFrame
        # ----------------------------------------------------

        df = (
            self._build_batch_dataframe(
                flows
            )
        )

        # ====================================================
        # STAGE 1
        # ====================================================

        stage1_features = (
            self.stage1_assembler
            .transform(df)
        )

        stage1_predictions = (
            self.stage1_model
            .transform(
                stage1_features
            )
            .select(
                "_flow_index",
                "prediction",
                "probability",
            )
        )

        stage1_rows = (
            stage1_predictions
            .collect()
        )

        stage1_results = {}

        attack_indices = []

        for row in stage1_rows:

            index = int(
                row["_flow_index"]
            )

            prediction = int(
                row["prediction"]
            )

            probability = (
                row["probability"]
            )

            stage1_results[index] = {
                "prediction": prediction,
                "probability": probability,
            }

            if prediction == 1:

                attack_indices.append(
                    index
                )

        # ====================================================
        # INITIALIZE RESULTS
        # ====================================================

        results = {}

        # ----------------------------------------------------
        # Benign flows
        # ----------------------------------------------------

        for index in range(
            len(flows)
        ):

            stage1 = (
                stage1_results[index]
            )

            if (
                stage1["prediction"]
                == 0
            ):

                probability = (
                    stage1[
                        "probability"
                    ]
                )

                confidence = float(
                    probability[0]
                )

                results[index] = {
                    "is_attack": False,
                    "attack_type": "Benign",
                    "severity": "NONE",
                    "confidence": confidence,
                    "stage1_confidence": confidence,
                    "stage2_confidence": 0.0,
                }

        # ====================================================
        # STAGE 2
        # ====================================================

        if attack_indices:

            attack_df = (
                df.filter(
                    col(
                        "_flow_index"
                    ).isin(
                        attack_indices
                    )
                )
            )

            stage2_results = (
                self.stage2_model
                .transform(
                    attack_df
                )
                .select(
                    "_flow_index",
                    "prediction",
                    "probability",
                )
                .collect()
            )

            for row in stage2_results:

                index = int(
                    row["_flow_index"]
                )

                stage1 = (
                    stage1_results[
                        index
                    ]
                )

                stage1_probability = (
                    stage1[
                        "probability"
                    ]
                )

                stage2_prediction = int(
                    row[
                        "prediction"
                    ]
                )

                stage2_probability = (
                    row[
                        "probability"
                    ]
                )

                attack_type = (
                    ATTACK_LABELS.get(
                        stage2_prediction,
                        "Unknown",
                    )
                )

                stage1_attack_confidence = (
                    float(
                        stage1_probability[
                            1
                        ]
                    )
                )

                stage2_confidence = (
                    float(
                        stage2_probability[
                            stage2_prediction
                        ]
                    )
                )

                confidence = (
                    stage1_attack_confidence
                    * stage2_confidence
                )

                severity = (
                    calculate_severity(
                        attack_type,
                        confidence,
                    )
                )

                results[index] = {
                    "is_attack": True,
                    "attack_type": attack_type,
                    "severity": severity,
                    "confidence": confidence,
                    "stage1_confidence": (
                        stage1_attack_confidence
                    ),
                    "stage2_confidence": (
                        stage2_confidence
                    ),
                }

        # ====================================================
        # RESTORE ORIGINAL ORDER
        # ====================================================

        return [
            results[index]
            for index in range(
                len(flows)
            )
        ]

    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):

        if self.spark:

            self.spark.stop()


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 80)
    print(
        "CYBERSENTINEL INFERENCE ENGINE TEST"
    )
    print("=" * 80)

    predictor = (
        CyberSentinelPredictor()
    )

    # --------------------------------------------------------
    # Real flow used previously
    # --------------------------------------------------------

    test_flow = {
        "Dst_Port": 22,
        "Protocol": 6,
        "Timestamp": "20/02/2018 08:34:07",
        "Flow_Duration": 888751,

        "Tot_Fwd_Pkts": 11,
        "Tot_Bwd_Pkts": 11,

        "TotLen_Fwd_Pkts": 1249,
        "TotLen_Bwd_Pkts": 1969,

        "Fwd_Pkt_Len_Max": 736,
        "Fwd_Pkt_Len_Min": 0,
        "Fwd_Pkt_Len_Mean": 113.5454545,
        "Fwd_Pkt_Len_Std": 220.8960677,

        "Bwd_Pkt_Len_Max": 976,
        "Bwd_Pkt_Len_Min": 0,
        "Bwd_Pkt_Len_Mean": 179,
        "Bwd_Pkt_Len_Std": 364.1864907,

        "Flow_Byts_per_s": 3620.811678,
        "Flow_Pkts_per_s": 24.75383994,

        "Flow_IAT_Mean": 42321.47619,
        "Flow_IAT_Std": 47851.73578,
        "Flow_IAT_Max": 101609,
        "Flow_IAT_Min": 14,

        "Fwd_IAT_Tot": 888751,
        "Fwd_IAT_Mean": 88875.1,
        "Fwd_IAT_Std": 49295.73551,
        "Fwd_IAT_Max": 140273,
        "Fwd_IAT_Min": 14,

        "Bwd_IAT_Tot": 788197,
        "Bwd_IAT_Mean": 78819.7,
        "Bwd_IAT_Std": 55863.18804,
        "Bwd_IAT_Max": 139285,
        "Bwd_IAT_Min": 72,

        "Fwd_PSH_Flags": 0,
        "Bwd_PSH_Flags": 0,
        "Fwd_URG_Flags": 0,
        "Bwd_URG_Flags": 0,

        "Fwd_Header_Len": 360,
        "Bwd_Header_Len": 360,

        "Fwd_Pkts_per_s": 12.37691997,
        "Bwd_Pkts_per_s": 12.37691997,

        "Pkt_Len_Min": 0,
        "Pkt_Len_Max": 976,
        "Pkt_Len_Mean": 139.9130435,
        "Pkt_Len_Std": 290.633933,
        "Pkt_Len_Var": 84468.083,

        "FIN_Flag_Cnt": 0,
        "SYN_Flag_Cnt": 0,
        "RST_Flag_Cnt": 0,
        "PSH_Flag_Cnt": 1,
        "ACK_Flag_Cnt": 0,
        "URG_Flag_Cnt": 0,

        "CWE_Flag_Count": 0,
        "ECE_Flag_Cnt": 0,

        "Down_per_Up_Ratio": 1,
        "Pkt_Size_Avg": 146.2727273,

        "Fwd_Seg_Size_Avg": 113.5454545,
        "Bwd_Seg_Size_Avg": 179,

        "Fwd_Byts_per_b_Avg": 0,
        "Fwd_Pkts_per_b_Avg": 0,
        "Fwd_Blk_Rate_Avg": 0,

        "Bwd_Byts_per_b_Avg": 0,
        "Bwd_Pkts_per_b_Avg": 0,
        "Bwd_Blk_Rate_Avg": 0,

        "Subflow_Fwd_Pkts": 11,
        "Subflow_Fwd_Byts": 1249,
        "Subflow_Bwd_Pkts": 11,
        "Subflow_Bwd_Byts": 1969,

        "Init_Fwd_Win_Byts": 14600,
        "Init_Bwd_Win_Byts": 233,

        "Fwd_Act_Data_Pkts": 7,
        "Fwd_Seg_Size_Min": 32,

        "Active_Mean": 0,
        "Active_Std": 0,
        "Active_Max": 0,
        "Active_Min": 0,

        "Idle_Mean": 0,
        "Idle_Std": 0,
        "Idle_Max": 0,
        "Idle_Min": 0,
    }

    # ========================================================
    # SINGLE-FLOW TEST
    # ========================================================

    result = (
        predictor.predict(
            test_flow
        )
    )

    print()
    print("=" * 80)
    print(
        "SINGLE-FLOW PREDICTION"
    )
    print("=" * 80)

    for key, value in (
        result.items()
    ):

        print(
            f"{key:<25}: {value}"
        )

    # ========================================================
    # BATCH TEST
    # ========================================================

    print()
    print("=" * 80)
    print(
        "BATCH INFERENCE TEST"
    )
    print("=" * 80)

    batch_flows = [
        test_flow,
        test_flow,
        test_flow,
    ]

    batch_results = (
        predictor.predict_batch(
            batch_flows
        )
    )

    for index, batch_result in enumerate(
        batch_results,
        start=1,
    ):

        print()
        print(
            f"FLOW {index}"
        )

        for key, value in (
            batch_result.items()
        ):

            print(
                f"{key:<25}: {value}"
            )

    print()
    print("=" * 80)
    print(
        f"Batch flows processed: "
        f"{len(batch_results)}"
    )
    print("=" * 80)

    predictor.close()
