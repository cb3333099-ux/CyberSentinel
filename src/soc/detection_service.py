from datetime import datetime
from typing import Any, Dict, Optional

import pandas as pd

from src.inference.predictor import CyberSentinelPredictor
from src.soc.alert_store import sync_alerts


class DetectionService:

    def __init__(
        self,
        predictor: Optional[CyberSentinelPredictor] = None,
    ):
        self.predictor = (
            predictor
            if predictor is not None
            else CyberSentinelPredictor()
        )

    def analyze_flow(
        self,
        flow: Dict[str, Any],
        persist_alert: bool = True,
    ) -> Dict[str, Any]:

        prediction = self.predictor.predict(flow)

        result = {
            "Timestamp": flow.get(
                "Timestamp",
                datetime.now().isoformat(),
            ),

            "Dst_Port": flow.get(
                "Dst_Port"
            ),

            "Protocol": flow.get(
                "Protocol"
            ),

            "attack_type": prediction[
                "attack_type"
            ],

            "severity": prediction[
                "severity"
            ],

            "attack_probability": prediction[
                "confidence"
            ],

            "confidence": prediction[
                "confidence"
            ],

            "is_attack": prediction[
                "is_attack"
            ],

            "stage1_confidence": prediction[
                "stage1_confidence"
            ],

            "stage2_confidence": prediction[
                "stage2_confidence"
            ],
        }

        # ----------------------------------------------------
        # Persist only actual attacks
        # ----------------------------------------------------

        if (
            persist_alert
            and prediction["is_attack"]
        ):

            alert_dataframe = pd.DataFrame(
                [result]
            )

            inserted = sync_alerts(
                alert_dataframe
            )

            result[
                "alert_persisted"
            ] = inserted > 0

            result[
                "alert_inserted_count"
            ] = inserted

        else:

            result[
                "alert_persisted"
            ] = False

            result[
                "alert_inserted_count"
            ] = 0

        return result

    def close(self):

        if self.predictor.spark:
            self.predictor.spark.stop()


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 80)
    print("CYBERSENTINEL DETECTION SERVICE TEST")
    print("=" * 80)

    service = DetectionService()

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

    result = service.analyze_flow(
        test_flow
    )

    print()
    print("Detection result:")

    for key, value in result.items():
        print(
            f"{key:<25}: {value}"
        )

    service.close()

    print()
    print("=" * 80)
    print("DETECTION SERVICE TEST COMPLETED")
    print("=" * 80)
