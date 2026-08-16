import math
import numpy as np
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from src.network.pcap_reader import PacketMetadata
from src.inference.predictor import STAGE1_FEATURE_COLUMNS, FEATURE_COLUMNS


def _stats(arr: List[float]) -> Tuple[float, float, float, float, float]:
    """
    Calculate min, max, mean, std, sum for a list of floats.
    """
    if not arr:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    arr_np = np.array(arr, dtype=np.float64)
    min_v = float(np.min(arr_np))
    max_v = float(np.max(arr_np))
    mean_v = float(np.mean(arr_np))
    std_v = float(np.std(arr_np)) if len(arr) > 1 else 0.0
    sum_v = float(np.sum(arr_np))
    return min_v, max_v, mean_v, std_v, sum_v


class FlowState:
    """
    State accumulator for an active bidirectional network flow.
    """

    def __init__(self, pkt: PacketMetadata):
        self.src_ip = pkt.src_ip
        self.dst_ip = pkt.dst_ip
        self.src_port = pkt.src_port
        self.dst_port = pkt.dst_port
        self.protocol = pkt.protocol

        self.start_time = pkt.timestamp
        self.last_time = pkt.timestamp

        self.fwd_last_time: Optional[float] = pkt.timestamp
        self.bwd_last_time: Optional[float] = None

        self.fwd_pkt_count: int = 0
        self.bwd_pkt_count: int = 0

        self.fwd_byte_count: int = 0
        self.bwd_byte_count: int = 0

        self.fwd_pkt_lens: List[float] = []
        self.bwd_pkt_lens: List[float] = []
        self.all_pkt_lens: List[float] = []

        self.fwd_iats: List[float] = []  # in microseconds
        self.bwd_iats: List[float] = []  # in microseconds
        self.all_iats: List[float] = []  # in microseconds

        self.fwd_psh_flags: int = 0
        self.bwd_psh_flags: int = 0
        self.fwd_urg_flags: int = 0
        self.bwd_urg_flags: int = 0

        self.fwd_header_len: int = 0
        self.bwd_header_len: int = 0

        self.fin_cnt: int = 0
        self.syn_cnt: int = 0
        self.rst_cnt: int = 0
        self.psh_cnt: int = 0
        self.ack_cnt: int = 0
        self.urg_cnt: int = 0
        self.cwe_cnt: int = 0
        self.ece_cnt: int = 0

        self.init_fwd_win_bytes: int = 0
        self.init_bwd_win_bytes: int = 0

        self.fwd_act_data_pkts: int = 0
        self.fwd_seg_size_min: int = 0

        self.active_times: List[float] = []
        self.idle_times: List[float] = []
        self._current_active_start: float = pkt.timestamp
        self._last_active_end: float = pkt.timestamp

        self.add_packet(pkt)

    def is_forward(self, pkt: PacketMetadata) -> bool:
        return (pkt.src_ip == self.src_ip) and (pkt.src_port == self.src_port)

    def add_packet(self, pkt: PacketMetadata) -> None:
        is_fwd = self.is_forward(pkt)

        # Flow duration / IAT calculation
        if self.last_time > 0:
            iat_us = (pkt.timestamp - self.last_time) * 1e6
            if iat_us >= 0:
                self.all_iats.append(iat_us)

                # Active / Idle tracking (pauses > 1s indicate idle)
                if iat_us > 1000000.0:  # 1 second
                    self.idle_times.append(iat_us)
                    active_dur = (self.last_time - self._current_active_start) * 1e6
                    if active_dur > 0:
                        self.active_times.append(active_dur)
                    self._current_active_start = pkt.timestamp

        self.last_time = pkt.timestamp

        # Direction-specific updates
        pkt_len = float(pkt.pkt_len)
        self.all_pkt_lens.append(pkt_len)

        flags = pkt.tcp_flags
        if flags.get("FIN"): self.fin_cnt += 1
        if flags.get("SYN"): self.syn_cnt += 1
        if flags.get("RST"): self.rst_cnt += 1
        if flags.get("PSH"): self.psh_cnt += 1
        if flags.get("ACK"): self.ack_cnt += 1
        if flags.get("URG"): self.urg_cnt += 1
        if flags.get("CWE"): self.cwe_cnt += 1
        if flags.get("ECE"): self.ece_cnt += 1

        if is_fwd:
            self.fwd_pkt_count += 1
            self.fwd_byte_count += pkt.pkt_len
            self.fwd_pkt_lens.append(pkt_len)
            self.fwd_header_len += pkt.header_len

            if flags.get("PSH"): self.fwd_psh_flags += 1
            if flags.get("URG"): self.fwd_urg_flags += 1

            if self.fwd_pkt_count == 1:
                self.init_fwd_win_bytes = pkt.win_bytes
                self.fwd_seg_size_min = pkt.header_len

            if pkt.payload_len > 0:
                self.fwd_act_data_pkts += 1

            if self.fwd_last_time is not None:
                fwd_iat = (pkt.timestamp - self.fwd_last_time) * 1e6
                if fwd_iat >= 0:
                    self.fwd_iats.append(fwd_iat)
            self.fwd_last_time = pkt.timestamp

        else:
            self.bwd_pkt_count += 1
            self.bwd_byte_count += pkt.pkt_len
            self.bwd_pkt_lens.append(pkt_len)
            self.bwd_header_len += pkt.header_len

            if flags.get("PSH"): self.bwd_psh_flags += 1
            if flags.get("URG"): self.bwd_urg_flags += 1

            if self.bwd_pkt_count == 1:
                self.init_bwd_win_bytes = pkt.win_bytes

            if self.bwd_last_time is not None:
                bwd_iat = (pkt.timestamp - self.bwd_last_time) * 1e6
                if bwd_iat >= 0:
                    self.bwd_iats.append(bwd_iat)
            self.bwd_last_time = pkt.timestamp

    def to_flow_dict(self) -> Dict[str, Any]:
        """
        Convert FlowState into a 78 CICFlowMeter feature dictionary + temporal features.
        """
        duration_sec = max(0.0, self.last_time - self.start_time)
        duration_us = duration_sec * 1e6

        # Flow stats
        fwd_min, fwd_max, fwd_mean, fwd_std, fwd_sum = _stats(self.fwd_pkt_lens)
        bwd_min, bwd_max, bwd_mean, bwd_std, bwd_sum = _stats(self.bwd_pkt_lens)
        pkt_min, pkt_max, pkt_mean, pkt_std, pkt_sum = _stats(self.all_pkt_lens)

        flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std, _ = _stats(self.all_iats)
        fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std, fwd_iat_sum = _stats(self.fwd_iats)
        bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std, bwd_iat_sum = _stats(self.bwd_iats)

        active_min, active_max, active_mean, active_std, _ = _stats(self.active_times)
        idle_min, idle_max, idle_mean, idle_std, _ = _stats(self.idle_times)

        total_bytes = self.fwd_byte_count + self.bwd_byte_count
        total_pkts = self.fwd_pkt_count + self.bwd_pkt_count

        flow_byts_s = (total_bytes / duration_sec) if duration_sec > 0 else 0.0
        flow_pkts_s = (total_pkts / duration_sec) if duration_sec > 0 else 0.0
        fwd_pkts_s = (self.fwd_pkt_count / duration_sec) if duration_sec > 0 else 0.0
        bwd_pkts_s = (self.bwd_pkt_count / duration_sec) if duration_sec > 0 else 0.0

        down_up_ratio = (self.bwd_pkt_count / self.fwd_pkt_count) if self.fwd_pkt_count > 0 else 0.0
        pkt_len_var = pkt_std ** 2

        # Temporal features
        dt = datetime.fromtimestamp(self.start_time)
        hour_val = float(dt.hour)
        day_of_week_val = float(dt.isoweekday() % 7 + 1)
        is_weekend_val = 1.0 if dt.isoweekday() in [6, 7] else 0.0

        flow_dict = {
            "Dst_Port": float(self.dst_port),
            "Protocol": float(self.protocol),
            "Flow_Duration": float(duration_us),
            "Tot_Fwd_Pkts": float(self.fwd_pkt_count),
            "Tot_Bwd_Pkts": float(self.bwd_pkt_count),
            "TotLen_Fwd_Pkts": float(self.fwd_byte_count),
            "TotLen_Bwd_Pkts": float(self.bwd_byte_count),
            "Fwd_Pkt_Len_Max": float(fwd_max),
            "Fwd_Pkt_Len_Min": float(fwd_min),
            "Fwd_Pkt_Len_Mean": float(fwd_mean),
            "Fwd_Pkt_Len_Std": float(fwd_std),
            "Bwd_Pkt_Len_Max": float(bwd_max),
            "Bwd_Pkt_Len_Min": float(bwd_min),
            "Bwd_Pkt_Len_Mean": float(bwd_mean),
            "Bwd_Pkt_Len_Std": float(bwd_std),
            "Flow_Byts_per_s": float(flow_byts_s),
            "Flow_Pkts_per_s": float(flow_pkts_s),
            "Flow_IAT_Mean": float(flow_iat_mean),
            "Flow_IAT_Std": float(flow_iat_std),
            "Flow_IAT_Max": float(flow_iat_max),
            "Flow_IAT_Min": float(flow_iat_min),
            "Fwd_IAT_Tot": float(fwd_iat_sum),
            "Fwd_IAT_Mean": float(fwd_iat_mean),
            "Fwd_IAT_Std": float(fwd_iat_std),
            "Fwd_IAT_Max": float(fwd_iat_max),
            "Fwd_IAT_Min": float(fwd_iat_min),
            "Bwd_IAT_Tot": float(bwd_iat_sum),
            "Bwd_IAT_Mean": float(bwd_iat_mean),
            "Bwd_IAT_Std": float(bwd_iat_std),
            "Bwd_IAT_Max": float(bwd_iat_max),
            "Bwd_IAT_Min": float(bwd_iat_min),
            "Fwd_PSH_Flags": float(self.fwd_psh_flags),
            "Bwd_PSH_Flags": float(self.bwd_psh_flags),
            "Fwd_URG_Flags": float(self.fwd_urg_flags),
            "Bwd_URG_Flags": float(self.bwd_urg_flags),
            "Fwd_Header_Len": float(self.fwd_header_len),
            "Bwd_Header_Len": float(self.bwd_header_len),
            "Fwd_Pkts_per_s": float(fwd_pkts_s),
            "Bwd_Pkts_per_s": float(bwd_pkts_s),
            "Pkt_Len_Min": float(pkt_min),
            "Pkt_Len_Max": float(pkt_max),
            "Pkt_Len_Mean": float(pkt_mean),
            "Pkt_Len_Std": float(pkt_std),
            "Pkt_Len_Var": float(pkt_len_var),
            "FIN_Flag_Cnt": float(self.fin_cnt),
            "SYN_Flag_Cnt": float(self.syn_cnt),
            "RST_Flag_Cnt": float(self.rst_cnt),
            "PSH_Flag_Cnt": float(self.psh_cnt),
            "ACK_Flag_Cnt": float(self.ack_cnt),
            "URG_Flag_Cnt": float(self.urg_cnt),
            "CWE_Flag_Count": float(self.cwe_cnt),
            "ECE_Flag_Cnt": float(self.ece_cnt),
            "Down_per_Up_Ratio": float(down_up_ratio),
            "Pkt_Size_Avg": float(pkt_mean),
            "Fwd_Seg_Size_Avg": float(fwd_mean),
            "Fwd_Byts_per_b_Avg": 0.0,
            "Fwd_Pkts_per_b_Avg": 0.0,
            "Fwd_Blk_Rate_Avg": 0.0,
            "Bwd_Seg_Size_Avg": float(bwd_mean),
            "Bwd_Byts_per_b_Avg": 0.0,
            "Bwd_Pkts_per_b_Avg": 0.0,
            "Bwd_Blk_Rate_Avg": 0.0,
            "Subflow_Fwd_Pkts": float(self.fwd_pkt_count),
            "Subflow_Fwd_Byts": float(self.fwd_byte_count),
            "Subflow_Bwd_Pkts": float(self.bwd_pkt_count),
            "Subflow_Bwd_Byts": float(self.bwd_byte_count),
            "Init_Fwd_Win_Byts": float(self.init_fwd_win_bytes),
            "Init_Bwd_Win_Byts": float(self.init_bwd_win_bytes),
            "Fwd_Act_Data_Pkts": float(self.fwd_act_data_pkts),
            "Fwd_Seg_Size_Min": float(self.fwd_seg_size_min),
            "Active_Mean": float(active_mean),
            "Active_Std": float(active_std),
            "Active_Max": float(active_max),
            "Active_Min": float(active_min),
            "Idle_Mean": float(idle_mean),
            "Idle_Std": float(idle_std),
            "Idle_Max": float(idle_max),
            "Idle_Min": float(idle_min),
            # Temporal
            "Hour": hour_val,
            "DayOfWeek": day_of_week_val,
            "IsWeekend": is_weekend_val,
            "Timestamp": dt.isoformat(),
            "Src_IP": self.src_ip,
            "Dst_IP": self.dst_ip,
            "Src_Port": float(self.src_port),
        }

        return flow_dict


class FlowBuilder:
    """
    Aggregates packets into active bidirectional network flows.
    """

    def __init__(self, flow_timeout: float = 10.0):
        self.flow_timeout = max(1.0, float(flow_timeout))
        self.active_flows: Dict[Tuple[str, str, int, int, int], FlowState] = {}
        self.total_packets_processed: int = 0
        self.total_flows_created: int = 0
        self.total_flows_completed: int = 0

    def _get_flow_key(self, pkt: PacketMetadata) -> Tuple[str, str, int, int, int]:
        """
        Normalize 5-tuple key for bidirectional matching.
        """
        ep1 = (pkt.src_ip, pkt.src_port)
        ep2 = (pkt.dst_ip, pkt.dst_port)
        if ep1 <= ep2:
            return (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        else:
            return (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)

    def add_packet(self, pkt: PacketMetadata) -> List[Dict[str, Any]]:
        """
        Process a single packet into active flows.
        Returns any flows finalized during this packet processing step.
        """
        self.total_packets_processed += 1
        key = self._get_flow_key(pkt)
        completed: List[Dict[str, Any]] = []

        # Check for expired active flows before processing
        expired_keys = [
            k for k, flow in self.active_flows.items()
            if (pkt.timestamp - flow.last_time) > self.flow_timeout
        ]
        for k in expired_keys:
            flow_state = self.active_flows.pop(k)
            self.total_flows_completed += 1
            completed.append(flow_state.to_flow_dict())

        # Update or create flow
        if key in self.active_flows:
            flow_state = self.active_flows[key]
            flow_state.add_packet(pkt)

            # Check TCP termination (FIN or RST flag)
            if pkt.tcp_flags.get("FIN") or pkt.tcp_flags.get("RST"):
                self.active_flows.pop(key)
                self.total_flows_completed += 1
                completed.append(flow_state.to_flow_dict())

        else:
            flow_state = FlowState(pkt)
            self.total_flows_created += 1

            if pkt.tcp_flags.get("FIN") or pkt.tcp_flags.get("RST"):
                self.total_flows_completed += 1
                completed.append(flow_state.to_flow_dict())
            else:
                self.active_flows[key] = flow_state

        return completed

    def flush_expired(self, current_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Flush all active flows that have exceeded flow_timeout.
        """
        completed: List[Dict[str, Any]] = []
        if not self.active_flows:
            return completed

        ref_time = current_time if current_time is not None else max(f.last_time for f in self.active_flows.values())
        expired_keys = [
            k for k, flow in self.active_flows.items()
            if (ref_time - flow.last_time) > self.flow_timeout
        ]
        for k in expired_keys:
            flow_state = self.active_flows.pop(k)
            self.total_flows_completed += 1
            completed.append(flow_state.to_flow_dict())
        return completed

    def flush_all(self) -> List[Dict[str, Any]]:
        """
        Flush all remaining active flows regardless of timeout.
        """
        completed: List[Dict[str, Any]] = []
        for k, flow_state in list(self.active_flows.items()):
            self.total_flows_completed += 1
            completed.append(flow_state.to_flow_dict())
        self.active_flows.clear()
        return completed


class FeatureValidator:
    """
    Strict validation layer comparing generated network flow dictionaries
    against CyberSentinelPredictor's required feature schema.
    """

    @staticmethod
    def validate_flow(flow: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate a single flow dictionary against STAGE1_FEATURE_COLUMNS.
        """
        expected_cols = set(STAGE1_FEATURE_COLUMNS)
        generated_cols = set(flow.keys())

        missing = expected_cols - generated_cols
        extra = generated_cols - expected_cols

        invalid_types: List[str] = []
        for col in STAGE1_FEATURE_COLUMNS:
            val = flow.get(col)
            if val is None or (isinstance(val, float) and (math.isnan(val) or math.isinf(val))):
                invalid_types.append(col)

        is_valid = (len(missing) == 0) and (len(invalid_types) == 0)

        summary = {
            "expected_count": len(STAGE1_FEATURE_COLUMNS),
            "generated_count": len(generated_cols),
            "missing_count": len(missing),
            "missing_features": list(missing),
            "invalid_types_count": len(invalid_types),
            "invalid_type_features": invalid_types,
            "schema_compatible": is_valid,
        }

        return is_valid, summary

    @staticmethod
    def print_validation_check(flow: Dict[str, Any]) -> None:
        """
        Print schema validation check summary.
        """
        is_valid, summary = FeatureValidator.validate_flow(flow)
        print()
        print("==================================================")
        print("NETWORK FLOW SCHEMA VALIDATION CHECK")
        print("==================================================")
        print(f"Expected model features : {summary['expected_count']}")
        print(f"Generated features      : {summary['generated_count']}")
        print(f"Missing features        : {summary['missing_count']}")
        print(f"Schema compatible       : {'YES' if is_valid else 'NO'}")
        if not is_valid:
            if summary['missing_features']:
                print(f"Missing: {summary['missing_features']}")
            if summary['invalid_type_features']:
                print(f"Invalid numeric values: {summary['invalid_type_features']}")
        print("==================================================")
