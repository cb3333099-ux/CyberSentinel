import argparse
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE_PATH = PROJECT_ROOT / "data" / "processed" / "ml-full" / "test"


class FlowStream:
    """
    Real-Time Flow Stream Component for CyberSentinel.

    Reads real network flows from CSE-CIC-IDS2018 processed test data
    and yields representative flows continuously or in configured batches using
    deterministic seeded sampling.
    """

    def __init__(
        self,
        source_path: str = str(DEFAULT_SOURCE_PATH),
        batch_size: int = 50,
        delay: float = 0.5,
        max_flows: Optional[int] = None,
        continuous: bool = False,
        seed: Optional[int] = 42,
        target_attack_ratio: float = 0.30,
    ):
        self.source_path = Path(source_path)
        self.batch_size = max(1, int(batch_size))
        self.delay = max(0.0, float(delay))
        self.max_flows = int(max_flows) if max_flows is not None and max_flows > 0 else None
        self.continuous = bool(continuous)
        self.seed = seed
        self.target_attack_ratio = max(0.0, min(1.0, float(target_attack_ratio)))

        self._dataframe: Optional[pd.DataFrame] = None
        self._flows_yielded: int = 0
        self._row_index: int = 0

    def _load_data(self) -> None:
        """
        Load dataset parquet files into memory using deterministic representative sampling.
        """
        if self._dataframe is not None:
            return

        if not self.source_path.exists():
            raise FileNotFoundError(
                f"Source path for flow stream does not exist: {self.source_path}"
            )

        if self.source_path.is_dir():
            files = sorted([f for f in self.source_path.glob("*.parquet") if not f.name.startswith(".")])
            if not files:
                raise ValueError(f"No parquet files found in {self.source_path}")
            dfs = []
            for f in files:
                dfs.append(pd.read_parquet(f))
                if self.max_flows and sum(len(d) for d in dfs) >= self.max_flows * 10:
                    break
            raw_df = pd.concat(dfs, ignore_index=True) if len(dfs) > 1 else dfs[0]
        else:
            raw_df = pd.read_parquet(self.source_path)
        if raw_df.empty:
            raise ValueError(f"No network flows found in {self.source_path}")

        # Check if stage1_label exists for ground truth separation
        if "stage1_label" in raw_df.columns:
            benign_df = raw_df[raw_df["stage1_label"] == 0.0]
            attack_df = raw_df[raw_df["stage1_label"] == 1.0]

            if not benign_df.empty and not attack_df.empty:
                if self.seed is not None:
                    benign_df = benign_df.sample(frac=1.0, random_state=self.seed).reset_index(drop=True)
                    attack_df = attack_df.sample(frac=1.0, random_state=self.seed).reset_index(drop=True)

                if self.max_flows is not None and self.max_flows > 0:
                    n_attacks = int(round(self.max_flows * self.target_attack_ratio))
                    n_benign = max(1, self.max_flows - n_attacks)

                    sample_benign = benign_df.head(n_benign)
                    sample_attacks = attack_df.head(n_attacks)

                    combined = pd.concat([sample_benign, sample_attacks], ignore_index=True)
                    if self.seed is not None:
                        combined = combined.sample(frac=1.0, random_state=self.seed).reset_index(drop=True)
                    self._dataframe = combined
                else:
                    combined = pd.concat([benign_df, attack_df], ignore_index=True)
                    if self.seed is not None:
                        combined = combined.sample(frac=1.0, random_state=self.seed).reset_index(drop=True)
                    self._dataframe = combined
            else:
                self._dataframe = raw_df
                if self.seed is not None:
                    self._dataframe = self._dataframe.sample(frac=1.0, random_state=self.seed).reset_index(drop=True)
        else:
            self._dataframe = raw_df
            if self.seed is not None:
                self._dataframe = self._dataframe.sample(frac=1.0, random_state=self.seed).reset_index(drop=True)

        self._row_index = 0

    def _row_to_flow(self, row: pd.Series) -> Dict[str, Any]:
        """
        Convert a pandas Series into a CyberSentinel network flow dictionary.

        Ground truth labels (stage1_label, attack_label) are preserved in the flow dictionary
        strictly for evaluation and telemetry, and are NOT passed into model prediction.
        """
        flow = row.to_dict()

        flow = {
            k: (None if pd.isna(v) else v)
            for k, v in flow.items()
        }

        if "Timestamp" not in flow or flow["Timestamp"] is None:
            flow["Timestamp"] = datetime.now().isoformat()
        else:
            flow["Timestamp"] = str(flow["Timestamp"])

        if flow.get("Dst_Port") is not None:
            try:
                flow["Dst_Port"] = float(flow["Dst_Port"])
            except (ValueError, TypeError):
                pass

        if flow.get("Protocol") is not None:
            try:
                flow["Protocol"] = float(flow["Protocol"])
            except (ValueError, TypeError):
                pass

        return flow

    def reset(self) -> None:
        """
        Reset stream progress pointers.
        """
        self._flows_yielded = 0
        self._row_index = 0

    def stream(self) -> Generator[Dict[str, Any], None, None]:
        """
        Yield individual flows continuously or up to max_flows.
        """
        self._load_data()
        assert self._dataframe is not None

        total_rows = len(self._dataframe)

        while True:
            if self.max_flows is not None and self._flows_yielded >= self.max_flows:
                break

            if self._row_index >= total_rows:
                if self.continuous:
                    self._row_index = 0
                else:
                    break

            row = self._dataframe.iloc[self._row_index]
            flow = self._row_to_flow(row)
            self._row_index += 1
            self._flows_yielded += 1

            yield flow

    def stream_batches(self) -> Generator[List[Dict[str, Any]], None, None]:
        """
        Yield batches of flows of size batch_size.

        Applies configured delay between batches.
        """
        self._load_data()
        assert self._dataframe is not None

        total_rows = len(self._dataframe)

        while True:
            if self.max_flows is not None and self._flows_yielded >= self.max_flows:
                break

            batch: List[Dict[str, Any]] = []

            while len(batch) < self.batch_size:
                if self.max_flows is not None and self._flows_yielded >= self.max_flows:
                    break

                if self._row_index >= total_rows:
                    if self.continuous:
                        self._row_index = 0
                    else:
                        break

                row = self._dataframe.iloc[self._row_index]
                flow = self._row_to_flow(row)
                batch.append(flow)

                self._row_index += 1
                self._flows_yielded += 1

            if not batch:
                break

            yield batch

            if self.delay > 0.0:
                time.sleep(self.delay)


# ============================================================
# DEMONSTRATION CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel Real-Time Flow Stream Simulator"
    )
    parser.add_argument(
        "--source",
        type=str,
        default=str(DEFAULT_SOURCE_PATH),
        help="Path to processed test flows Parquet directory",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Batch size for flow streaming (default: 50)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay in seconds between batches (default: 0.5)",
    )
    parser.add_argument(
        "--flows",
        type=int,
        default=1000,
        help="Maximum flows to stream (default: 1000)",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Stream continuously / indefinitely",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for representative sampling (default: 42)",
    )
    parser.add_argument(
        "--attack-ratio",
        type=float,
        default=0.30,
        help="Target ground truth attack ratio (default: 0.30)",
    )

    args = parser.parse_args()

    print()
    print("=" * 50)
    print("CYBERSENTINEL REAL-TIME STREAM")
    print("=" * 50)
    print(f"Status       : RUNNING")
    print(f"Source       : {args.source}")
    print(f"Batch Size   : {args.batch_size}")
    print(f"Delay        : {args.delay} sec")
    print(f"Max Flows    : {args.flows if args.flows else 'Unlimited'}")
    print(f"Seed         : {args.seed}")
    print(f"Attack Ratio : {args.attack_ratio * 100:.1f}%")
    print("=" * 50)
    print()

    streamer = FlowStream(
        source_path=args.source,
        batch_size=args.batch_size,
        delay=args.delay,
        max_flows=args.flows,
        continuous=args.continuous,
        seed=args.seed,
        target_attack_ratio=args.attack_ratio,
    )

    start_time = time.time()
    total_processed = 0

    try:
        for batch in streamer.stream_batches():
            total_processed += len(batch)
            elapsed = time.time() - start_time
            throughput = total_processed / elapsed if elapsed > 0 else 0.0

            print(
                f"\rFlows Processed : {total_processed:<8} | "
                f"Batch Size: {len(batch):<4} | "
                f"Throughput: {throughput:.1f} flows/sec",
                end="",
                flush=True,
            )

    except KeyboardInterrupt:
        print("\n\nStreaming interrupted by user.")

    elapsed = time.time() - start_time
    throughput = total_processed / elapsed if elapsed > 0 else 0.0

    print()
    print()
    print("=" * 50)
    print("STREAMING SUMMARY")
    print("=" * 50)
    print(f"Total Flows Processed: {total_processed:,}")
    print(f"Total Time           : {elapsed:.2f} sec")
    print(f"Average Throughput   : {throughput:.1f} flows/sec")
    print("=" * 50)


if __name__ == "__main__":
    main()
