import hashlib
import sqlite3
from pathlib import Path
from typing import Optional

import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_ALERT_LIMIT = 10000
MAX_ALERT_LIMIT = 10000

DB_DIR = Path(
    "/home/charay/cybersentinel-data/soc"
)

DB_PATH = DB_DIR / "alerts.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    """
    Create and return a SQLite connection.
    """

    DB_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DB_PATH,
        timeout=60.0,
        check_same_thread=False,
    )

    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass

    return connection


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database():
    """
    Create the alert-management and replay-history tables if they do not exist.
    """
    import time
    for attempt in range(5):
        try:
            connection = get_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    attack_type TEXT,
                    severity TEXT,
                    confidence REAL,
                    destination_port INTEGER,
                    protocol TEXT,
                    status TEXT NOT NULL DEFAULT 'NEW',
                    replay_run_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

            # Check if replay_run_id column exists for existing database instances
            cursor.execute("PRAGMA table_info(alerts)")
            columns = [row[1] for row in cursor.fetchall()]
            if "replay_run_id" not in columns:
                try:
                    cursor.execute("ALTER TABLE alerts ADD COLUMN replay_run_id TEXT")
                except Exception:
                    pass

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_history (
                    replay_id TEXT PRIMARY KEY,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    flows_requested INTEGER NOT NULL,
                    flows_processed INTEGER NOT NULL,
                    gt_benign INTEGER NOT NULL,
                    gt_attacks INTEGER NOT NULL,
                    pred_benign INTEGER NOT NULL,
                    pred_attacks INTEGER NOT NULL,
                    alerts_inserted INTEGER NOT NULL,
                    throughput REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'COMPLETED'
                )
                """
            )

            connection.commit()
            connection.close()
            break
        except sqlite3.OperationalError:
            time.sleep(0.5)


# ============================================================
# ALERT ID GENERATION
# ============================================================

def generate_alert_key(row) -> str:
    """
    Generate a key representing the observable properties
    of an alert.

    This key is NOT necessarily unique.

    It is used together with an occurrence counter so that
    identical network-flow alerts still receive separate IDs.
    """

    values = [
        str(row.get("Timestamp", "")),
        str(row.get("attack_type", "")),
        str(row.get("severity", "")),
        str(row.get("Dst_Port", "")),
        str(row.get("Protocol", "")),
        str(row.get("attack_probability", "")),
    ]

    raw = "|".join(values)

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()


def generate_alert_id(
    row,
    occurrence: int,
) -> str:
    """
    Generate a deterministic unique alert ID.

    The occurrence number distinguishes multiple
    identical alerts.
    """

    base_key = generate_alert_key(row)

    raw = (
        f"{base_key}|{occurrence}"
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:16]


# ============================================================
# PROTOCOL CONVERSION
# ============================================================

def protocol_name(protocol_value) -> str:
    """
    Convert protocol numbers into readable names.
    """

    if pd.isna(protocol_value):
        return "Unknown"

    try:
        protocol_value = int(
            protocol_value
        )
    except (ValueError, TypeError):
        return "Unknown"

    protocol_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }

    return protocol_map.get(
        protocol_value,
        "Other",
    )


# ============================================================
# SYNCHRONIZE ALERTS
# ============================================================

def sync_alerts(
    alert_dataframe: pd.DataFrame,
) -> int:
    """
    Synchronize inference alerts into SQLite.

    New alerts are inserted with status NEW.

    Existing alerts retain their current status.

    Identical alerts are distinguished using an
    occurrence counter.

    Returns the number of newly inserted alerts.
    """

    if alert_dataframe.empty:
        return 0

    initialize_database()

    connection = get_connection()

    cursor = connection.cursor()

    now = pd.Timestamp.now(
        tz="UTC"
    ).isoformat()

    inserted = 0

    # Track duplicate occurrences.

    occurrence_counts = {}

    for _, row in alert_dataframe.iterrows():

        base_key = generate_alert_key(row)

        occurrence = occurrence_counts.get(
            base_key,
            0,
        )

        occurrence_counts[base_key] = (
            occurrence + 1
        )

        alert_id = generate_alert_id(
            row,
            occurrence,
        )

        # Check whether this exact alert
        # already exists.

        cursor.execute(
            """
            SELECT alert_id
            FROM alerts
            WHERE alert_id = ?
            """,
            (alert_id,),
        )

        existing = cursor.fetchone()

        if existing is not None:
            continue

        # Timestamp

        timestamp = row.get(
            "Timestamp"
        )

        if pd.notna(timestamp):
            timestamp = str(timestamp)
        else:
            timestamp = None

        # Confidence

        confidence = row.get(
            "attack_probability"
        )

        if pd.isna(confidence):
            confidence = 0.0

        # Destination port

        destination_port = row.get(
            "Dst_Port"
        )

        if pd.notna(destination_port):

            try:
                destination_port = int(
                    destination_port
                )
            except (
                ValueError,
                TypeError,
            ):
                destination_port = None

        else:
            destination_port = None

        # Protocol

        protocol = protocol_name(
            row.get("Protocol")
        )

        # Attack type

        attack_type = str(
            row.get(
                "attack_type",
                "Unknown",
            )
        )

        # Severity

        severity = str(
            row.get(
                "severity",
                "UNKNOWN",
            )
        )

        # Insert

        cursor.execute(
            """
            INSERT INTO alerts (
                alert_id,
                timestamp,
                attack_type,
                severity,
                confidence,
                destination_port,
                protocol,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                timestamp,
                attack_type,
                severity,
                float(confidence),
                destination_port,
                protocol,
                "NEW",
                now,
                now,
            ),
        )

        inserted += 1

    connection.commit()
    connection.close()

    return inserted


# ============================================================
# GET ALERTS
# ============================================================

def get_alerts(
    status: Optional[str] = None,
    limit: Optional[int] = None,
) -> pd.DataFrame:
    """
    Return alerts from the database.

    Optional status filtering and limit are supported.
    """

    initialize_database()

    connection = get_connection()

    params = []
    where_clauses = []

    if status:
        where_clauses.append("status = ?")
        params.append(status)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    query = f"""
        SELECT *
        FROM alerts
        {where_sql}
        ORDER BY timestamp DESC
    """

    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)

    dataframe = pd.read_sql_query(
        query,
        connection,
        params=tuple(params) if params else None,
    )

    connection.close()

    return dataframe


# ============================================================
# GET SINGLE ALERT
# ============================================================

def get_alert(
    alert_id: str,
):
    """
    Retrieve one alert by ID.
    """

    initialize_database()

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM alerts
        WHERE alert_id = ?
        """,
        (alert_id,),
    )

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return None

    return dict(row)


# ============================================================
# UPDATE STATUS
# ============================================================

def update_status(
    alert_id: str,
    status: str,
) -> bool:
    """
    Update the workflow status of an alert.

    Valid statuses:

        NEW
        INVESTIGATING
        ESCALATED
        RESOLVED
    """

    valid_statuses = {
        "NEW",
        "INVESTIGATING",
        "ESCALATED",
        "RESOLVED",
    }

    status = status.upper()

    if status not in valid_statuses:

        raise ValueError(
            f"Invalid alert status: {status}. "
            f"Expected one of: "
            f"{sorted(valid_statuses)}"
        )

    initialize_database()

    connection = get_connection()

    cursor = connection.cursor()

    updated_at = pd.Timestamp.now(
        tz="UTC"
    ).isoformat()

    cursor.execute(
        """
        UPDATE alerts
        SET status = ?,
            updated_at = ?
        WHERE alert_id = ?
        """,
        (
            status,
            updated_at,
            alert_id,
        ),
    )

    changed = (
        cursor.rowcount > 0
    )

    connection.commit()
    connection.close()

    return changed


# ============================================================
# STATUS COUNTS
# ============================================================

def get_status_counts():
    """
    Return alert counts grouped by workflow status.
    """

    initialize_database()

    connection = get_connection()

    query = """
        SELECT
            status,
            COUNT(*) AS count
        FROM alerts
        GROUP BY status
        ORDER BY status
    """

    dataframe = pd.read_sql_query(
        query,
        connection,
    )

    connection.close()

    return dataframe


# ============================================================
# REPLAY HISTORY FUNCTIONS
# ============================================================

def record_replay_run(data: dict):
    """
    Record or update a historical SOC replay run.
    """
    initialize_database()
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO replay_history (
            replay_id, start_time, end_time, flows_requested, flows_processed,
            gt_benign, gt_attacks, pred_benign, pred_attacks, alerts_inserted, throughput, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(replay_id) DO UPDATE SET
            end_time = excluded.end_time,
            flows_requested = excluded.flows_requested,
            flows_processed = excluded.flows_processed,
            gt_benign = excluded.gt_benign,
            gt_attacks = excluded.gt_attacks,
            pred_benign = excluded.pred_benign,
            pred_attacks = excluded.pred_attacks,
            alerts_inserted = excluded.alerts_inserted,
            throughput = excluded.throughput,
            status = excluded.status
        """,
        (
            data["replay_id"],
            data.get("start_time", pd.Timestamp.now(tz="UTC").isoformat()),
            data.get("end_time", pd.Timestamp.now(tz="UTC").isoformat()),
            data.get("flows_requested", 0),
            data.get("flows_processed", 0),
            data.get("gt_benign", 0),
            data.get("gt_attacks", 0),
            data.get("pred_benign", 0),
            data.get("pred_attacks", 0),
            data.get("alerts_inserted", 0),
            float(data.get("throughput", 0.0)),
            data.get("status", "COMPLETED"),
        ),
    )

    connection.commit()
    connection.close()


def get_replay_run(replay_id: str) -> Optional[dict]:
    """
    Retrieve a specific replay run record by replay_id.
    """
    initialize_database()
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM replay_history WHERE replay_id = ?", (replay_id,))
    row = cursor.fetchone()
    connection.close()

    if row is not None:
        return dict(row)
    return None


def get_replay_history() -> pd.DataFrame:
    """
    Retrieve all recorded replay runs ordered by start time.
    """
    initialize_database()
    connection = get_connection()

    query = """
        SELECT
            replay_id,
            start_time,
            end_time,
            flows_requested,
            flows_processed,
            gt_benign,
            gt_attacks,
            pred_benign,
            pred_attacks,
            alerts_inserted,
            throughput,
            status
        FROM replay_history
        ORDER BY start_time DESC
    """

    dataframe = pd.read_sql_query(query, connection)
    connection.close()
    return dataframe


def backup_and_reset_soc_alerts(confirm: bool = False) -> dict:
    """
    Safely backup database file and reset ONLY the operational alerts table.
    Preserves replay_history table and all historical replay records.
    """
    if not confirm:
        raise ValueError("Confirmation flag required to reset operational SOC alerts.")

    initialize_database()
    connection = get_connection()
    cursor = connection.cursor()

    # Pre-reset counts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    pre_total_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")
    pre_status_dist = dict(cursor.fetchall())

    cursor.execute("SELECT COUNT(*) FROM replay_history")
    pre_replays_count = cursor.fetchone()[0]

    connection.close()

    # Create backup copy
    import shutil
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"alerts_backup_before_demo_20k_{timestamp}.db"
    backup_path = DB_DIR / backup_filename

    if DB_PATH.exists():
        shutil.copy2(DB_PATH, backup_path)

    # Perform DELETE FROM alerts only
    conn_reset = get_connection()
    cur_reset = conn_reset.cursor()
    cur_reset.execute("DELETE FROM alerts")
    conn_reset.commit()

    cur_reset.execute("SELECT COUNT(*) FROM alerts")
    post_alerts_count = cur_reset.fetchone()[0]

    cur_reset.execute("SELECT COUNT(*) FROM replay_history")
    post_replays_count = cur_reset.fetchone()[0]
    conn_reset.close()

    return {
        "backup_path": str(backup_path),
        "pre_total_alerts": pre_total_alerts,
        "pre_status_dist": pre_status_dist,
        "pre_replays_count": pre_replays_count,
        "post_alerts_count": post_alerts_count,
        "post_replays_count": post_replays_count,
    }


def reset_database():
    """
    Delete the current alert database.

    Used when rebuilding the alert store from a
    fresh inference output.
    """

    if DB_PATH.exists():
        DB_PATH.unlink()

    initialize_database()


# ============================================================
# MAIN TEST
# ============================================================

if __name__ == "__main__":

    initialize_database()

    print(
        "CyberSentinel alert database initialized."
    )

    print(
        f"Database path: {DB_PATH}"
    )
