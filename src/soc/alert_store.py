import hashlib
import sqlite3
from pathlib import Path
from typing import Optional

import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

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
        check_same_thread=False,
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database():
    """
    Create the alert-management table if it does not exist.
    """

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
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


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
) -> pd.DataFrame:
    """
    Return alerts from the database.

    Optional status filtering is supported.
    """

    initialize_database()

    connection = get_connection()

    if status:

        query = """
            SELECT *
            FROM alerts
            WHERE status = ?
            ORDER BY timestamp DESC
        """

        dataframe = pd.read_sql_query(
            query,
            connection,
            params=(status,),
        )

    else:

        query = """
            SELECT *
            FROM alerts
            ORDER BY timestamp DESC
        """

        dataframe = pd.read_sql_query(
            query,
            connection,
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
# DATABASE RESET
# ============================================================

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
