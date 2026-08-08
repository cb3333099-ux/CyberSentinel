from typing import Optional

import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.soc.alert_store import (
    get_alert,
    get_alerts,
    get_status_counts,
    update_status,
)


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "CyberSentinel SOC API"
APP_VERSION = "1.0.0"


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title=APP_NAME,
    description=(
        "Backend API for CyberSentinel's "
        "AI-powered network threat detection "
        "and SOC alert management platform."
    ),
    version=APP_VERSION,
)


# ============================================================
# REQUEST MODELS
# ============================================================

class StatusUpdate(BaseModel):
    status: str


# ============================================================
# HELPERS
# ============================================================

def clean_value(value):
    """
    Convert pandas / NumPy values into
    JSON-safe Python values.
    """

    if value is None:
        return None

    try:
        if pd.isna(value):
            return None
    except Exception:
        pass

    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass

    if isinstance(value, pd.Timestamp):
        return str(value)

    return value


def serialize_alert(alert):
    """
    Convert an alert returned from SQLite
    into the canonical CyberSentinel API format.

    Database fields:
        confidence
        destination_port
        protocol

    API fields:
        attack_probability
        model_confidence
        dst_port
        protocol
    """

    if alert is None:
        return None

    # --------------------------------------------------------
    # SQLite Row
    # --------------------------------------------------------

    if hasattr(alert, "keys") and not isinstance(
        alert,
        pd.DataFrame,
    ):

        try:
            data = dict(alert)
        except Exception:
            data = {}

    # --------------------------------------------------------
    # Pandas Series
    # --------------------------------------------------------

    elif isinstance(alert, pd.Series):

        data = alert.to_dict()

    # --------------------------------------------------------
    # Dictionary
    # --------------------------------------------------------

    elif isinstance(alert, dict):

        data = dict(alert)

    # --------------------------------------------------------
    # Generic object
    # --------------------------------------------------------

    else:

        try:
            data = dict(alert)
        except Exception:
            return None

    # --------------------------------------------------------
    # Database fields
    # --------------------------------------------------------

    alert_id = data.get(
        "alert_id"
    )

    timestamp = data.get(
        "timestamp"
    )

    attack_type = data.get(
        "attack_type",
        "Unknown",
    )

    severity = data.get(
        "severity",
        "UNKNOWN",
    )

    confidence = data.get(
        "confidence"
    )

    destination_port = data.get(
        "destination_port"
    )

    protocol = data.get(
        "protocol",
        "Unknown",
    )

    status = data.get(
        "status",
        "NEW",
    )

    # --------------------------------------------------------
    # Confidence normalization
    # --------------------------------------------------------

    confidence = clean_value(
        confidence
    )

    if confidence is None:
        confidence = 0.0

    try:
        confidence = float(
            confidence
        )
    except (
        TypeError,
        ValueError,
    ):
        confidence = 0.0

    # --------------------------------------------------------
    # Destination port normalization
    # --------------------------------------------------------

    destination_port = clean_value(
        destination_port
    )

    if destination_port is not None:

        try:
            destination_port = int(
                float(destination_port)
            )
        except (
            TypeError,
            ValueError,
        ):
            destination_port = None

    # --------------------------------------------------------
    # Timestamp normalization
    # --------------------------------------------------------

    timestamp = clean_value(
        timestamp
    )

    if timestamp is not None:

        timestamp = str(
            timestamp
        )

    # --------------------------------------------------------
    # Canonical API response
    # --------------------------------------------------------

    return {
        "alert_id": clean_value(
            alert_id
        ),

        "timestamp": timestamp,

        "attack_type": str(
            attack_type
            if attack_type is not None
            else "Unknown"
        ),

        "severity": str(
            severity
            if severity is not None
            else "UNKNOWN"
        ).upper(),

        "attack_probability": confidence,

        "model_confidence": confidence,

        "dst_port": destination_port,

        "protocol": str(
            protocol
            if protocol is not None
            else "Unknown"
        ),

        "status": str(
            status
            if status is not None
            else "NEW"
        ).upper(),

        # Original database names retained
        # for backwards compatibility.
        "confidence": confidence,

        "destination_port": destination_port,
    }


def serialize_dataframe(dataframe):
    """
    Serialize a pandas DataFrame containing alerts.
    """

    if dataframe is None:
        return []

    if dataframe.empty:
        return []

    alerts = []

    for _, row in dataframe.iterrows():

        alert = serialize_alert(
            row
        )

        if alert is not None:

            alerts.append(
                alert
            )

    return alerts


def filter_dataframe(
    dataframe,
    severity=None,
    attack_type=None,
):
    """
    Apply optional API filters.
    """

    if dataframe is None:
        return pd.DataFrame()

    if dataframe.empty:
        return dataframe

    result = dataframe.copy()

    # --------------------------------------------------------
    # Severity filter
    # --------------------------------------------------------

    if severity:

        if "severity" in result.columns:

            result = result[
                result["severity"]
                .astype(str)
                .str.upper()
                ==
                severity.upper()
            ]

    # --------------------------------------------------------
    # Attack type filter
    # --------------------------------------------------------

    if attack_type:

        if "attack_type" in result.columns:

            result = result[
                result["attack_type"]
                .astype(str)
                ==
                attack_type
            ]

    return result


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    """
    API root endpoint.
    """

    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    """
    Health check endpoint.
    """

    return {
        "status": "healthy",
        "service": "cybersentinel-soc-api",
    }


# ============================================================
# ALERTS
# ============================================================

@app.get("/api/alerts")
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    limit: int = 100,
):
    """
    Return SOC alerts with optional filtering.
    """

    # --------------------------------------------------------
    # Validate limit
    # --------------------------------------------------------

    if limit < 1:

        raise HTTPException(
            status_code=400,
            detail="limit must be greater than 0",
        )

    if limit > 1000:

        raise HTTPException(
            status_code=400,
            detail="limit cannot exceed 1000",
        )

    # --------------------------------------------------------
    # Load alerts
    # --------------------------------------------------------

    dataframe = get_alerts(
        status=status,
    )

    if dataframe is None or dataframe.empty:

        return {
            "count": 0,
            "alerts": [],
        }

    # --------------------------------------------------------
    # Filters
    # --------------------------------------------------------

    dataframe = filter_dataframe(
        dataframe,
        severity=severity,
        attack_type=attack_type,
    )

    # --------------------------------------------------------
    # Limit
    # --------------------------------------------------------

    dataframe = dataframe.head(
        limit
    )

    alerts = serialize_dataframe(
        dataframe
    )

    return {
        "count": len(alerts),
        "alerts": alerts,
    }


# ============================================================
# RECENT ALERTS
#
# IMPORTANT:
# This route MUST appear BEFORE
# /api/alerts/{alert_id}
#
# Otherwise FastAPI can interpret
# "recent" as alert_id="recent".
# ============================================================

@app.get("/api/alerts/recent")
def recent_alerts(
    limit: int = 10,
):
    """
    Return the most recent SOC alerts.
    """

    # --------------------------------------------------------
    # Validate limit
    # --------------------------------------------------------

    if limit < 1:

        raise HTTPException(
            status_code=400,
            detail="limit must be greater than 0",
        )

    if limit > 100:

        raise HTTPException(
            status_code=400,
            detail="limit cannot exceed 100",
        )

    # --------------------------------------------------------
    # Load alerts
    # --------------------------------------------------------

    dataframe = get_alerts()

    if dataframe is None or dataframe.empty:

        return {
            "count": 0,
            "alerts": [],
        }

    dataframe = dataframe.copy()

    # --------------------------------------------------------
    # Sort by timestamp
    # --------------------------------------------------------

    if "timestamp" in dataframe.columns:

        dataframe["_sort_timestamp"] = (
            pd.to_datetime(
                dataframe["timestamp"],
                errors="coerce",
            )
        )

        dataframe = dataframe.sort_values(
            "_sort_timestamp",
            ascending=False,
            na_position="last",
        )

        dataframe = dataframe.drop(
            columns=[
                "_sort_timestamp"
            ]
        )

    # --------------------------------------------------------
    # Fallback to created_at if timestamp
    # is unavailable.
    # --------------------------------------------------------

    elif "created_at" in dataframe.columns:

        dataframe["_sort_created"] = (
            pd.to_datetime(
                dataframe["created_at"],
                errors="coerce",
            )
        )

        dataframe = dataframe.sort_values(
            "_sort_created",
            ascending=False,
            na_position="last",
        )

        dataframe = dataframe.drop(
            columns=[
                "_sort_created"
            ]
        )

    # --------------------------------------------------------
    # Limit results
    # --------------------------------------------------------

    dataframe = dataframe.head(
        limit
    )

    alerts = serialize_dataframe(
        dataframe
    )

    return {
        "count": len(alerts),
        "alerts": alerts,
    }


# ============================================================
# SINGLE ALERT
#
# This MUST remain AFTER /recent.
# ============================================================

@app.get("/api/alerts/{alert_id}")
def single_alert(
    alert_id: str,
):
    """
    Return a single alert by ID.
    """

    alert = get_alert(
        alert_id
    )

    if alert is None:

        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    serialized = serialize_alert(
        alert
    )

    if serialized is None:

        raise HTTPException(
            status_code=500,
            detail="Failed to serialize alert",
        )

    return serialized


# ============================================================
# UPDATE ALERT STATUS
# ============================================================

@app.patch("/api/alerts/{alert_id}/status")
def change_alert_status(
    alert_id: str,
    payload: StatusUpdate,
):
    """
    Update an alert's SOC workflow status.
    """

    status = payload.status.upper()

    valid_statuses = {
        "NEW",
        "INVESTIGATING",
        "ESCALATED",
        "RESOLVED",
    }

    # --------------------------------------------------------
    # Validate status
    # --------------------------------------------------------

    if status not in valid_statuses:

        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid status '{status}'. "
                f"Allowed values: "
                f"{sorted(valid_statuses)}"
            ),
        )

    # --------------------------------------------------------
    # Check alert exists
    # --------------------------------------------------------

    alert = get_alert(
        alert_id
    )

    if alert is None:

        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    # --------------------------------------------------------
    # Update status
    # --------------------------------------------------------

    updated = update_status(
        alert_id,
        status,
    )

    if not updated:

        raise HTTPException(
            status_code=500,
            detail="Failed to update alert",
        )

    # --------------------------------------------------------
    # Retrieve updated alert
    # --------------------------------------------------------

    updated_alert = get_alert(
        alert_id
    )

    return {
        "message": "Alert status updated",
        "alert": serialize_alert(
            updated_alert
        ),
    }


# ============================================================
# STATUS METRICS
# ============================================================

@app.get("/api/metrics/status")
def status_metrics():
    """
    Return alert workflow status counts.
    """

    dataframe = get_status_counts()

    counts = {
        "NEW": 0,
        "INVESTIGATING": 0,
        "ESCALATED": 0,
        "RESOLVED": 0,
    }

    if dataframe is not None:

        if not dataframe.empty:

            for _, row in dataframe.iterrows():

                status = str(
                    row["status"]
                ).upper()

                if status in counts:

                    counts[status] = int(
                        row["count"]
                    )

    return {
        "total": sum(
            counts.values()
        ),
        "by_status": counts,
    }


# ============================================================
# SOC METRICS
# ============================================================

@app.get("/api/metrics")
def soc_metrics():
    """
    Return overall SOC metrics.
    """

    dataframe = get_alerts()

    if dataframe is None or dataframe.empty:

        return {
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "attack_types": 0,
            "average_confidence": 0.0,
        }

    # --------------------------------------------------------
    # Total alerts
    # --------------------------------------------------------

    total_alerts = len(
        dataframe
    )

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    if "severity" in dataframe.columns:

        severity_series = (
            dataframe["severity"]
            .astype(str)
            .str.upper()
        )

        critical_alerts = int(
            (
                severity_series
                == "CRITICAL"
            ).sum()
        )

        high_alerts = int(
            (
                severity_series
                == "HIGH"
            ).sum()
        )

    else:

        critical_alerts = 0
        high_alerts = 0

    # --------------------------------------------------------
    # Attack types
    # --------------------------------------------------------

    if "attack_type" in dataframe.columns:

        attack_types = int(
            dataframe["attack_type"]
            .dropna()
            .astype(str)
            .nunique()
        )

    else:

        attack_types = 0

    # --------------------------------------------------------
    # Average confidence
    # --------------------------------------------------------

    if "confidence" in dataframe.columns:

        confidence = pd.to_numeric(
            dataframe["confidence"],
            errors="coerce",
        )

        average_confidence = float(
            confidence
            .fillna(0)
            .mean()
        )

    else:

        average_confidence = 0.0

    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "attack_types": attack_types,
        "average_confidence": round(
            average_confidence,
            4,
        ),
    }


# ============================================================
# ATTACK METRICS
# ============================================================

@app.get("/api/metrics/attacks")
def attack_metrics():
    """
    Return alert counts grouped by attack type.
    """

    dataframe = get_alerts()

    if dataframe is None or dataframe.empty:

        return []

    if "attack_type" not in dataframe.columns:

        return []

    result = (
        dataframe["attack_type"]
        .fillna("Unknown")
        .astype(str)
        .value_counts()
        .reset_index()
    )

    result.columns = [
        "attack_type",
        "count",
    ]

    return result.to_dict(
        orient="records"
    )


# ============================================================
# SEVERITY METRICS
# ============================================================

@app.get("/api/metrics/severity")
def severity_metrics():
    """
    Return alert counts grouped by severity.
    """

    dataframe = get_alerts()

    if dataframe is None or dataframe.empty:

        return []

    if "severity" not in dataframe.columns:

        return []

    result = (
        dataframe["severity"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
        .value_counts()
        .reset_index()
    )

    result.columns = [
        "severity",
        "count",
    ]

    return result.to_dict(
        orient="records"
    )


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )