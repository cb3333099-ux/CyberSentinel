# src/api/main.py

from typing import Optional

import pandas as pd

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.soc.alert_store import (
    get_alert,
    get_alerts,
    get_status_counts,
    update_status,
    get_replay_history,
    get_replay_run,
)


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "CyberSentinel SOC API"
APP_VERSION = "1.0.0"
DEFAULT_ALERT_LIMIT = 10000
MAX_ALERT_LIMIT = 10000


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
# HEALTH CHECK
# ============================================================

@app.get("/")
def root():

    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "status": "online",
    }


@app.get("/health")
def health():

    return {
        "status": "healthy",
        "service": "cybersentinel-soc-api",
    }


# ============================================================
# ALERT ENDPOINTS
# ============================================================

@app.get("/api/alerts")
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    limit: int = DEFAULT_ALERT_LIMIT,
):

    if limit < 1:

        raise HTTPException(
            status_code=400,
            detail="limit must be greater than 0",
        )

    if limit > MAX_ALERT_LIMIT:

        raise HTTPException(
            status_code=400,
            detail=f"limit cannot exceed {MAX_ALERT_LIMIT}",
        )

    fetch_limit = limit if (not severity and not attack_type) else None

    dataframe = get_alerts(
        status=status,
        limit=fetch_limit,
    )


    if dataframe.empty:

        return {
            "count": 0,
            "alerts": [],
        }


    if severity:

        dataframe = dataframe[
            dataframe["severity"]
            .astype(str)
            .str.upper()
            == severity.upper()
        ]


    if attack_type:

        dataframe = dataframe[
            dataframe["attack_type"]
            .astype(str)
            == attack_type
        ]


    dataframe = dataframe.head(
        limit
    )


    dataframe = dataframe.where(
        pd.notna(dataframe),
        None,
    )


    alerts = dataframe.to_dict(
        orient="records"
    )


    return {
        "count": len(alerts),
        "alerts": alerts,
    }


# ============================================================
# RECENT ALERTS
# ============================================================

@app.get("/api/alerts/recent")
def recent_alerts(
    limit: int = 20,
):
    if limit < 1:
        raise HTTPException(
            status_code=400,
            detail="limit must be greater than 0",
        )

    if limit > MAX_ALERT_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f"limit cannot exceed {MAX_ALERT_LIMIT}",
        )

    dataframe = get_alerts(
        limit=limit,
    )

    if dataframe.empty:
        return {
            "count": 0,
            "alerts": [],
        }

    dataframe = dataframe.where(
        pd.notna(dataframe),
        None,
    )

    alerts = dataframe.to_dict(
        orient="records"
    )

    return {
        "count": len(alerts),
        "alerts": alerts,
    }


# ============================================================
# SINGLE ALERT
# ============================================================

@app.get("/api/alerts/{alert_id}")
def single_alert(
    alert_id: str,
):

    alert = get_alert(
        alert_id
    )

    if alert is None:

        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return {
        "alert": alert,
    }


# ============================================================
# UPDATE ALERT STATUS
# ============================================================

@app.patch("/api/alerts/{alert_id}/status")
def change_alert_status(
    alert_id: str,
    payload: StatusUpdate,
):

    status = payload.status.upper()

    valid_statuses = {
        "NEW",
        "INVESTIGATING",
        "ESCALATED",
        "RESOLVED",
    }


    if status not in valid_statuses:

        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid status '{status}'. "
                f"Allowed values: "
                f"{sorted(valid_statuses)}"
            ),
        )


    alert = get_alert(
        alert_id
    )


    if alert is None:

        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )


    updated = update_status(
        alert_id,
        status,
    )


    if not updated:

        raise HTTPException(
            status_code=500,
            detail="Failed to update alert",
        )


    updated_alert = get_alert(
        alert_id
    )


    return {
        "message": "Alert status updated",
        "alert": updated_alert,
    }


# ============================================================
# STATUS COUNTS
# ============================================================

@app.get("/api/metrics/status")
def status_metrics():

    dataframe = get_status_counts()


    counts = {
        "NEW": 0,
        "INVESTIGATING": 0,
        "ESCALATED": 0,
        "RESOLVED": 0,
    }


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

    dataframe = get_alerts()


    if dataframe.empty:

        return {
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0,
            "average_confidence": 0,
            "attack_types": 0,
        }


    total_alerts = len(
        dataframe
    )


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


    medium_alerts = int(
        (
            severity_series
            == "MEDIUM"
        ).sum()
    )


    low_alerts = int(
        (
            severity_series
            == "LOW"
        ).sum()
    )


    confidence = pd.to_numeric(
        dataframe["confidence"],
        errors="coerce",
    )


    average_confidence = (
        confidence
        .dropna()
        .mean()
    )


    if pd.isna(
        average_confidence
    ):

        average_confidence = 0.0


    attack_types = (
        dataframe["attack_type"]
        .dropna()
        .astype(str)
        .nunique()
    )


    return {
        "total_alerts":
            total_alerts,

        "critical_alerts":
            critical_alerts,

        "high_alerts":
            high_alerts,

        "medium_alerts":
            medium_alerts,

        "low_alerts":
            low_alerts,

        "average_confidence":
            float(
                average_confidence
            ),

        "attack_types":
            int(
                attack_types
            ),
    }


# ============================================================
# ATTACK METRICS
# ============================================================

@app.get("/api/metrics/attacks")
def attack_metrics():
    dataframe = get_alerts()

    if dataframe.empty:
        return []

    counts = (
        dataframe.groupby("attack_type")
        .size()
        .reset_index(name="count")
        .sort_values(by="count", ascending=False)
    )

    return counts.to_dict(
        orient="records"
    )


# ============================================================
# SEVERITY METRICS
# ============================================================

@app.get("/api/metrics/severity")
def severity_metrics():
    dataframe = get_alerts()

    if dataframe.empty:
        return []

    counts = (
        dataframe.groupby("severity")
        .size()
        .reset_index(name="count")
        .sort_values(by="count", ascending=False)
    )

    return counts.to_dict(
        orient="records"
    )


# ============================================================
# REPLAY HISTORY ENDPOINTS
# ============================================================

@app.get("/api/replays")
def list_replays():
    df = get_replay_history()
    if df.empty:
        return {"count": 0, "replays": []}
    return {
        "count": len(df),
        "replays": df.to_dict(orient="records")
    }


@app.get("/api/replays/{replay_id}")
def get_replay_details(replay_id: str):
    record = get_replay_run(replay_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Replay run '{replay_id}' not found")
    return record