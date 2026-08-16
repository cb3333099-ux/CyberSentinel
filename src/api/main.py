# src/api/main.py

from typing import Optional

import pandas as pd

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.soc.alert_store import (
    get_alert,
    get_alerts,
    get_status_counts,
    update_status,
    get_replay_history,
    get_replay_run,
)
from src.streaming.stream_manager import stream_manager



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


class StreamStartRequest(BaseModel):
    batch_size: int = 50
    delay: float = 0.5
    flows: Optional[int] = None
    continuous: bool = False
    source_path: Optional[str] = None
    seed: Optional[int] = 42
    target_attack_ratio: float = 0.30




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


    alerts = dataframe.to_dict(
        orient="records"
    )
    for r in alerts:
        for k, v in list(r.items()):
            if pd.isna(v):
                r[k] = None

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


# ============================================================
# REAL-TIME STREAMING ENDPOINTS
# ============================================================

@app.get("/api/stream/status")
def stream_status():
    return stream_manager.get_status()


@app.post("/api/stream/start")
def start_stream_endpoint(
    req: Optional[StreamStartRequest] = None,
    batch_size: int = 50,
    delay: float = 0.5,
    flows: Optional[int] = None,
    continuous: bool = False,
    seed: Optional[int] = 42,
    target_attack_ratio: float = 0.30,
):
    b_size = req.batch_size if req and req.batch_size is not None else batch_size
    d_lay = req.delay if req and req.delay is not None else delay
    f_lows = req.flows if req and req.flows is not None else flows
    c_ont = req.continuous if req and req.continuous is not None else continuous
    s_path = req.source_path if req and req.source_path is not None else None
    s_eed = req.seed if req and req.seed is not None else seed
    t_ratio = req.target_attack_ratio if req and req.target_attack_ratio is not None else target_attack_ratio

    return stream_manager.start(
        source_path=s_path,
        batch_size=b_size,
        delay=d_lay,
        max_flows=f_lows,
        continuous=c_ont,
        seed=s_eed,
        target_attack_ratio=t_ratio,
    )



@app.post("/api/stream/stop")
def stop_stream_endpoint():
    return stream_manager.stop()


# ============================================================
# NETWORK INGESTION & FLOW STREAM ENDPOINTS (PHASE 2)
# ============================================================

from src.network.packet_capture import PacketCapture
from src.network.network_stream import network_stream_manager


class NetworkStartRequest(BaseModel):
    source_type: str = "pcap"  # pcap or live
    pcap_path: Optional[str] = None
    interface: Optional[str] = None
    batch_size: int = 20
    flow_timeout: float = 10.0


@app.get("/api/network/interfaces")
def get_network_interfaces():
    return PacketCapture.list_interfaces()


@app.get("/api/network/status")
def get_network_status():
    return network_stream_manager.get_status()


@app.post("/api/network/start")
def start_network_stream_endpoint(req: NetworkStartRequest):
    if req.source_type == "pcap":
        if not req.pcap_path:
            raise HTTPException(status_code=400, detail="pcap_path is required for PCAP mode")
        return network_stream_manager.start_pcap_stream(
            pcap_path=req.pcap_path,
            batch_size=req.batch_size,
            flow_timeout=req.flow_timeout,
        )
    elif req.source_type == "live":
        if not req.interface:
            raise HTTPException(status_code=400, detail="interface is required for Live mode")
        try:
            return network_stream_manager.start_live_stream(
                interface=req.interface,
                batch_size=req.batch_size,
                flow_timeout=req.flow_timeout,
            )
        except PermissionError as err:
            raise HTTPException(status_code=403, detail=str(err))
    else:
        raise HTTPException(status_code=400, detail="source_type must be 'pcap' or 'live'")


@app.post("/api/network/stop")
def stop_network_stream_endpoint():
    return network_stream_manager.stop_stream()


@app.get("/api/network/flows")
def get_network_flows():
    status = network_stream_manager.get_status()
    return status.get("recent_completed_flows", [])



@app.post("/api/stream/pause")
def pause_stream_endpoint():
    return stream_manager.pause()


@app.post("/api/stream/resume")
def resume_stream_endpoint():
    return stream_manager.resume()


# ============================================================
# PHASE 3A — INCIDENT API ENDPOINTS
# ============================================================

class IncidentStatusUpdate(BaseModel):
    status: str
    actor: Optional[str] = "ANALYST"


class IncidentAssignRequest(BaseModel):
    assigned_to: str
    actor: Optional[str] = "ANALYST"


@app.get("/api/incidents")
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
):
    from src.soc.incident_engine import get_incidents
    incidents = get_incidents(status=status, severity=severity, limit=limit)
    return {
        "count": len(incidents),
        "incidents": incidents,
    }


@app.get("/api/incidents/{incident_id}")
def get_incident_endpoint(incident_id: str):
    from src.soc.incident_engine import get_incident
    inc = get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return {
        "incident": inc,
    }


@app.post("/api/incidents/{incident_id}/status")
def update_incident_status_endpoint(incident_id: str, req: IncidentStatusUpdate):
    from src.soc.incident_engine import update_incident_status
    try:
        inc = update_incident_status(incident_id=incident_id, new_status=req.status, actor=req.actor or "ANALYST")
        if not inc:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
        return {
            "message": f"Incident status updated to '{req.status}'",
            "incident": inc,
        }
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))


@app.get("/api/incidents/{incident_id}/alerts")
def get_incident_alerts_endpoint(incident_id: str):
    from src.soc.incident_engine import get_incident_alerts
    alerts = get_incident_alerts(incident_id)
    return {
        "count": len(alerts),
        "alerts": alerts,
    }


@app.post("/api/incidents/{incident_id}/assign")
def assign_incident_endpoint(incident_id: str, req: IncidentAssignRequest):
    from src.soc.incident_engine import assign_incident
    inc = assign_incident(incident_id=incident_id, assigned_to=req.assigned_to, actor=req.actor or "ANALYST")
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return {
        "message": f"Incident assigned to '{req.assigned_to}'",
        "incident": inc,
    }


@app.get("/api/incidents/{incident_id}/timeline")
def get_incident_timeline_endpoint(incident_id: str):
    from src.soc.incident_engine import get_incident_timeline
    events = get_incident_timeline(incident_id)
    return {
        "count": len(events),
        "timeline": events,
    }


# ============================================================
# PHASE 3B — THREAT INTELLIGENCE, RULES & MITRE ATT&CK API
# ============================================================

@app.get("/api/intel/indicators")
def list_indicators_endpoint(indicator_type: Optional[str] = None, limit: int = 100):
    from src.intel.indicator_store import IndicatorStore
    indicators = IndicatorStore.list_indicators(indicator_type=indicator_type, limit=limit)
    return {
        "count": len(indicators),
        "indicators": indicators,
    }


@app.get("/api/intel/indicators/{value}")
def get_indicator_by_value_endpoint(value: str):
    from src.intel.indicator_store import IndicatorStore
    ind = IndicatorStore.search_indicator(value)
    if not ind:
        raise HTTPException(status_code=404, detail=f"Indicator '{value}' not found")
    return {
        "indicator": ind,
    }


from fastapi import Request

@app.post("/api/intel/indicators")
async def add_indicator_endpoint(request: Request):
    from src.intel.indicator_store import IndicatorStore
    req = await request.json()
    try:
        ind = IndicatorStore.add_indicator(req)
        return {
            "message": f"Threat indicator '{req.get('indicator_value')}' added successfully",
            "indicator": ind,
        }
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))


@app.delete("/api/intel/indicators/{indicator_id}")
def remove_indicator_endpoint(indicator_id: str):
    from src.intel.indicator_store import IndicatorStore
    success = IndicatorStore.remove_indicator(indicator_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Indicator ID '{indicator_id}' not found")
    return {
        "message": f"Indicator '{indicator_id}' removed successfully",
    }


@app.get("/api/intel/enrich/{alert_id}")
def enrich_alert_endpoint(alert_id: str):
    from src.soc.alert_store import get_alert
    from src.intel.enrichment import enrich_alert
    raw_alert = get_alert(alert_id)
    if not raw_alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    enriched = enrich_alert(dict(raw_alert))
    return {
        "enriched_alert": enriched,
    }


@app.get("/api/rules")
def list_rules_endpoint():
    from src.soc.detection_rules import list_rules
    rules = list_rules()
    return {
        "count": len(rules),
        "rules": rules,
    }


@app.get("/api/rules/{rule_id}")
def get_rule_endpoint(rule_id: str):
    from src.soc.detection_rules import get_rule
    rule = get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found")
    return {
        "rule": rule,
    }


@app.get("/api/mitre/techniques")
def list_mitre_techniques_endpoint():
    from src.intel.mitre_attack import MitreAttackEngine
    techs = MitreAttackEngine.list_techniques()
    return {
        "count": len(techs),
        "techniques": techs,
    }


@app.get("/api/mitre/tactics")
def list_mitre_tactics_endpoint():
    from src.intel.mitre_attack import MitreAttackEngine
    tactics = MitreAttackEngine.list_tactics()
    return {
        "count": len(tactics),
        "tactics": tactics,
    }


@app.get("/api/mitre/coverage")
def get_mitre_coverage_endpoint():
    from src.intel.mitre_attack import MitreAttackEngine
    return MitreAttackEngine.get_coverage()


@app.get("/api/incidents/{incident_id}/intelligence")
def get_incident_intelligence_endpoint(incident_id: str):
    from src.soc.incident_engine import get_incident, get_incident_alerts
    from src.intel.enrichment import enrich_incident
    inc = get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    rel_alerts = get_incident_alerts(incident_id)
    enriched_inc = enrich_incident(inc, correlated_alerts=rel_alerts)
    return {
        "incident_intelligence": enriched_inc,
    }


# ============================================================
# PHASE 4 — SOC ANALYTICS & MODEL MONITORING API
# ============================================================

@app.get("/api/analytics/summary")
def get_analytics_summary_endpoint(window: str = "24h"):
    from src.analytics.soc_analytics import get_summary_metrics
    return get_summary_metrics(window=window)


@app.get("/api/analytics/trends")
def get_analytics_trends_endpoint(window: str = "24h"):
    from src.analytics.soc_analytics import get_attack_activity_trends
    trends = get_attack_activity_trends(window=window)
    return {
        "window": window,
        "count": len(trends),
        "trends": trends,
    }


@app.get("/api/analytics/attacks")
def get_analytics_attacks_endpoint(window: str = "24h"):
    from src.analytics.soc_analytics import get_attack_distribution
    dist = get_attack_distribution(window=window)
    return {
        "window": window,
        "attack_distribution": dist,
    }


@app.get("/api/analytics/severity")
def get_analytics_severity_endpoint(window: str = "24h"):
    from src.analytics.soc_analytics import get_severity_analytics
    return get_severity_analytics(window=window)


@app.get("/api/analytics/entities")
def get_analytics_entities_endpoint(window: str = "24h", limit: int = 10):
    from src.analytics.soc_analytics import get_top_entities
    return get_top_entities(window=window, limit=limit)


@app.get("/api/analytics/protocols")
def get_analytics_protocols_endpoint(window: str = "24h"):
    from src.analytics.soc_analytics import get_protocol_analytics
    proto = get_protocol_analytics(window=window)
    return {
        "window": window,
        "protocols": proto,
    }


@app.get("/api/analytics/incidents")
def get_analytics_incidents_endpoint(window: str = "24h"):
    from src.analytics.soc_analytics import get_incident_analytics
    return get_incident_analytics(window=window)


@app.get("/api/analytics/model")
def get_analytics_model_endpoint(window: str = "24h"):
    from src.analytics.model_monitor import get_model_monitoring_metrics
    return get_model_monitoring_metrics(window=window)


@app.get("/api/analytics/dataset")
def get_analytics_dataset_endpoint():
    from src.analytics.dataset_analytics import get_historical_dataset_analytics
    return get_historical_dataset_analytics()
