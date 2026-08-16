import requests


# ============================================================
# CONFIGURATION
# ============================================================

API_BASE_URL = "http://localhost:8000"
DEFAULT_ALERT_LIMIT = 10000
MAX_ALERT_LIMIT = 10000


# ============================================================
# INTERNAL REQUEST HELPER
# ============================================================

def _request(
    method,
    endpoint,
    params=None,
    json=None,
    timeout=10,
):
    """
    Execute an HTTP request against the CyberSentinel SOC API.
    """

    url = f"{API_BASE_URL}{endpoint}"

    try:

        response = requests.request(
            method=method,
            url=url,
            params=params,
            json=json,
            timeout=timeout,
        )

        response.raise_for_status()

        return response.json()

    except requests.exceptions.ConnectionError:

        raise RuntimeError(
            "Unable to connect to CyberSentinel API. "
            "Make sure Uvicorn is running on port 8000."
        )

    except requests.exceptions.Timeout:

        raise RuntimeError(
            "CyberSentinel API request timed out."
        )

    except requests.exceptions.HTTPError as exc:

        try:

            body = response.json()

            if isinstance(body, dict):

                detail = body.get(
                    "detail",
                    str(exc),
                )

            else:

                detail = str(exc)

        except Exception:

            detail = str(exc)

        raise RuntimeError(
            f"CyberSentinel API error: {detail}"
        )


# ============================================================
# HEALTH
# ============================================================

def get_health():
    """
    Check API health.
    """

    return _request(
        "GET",
        "/health",
    )


# ============================================================
# ALERTS
# ============================================================

def get_alerts(
    status=None,
    severity=None,
    attack_type=None,
    limit=DEFAULT_ALERT_LIMIT,
):
    """
    Retrieve alerts from the SOC API.

    Returns:
        list[dict]
    """

    params = {
        "limit": limit,
    }

    if status:
        params["status"] = status

    if severity:
        params["severity"] = severity

    if attack_type:
        params["attack_type"] = attack_type

    result = _request(
        "GET",
        "/api/alerts",
        params=params,
    )

    # --------------------------------------------------------
    # Expected API format:
    #
    # {
    #     "count": 5,
    #     "alerts": [...]
    # }
    # --------------------------------------------------------

    if isinstance(result, dict):

        alerts = result.get(
            "alerts",
            [],
        )

        if isinstance(alerts, list):
            return alerts

        return []

    # Defensive fallback
    if isinstance(result, list):
        return result

    return []


# ============================================================
# SINGLE ALERT
# ============================================================

def get_alert(
    alert_id,
):
    """
    Retrieve one alert by ID.

    The current API returns the alert object directly.
    """

    result = _request(
        "GET",
        f"/api/alerts/{alert_id}",
    )

    # Current API:
    #
    # {
    #     "alert_id": "...",
    #     "attack_type": "...",
    #     ...
    # }

    if isinstance(result, dict):

        # Support both:
        #
        # 1. Direct alert response
        # 2. {"alert": {...}}

        if "alert" in result:

            return result.get(
                "alert"
            )

        return result

    return None


# ============================================================
# STATUS UPDATE
# ============================================================

def update_alert_status(
    alert_id,
    status,
):
    """
    Update an alert's SOC workflow status.
    """

    result = _request(
        "PATCH",
        f"/api/alerts/{alert_id}/status",
        json={
            "status": status,
        },
    )

    if isinstance(result, dict):

        # Current API returns:
        #
        # {
        #     "message": "...",
        #     "alert": {...}
        # }

        if "alert" in result:

            return result.get(
                "alert"
            )

        # Defensive fallback
        return result

    return None


# ============================================================
# STATUS METRICS
# ============================================================

def get_status_metrics():
    """
    Retrieve NEW / INVESTIGATING /
    ESCALATED / RESOLVED counts.

    Returns:
        dict
    """

    result = _request(
        "GET",
        "/api/metrics/status",
    )

    if isinstance(result, dict):
        return result

    # Defensive fallback
    return {
        "total": 0,
        "by_status": {
            "NEW": 0,
            "INVESTIGATING": 0,
            "ESCALATED": 0,
            "RESOLVED": 0,
        },
    }


# ============================================================
# SOC METRICS
# ============================================================

def get_soc_metrics():
    """
    Retrieve overall SOC metrics.

    Expected API response:

    {
        "total_alerts": 1694,
        "critical_alerts": 1373,
        "high_alerts": 267,
        "attack_types": 3,
        "average_confidence": 0.9613
    }

    Returns:
        dict
    """

    result = _request(
        "GET",
        "/api/metrics",
    )

    if isinstance(result, dict):
        return result

    # Prevent dashboard crashes if the API
    # unexpectedly returns a list.

    return {
        "total_alerts": 0,
        "critical_alerts": 0,
        "high_alerts": 0,
        "attack_types": 0,
        "average_confidence": 0.0,
    }


# ============================================================
# ATTACK METRICS
# ============================================================

def get_attack_metrics():
    """
    Retrieve attack-type statistics.

    Current API response:

    [
        {
            "attack_type": "Brute Force -Web",
            "count": 1439
        },
        ...
    ]

    Returns:
        list[dict]
    """

    result = _request(
        "GET",
        "/api/metrics/attacks",
    )

    # Current API returns a list directly.
    if isinstance(result, list):
        return result

    # Defensive support for:
    #
    # {
    #     "attacks": [...]
    # }

    if isinstance(result, dict):

        attacks = result.get(
            "attacks",
            [],
        )

        if isinstance(attacks, list):
            return attacks

    return []


# ============================================================
# SEVERITY METRICS
# ============================================================

def get_severity_metrics():
    """
    Retrieve severity statistics.

    Current API response:

    [
        {
            "severity": "CRITICAL",
            "count": 1373
        },
        ...
    ]

    Returns:
        list[dict]
    """

    result = _request(
        "GET",
        "/api/metrics/severity",
    )

    # Current API returns a list directly.
    if isinstance(result, list):
        return result

    # Defensive support for:
    #
    # {
    #     "severity": [...]
    # }

    if isinstance(result, dict):

        severity = result.get(
            "severity",
            [],
        )

        if isinstance(severity, list):
            return severity

    return []


# ============================================================
# RECENT ALERTS
# ============================================================

def get_recent_alerts(
    limit=20,
):
    """
    Retrieve the most recent alerts.

    Returns:
        list[dict]
    """

    result = _request(
        "GET",
        "/api/alerts/recent",
        params={
            "limit": limit,
        },
    )

    # Current API:
    #
    # {
    #     "count": 5,
    #     "alerts": [...]
    # }

    if isinstance(result, dict):

        alerts = result.get(
            "alerts",
            [],
        )

        if isinstance(alerts, list):
            return alerts

        return []

    # Defensive fallback
    if isinstance(result, list):
        return result

    return []


# ============================================================
# CONNECTION TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("CYBERSENTINEL API CLIENT TEST")
    print("=" * 60)

    # --------------------------------------------------------
    # Health
    # --------------------------------------------------------

# ============================================================
# REPLAY HISTORY
# ============================================================

def get_replays():
    data = _request("GET", "/api/replays")
    return data.get("replays", [])


def get_replay(replay_id: str):
    return _request("GET", f"/api/replays/{replay_id}")


# ============================================================
# REAL-TIME STREAMING CLIENT
# ============================================================

def get_stream_status():
    return _request("GET", "/api/stream/status")


def start_stream(batch_size=50, delay=0.5, flows=None, continuous=False, seed=42, target_attack_ratio=0.30):
    return _request(
        "POST",
        "/api/stream/start",
        json={
            "batch_size": batch_size,
            "delay": delay,
            "flows": flows,
            "continuous": continuous,
            "seed": seed,
            "target_attack_ratio": target_attack_ratio,
        },
    )



def stop_stream():
    return _request("POST", "/api/stream/stop")


def pause_stream():
    return _request("POST", "/api/stream/pause")


def resume_stream():
    return _request("POST", "/api/stream/resume")


# ============================================================
# REAL NETWORK STREAMING HELPERS (PHASE 2)
# ============================================================

def get_network_interfaces():
    return _request("GET", "/api/network/interfaces")


def get_network_status():
    return _request("GET", "/api/network/status")


def start_network_pcap(pcap_path, batch_size=20, flow_timeout=10.0):
    return _request(
        "POST",
        "/api/network/start",
        json={
            "source_type": "pcap",
            "pcap_path": pcap_path,
            "batch_size": batch_size,
            "flow_timeout": flow_timeout,
        },
    )


def start_network_live(interface, batch_size=20, flow_timeout=10.0):
    return _request(
        "POST",
        "/api/network/start",
        json={
            "source_type": "live",
            "interface": interface,
            "batch_size": batch_size,
            "flow_timeout": flow_timeout,
        },
    )


def stop_network_stream():
    return _request("POST", "/api/network/stop")


def get_network_flows():
    return _request("GET", "/api/network/flows")


# ============================================================
# PHASE 3A — INCIDENT CLIENT HELPERS
# ============================================================

def get_incidents(status=None, severity=None, limit=100):
    params = {"limit": limit}
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity
    res = _request("GET", "/api/incidents", params=params)
    if isinstance(res, dict):
        return res.get("incidents", [])
    return []


def get_incident(incident_id):
    res = _request("GET", f"/api/incidents/{incident_id}")
    if isinstance(res, dict):
        return res.get("incident")
    return None


def update_incident_status(incident_id, status, actor="ANALYST"):
    res = _request(
        "POST",
        f"/api/incidents/{incident_id}/status",
        json={"status": status, "actor": actor},
    )
    if isinstance(res, dict):
        return res.get("incident")
    return None


def assign_incident(incident_id, assigned_to, actor="ANALYST"):
    res = _request(
        "POST",
        f"/api/incidents/{incident_id}/assign",
        json={"assigned_to": assigned_to, "actor": actor},
    )
    if isinstance(res, dict):
        return res.get("incident")
    return None


def get_incident_alerts(incident_id):
    res = _request("GET", f"/api/incidents/{incident_id}/alerts")
    if isinstance(res, dict):
        return res.get("alerts", [])
    return []


def get_incident_timeline(incident_id):
    res = _request("GET", f"/api/incidents/{incident_id}/timeline")
    if isinstance(res, dict):
        return res.get("timeline", [])
    return []


# ============================================================
# PHASE 3B — THREAT INTELLIGENCE, RULES & MITRE CLIENT HELPERS
# ============================================================

def get_indicators(indicator_type=None, limit=100):
    params = {"limit": limit}
    if indicator_type:
        params["indicator_type"] = indicator_type
    res = _request("GET", "/api/intel/indicators", params=params)
    if isinstance(res, dict):
        return res.get("indicators", [])
    return []


def get_indicator_by_value(value):
    res = _request("GET", f"/api/intel/indicators/{value}")
    if isinstance(res, dict):
        return res.get("indicator")
    return None


def add_indicator(indicator_type, indicator_value, threat_name="Known Malicious Entity", confidence=0.90, severity="HIGH", source="LOCAL_SOC", description=None):
    res = _request(
        "POST",
        "/api/intel/indicators",
        json={
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "threat_name": threat_name,
            "confidence": confidence,
            "severity": severity,
            "source": source,
            "description": description,
        },
    )
    if isinstance(res, dict):
        return res.get("indicator")
    return None


def remove_indicator(indicator_id):
    return _request("DELETE", f"/api/intel/indicators/{indicator_id}")


def enrich_alert_intel(alert_id):
    res = _request("GET", f"/api/intel/enrich/{alert_id}")
    if isinstance(res, dict):
        return res.get("enriched_alert")
    return None


def get_rules():
    res = _request("GET", "/api/rules")
    if isinstance(res, dict):
        return res.get("rules", [])
    return []


def get_rule(rule_id):
    res = _request("GET", f"/api/rules/{rule_id}")
    if isinstance(res, dict):
        return res.get("rule")
    return None


def get_mitre_techniques():
    res = _request("GET", "/api/mitre/techniques")
    if isinstance(res, dict):
        return res.get("techniques", [])
    return []


def get_mitre_tactics():
    res = _request("GET", "/api/mitre/tactics")
    if isinstance(res, dict):
        return res.get("tactics", [])
    return []


def get_mitre_coverage():
    return _request("GET", "/api/mitre/coverage")


def get_incident_intelligence(incident_id):
    res = _request("GET", f"/api/incidents/{incident_id}/intelligence")
    if isinstance(res, dict):
        return res.get("incident_intelligence")
    return None


# ============================================================
# PHASE 4 — SOC ANALYTICS & MODEL MONITORING CLIENT HELPERS
# ============================================================

def get_analytics_summary(window="24h"):
    return _request("GET", "/api/analytics/summary", params={"window": window})


def get_analytics_trends(window="24h"):
    return _request("GET", "/api/analytics/trends", params={"window": window})


def get_analytics_attacks(window="24h"):
    return _request("GET", "/api/analytics/attacks", params={"window": window})


def get_analytics_severity(window="24h"):
    return _request("GET", "/api/analytics/severity", params={"window": window})


def get_analytics_entities(window="24h", limit=10):
    return _request("GET", "/api/analytics/entities", params={"window": window, "limit": limit})


def get_analytics_protocols(window="24h"):
    return _request("GET", "/api/analytics/protocols", params={"window": window})


def get_analytics_incidents(window="24h"):
    return _request("GET", "/api/analytics/incidents", params={"window": window})


def get_analytics_model(window="24h"):
    return _request("GET", "/api/analytics/model", params={"window": window})


def get_analytics_dataset():
    return _request("GET", "/api/analytics/dataset")




    health = get_health()

    print("\nAPI Health:")
    print(health)

    # --------------------------------------------------------
    # SOC metrics
    # --------------------------------------------------------

    metrics = get_soc_metrics()

    print("\nSOC Metrics:")
    print(metrics)

    # --------------------------------------------------------
    # Status metrics
    # --------------------------------------------------------

    status = get_status_metrics()

    print("\nStatus Metrics:")
    print(status)

    # --------------------------------------------------------
    # Attack metrics
    # --------------------------------------------------------

    attacks = get_attack_metrics()

    print(
        "\nAttack Metrics:"
    )

    print(attacks)

    # --------------------------------------------------------
    # Severity metrics
    # --------------------------------------------------------

    severity = get_severity_metrics()

    print(
        "\nSeverity Metrics:"
    )

    print(severity)

    # --------------------------------------------------------
    # Recent alerts
    # --------------------------------------------------------

    alerts = get_recent_alerts(
        limit=5
    )

    print(
        f"\nRecent alerts returned: "
        f"{len(alerts)}"
    )

    # --------------------------------------------------------
    # Sample alert
    # --------------------------------------------------------

    if alerts:

        print(
            "\nSample recent alert:"
        )

        print(
            alerts[0]
        )

    # --------------------------------------------------------
    # Complete
    # --------------------------------------------------------

    print(
        "\nAPI client test completed successfully."
    )