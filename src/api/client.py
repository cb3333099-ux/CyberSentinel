import requests


# ============================================================
# CONFIGURATION
# ============================================================

API_BASE_URL = "http://localhost:8000"


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
    limit=100,
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