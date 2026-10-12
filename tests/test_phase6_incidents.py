from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.soc.alert_store import get_connection, initialize_database
from src.soc.incident_engine import (
    IncidentEngine,
    add_incident_evidence,
    add_incident_note,
    get_incident,
    get_incident_evidence_list,
    get_incident_notes,
    get_incident_report,
    get_incident_timeline,
    get_response_recommendations,
    render_incident_report_markdown,
    review_response_recommendation,
    update_incident_status,
)


client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_phase6_records():
    initialize_database()
    conn = get_connection()
    conn.execute("DELETE FROM incident_recommendation_reviews")
    conn.execute("DELETE FROM incident_evidence")
    conn.execute("DELETE FROM incident_notes")
    conn.execute("DELETE FROM incident_timeline")
    conn.execute("DELETE FROM incident_alerts")
    conn.execute("DELETE FROM incidents")
    conn.execute("DELETE FROM alerts WHERE alert_id LIKE 'phase6_%'")
    conn.commit()
    conn.close()
    yield


def create_incident():
    return IncidentEngine.correlate_alert({
        "alert_id": "phase6_alert_01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_type": "SSH-Bruteforce",
        "severity": "HIGH",
        "confidence": 0.95,
        "destination_port": 22,
        "protocol": "TCP",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
    })


def test_notes_evidence_and_timeline_persist():
    incident_id = create_incident()
    note = add_incident_note(incident_id, "Validated the source against retained telemetry.", "Analyst-A")
    evidence = add_incident_evidence(
        incident_id,
        "pcap",
        "Captured flow metadata for the investigation.",
        "sensor-01",
        "2026-10-12T10:00:00+00:00",
    )

    assert note["author"] == "Analyst-A"
    assert evidence["evidence_type"] == "pcap"
    assert get_incident_notes(incident_id)[0]["note_id"] == note["note_id"]
    assert get_incident_evidence_list(incident_id)[0]["evidence_id"] == evidence["evidence_id"]
    assert {event["event_type"] for event in get_incident_timeline(incident_id)} >= {"NOTE_ADDED", "EVIDENCE_REGISTERED"}


def test_lifecycle_rejects_invalid_transition_and_stores_resolution():
    incident_id = create_incident()
    with pytest.raises(ValueError, match="Invalid incident transition"):
        update_incident_status(incident_id, "RESOLVED", actor="Analyst-A")

    update_incident_status(incident_id, "INVESTIGATING", actor="Analyst-A")
    resolved = update_incident_status(
        incident_id,
        "RESOLVED",
        actor="Analyst-A",
        resolution_summary="Blocked the source and confirmed no further activity.",
    )
    assert resolved["resolution_summary"] == "Blocked the source and confirmed no further activity."
    assert resolved["resolved_at"]


def test_recommendations_are_reviewable_and_reports_are_complete():
    incident_id = create_incident()
    recommendations = get_response_recommendations(incident_id)
    assert recommendations
    assert all(item["performed"] is False for item in recommendations)
    assert recommendations[0]["mitre_attack"]["technique_id"] == "T1110"

    reviewed = review_response_recommendation(
        incident_id,
        recommendations[0]["recommendation_id"],
        "APPROVED",
        reviewer="Lead-A",
        comment="Proceed through the approved change process.",
    )
    assert reviewed["review_status"] == "APPROVED"

    report = get_incident_report(incident_id)
    assert report["incident"]["incident_id"] == incident_id
    assert report["related_alerts"]
    assert report["timeline"]
    assert "# Incident" in render_incident_report_markdown(report)


def test_phase6_validation_for_missing_incident_and_bad_timestamp():
    assert add_incident_note("INC-MISSING", "test", "Analyst") is None
    assert add_incident_evidence("INC-MISSING", "log", "test", "sensor") is None
    incident_id = create_incident()
    with pytest.raises(ValueError, match="ISO-8601"):
        add_incident_evidence(incident_id, "log", "test", "sensor", "not-a-date")


def test_phase6_api_validation_and_report_endpoints():
    incident_id = create_incident()
    response = client.post(f"/api/incidents/{incident_id}/notes", json={"content": "API note", "author": "API-A"})
    assert response.status_code == 200
    assert response.json()["note"]["author"] == "API-A"

    response = client.post(
        f"/api/incidents/{incident_id}/evidence",
        json={"evidence_type": "log", "description": "API evidence", "source": "sensor-api"},
    )
    assert response.status_code == 200

    response = client.post(f"/api/incidents/{incident_id}/status", json={"status": "RESOLVED", "actor": "API-A"})
    assert response.status_code == 400
    assert "Invalid incident transition" in response.json()["detail"]

    response = client.get(f"/api/incidents/{incident_id}/report?format=markdown")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert "API note" in response.text

    assert client.get("/api/incidents/INC-MISSING/notes").status_code == 404
    assert client.get(f"/api/incidents/{incident_id}/report?format=xml").status_code == 400
