import os
import sqlite3
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.soc.alert_store import get_connection, initialize_database
from src.soc.auth_service import (
    authenticate_user,
    count_admins,
    create_session,
    create_user,
    deactivate_user,
    get_auth_audit_logs,
    get_user_by_username,
    hash_password,
    invalidate_session,
    list_users,
    reactivate_user,
    reset_password,
    setup_initial_admin,
    validate_session,
    verify_password,
)
from src.soc.db_backup import (
    create_backup,
    list_backups,
    restore_backup,
    validate_backup,
)


@pytest.fixture(autouse=True)
def isolated_test_db(tmp_path, monkeypatch):
    """
    Ensures every test runs against an isolated SQLite test database and backup dir.
    """
    db_file = tmp_path / "test_soc.db"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("CYBERSENTINEL_SOC_DB_PATH", str(db_file))
    monkeypatch.setenv("CYBERSENTINEL_BACKUP_DIR", str(backup_dir))

    initialize_database()
    yield db_file


# ============================================================
# 1. PASSWORD HASHING & CRYPTOGRAPHY TESTS
# ============================================================

def test_password_hashing_and_verification():
    raw_pass = "P@ssw0rdSecure123!"
    p_hash = hash_password(raw_pass)

    assert p_hash.startswith("pbkdf2_sha256$")
    assert verify_password(raw_pass, p_hash) is True
    assert verify_password("WrongPassword!", p_hash) is False
    assert verify_password("", p_hash) is False


def test_password_hashing_rejects_short_passwords():
    with pytest.raises(ValueError, match="at least 8 characters"):
        hash_password("short")


def test_verify_password_handles_corrupt_hashes():
    assert verify_password("Password123", "corrupt_hash_format") is False
    assert verify_password("Password123", "pbkdf2_sha256$1000$bad$salt") is False


# ============================================================
# 2. USER MANAGEMENT & FIRST-ADMIN BOOTSTRAP
# ============================================================

def test_setup_initial_admin_and_prevent_duplicate():
    assert count_admins() == 0

    admin = setup_initial_admin("soc_admin", "AdminPassword123!", display_name="Primary Admin")
    assert admin["username"] == "soc_admin"
    assert admin["role"] == "admin"
    assert count_admins() == 1

    # Second bootstrap attempt must be rejected
    with pytest.raises(ValueError, match="already.*configured"):
        setup_initial_admin("second_admin", "AnotherPassword123!")


def test_user_crud_and_status_transitions():
    setup_initial_admin("admin_user", "AdminSecret123!")

    # Create analyst and read_only users
    analyst = create_user("analyst_bob", "AnalystPass123!", role="analyst", display_name="Bob Analyst", actor="admin_user")
    assert analyst["username"] == "analyst_bob"
    assert analyst["role"] == "analyst"

    reader = create_user("reader_alice", "ReaderPass123!", role="read_only", display_name="Alice Reader", actor="admin_user")
    assert reader["role"] == "read_only"

    # Verify listing users
    all_users = list_users()
    assert len(all_users) == 3
    for u in all_users:
        assert "password_hash" not in u

    # Deactivate analyst
    deactivate_user(analyst["user_id"], actor="admin_user")
    u_deact, _ = authenticate_user("analyst_bob", "AnalystPass123!")
    assert u_deact is None

    # Reactivate analyst
    reactivate_user(analyst["user_id"], actor="admin_user")
    u_react, _ = authenticate_user("analyst_bob", "AnalystPass123!")
    assert u_react is not None

    # Reset password
    reset_password(analyst["user_id"], "NewAnalystPass123!", actor="admin_user")
    u_old, _ = authenticate_user("analyst_bob", "AnalystPass123!")
    assert u_old is None
    u_new, _ = authenticate_user("analyst_bob", "NewAnalystPass123!")
    assert u_new is not None


# ============================================================
# 3. SESSIONS AND EXPIRATION
# ============================================================

def test_session_lifecycle_and_invalidation():
    setup_initial_admin("admin_user", "AdminSecret123!")
    user, _ = authenticate_user("admin_user", "AdminSecret123!")
    assert user is not None

    session = create_session(user)
    token = session["session_token"]

    validated = validate_session(token)
    assert validated is not None
    assert validated["username"] == "admin_user"

    # Logout / Invalidate
    assert invalidate_session(token) is True
    assert validate_session(token) is None


def test_expired_session_is_rejected(monkeypatch):
    setup_initial_admin("admin_user", "AdminSecret123!")
    user, _ = authenticate_user("admin_user", "AdminSecret123!")
    session = create_session(user)
    token = session["session_token"]

    # Directly expire the token in database
    conn = get_connection()
    conn.execute("UPDATE user_sessions SET expires_at = '2000-01-01T00:00:00+00:00' WHERE session_id = ?", (token,))
    conn.commit()
    conn.close()

    assert validate_session(token) is None


# ============================================================
# 4. HEALTH & READINESS PROBES
# ============================================================

def test_health_and_readiness_endpoints():
    client = TestClient(app)

    res_h = client.get("/health")
    assert res_h.status_code == 200
    assert res_h.json()["status"] == "healthy"

    res_r = client.get("/ready")
    assert res_r.status_code == 200
    data = res_r.json()
    assert data["status"] == "ready"
    assert data["database_ready"] is True
    assert "config" in data
    assert "db_configured" in data["config"]


# ============================================================
# 5. RESTFUL API AUTHENTICATION & RBAC ENFORCEMENT
# ============================================================

def test_api_auth_middleware_blocks_unauthenticated_requests(monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_AUTH_ENABLED", "true")
    client = TestClient(app)

    # Health and public auth status remain open
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert client.get("/api/auth/status").status_code == 200

    # Protected endpoints require auth
    res = client.get("/api/alerts")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]

    res_inc = client.get("/api/incidents")
    assert res_inc.status_code == 401

    res_rules = client.get("/api/rules")
    assert res_rules.status_code == 401


def test_api_rbac_roles_permissions(monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_AUTH_ENABLED", "true")
    client = TestClient(app)

    # 1. Setup admin
    setup_res = client.post("/api/auth/setup-admin", json={
        "username": "super_admin",
        "password": "AdminPassword123!",
        "display_name": "Super Admin",
    })
    assert setup_res.status_code == 200
    admin_token = setup_res.json()["session"]["session_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 2. Admin creates analyst and read_only users
    r_analyst = client.post("/api/users", json={
        "username": "analyst_carol",
        "password": "CarolPassword123!",
        "role": "analyst",
    }, headers=admin_headers)
    assert r_analyst.status_code == 200

    r_reader = client.post("/api/users", json={
        "username": "reader_dave",
        "password": "DavePassword123!",
        "role": "read_only",
    }, headers=admin_headers)
    assert r_reader.status_code == 200

    # 3. Log in as analyst and read_only
    analyst_login = client.post("/api/auth/login", json={"username": "analyst_carol", "password": "CarolPassword123!"})
    assert analyst_login.status_code == 200
    analyst_token = analyst_login.json()["session_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    reader_login = client.post("/api/auth/login", json={"username": "reader_dave", "password": "DavePassword123!"})
    assert reader_login.status_code == 200
    reader_token = reader_login.json()["session_token"]
    reader_headers = {"Authorization": f"Bearer {reader_token}"}

    # 4. READ-ONLY USER PERMISSIONS
    # Can view alerts, incidents, rules
    assert client.get("/api/alerts", headers=reader_headers).status_code == 200
    assert client.get("/api/incidents", headers=reader_headers).status_code == 200
    assert client.get("/api/rules", headers=reader_headers).status_code == 200

    # CANNOT modify incidents -> 403 Forbidden
    inc_mut = client.post("/api/incidents/INC-NONEXIST/status", json={"status": "INVESTIGATING"}, headers=reader_headers)
    assert inc_mut.status_code == 403

    # CANNOT create rules -> 403 Forbidden
    rule_mut = client.post("/api/rules", json={"rule_id": "RULE-TEST", "rule_name": "Test", "severity": "HIGH"}, headers=reader_headers)
    assert rule_mut.status_code == 403

    # CANNOT manage users -> 403 Forbidden
    user_mut = client.post("/api/users", json={"username": "hacker", "password": "HackerPass123!"}, headers=reader_headers)
    assert user_mut.status_code == 403

    # CANNOT run backup -> 403 Forbidden
    b_mut = client.post("/api/admin/backup", headers=reader_headers)
    assert b_mut.status_code == 403

    # 5. ANALYST USER PERMISSIONS
    # Analyst CAN manage detection rules
    create_rule_res = client.post("/api/rules", json={
        "rule_id": "RULE-PHASE8-TEST",
        "rule_name": "Phase 8 Test Rule",
        "description": "Rule created during Phase 8 RBAC integration testing.",
        "severity": "HIGH",
        "threshold_value": 3.0,
        "window_seconds": 60,
    }, headers=analyst_headers)
    assert create_rule_res.status_code == 200

    # Analyst CANNOT manage users -> 403 Forbidden
    analyst_create_user = client.post("/api/users", json={"username": "user_two", "password": "Password123!"}, headers=analyst_headers)
    assert analyst_create_user.status_code == 403

    # Analyst CANNOT access admin backup endpoints -> 403 Forbidden
    assert client.post("/api/admin/backup", headers=analyst_headers).status_code == 403
    assert client.get("/api/admin/backups", headers=analyst_headers).status_code == 403

    # 6. ADMIN USER PERMISSIONS
    # Admin CAN create backup
    admin_backup = client.post("/api/admin/backup?label=test-admin-b", headers=admin_headers)
    assert admin_backup.status_code == 200
    assert "backup_file" in admin_backup.json()

    # Admin CAN list users
    users_list_res = client.get("/api/users", headers=admin_headers)
    assert users_list_res.status_code == 200
    assert users_list_res.json()["count"] == 3


# ============================================================
# 6. DATABASE BACKUP AND RECOVERY UTILITIES
# ============================================================

def test_database_backup_validation_and_safe_restore(isolated_test_db, tmp_path):
    # Insert some initial data into test DB
    conn = get_connection()
    conn.execute(
        "INSERT INTO alerts (alert_id, timestamp, source_ip, destination_ip, attack_type, severity, confidence, status, created_at, updated_at) "
        "VALUES ('ALT-BACKUP-1', '2026-10-12T10:00:00Z', '10.0.0.1', '10.0.0.2', 'Bot', 'HIGH', 0.95, 'NEW', '2026-10-12T10:00:00Z', '2026-10-12T10:00:00Z')"
    )
    conn.commit()
    conn.close()

    # 1. Create backup
    backup_meta = create_backup(label="snapshot-one")
    b_path = backup_meta["full_path"]
    assert Path(b_path).exists()
    assert backup_meta["size_bytes"] > 0

    # 2. List backups
    backups = list_backups()
    assert len(backups) >= 1
    assert any(b["backup_file"] == backup_meta["backup_file"] for b in backups)

    # 3. Validate backup
    is_valid, msg = validate_backup(b_path)
    assert is_valid is True
    assert "passed PRAGMA integrity_check" in msg

    # Validate corrupt file detection
    corrupt_file = tmp_path / "corrupt.db"
    corrupt_file.write_text("NOT A SQLITE DATABASE FILE")
    bad_valid, bad_msg = validate_backup(str(corrupt_file))
    assert bad_valid is False
    assert "Invalid SQLite header" in bad_msg

    # 4. Modify live database
    conn2 = get_connection()
    conn2.execute("DELETE FROM alerts WHERE alert_id = 'ALT-BACKUP-1'")
    conn2.commit()
    count_now = conn2.execute("SELECT count(*) FROM alerts WHERE alert_id = 'ALT-BACKUP-1'").fetchone()[0]
    conn2.close()
    assert count_now == 0

    # 5. Restore backup requiring confirmation string
    with pytest.raises(ValueError, match="Safety check failed"):
        restore_backup(b_path, confirmation="wrong_confirmation")

    restore_res = restore_backup(b_path, confirmation="CONFIRM_RESTORE", actor="TEST-ADMIN")
    assert restore_res["success"] is True
    assert Path(restore_res["safety_snapshot"]).exists()

    # Verify restored database has the original alert record
    conn3 = get_connection()
    count_restored = conn3.execute("SELECT count(*) FROM alerts WHERE alert_id = 'ALT-BACKUP-1'").fetchone()[0]
    conn3.close()
    assert count_restored == 1


# ============================================================
# 7. SECURITY AUDITING & SECRET REDACTION
# ============================================================

def test_auth_audit_logs_record_events_without_secrets():
    setup_initial_admin("sec_admin", "SecPassword123!")
    authenticate_user("sec_admin", "SecPassword123!")
    authenticate_user("sec_admin", "WrongPasswordAttempt")

    logs = get_auth_audit_logs(limit=20)
    assert len(logs) >= 2

    for log in logs:
        # Passwords and session tokens must never appear in audit details
        log_str = str(log)
        assert "SecPassword123!" not in log_str
        assert "WrongPasswordAttempt" not in log_str


# ============================================================
# 8. REGRESSION TESTS: PHASE 8 ADMINISTRATION FIXES
# ============================================================

def test_user_listing_schema_alignment_and_optional_last_login():
    """
    Regression test for User Management:
    Ensures user listing preserves database schema (last_login_at), provides last_login alias,
    gracefully handles unauthenticated users without inventing fake values, and renders safely in DataFrame.
    """
    import pandas as pd

    setup_initial_admin("lead_admin", "AdminPassword123!", display_name="Lead Admin")
    analyst = create_user("new_analyst", "AnalystSecret123!", role="analyst", display_name="New Analyst")

    # 1. Direct auth_service list_users
    users = list_users()
    assert len(users) >= 2

    analyst_record = next(u for u in users if u["username"] == "new_analyst")
    # New user who never logged in must have None for last_login_at and last_login without invented values
    assert analyst_record.get("last_login_at") is None
    assert analyst_record.get("last_login") is None
    assert analyst_record["is_active"] is True
    assert "password_hash" not in analyst_record

    # 2. DataFrame rendering simulation matching Streamlit dashboard
    df_users = pd.DataFrame(users)
    login_col = "last_login_at" if "last_login_at" in df_users.columns else ("last_login" if "last_login" in df_users.columns else None)
    assert login_col is not None

    base_cols = ["user_id", "username", "role", "display_name", "is_active", "created_at"]
    for c in base_cols:
        assert c in df_users.columns

    rendered_df = df_users[base_cols + [login_col]].rename(columns={
        "user_id": "USER ID",
        "username": "USERNAME",
        "role": "ROLE",
        "display_name": "DISPLAY NAME",
        "is_active": "ACTIVE",
        "created_at": "CREATED AT",
        login_col: "LAST LOGIN",
    })
    assert "LAST LOGIN" in rendered_df.columns
    assert len(rendered_df) == len(users)

    # 3. Authenticate analyst and verify last_login_at updates to real ISO timestamp
    user_clean, err = authenticate_user("new_analyst", "AnalystSecret123!")
    assert err is None
    assert user_clean["last_login_at"] is not None
    assert user_clean["last_login"] == user_clean["last_login_at"]

    users_after_login = list_users()
    updated_analyst = next(u for u in users_after_login if u["username"] == "new_analyst")
    assert updated_analyst["last_login_at"] == user_clean["last_login_at"]
    assert updated_analyst["last_login"] == user_clean["last_login_at"]

    # 4. API endpoint test via TestClient
    client = TestClient(app)
    admin_auth = authenticate_user("lead_admin", "AdminPassword123!")[0]
    admin_sess = create_session(admin_auth)
    headers = {"Authorization": f"Bearer {admin_sess['session_token']}"}

    res = client.get("/api/users", headers=headers)
    assert res.status_code == 200
    api_users = res.json()["users"]
    target_api_u = next(u for u in api_users if u["username"] == "new_analyst")
    assert "last_login_at" in target_api_u
    assert "last_login" in target_api_u


def test_security_audit_logs_retrieval_and_dataframe_rendering():
    """
    Regression test for Security Audit Logs:
    Ensures auth_audit_log schema fields (audit_id, event_type, username, actor, timestamp)
    are preserved, API responses are unpacked correctly, and DataFrame renderer avoids missing-column errors.
    """
    import pandas as pd
    from src.api.client import get_auth_audit_logs as client_get_audit_logs

    setup_initial_admin("audit_admin", "AdminPassword123!")
    authenticate_user("audit_admin", "AdminPassword123!")
    authenticate_user("audit_admin", "WrongPassword!")

    # 1. Direct auth_service get_auth_audit_logs
    logs = get_auth_audit_logs(limit=50)
    assert len(logs) >= 3

    for entry in logs:
        assert "audit_id" in entry
        assert "event_type" in entry
        assert "username" in entry
        assert "actor" in entry
        assert "timestamp" in entry
        assert entry["audit_id"].startswith("AUTH-")

    # 2. API endpoint /api/auth/audit via TestClient
    client = TestClient(app)
    admin_u = authenticate_user("audit_admin", "AdminPassword123!")[0]
    admin_sess = create_session(admin_u)
    headers = {"Authorization": f"Bearer {admin_sess['session_token']}"}

    api_res = client.get("/api/auth/audit?limit=50", headers=headers)
    assert api_res.status_code == 200
    res_body = api_res.json()
    assert "count" in res_body
    assert "logs" in res_body
    assert isinstance(res_body["logs"], list)

    # 3. client.py helper unpacking
    unpacked_logs = client_get_audit_logs(limit=50)
    assert isinstance(unpacked_logs, list)
    assert len(unpacked_logs) >= 3

    # 4. Streamlit DataFrame rendering simulation with column rename
    df_audit = pd.DataFrame(unpacked_logs)
    expected_cols = ["audit_id", "event_type", "username", "actor", "timestamp"]
    for col in expected_cols:
        assert col in df_audit.columns

    rendered_audit = df_audit[expected_cols].rename(columns={
        "audit_id": "AUDIT ID",
        "event_type": "EVENT",
        "username": "TARGET USER",
        "actor": "ACTOR",
        "timestamp": "TIMESTAMP",
    })
    assert list(rendered_audit.columns) == ["AUDIT ID", "EVENT", "TARGET USER", "ACTOR", "TIMESTAMP"]
    assert len(rendered_audit) >= 3


def test_ml_readiness_model_paths_and_diagnostics_probe(monkeypatch):
    """
    Regression test for ML Readiness:
    Ensures configured model paths match actual trained model artifacts, /ready endpoint reports
    ml_engine_ready: True, and fallback occurs gracefully if model artifacts are truly missing.
    """
    from src.config import get_system_config_summary, STAGE1_MODEL_PATH, STAGE2_MODEL_PATH
    from src.api.client import get_readiness as client_get_readiness

    # 1. Configuration summary checks
    cfg = get_system_config_summary()
    assert cfg["stage1_model_exists"] is True
    assert cfg["stage2_model_exists"] is True
    assert Path(cfg["stage1_model_path"]).exists()
    assert Path(cfg["stage2_model_path"]).exists()

    # Model paths should resolve to actual trained model artifacts
    assert "stage1_random_forest" in cfg["stage1_model_path"]
    assert "stage2_attack_classifier" in cfg["stage2_model_path"]

    # 2. FastAPI /ready probe via TestClient
    client = TestClient(app)
    ready_res = client.get("/ready")
    assert ready_res.status_code == 200
    ready_data = ready_res.json()
    assert ready_data["status"] == "ready"
    assert ready_data["ml_engine_ready"] is True
    assert ready_data["database_ready"] is True

    # 3. Client get_readiness probe
    c_ready = client_get_readiness()
    assert c_ready["ml_engine_ready"] is True
    assert c_ready["status"] == "ready"

    # 4. Genuine unavailability handling: when models are missing, report limitation clearly
    monkeypatch.setenv("CYBERSENTINEL_STAGE1_MODEL_PATH", "/nonexistent/stage1/model")
    cfg_missing = get_system_config_summary()
    assert cfg_missing["stage1_model_exists"] is False

    ready_res_missing = client.get("/ready")
    assert ready_res_missing.status_code == 200
    assert ready_res_missing.json()["ml_engine_ready"] is False
