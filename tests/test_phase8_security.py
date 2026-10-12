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
