import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.config import HASH_ITERATIONS, TOKEN_EXPIRE_MINUTES
from src.soc.alert_store import get_connection, initialize_database


VALID_ROLES = {"admin", "analyst", "read_only"}


# ============================================================
# CRYPTOGRAPHIC PASSWORD HASHING (PBKDF2-HMAC-SHA256)
# ============================================================

def hash_password(password: str) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a cryptographically random 16-byte salt.
    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        HASH_ITERATIONS,
    )
    return f"pbkdf2_sha256${HASH_ITERATIONS}${salt}${dk.hex()}"


def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    Constant-time password hash verification against timing attacks.
    """
    if not plain_password or not password_hash:
        return False
    try:
        parts = password_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        stored_hash = bytes.fromhex(parts[3])
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(stored_hash, computed_hash)
    except Exception:
        return False


# ============================================================
# AUDIT LOGGING
# ============================================================

def record_auth_audit(
    event_type: str,
    username: str,
    actor: str = "SYSTEM",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Records security/authentication audit log. Never logs passwords or tokens.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    audit_id = f"AUTH-{secrets.token_hex(8).upper()}"
    details_str = json.dumps(details or {})
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO auth_audit_log (audit_id, event_type, username, actor, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (audit_id, event_type, username, actor, details_str, now_iso),
        )
        conn.commit()
    finally:
        conn.close()


def get_auth_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM auth_audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d.get("details") or "{}")
            except Exception:
                d["details"] = {}
            result.append(d)
        return result
    finally:
        conn.close()


# ============================================================
# USER MANAGEMENT & REPOSITORY
# ============================================================

def _clean_user_dict(row: Any) -> Dict[str, Any]:
    d = dict(row)
    d.pop("password_hash", None)
    d["is_active"] = bool(d.get("is_active", 1))
    return d


def count_admins() -> int:
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM users WHERE role = 'admin' AND is_active = 1")
        row = cursor.fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def get_user_by_username(username: str, include_hash: bool = False) -> Optional[Dict[str, Any]]:
    username_clean = str(username or "").strip().lower()
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username_clean,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        d["is_active"] = bool(d.get("is_active", 1))
        if not include_hash:
            d.pop("password_hash", None)
        return d
    finally:
        conn.close()


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (str(user_id).strip(),))
        row = cursor.fetchone()
        if not row:
            return None
        return _clean_user_dict(row)
    finally:
        conn.close()


def list_users() -> List[Dict[str, Any]]:
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY created_at ASC")
        return [_clean_user_dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def create_user(
    username: str,
    password: str,
    role: str = "analyst",
    display_name: Optional[str] = None,
    actor: str = "ADMIN",
) -> Dict[str, Any]:
    username_clean = str(username or "").strip().lower()
    if not re.match(r"^[a-z0-9_\-\.]{3,32}$", username_clean):
        raise ValueError("Username must be 3-32 characters and contain only lowercase letters, numbers, hyphens, underscores, or dots")

    role_clean = str(role or "").strip().lower()
    if role_clean not in VALID_ROLES:
        raise ValueError(f"Role must be one of {sorted(list(VALID_ROLES))}")

    if get_user_by_username(username_clean):
        raise ValueError(f"User '{username_clean}' already exists")

    pwd_hash = hash_password(password)
    user_id = f"USR-{secrets.token_hex(6).upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    disp_name = str(display_name or username_clean).strip()

    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (user_id, username, password_hash, role, display_name, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (user_id, username_clean, pwd_hash, role_clean, disp_name, now_iso, now_iso),
        )
        conn.commit()
    finally:
        conn.close()

    record_auth_audit(
        event_type="USER_CREATED",
        username=username_clean,
        actor=actor,
        details={"user_id": user_id, "role": role_clean},
    )
    return get_user_by_id(user_id)  # type: ignore


def setup_initial_admin(username: str, password: str, display_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Sets up the first administrator. Only permitted when no active admin exists.
    """
    if count_admins() > 0:
        raise ValueError("Administrator has already been configured")
    return create_user(
        username=username,
        password=password,
        role="admin",
        display_name=display_name or "System Administrator",
        actor="BOOTSTRAP_SETUP",
    )


def deactivate_user(user_id: str, actor: str = "ADMIN") -> Dict[str, Any]:
    target = get_user_by_id(user_id)
    if not target:
        raise ValueError("User not found")
    if target["role"] == "admin" and count_admins() <= 1:
        raise ValueError("Cannot deactivate the only remaining administrator")

    now_iso = datetime.now(timezone.utc).isoformat()
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET is_active = 0, updated_at = ? WHERE user_id = ?",
            (now_iso, user_id),
        )
        # Invalidate active sessions immediately
        cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()

    record_auth_audit(
        event_type="USER_DEACTIVATED",
        username=target["username"],
        actor=actor,
        details={"user_id": user_id},
    )
    return get_user_by_id(user_id)  # type: ignore


def reactivate_user(user_id: str, actor: str = "ADMIN") -> Dict[str, Any]:
    target = get_user_by_id(user_id)
    if not target:
        raise ValueError("User not found")

    now_iso = datetime.now(timezone.utc).isoformat()
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET is_active = 1, updated_at = ? WHERE user_id = ?",
            (now_iso, user_id),
        )
        conn.commit()
    finally:
        conn.close()

    record_auth_audit(
        event_type="USER_REACTIVATED",
        username=target["username"],
        actor=actor,
        details={"user_id": user_id},
    )
    return get_user_by_id(user_id)  # type: ignore


def reset_password(user_id: str, new_password: str, actor: str = "ADMIN") -> Dict[str, Any]:
    target = get_user_by_id(user_id)
    if not target:
        raise ValueError("User not found")

    pwd_hash = hash_password(new_password)
    now_iso = datetime.now(timezone.utc).isoformat()
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE user_id = ?",
            (pwd_hash, now_iso, user_id),
        )
        # Invalidate existing sessions on password change
        cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()

    record_auth_audit(
        event_type="PASSWORD_RESET",
        username=target["username"],
        actor=actor,
        details={"user_id": user_id},
    )
    return get_user_by_id(user_id)  # type: ignore


# ============================================================
# SESSION MANAGEMENT & TOKENS
# ============================================================

def create_session(user: Any, expire_minutes: Optional[int] = None) -> Dict[str, Any]:
    if isinstance(user, (tuple, list)):
        user = user[0]
    if not isinstance(user, dict):
        raise ValueError(f"Expected user dict for create_session, got {type(user)}")

    expire_mins = expire_minutes or TOKEN_EXPIRE_MINUTES
    token = f"cys_{secrets.token_urlsafe(32)}"
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=expire_mins)

    now_iso = now.isoformat()
    expires_iso = expires_at.isoformat()

    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO user_sessions (session_id, user_id, username, role, created_at, expires_at, last_active_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (token, user["user_id"], user["username"], user["role"], now_iso, expires_iso, now_iso),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "token": token,
        "session_token": token,
        "expires_at": expires_iso,
        "session_id": token,
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "display_name": user.get("display_name", user["username"]),
        "user": {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "display_name": user.get("display_name", user["username"]),
        },
    }


def validate_session(token: str) -> Optional[Dict[str, Any]]:
    if not token or not isinstance(token, str):
        return None
    token_clean = token.strip()
    if token_clean.startswith("Bearer "):
        token_clean = token_clean[7:].strip()

    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT s.*, u.is_active, u.display_name
            FROM user_sessions s
            JOIN users u ON s.user_id = u.user_id
            WHERE s.session_id = ?
            """,
            (token_clean,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        d = dict(row)
        if not d.get("is_active"):
            # Inactive user; revoke session
            cursor.execute("DELETE FROM user_sessions WHERE session_id = ?", (token_clean,))
            conn.commit()
            return None

        now = datetime.now(timezone.utc)
        exp = datetime.fromisoformat(str(d["expires_at"]).replace("Z", "+00:00"))
        if now > exp:
            # Expired session; delete
            cursor.execute("DELETE FROM user_sessions WHERE session_id = ?", (token_clean,))
            conn.commit()
            return None

        # Session valid -> update last_active_at
        now_iso = now.isoformat()
        cursor.execute("UPDATE user_sessions SET last_active_at = ? WHERE session_id = ?", (now_iso, token_clean))
        conn.commit()

        return {
            "session_id": d["session_id"],
            "user_id": d["user_id"],
            "username": d["username"],
            "role": d["role"],
            "display_name": d.get("display_name") or d["username"],
            "expires_at": d["expires_at"],
        }
    finally:
        conn.close()


def invalidate_session(token: str) -> bool:
    if not token:
        return False
    token_clean = token.strip()
    if token_clean.startswith("Bearer "):
        token_clean = token_clean[7:].strip()

    session_info = validate_session(token_clean)
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_sessions WHERE session_id = ?", (token_clean,))
        conn.commit()
        if session_info:
            record_auth_audit(
                event_type="LOGOUT",
                username=session_info["username"],
                actor=session_info["username"],
            )
        return True
    finally:
        conn.close()


# ============================================================
# AUTHENTICATION WORKFLOW
# ============================================================

def authenticate_user(username: str, password: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    username_clean = str(username or "").strip().lower()
    user_record = get_user_by_username(username_clean, include_hash=True)
    if not user_record:
        record_auth_audit("LOGIN_FAILED", username_clean, actor="ANONYMOUS", details={"reason": "User does not exist"})
        return None, "Invalid username or password"

    if not user_record.get("is_active"):
        record_auth_audit("LOGIN_FAILED", username_clean, actor=username_clean, details={"reason": "Account is deactivated"})
        return None, "Account is deactivated. Contact an administrator."

    if not verify_password(password, user_record.get("password_hash", "")):
        record_auth_audit("LOGIN_FAILED", username_clean, actor=username_clean, details={"reason": "Incorrect password"})
        return None, "Invalid username or password"

    now_iso = datetime.now(timezone.utc).isoformat()
    initialize_database()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login_at = ? WHERE user_id = ?", (now_iso, user_record["user_id"]))
        conn.commit()
    finally:
        conn.close()

    record_auth_audit("LOGIN_SUCCESS", username_clean, actor=username_clean)
    user_clean = _clean_user_dict(user_record)
    user_clean["last_login_at"] = now_iso
    return user_clean, None
