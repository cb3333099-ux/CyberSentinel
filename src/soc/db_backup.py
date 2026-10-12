import hashlib
import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.config import get_backup_dir, get_soc_db_path
from src.soc.alert_store import get_connection, initialize_database


SQLITE_HEADER = b"SQLite format 3\x00"


def ensure_backup_dir() -> Path:
    bdir = get_backup_dir()
    bdir.mkdir(parents=True, exist_ok=True)
    return bdir


def compute_file_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def validate_backup(backup_path: str | Path) -> Tuple[bool, str]:
    """
    Validates that a backup file exists, is non-empty, possesses the valid SQLite header,
    and passes SQLite's internal integrity check (PRAGMA integrity_check).
    """
    path = Path(backup_path)
    if not path.exists():
        return False, f"Backup file does not exist: {path}"
    if not path.is_file():
        return False, f"Target path is not a file: {path}"
    if path.stat().st_size < 16:
        return False, "File is too small to be a valid SQLite database"

    # Check magic header bytes
    try:
        with open(path, "rb") as f:
            header = f.read(16)
        if header != SQLITE_HEADER:
            return False, "Invalid SQLite header magic bytes"
    except Exception as exc:
        return False, f"Failed to read file header: {exc}"

    if path.stat().st_size < 100:
        return False, "File is too small to be a valid SQLite database"

    # Run SQLite PRAGMA integrity check
    try:
        conn = sqlite3.connect(str(path))
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check")
        res = cursor.fetchone()
        conn.close()
        if not res or res[0] != "ok":
            return False, f"SQLite integrity check failed: {res[0] if res else 'Unknown'}"
    except Exception as exc:
        return False, f"SQLite integrity validation error: {exc}"

    return True, "Valid SQLite database backup (passed PRAGMA integrity_check)"


def create_backup(target_path: Optional[str | Path] = None, label: Optional[str] = None) -> Dict[str, Any]:
    """
    Creates a point-in-time, transactional backup of the active SOC database
    using SQLite's online backup API (sqlite3.Connection.backup).
    """
    initialize_database()
    ensure_backup_dir()

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    now_tag = now.strftime("%Y%m%d_%H%M%S")

    if target_path:
        dest_path = Path(target_path)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
    elif label:
        clean_lbl = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(label).strip())
        dest_path = get_backup_dir() / f"soc_backup_{clean_lbl}_{now_tag}.db"
    else:
        dest_path = get_backup_dir() / f"soc_backup_{now_tag}.db"

    # Connect to live source and empty destination
    source_conn = get_connection()
    try:
        dest_conn = sqlite3.connect(str(dest_path))
        try:
            # Perform atomic online backup
            source_conn.backup(dest_conn)
            dest_conn.commit()
        finally:
            dest_conn.close()
    finally:
        source_conn.close()

    # Validate newly generated backup
    is_valid, msg = validate_backup(dest_path)
    if not is_valid:
        if dest_path.exists():
            dest_path.unlink()
        raise RuntimeError(f"Generated backup failed validation: {msg}")

    checksum = compute_file_sha256(dest_path)
    size_bytes = dest_path.stat().st_size

    # Record audit log
    from src.soc.auth_service import record_auth_audit
    record_auth_audit(
        event_type="BACKUP_CREATED",
        username="SYSTEM",
        actor="SYSTEM",
        details={"backup_path": str(dest_path), "size_bytes": size_bytes, "sha256": checksum},
    )

    return {
        "status": "success",
        "success": True,
        "backup_path": str(dest_path),
        "full_path": str(dest_path),
        "filename": dest_path.name,
        "backup_file": dest_path.name,
        "size_bytes": size_bytes,
        "created_at": now_iso,
        "sha256": checksum,
        "validation": msg,
    }


def list_backups() -> List[Dict[str, Any]]:
    ensure_backup_dir()
    backups = []
    for file in sorted(get_backup_dir().glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True):
        is_valid, status_msg = validate_backup(file)
        backups.append({
            "filename": file.name,
            "backup_file": file.name,
            "filepath": str(file),
            "full_path": str(file),
            "size_bytes": file.stat().st_size,
            "created_at": datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc).isoformat(),
            "modified_at": datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc).isoformat(),
            "is_valid": is_valid,
            "status": status_msg,
        })
    return backups


def restore_backup(backup_path: str | Path, confirmation: str, actor: str = "ADMIN") -> Dict[str, Any]:
    """
    Safely restores the live SOC database from a verified backup file.
    Requires explicit confirmation string 'CONFIRM_RESTORE'.
    Creates a pre-restore safety snapshot before touching the live database.
    """
    if str(confirmation or "").strip() != "CONFIRM_RESTORE":
        raise ValueError("Safety check failed: Deliberate confirmation string 'CONFIRM_RESTORE' is required for database restoration")

    src_backup_path = Path(backup_path)
    is_valid, msg = validate_backup(src_backup_path)
    if not is_valid:
        raise ValueError(f"Cannot restore from invalid backup: {msg}")

    # Step 1: Create emergency safety backup of live DB before restoring
    now_tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safety_backup_path = get_backup_dir() / f"pre_restore_safety_{now_tag}.db"
    create_backup(safety_backup_path)

    # Step 2: Perform atomic online restore into live SOC DB
    backup_conn = sqlite3.connect(str(src_backup_path))
    live_conn = get_connection()
    try:
        backup_conn.backup(live_conn)
        live_conn.commit()
    finally:
        live_conn.close()
        backup_conn.close()

    # Step 3: Validate the newly restored live database
    live_valid, live_msg = validate_backup(get_soc_db_path())
    if not live_valid:
        raise RuntimeError(f"Live database failed validation after restore: {live_msg}")

    from src.soc.auth_service import record_auth_audit
    record_auth_audit(
        event_type="BACKUP_RESTORED",
        username=actor,
        actor=actor,
        details={
            "restored_from": str(src_backup_path),
            "safety_backup": str(safety_backup_path),
        },
    )

    return {
        "status": "success",
        "success": True,
        "message": f"Successfully restored live SOC database from {src_backup_path.name}",
        "restored_from": str(src_backup_path),
        "safety_backup": str(safety_backup_path),
        "safety_snapshot": str(safety_backup_path),
        "safety_backup_created": str(safety_backup_path),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "live_db_validation": live_msg,
    }
