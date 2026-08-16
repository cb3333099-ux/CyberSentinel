import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.soc.alert_store import get_connection, initialize_database


import ipaddress
import re
from urllib.parse import urlparse


def validate_indicator(indicator_type: str, indicator_value: str) -> None:
    """
    Validate format of threat intelligence indicator (IP, DOMAIN, URL, HASH).
    """
    ind_type = str(indicator_type).upper().strip()
    val = str(indicator_value).strip()

    if not val:
        raise ValueError("Indicator value cannot be empty.")

    if ind_type == "IP":
        try:
            ipaddress.ip_address(val)
        except ValueError:
            raise ValueError(f"Invalid IP address format '{val}'. Must be a valid IPv4 or IPv6 address.")

    elif ind_type == "DOMAIN":
        domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(domain_regex, val):
            raise ValueError(f"Invalid domain syntax '{val}'. Example valid format: malicious-domain.com")

    elif ind_type == "URL":
        parsed = urlparse(val)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL format '{val}'. Must include scheme (http:// or https://) and domain.")

    elif ind_type == "HASH":
        if not (len(val) in (32, 40, 64) and re.match(r"^[a-fA-F0-9]+$", val)):
            raise ValueError(f"Invalid hash format '{val}'. Must be valid MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex).")


class IndicatorStore:
    """
    Local Threat Intelligence Store for CyberSentinel (Phase 3B).
    Manages deterministic lookup, storage, and retrieval of threat indicators.
    """

    @staticmethod
    def add_indicator(indicator_data: Dict[str, Any]) -> Dict[str, Any]:
        initialize_database()
        conn = get_connection()
        cursor = conn.cursor()

        ind_type = str(indicator_data.get("indicator_type", "IP")).upper().strip()
        ind_val = str(indicator_data.get("indicator_value", "")).strip()

        # Input Format Validation
        validate_indicator(ind_type, ind_val)

        now_iso = datetime.now(timezone.utc).isoformat()
        ind_id = f"IND-{hashlib.md5(f'{ind_type}:{ind_val}'.encode()).hexdigest()[:12].upper()}"

        tags = indicator_data.get("tags", [])
        tags_json = json.dumps(tags if isinstance(tags, list) else [])

        threat_name = str(indicator_data.get("threat_name", "Known Malicious Entity"))
        confidence = float(indicator_data.get("confidence", 0.90))
        severity = str(indicator_data.get("severity", "HIGH")).upper()
        source = str(indicator_data.get("source", "LOCAL_SOC"))
        expires_at = indicator_data.get("expires_at")
        description = indicator_data.get("description", f"Local Threat Indicator for {ind_val}")

        cursor.execute(
            """
            INSERT INTO threat_intel_indicators (
                indicator_id, indicator_type, indicator_value, threat_name,
                confidence, severity, source, tags, first_seen, last_seen,
                expires_at, description, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator_id) DO UPDATE SET
                threat_name=excluded.threat_name,
                confidence=excluded.confidence,
                severity=excluded.severity,
                source=excluded.source,
                tags=excluded.tags,
                last_seen=excluded.created_at,
                description=excluded.description
            """,
            (
                ind_id, ind_type, ind_val, threat_name,
                confidence, severity, source, tags_json, now_iso, now_iso,
                expires_at, description, now_iso
            ),
        )

        conn.commit()
        conn.close()
        return IndicatorStore.get_indicator(ind_id)  # type: ignore

    @staticmethod
    def remove_indicator(indicator_id: str) -> bool:
        initialize_database()
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM threat_intel_indicators WHERE indicator_id = ?", (indicator_id,))
        deleted = cursor.rowcount > 0

        conn.commit()
        conn.close()
        return deleted

    @staticmethod
    def get_indicator(indicator_id: str) -> Optional[Dict[str, Any]]:
        initialize_database()
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM threat_intel_indicators WHERE indicator_id = ?", (indicator_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        d = dict(row)
        d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
        return d

    @staticmethod
    def search_indicator(value: str) -> Optional[Dict[str, Any]]:
        initialize_database()
        conn = get_connection()
        cursor = conn.cursor()

        val_clean = str(value).strip()
        cursor.execute("SELECT * FROM threat_intel_indicators WHERE indicator_value = ?", (val_clean,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        d = dict(row)
        d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
        return d

    @staticmethod
    def list_indicators(indicator_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        initialize_database()
        conn = get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM threat_intel_indicators"
        params: List[Any] = []

        if indicator_type:
            query += " WHERE UPPER(indicator_type) = ?"
            params.append(indicator_type.upper())

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()

        for r in rows:
            r["tags"] = json.loads(r["tags"]) if r.get("tags") else []

        return rows

    @staticmethod
    def match_indicator(entity_value: str, entity_type: str = "IP") -> Optional[Dict[str, Any]]:
        if not entity_value:
            return None

        val_clean = str(entity_value).strip()
        initialize_database()
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM threat_intel_indicators
            WHERE indicator_value = ? AND UPPER(indicator_type) = ?
            """,
            (val_clean, entity_type.upper()),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        d = dict(row)
        d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
        return d
