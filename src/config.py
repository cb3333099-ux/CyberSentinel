import os
from pathlib import Path
from typing import Any, Dict


# ============================================================
# CYBERSENTINEL CENTRALIZED CONFIGURATION (PHASE 8)
# ============================================================

# API & Networking
API_HOST: str = os.environ.get("CYBERSENTINEL_API_HOST", "0.0.0.0")
API_PORT: int = int(os.environ.get("CYBERSENTINEL_API_PORT", 8000))
DASHBOARD_HOST: str = os.environ.get("CYBERSENTINEL_DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT: int = int(os.environ.get("CYBERSENTINEL_DASHBOARD_PORT", 8501))

# Database & Storage
_default_db_dir = Path("/home/charay/cybersentinel-data/soc")

def get_soc_db_path() -> Path:
    _env_db_path = os.environ.get("CYBERSENTINEL_SOC_DB_PATH")
    return Path(_env_db_path) if _env_db_path else _default_db_dir / "alerts.db"

def get_backup_dir() -> Path:
    _env_backup_dir = os.environ.get("CYBERSENTINEL_BACKUP_DIR")
    if _env_backup_dir:
        return Path(_env_backup_dir)
    return get_soc_db_path().parent / "backups"

SOC_DB_PATH: Path = get_soc_db_path()
SOC_DB_DIR: Path = SOC_DB_PATH.parent
BACKUP_DIR: Path = get_backup_dir()

# Authentication & Security
def is_auth_enabled() -> bool:
    return os.environ.get("CYBERSENTINEL_AUTH_ENABLED", "true").lower() in ("true", "1", "yes")

AUTH_ENABLED: bool = is_auth_enabled()
SECRET_KEY: str = os.environ.get("CYBERSENTINEL_SECRET_KEY", "cybersentinel-soc-production-secret-key-change-in-prod")
TOKEN_EXPIRE_MINUTES: int = int(os.environ.get("CYBERSENTINEL_TOKEN_EXPIRE_MINUTES", 480))
HASH_ITERATIONS: int = int(os.environ.get("CYBERSENTINEL_HASH_ITERATIONS", 100000))

# Initial Administrator Bootstrap (Environment-based)
ADMIN_USERNAME: str = os.environ.get("CYBERSENTINEL_ADMIN_USERNAME", "").strip()
ADMIN_PASSWORD: str = os.environ.get("CYBERSENTINEL_ADMIN_PASSWORD", "").strip()

# Logging & Telemetry
LOG_LEVEL: str = os.environ.get("CYBERSENTINEL_LOG_LEVEL", "INFO").upper()

# Model Artifacts
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
MODEL_DIR: Path = PROJECT_ROOT / "models"


def get_stage1_model_path() -> Path:
    _env_path = os.environ.get("CYBERSENTINEL_STAGE1_MODEL_PATH")
    if _env_path:
        return Path(_env_path)
    primary = MODEL_DIR / "stage1_random_forest"
    if primary.exists():
        return primary
    return MODEL_DIR / "rf_stage1_model"


def get_stage2_model_path() -> Path:
    _env_path = os.environ.get("CYBERSENTINEL_STAGE2_MODEL_PATH")
    if _env_path:
        return Path(_env_path)
    no_temp = MODEL_DIR / "stage2_attack_classifier_no_temporal"
    if no_temp.exists():
        return no_temp
    primary = MODEL_DIR / "stage2_attack_classifier"
    if primary.exists():
        return primary
    return MODEL_DIR / "gbt_stage2_model"


STAGE1_MODEL_PATH: Path = get_stage1_model_path()
STAGE2_MODEL_PATH: Path = get_stage2_model_path()
SCALER_PATH: Path = MODEL_DIR / "scaler_model"


def get_system_config_summary() -> Dict[str, Any]:
    """
    Returns public, safe configuration metadata for health/readiness reporting.
    Does NOT leak secrets, passwords, or raw hashes.
    """
    s1_path = get_stage1_model_path()
    s2_path = get_stage2_model_path()
    return {
        "api_host": API_HOST,
        "api_port": API_PORT,
        "dashboard_port": DASHBOARD_PORT,
        "auth_enabled": is_auth_enabled(),
        "token_expire_minutes": TOKEN_EXPIRE_MINUTES,
        "log_level": LOG_LEVEL,
        "db_configured": str(get_soc_db_path()),
        "backup_directory": str(get_backup_dir()),
        "stage1_model_path": str(s1_path),
        "stage2_model_path": str(s2_path),
        "stage1_model_exists": s1_path.exists(),
        "stage2_model_exists": s2_path.exists(),
    }
