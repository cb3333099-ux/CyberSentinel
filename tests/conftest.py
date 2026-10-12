import os
import tempfile
from pathlib import Path


# Keep the test suite isolated from any analyst or demo SOC database.
_test_db_dir = Path(tempfile.mkdtemp(prefix="cybersentinel-test-soc-"))
os.environ.setdefault("CYBERSENTINEL_SOC_DB_PATH", str(_test_db_dir / "alerts.db"))