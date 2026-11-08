import hashlib
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Test ke liye alag database. Ye import se pehle set hona zaroori hai.
os.environ["AGENTGUARD_DATABASE"] = str(Path(tempfile.mkdtemp()) / "test.db")
os.environ.setdefault("AGENTGUARD_ADMIN_PASSWORD", "ChangeMe123!")

import pytest  # noqa: E402
import app as appmod  # noqa: E402
from database import connect  # noqa: E402

DEMO_KEY = "pytest-demo-key-123"
ADMIN_PASSWORD = "ChangeMe123!"


@pytest.fixture(scope="session")
def client():
    with appmod.app.app_context():
        with connect() as db:
            db.execute("UPDATE agents SET api_key_hash=? WHERE name='Demo Agent'",
                       (hashlib.sha256(DEMO_KEY.encode()).hexdigest(),))
            db.execute("""INSERT INTO policies(agent_id,tool_id,decision,expires_at)
                SELECT a.id,t.id,'allow',NULL FROM agents a, tools t
                WHERE a.name='Demo Agent' AND t.name IN ('file_reader','report_export','database_search')
                ON CONFLICT(agent_id,tool_id) DO UPDATE SET decision='allow', expires_at=NULL""")
    return appmod.app.test_client()


def csrf(client):
    """Login page render karke CSRF token session se lenta hai."""
    client.get("/login")
    with client.session_transaction() as s:
        return s["csrf_token"]


def login(client, username="admin", password=ADMIN_PASSWORD):
    token = csrf(client)
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token})
