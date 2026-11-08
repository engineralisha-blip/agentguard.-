import app as appmod
from database import connect
from werkzeug.security import generate_password_hash
from tests.conftest import DEMO_KEY, csrf, login

PASSWORD = "rbac-pass-12345"


def as_user(client, name, role):
    with appmod.app.app_context():
        with connect() as db:
            db.execute("INSERT OR IGNORE INTO users(username,password_hash,role) VALUES(?,?,?)",
                       (name, generate_password_hash(PASSWORD), role))
    login(client, name, PASSWORD)
    return client


def test_viewer_can_read(client):
    as_user(client, "rbac_viewer", "viewer")
    assert client.get("/api/agents").status_code == 200
    client.get("/logout")


def test_viewer_cannot_decide_approval(client):
    as_user(client, "rbac_viewer", "viewer")
    r = client.post("/api/approvals/999/decide", json={"decision": "approve"},
                    headers={"X-CSRF-Token": csrf(client)})
    assert r.status_code == 403
    client.get("/logout")


def test_analyst_cannot_create_agent(client):
    as_user(client, "rbac_analyst", "analyst")
    r = client.post("/api/agents", json={"name": "Nope"}, headers={"X-CSRF-Token": csrf(client)})
    assert r.status_code == 403
    client.get("/logout")


def test_analyst_can_decide_approval(client):
    h = {"Authorization": f"Bearer {DEMO_KEY}"}
    body = client.post("/api/v1/tool-invocations",
                       json={"tool_name": "report_export", "parameters": {"report": "rbac"}},
                       headers=h).get_json()
    aid = body["approval_id"]
    as_user(client, "rbac_analyst", "analyst")
    r = client.post(f"/api/approvals/{aid}/decide", json={"decision": "approve"},
                    headers={"X-CSRF-Token": csrf(client)})
    assert r.status_code == 200
    client.get("/logout")


def test_admin_can_create_agent(client):
    login(client)
    r = client.post("/api/agents", json={"name": "RBAC Agent"}, headers={"X-CSRF-Token": csrf(client)})
    assert r.status_code == 201
    client.get("/logout")
