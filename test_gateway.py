from tests.conftest import DEMO_KEY, csrf, login

H = {"Authorization": f"Bearer {DEMO_KEY}"}


def invoke(client, tool, params):
    r = client.post("/api/v1/tool-invocations",
                    json={"tool_name": tool, "parameters": params}, headers=H)
    return r.status_code, r.get_json()


def decide(client, aid, choice):
    return client.post(f"/api/approvals/{aid}/decide", json={"decision": choice},
                       headers={"X-CSRF-Token": csrf(client)})


def test_bad_key_rejected(client):
    r = client.post("/api/v1/tool-invocations",
                    json={"tool_name": "file_reader", "parameters": {"path": "notes.txt"}},
                    headers={"Authorization": "Bearer wrong-key"})
    assert r.status_code == 401


def test_allowed_read(client):
    code, body = invoke(client, "file_reader", {"path": "notes.txt"})
    assert code == 200 and body["decision"] == "ALLOW"


def test_traversal_blocked(client):
    _, body = invoke(client, "file_reader", {"path": "../../etc/passwd"})
    assert body["decision"] == "BLOCK"


def test_destructive_tool_blocked(client):
    _, body = invoke(client, "delete_database", {"name": "production"})
    assert body["decision"] == "BLOCK"


def test_review_then_approve(client):
    _, body = invoke(client, "report_export", {"report": "weekly"})
    assert body["decision"] == "REVIEW" and body["approval_id"]
    aid = body["approval_id"]

    r = client.get(f"/api/v1/approvals/{aid}", headers=H)
    assert r.get_json()["status"] == "pending"

    login(client)
    assert decide(client, aid, "approve").status_code == 200
    client.get("/logout")

    r = client.get(f"/api/v1/approvals/{aid}", headers=H)
    assert r.get_json()["status"] == "approved"


def test_review_then_deny(client):
    _, body = invoke(client, "report_export", {"report": "other"})
    aid = body["approval_id"]

    login(client)
    decide(client, aid, "deny")
    client.get("/logout")

    r = client.get(f"/api/v1/approvals/{aid}", headers=H)
    assert r.get_json()["status"] == "denied"


def test_cannot_decide_twice(client):
    _, body = invoke(client, "report_export", {"report": "twice"})
    aid = body["approval_id"]
    login(client)
    decide(client, aid, "approve")
    r = decide(client, aid, "deny")
    client.get("/logout")
    assert r.status_code == 409
