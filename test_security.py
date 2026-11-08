from tests.conftest import DEMO_KEY, csrf, login


def test_post_without_token_rejected(client):
    r = client.post("/api/approvals/1/decide", json={"decision": "approve"})
    assert r.status_code == 403


def test_wrong_token_rejected(client):
    csrf(client)
    r = client.post("/api/approvals/1/decide", json={"decision": "approve"},
                    headers={"X-CSRF-Token": "not-the-real-token"})
    assert r.status_code == 403


def test_login_without_token_rejected(client):
    r = client.post("/login", data={"username": "admin", "password": "ChangeMe123!"})
    assert r.status_code == 403


def test_bearer_api_exempt_from_csrf(client):
    r = client.post("/api/v1/tool-invocations",
                    json={"tool_name": "file_reader", "parameters": {"path": "notes.txt"}},
                    headers={"Authorization": f"Bearer {DEMO_KEY}"})
    assert r.status_code == 200


def test_login_rate_limit(client):
    for _ in range(5):
        login(client, "lockuser", "wrong-password")
    r = login(client, "lockuser", "wrong-password")
    assert r.status_code == 429


def test_rate_limit_blocks_burst(client):
    import hashlib
    import app as appmod
    from database import connect
    key = "rate-test-key"
    with appmod.app.app_context():
        with connect() as db:
            cur = db.execute("INSERT INTO agents(name,description,api_key_hash) VALUES(?,?,?)",
                             ("RateAgent", "rate limit test", hashlib.sha256(key.encode()).hexdigest()))
            aid = cur.lastrowid
            db.execute("INSERT INTO policies(agent_id,tool_id,decision,expires_at) "
                       "SELECT ?,id,'allow',NULL FROM tools WHERE name='file_reader'", (aid,))
    h = {"Authorization": f"Bearer {key}"}
    decisions = []
    for _ in range(21):
        r = client.post("/api/v1/tool-invocations",
                        json={"tool_name": "file_reader", "parameters": {"path": "notes.txt"}}, headers=h)
        decisions.append(r.get_json()["decision"])
    assert decisions[:20] == ["ALLOW"] * 20
    assert decisions[20] == "BLOCK"
