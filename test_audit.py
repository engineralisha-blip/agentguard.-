from tests.conftest import login
import app as appmod


def test_chain_verifies(client):
    login(client)
    r = client.get("/api/audit/verify")
    assert r.status_code == 200 and r.get_json()["ok"] is True
    client.get("/logout")


def test_tampering_detected(client):
    login(client)
    client.get("/logout")
    from database import connect
    with appmod.app.app_context():
        with connect() as db:
            db.execute("UPDATE audit_logs SET details='tampered' WHERE id=(SELECT MIN(id) FROM audit_logs)")
    login(client)
    r = client.get("/api/audit/verify")
    assert r.get_json()["ok"] is False
