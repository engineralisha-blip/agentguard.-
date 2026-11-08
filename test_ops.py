from pathlib import Path

from tests.conftest import login

ROOT = Path(__file__).resolve().parent.parent


def test_gitignore_protects_secrets():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in text and "instance/" in text and "venv/" in text


def test_metrics_requires_login(client):
    client.get("/logout")
    assert client.get("/metrics").status_code == 401


def test_metrics_exposes_counts_after_login(client):
    login(client)
    r = client.get("/metrics")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "agentguard_invocations_total" in body
    assert "agentguard_approvals_pending" in body
    client.get("/logout")


def test_cyber_theme_is_loaded(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "css/cyber.css" in r.get_data(as_text=True)
