from tests.conftest import login


def test_stream_sends_ready_event(client):
    login(client)
    r = client.get("/api/stream", buffered=False)
    assert r.status_code == 200
    assert r.mimetype == "text/event-stream"
    first = next(iter(r.response))
    assert b"ready" in first
    r.close()
    client.get("/logout")
