from tests.conftest import login


def test_pdf_report_downloads(client):
    login(client)
    r = client.get("/api/reports.pdf")
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"
    assert r.get_data()[:4] == b"%PDF"
    client.get("/logout")


def test_pdf_report_requires_login(client):
    client.get("/logout")
    assert client.get("/api/reports.pdf").status_code == 401
