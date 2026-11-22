from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint_reports_online():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_frontend_is_served_at_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "Log Analyzer" in response.text
