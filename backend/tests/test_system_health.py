from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_system_health_endpoint():
    response = client.get("/system/health")
    assert response.status_code == 200
