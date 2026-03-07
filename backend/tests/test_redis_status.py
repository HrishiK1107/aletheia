from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_redis_status_endpoint():
    response = client.get("/redis/status")
    assert response.status_code == 200
