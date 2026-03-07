from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_db_status_endpoint():
    response = client.get("/db/status")
    assert response.status_code == 200
