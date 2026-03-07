from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_neo4j_status_endpoint():
    response = client.get("/neo4j/status")
    assert response.status_code == 200
