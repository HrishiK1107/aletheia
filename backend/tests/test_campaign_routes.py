from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_campaigns_endpoint():

    response = client.get("/campaigns/")

    assert response.status_code == 200
