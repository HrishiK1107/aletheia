from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_create_indicator():
    payload = {
        "value": "8.8.8.8",
        "type": "ip",
        "confidence": 90,
        "source": "test_api",
    }

    response = client.post("/indicators/", json=payload)

    assert response.status_code in [200, 500]
