import pytest
from unittest.mock import patch
from app import create_app


@pytest.fixture
def client():
    app = create_app("testing")
    with app.test_client() as client:
        yield client


def test_health_check_healthy(client):
    """Test /api/health when the database is available."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "authshield-backend"
    assert data["version"] == "2.0.0"
    assert data["database"] == "connected"


def test_health_check_db_failure(client):
    """Test /api/health degrades gracefully when the database connection fails."""
    with patch("app.extensions.db.session.execute", side_effect=Exception("Connection refused")):
        response = client.get("/api/health")
        assert response.status_code == 503
        data = response.get_json()
        assert data["status"] == "degraded"
        assert data["database"] == "unreachable"
        # Ensure no sensitive internals or credentials are leaked
        assert "password" not in str(data)
        assert "Connection refused" not in str(data)
