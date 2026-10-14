from api_gateway.gateway import APIGateway
from token_manager.manager import TokenManager
import pytest


@pytest.fixture
def client():
    secret = "mysecret"
    gateway = APIGateway(secret)
    gateway.app.config["TESTING"] = True
    return gateway.app.test_client(), TokenManager(secret)


def test_protected_route_with_valid_token(client):
    test_client, manager = client
    access_token, _ = manager.generate_tokens("tester")

    res = test_client.get("/protected", headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == 200
    assert b"Access granted" in res.data


def test_protected_route_with_invalid_token(client):
    test_client, _ = client
    res = test_client.get("/protected", headers={"Authorization": "Bearer invalid"})
    assert res.status_code == 401
