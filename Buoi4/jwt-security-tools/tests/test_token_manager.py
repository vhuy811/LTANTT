from token_manager.manager import TokenManager
import jwt


def test_token_creation_and_refresh():
    manager = TokenManager("key123")
    access, refresh = manager.generate_tokens("user1")

    payload = jwt.decode(access, "key123", algorithms=["HS256"])
    assert payload["sub"] == "user1"
    assert payload["type"] == "access"

    new_access = manager.refresh_access_token(refresh)
    assert new_access is not None
