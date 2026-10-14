from oauth_client.client import OAuthClient


def test_auth_url():
    client = OAuthClient("client_id", "secret", "https://auth.com",
                         "https://token.com", "http://localhost")
    url = client.get_auth_url()
    assert url.startswith("https://auth.com?")
    assert "client_id=client_id" in url
