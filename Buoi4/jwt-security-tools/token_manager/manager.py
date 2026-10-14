import jwt
import datetime


class TokenManager:
    def __init__(self, secret, algorithm="HS256", access_exp=15, refresh_exp=60*24):
        self.secret = secret
        self.algorithm = algorithm
        self.access_exp = access_exp
        self.refresh_exp = refresh_exp

    def _generate(self, payload, exp_minutes):
        payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(minutes=exp_minutes)
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def generate_tokens(self, user_id):
        access_token = self._generate({"sub": user_id, "type": "access"}, self.access_exp)
        refresh_token = self._generate({"sub": user_id, "type": "refresh"}, self.refresh_exp)
        return access_token, refresh_token

    def refresh_access_token(self, refresh_token):
        try:
            payload = jwt.decode(refresh_token, self.secret, algorithms=[self.algorithm])
            if payload.get("type") == "refresh":
                return self._generate({"sub": payload["sub"], "type": "access"}, self.access_exp)
        except jwt.ExpiredSignatureError:
            return None
