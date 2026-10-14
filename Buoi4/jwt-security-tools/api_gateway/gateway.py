from flask import Flask, request, jsonify
import jwt


class APIGateway:
    def __init__(self, secret, algorithm="HS256"):
        self.secret = secret
        self.algorithm = algorithm
        self.app = Flask(__name__)
        self.routes()

    def routes(self):
        @self.app.route("/protected")
        def protected():
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            try:
                payload = jwt.decode(token, self.secret, algorithms=[self.algorithm])
                return jsonify({"message": "Access granted", "user": payload["sub"]})
            except jwt.InvalidTokenError:
                return jsonify({"message": "Access denied"}), 401

    def run(self):
        self.app.run(port=5000)
