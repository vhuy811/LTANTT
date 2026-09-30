"""REST API cho securecrypto (Flask).

POST /encrypt  form-data: file=<file>,      password=<mật khẩu>   -> {"key": "..."}
POST /decrypt  form-data: file=<file.enc>,  password=<Key/mật khẩu> -> {"output": "..."}
"""
import os
import sys

from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

try:
    from securecrypto import aes_utils
except ImportError:  # chạy trực tiếp "python securecrypto/api.py" khi chưa pip install -e .
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from securecrypto import aes_utils

from cryptography.exceptions import InvalidTag

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "upload")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024   # chặn upload quá 10 MB


class BadRequest(Exception):
    pass


@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return jsonify({"error": str(e)}), 400


@app.errorhandler(413)
def handle_too_large(e):
    return jsonify({"error": "file too large (max 10 MB)"}), 413


def _save_upload():
    """Lưu file upload vào UPLOAD_DIR, trả về (đường dẫn, password)."""
    uploaded = request.files.get("file")
    password = request.form.get("password", "")
    if uploaded is None or not password:
        raise BadRequest("form-data must contain 'file' and 'password'")
    # secure_filename bỏ "../", "/", "\" ... -> chống path traversal khi ghi file
    name = secure_filename(uploaded.filename or "")
    if not name:
        raise BadRequest("invalid file name")
    path = os.path.join(UPLOAD_DIR, name)
    uploaded.save(path)
    return path, password


@app.post("/encrypt")
def encrypt():
    path, password = _save_upload()
    key = aes_utils.encrypt_file_aes(path, password)
    return jsonify({"key": key})


@app.post("/decrypt")
def decrypt():
    path, password = _save_upload()
    try:
        out = aes_utils.decrypt_file_aes(path, password)
    except InvalidTag:
        raise BadRequest("wrong password/key or the file was modified")
    # chỉ trả tên file, không lộ đường dẫn tuyệt đối trên server
    return jsonify({"output": os.path.basename(out)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)   # chỉ lắng nghe localhost, debug tắt
