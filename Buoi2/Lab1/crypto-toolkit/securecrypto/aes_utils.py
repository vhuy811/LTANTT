"""Mã hoá / giải mã file bằng AES-256-GCM.

Định dạng file .enc:  salt (16 byte) | nonce (12 byte) | ciphertext + tag GCM (16 byte)

- Khoá AES 32 byte được dẫn xuất từ mật khẩu bằng PBKDF2-HMAC-SHA256 với salt ngẫu nhiên,
  nên cùng một mật khẩu mã hoá 2 lần vẫn ra 2 khoá khác nhau.
- GCM là chế độ mã hoá có xác thực (AEAD): sai khoá hoặc file bị sửa dù 1 byte thì
  giải mã sẽ ném InvalidTag, không trả về dữ liệu rác.
"""
import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
NONCE_SIZE = 12          # 96 bit – kích thước nonce khuyến nghị cho GCM
KEY_SIZE = 32            # 256 bit -> AES-256
PBKDF2_ITERATIONS = 100_000
ENC_EXT = ".enc"
DEC_EXT = ".dec"


def derive_key(password: str, salt: bytes) -> bytes:
    """Dẫn xuất khoá AES-256 từ mật khẩu + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file_aes(filepath: str, password: str) -> str:
    """Mã hoá file, ghi ra <filepath>.enc và trả về khoá AES (base64).

    Khoá trả về có thể dùng thay cho mật khẩu khi giải mã.
    """
    if not password:
        raise ValueError("password must not be empty")
    with open(filepath, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)   # nonce mới cho mỗi lần mã hoá, không bao giờ dùng lại
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    with open(filepath + ENC_EXT, "wb") as f:
        f.write(salt + nonce + ciphertext)
    return base64.b64encode(key).decode("ascii")


def _keys_to_try(secret: str, salt: bytes):
    """secret có thể là Key base64 (do encrypt_file_aes trả về) hoặc mật khẩu gốc."""
    try:
        raw = base64.b64decode(secret, validate=True)
        if len(raw) == KEY_SIZE:
            yield raw
    except (binascii.Error, ValueError):
        pass
    yield derive_key(secret, salt)


def _output_path(encrypted_file: str) -> str:
    # Chỉ bỏ đuôi .enc ở cuối tên file (không dùng str.replace vì sẽ thay cả ".enc"
    # nằm giữa đường dẫn), rồi thêm .dec để không ghi đè file gốc.
    if encrypted_file.endswith(ENC_EXT):
        return encrypted_file[: -len(ENC_EXT)] + DEC_EXT
    return encrypted_file + DEC_EXT


def decrypt_file_aes(encrypted_file: str, password: str) -> str:
    """Giải mã file .enc bằng mật khẩu hoặc Key base64, trả về đường dẫn file .dec.

    Ném InvalidTag nếu sai mật khẩu/Key hoặc file đã bị chỉnh sửa.
    """
    with open(encrypted_file, "rb") as f:
        blob = f.read()
    if len(blob) < SALT_SIZE + NONCE_SIZE + 16:
        raise InvalidTag("file too short to be a valid .enc file")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:]

    plaintext = None
    for key in _keys_to_try(password, salt):
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
            break
        except InvalidTag:
            continue
    if plaintext is None:
        raise InvalidTag("wrong password/key or the file has been modified")

    out_path = _output_path(encrypted_file)
    with open(out_path, "wb") as f:
        f.write(plaintext)
    return out_path
