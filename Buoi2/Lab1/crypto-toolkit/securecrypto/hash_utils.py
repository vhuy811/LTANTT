"""Băm mật khẩu an toàn bằng Argon2id (argon2-cffi)."""
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError

# Tham số mặc định của argon2-cffi: Argon2id, salt ngẫu nhiên 16 byte, time_cost=3,
# memory_cost=64 MiB -> chậm và tốn RAM có chủ đích để chống brute-force bằng GPU.
_ph = PasswordHasher()


def hash_password_secure(password: str) -> str:
    """Trả về chuỗi băm dạng $argon2id$v=19$m=...,t=...,p=...$salt$hash"""
    return _ph.hash(password)


def verify_password(hashed: str, password: str) -> bool:
    """Kiểm tra mật khẩu với chuỗi băm đã lưu."""
    try:
        return _ph.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False
