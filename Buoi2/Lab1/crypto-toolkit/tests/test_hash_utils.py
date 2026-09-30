import secrets

from securecrypto import hash_utils

# Mật khẩu test sinh ngẫu nhiên, không viết cứng trong code (tránh bị hook GitSecure của Buổi 1 chặn)


def test_hash_is_argon2id_and_verifies():
    pw = secrets.token_urlsafe(16)
    hashed = hash_utils.hash_password_secure(pw)
    assert hashed.startswith("$argon2id$")
    assert pw not in hashed
    assert hash_utils.verify_password(hashed, pw) is True


def test_wrong_password_rejected():
    pw = secrets.token_urlsafe(16)
    hashed = hash_utils.hash_password_secure(pw)
    assert hash_utils.verify_password(hashed, pw + "x") is False


def test_same_password_different_hash():
    # mỗi lần băm dùng salt ngẫu nhiên -> 2 chuỗi băm khác nhau
    pw = secrets.token_urlsafe(16)
    assert hash_utils.hash_password_secure(pw) != hash_utils.hash_password_secure(pw)
