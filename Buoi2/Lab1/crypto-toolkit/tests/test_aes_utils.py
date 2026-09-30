import secrets

import pytest
from cryptography.exceptions import InvalidTag

from securecrypto import aes_utils

CONTENT = b"UEF - Lap trinh an ninh thong tin"


def _make_file(tmp_path):
    src = tmp_path / "data.txt"
    src.write_bytes(CONTENT)
    return src


def test_encrypt_then_decrypt_with_key(tmp_path):
    src = _make_file(tmp_path)
    key = aes_utils.encrypt_file_aes(str(src), secrets.token_urlsafe(12))
    enc = tmp_path / "data.txt.enc"
    assert enc.exists()
    assert CONTENT not in enc.read_bytes()          # bản mã không chứa bản rõ

    out = aes_utils.decrypt_file_aes(str(enc), key)
    assert out == str(tmp_path / "data.txt.dec")
    assert (tmp_path / "data.txt.dec").read_bytes() == CONTENT


def test_decrypt_with_password(tmp_path):
    src = _make_file(tmp_path)
    secret = secrets.token_urlsafe(12)
    aes_utils.encrypt_file_aes(str(src), secret)
    out = aes_utils.decrypt_file_aes(str(src) + ".enc", secret)
    assert open(out, "rb").read() == CONTENT


def test_same_password_gives_different_ciphertext(tmp_path):
    # salt + nonce ngẫu nhiên -> 2 lần mã hoá cùng file, cùng mật khẩu cho bản mã khác nhau
    src = _make_file(tmp_path)
    secret = secrets.token_urlsafe(12)
    key1 = aes_utils.encrypt_file_aes(str(src), secret)
    blob1 = (tmp_path / "data.txt.enc").read_bytes()
    key2 = aes_utils.encrypt_file_aes(str(src), secret)
    blob2 = (tmp_path / "data.txt.enc").read_bytes()
    assert key1 != key2 and blob1 != blob2


def test_wrong_secret_fails(tmp_path):
    src = _make_file(tmp_path)
    aes_utils.encrypt_file_aes(str(src), secrets.token_urlsafe(12))
    with pytest.raises(InvalidTag):
        aes_utils.decrypt_file_aes(str(src) + ".enc", secrets.token_urlsafe(12))
    assert not (tmp_path / "data.txt.dec").exists()


def test_tampered_file_fails(tmp_path):
    # GCM phát hiện chỉ cần 1 bit của bản mã bị lật
    src = _make_file(tmp_path)
    key = aes_utils.encrypt_file_aes(str(src), secrets.token_urlsafe(12))
    enc = tmp_path / "data.txt.enc"
    blob = bytearray(enc.read_bytes())
    blob[-1] ^= 0x01
    enc.write_bytes(bytes(blob))
    with pytest.raises(InvalidTag):
        aes_utils.decrypt_file_aes(str(enc), key)
