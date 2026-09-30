"""Tạo khoá RSA, ký số và xác thực chữ ký (RSA-PSS + SHA-256)."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PUBLIC_EXPONENT = 65537

# PSS là padding ký số được khuyến nghị cho RSA (có yếu tố ngẫu nhiên, có chứng minh
# an toàn), thay cho PKCS#1 v1.5 kiểu cũ.
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                   salt_length=padding.PSS.MAX_LENGTH)


def generate_rsa_keypair(key_size: int = 2048):
    """Trả về (private_key, public_key). key_size tối thiểu 2048 bit."""
    if key_size < 2048:
        raise ValueError("RSA key size must be at least 2048 bits")
    private_key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT,
                                           key_size=key_size)
    return private_key, private_key.public_key()


def sign_data_rsa(data: bytes, private_key) -> bytes:
    """Ký dữ liệu bằng khoá riêng, trả về chữ ký (bytes)."""
    return private_key.sign(data, _PSS, hashes.SHA256())


def verify_signature_rsa(data: bytes, signature: bytes, public_key) -> bool:
    """True nếu chữ ký hợp lệ với dữ liệu và khoá công khai, ngược lại False."""
    try:
        public_key.verify(signature, data, _PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def public_key_to_pem(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)
