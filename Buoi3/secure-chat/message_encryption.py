from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os


class MessageEncryption:
    """Mã hoá đầu-cuối từng tin nhắn bằng AES-256-CBC + PKCS7.

    Mỗi client có một khoá AES-256 riêng (32 byte). Mỗi tin nhắn dùng một IV
    ngẫu nhiên 16 byte, gói theo định dạng: IV ‖ ciphertext.
    """

    def __init__(self, key=None):
        self.key = key or os.urandom(32)   # khoá AES-256
        self.backend = default_backend()

    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        ct = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ct

    def decrypt(self, ciphertext):
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode('utf-8')
