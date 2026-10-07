"""Sinh bộ chứng chỉ CA / server / client giống make-certs.bat nhưng bằng Python
(thư viện cryptography) — dùng khi máy chưa cài OpenSSL. Chạy: python make_certs.py

Kết quả giống hệt make-certs.bat:
  certs/ca/ca.key, ca.crt        (CA tự ký, RSA 2048, SHA-256, 3650 ngày)
  certs/server/server.key, .crt  (CN=localhost, CA ký, 365 ngày)
  certs/client/client.key, .crt  (CN=client,    CA ký, 365 ngày)
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _save_key(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))


def _save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "HN"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "HN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Dept"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def main():
    for sub in ("ca", "server", "client"):
        os.makedirs(os.path.join(BASE, sub), exist_ok=True)

    # --- CA tự ký ---
    ca_key = _key()
    ca_name = _name("MyRootCA")
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(_now() - datetime.timedelta(minutes=1))
               .not_valid_after(_now() + datetime.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                            key_encipherment=False, data_encipherment=False,
                                            key_agreement=False, key_cert_sign=True, crl_sign=True,
                                            encipher_only=False, decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))
    _save_key(ca_key, os.path.join(BASE, "ca", "ca.key"))
    _save_cert(ca_cert, os.path.join(BASE, "ca", "ca.crt"))

    # --- Server (CN=localhost) và Client (CN=client), đều do CA ký ---
    for sub, cn in (("server", "localhost"), ("client", "client")):
        key = _key()
        cert = (x509.CertificateBuilder()
                .subject_name(_name(cn)).issuer_name(ca_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(_now() - datetime.timedelta(minutes=1))
                .not_valid_after(_now() + datetime.timedelta(days=365))
                .sign(ca_key, hashes.SHA256()))
        _save_key(key, os.path.join(BASE, sub, f"{sub}.key"))
        _save_cert(cert, os.path.join(BASE, sub, f"{sub}.crt"))

    print("Cac chung chi da tao xong (bang Python):")
    for sub in ("ca", "server", "client"):
        print(" -", os.path.join("certs", sub))


if __name__ == "__main__":
    main()
