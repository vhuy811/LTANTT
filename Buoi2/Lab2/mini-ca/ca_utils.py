"""Mini CA: tạo Root CA, Intermediate CA, phát hành và xác thực chứng chỉ X.509.

Mô hình PKI 3 cấp:
    Root CA (tự ký, 10 năm, path_length=1)
      └── Intermediate CA (Root ký, 5 năm, path_length=0)
            └── End-entity (Intermediate ký, 1 năm, không phải CA)

Một CA ở đây được biểu diễn bằng tuple (private_key, certificate).
"""
import datetime
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Neo vào thư mục chứa file này để chạy từ đâu cũng ghi vào mini-ca/certs
CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
os.makedirs(CERTS_DIR, exist_ok=True)

ROOT_KEY_FILE = os.path.join(CERTS_DIR, "root_ca_key.pem")
ROOT_CERT_FILE = os.path.join(CERTS_DIR, "root_ca_cert.pem")
INTER_KEY_FILE = os.path.join(CERTS_DIR, "intermediate_key.pem")
INTER_CERT_FILE = os.path.join(CERTS_DIR, "intermediate_cert.pem")


# ---------------------------------------------------------------- tiện ích
def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def generate_key(key_size=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def save_key(key, path):
    # Lab: khoá riêng lưu KHÔNG mã hoá -> thư mục certs/ và *.pem được đưa vào .gitignore
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))


def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_ca(key_path=INTER_KEY_FILE, cert_path=INTER_CERT_FILE):
    return load_key(key_path), load_cert(cert_path)


def _name(country, org, common_name):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _ca_key_usage():
    # CA chỉ được dùng khoá để ký chứng chỉ (keyCertSign) và ký CRL (cRLSign)
    return x509.KeyUsage(digital_signature=True, content_commitment=False,
                         key_encipherment=False, data_encipherment=False,
                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                         encipher_only=False, decipher_only=False)


def _base_builder(subject, issuer, public_key, days):
    now = utcnow()
    return (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key),
                           critical=False))


# ---------------------------------------------------------------- 1. Root CA
def create_root_ca():
    """Tạo Root CA tự ký. Trả về (root_key, root_cert)."""
    key = generate_key(4096)
    name = _name("VN", "UEF Mini PKI", "UEF Mini Root CA")
    cert = (_base_builder(name, name, key.public_key(), days=3650)
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(_ca_key_usage(), critical=True)
            .sign(key, hashes.SHA256()))
    save_key(key, ROOT_KEY_FILE)
    save_cert(cert, ROOT_CERT_FILE)
    return key, cert


# ---------------------------------------------------------------- 2. Intermediate CA
def create_intermediate_ca(root_ca):
    """root_ca = (root_key, root_cert). Trả về (inter_key, inter_cert) do Root ký."""
    root_key, root_cert = root_ca
    key = generate_key()
    subject = _name("VN", "UEF Mini PKI", "UEF Mini Intermediate CA")
    cert = (_base_builder(subject, root_cert.subject, key.public_key(), days=1825)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_ca_key_usage(), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                           critical=False)
            .sign(root_key, hashes.SHA256()))
    save_key(key, INTER_KEY_FILE)
    save_cert(cert, INTER_CERT_FILE)
    return key, cert


# ---------------------------------------------------------------- 3. End-entity
def issue_certificate(ca, subject_info: dict):
    """ca = (ca_key, ca_cert); subject_info = {"common_name", "org", "country", "email"?}.

    Trả về (key, cert) và lưu <common_name>_key.pem, <common_name>_cert.pem trong certs/.
    """
    ca_key, ca_cert = ca
    key = generate_key()
    cn = subject_info["common_name"]
    subject = _name(subject_info.get("country", "VN"), subject_info.get("org", "UEF"), cn)
    builder = (_base_builder(subject, ca_cert.subject, key.public_key(), days=365)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True,
                                            key_encipherment=True, data_encipherment=False,
                                            key_agreement=False, key_cert_sign=False,
                                            crl_sign=False, encipher_only=False,
                                            decipher_only=False), critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,
                                                     ExtendedKeyUsageOID.EMAIL_PROTECTION]),
                              critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                              critical=False))
    if subject_info.get("email"):
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(subject_info["email"])]), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())

    prefix = cn.replace(" ", "_")
    save_key(key, os.path.join(CERTS_DIR, f"{prefix}_key.pem"))
    save_cert(cert, os.path.join(CERTS_DIR, f"{prefix}_cert.pem"))
    return key, cert


# ---------------------------------------------------------------- 4. Xác thực chuỗi
class ChainError(Exception):
    pass


def _check_period(cert, now):
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise ChainError(f"{cn(cert.subject)}: hết hạn hoặc chưa có hiệu lực")


def _check_signature(child, issuer):
    try:
        child.verify_directly_issued_by(issuer)   # kiểm chữ ký bằng khoá công khai của issuer
    except InvalidSignature:
        raise ChainError(f"chữ ký của '{cn(child.subject)}' không khớp khoá công khai "
                         f"của '{cn(issuer.subject)}' đang có trong chuỗi") from None


def verify_certificate_chain(cert, ca_chain, verbose=False):
    """Xác thực cert với ca_chain = [CA cấp trực tiếp, ..., Root CA].

    Kiểm tra từng mắt xích: thời hạn, issuer == subject của CA cấp trên, CA cấp trên có
    BasicConstraints ca=True + keyCertSign và không vượt path_length, chữ ký hợp lệ;
    cuối chuỗi phải là Root tự ký. Trả về True/False (verbose=True in lý do khi False).
    """
    try:
        if not ca_chain:
            raise ChainError("ca_chain rỗng")
        now = utcnow()
        child = cert
        for depth, issuer in enumerate(ca_chain):
            _check_period(child, now)
            if child.issuer != issuer.subject:
                raise ChainError(f"issuer của '{cn(child.subject)}' là '{cn(child.issuer)}', "
                                 f"không phải '{cn(issuer.subject)}'")
            bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not bc.ca:
                raise ChainError(f"'{cn(issuer.subject)}' không phải CA")
            # depth = số CA trung gian nằm dưới issuer trong chuỗi
            if bc.path_length is not None and depth > bc.path_length:
                raise ChainError(f"'{cn(issuer.subject)}' vượt path_length={bc.path_length}")
            ku = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
            if not ku.key_cert_sign:
                raise ChainError(f"'{cn(issuer.subject)}' không có quyền keyCertSign")
            _check_signature(child, issuer)
            child = issuer
        # mắt xích cuối phải là Root tự ký, còn hạn
        _check_period(child, now)
        _check_signature(child, child)
        return True
    except Exception as e:  # noqa: BLE001 – mọi lỗi đều có nghĩa là chuỗi không hợp lệ
        if verbose:
            print(f"  -> Chuỗi KHÔNG hợp lệ: {e.__class__.__name__}: {e}")
        return False


def cn(name):
    """Lấy Common Name từ một x509.Name (để in cho gọn)."""
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def describe(cert):
    """Chuỗi mô tả ngắn gọn một chứng chỉ để in ra màn hình."""
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    kind = f"CA, path_length={bc.path_length}" if bc.ca else "end-entity"
    return (f"CN={cn(cert.subject)} | issuer CN={cn(cert.issuer)} | {kind} | "
            f"serial {hex(cert.serial_number)[:14]}... | hạn đến {cert.not_valid_after_utc:%Y-%m-%d}")
