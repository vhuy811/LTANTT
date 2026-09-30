"""Thu hồi chứng chỉ bằng CRL và tra trạng thái (mô phỏng OCSP).

CRL (Certificate Revocation List) được Intermediate CA ký và lưu ở certs/ca_crl.pem.
check_ocsp_status() mô phỏng câu trả lời của một OCSP responder: GOOD / REVOKED / UNKNOWN,
bằng cách tra serial trong CRL sau khi đã kiểm chữ ký CRL (không có responder thật).
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ca_utils import CERTS_DIR, INTER_CERT_FILE, load_ca, load_cert, utcnow

CRL_FILE = os.path.join(CERTS_DIR, "ca_crl.pem")

GOOD, REVOKED, UNKNOWN = "GOOD", "REVOKED", "UNKNOWN"


def _load_crl():
    if not os.path.exists(CRL_FILE):
        return None
    with open(CRL_FILE, "rb") as f:
        return x509.load_pem_x509_crl(f.read())


def _write_crl(ca_key, ca_cert, revoked_entries):
    now = utcnow()
    builder = (x509.CertificateRevocationListBuilder()
               .issuer_name(ca_cert.subject)
               .last_update(now)
               .next_update(now + datetime.timedelta(days=7)))
    for entry in revoked_entries:
        builder = builder.add_revoked_certificate(entry)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    with open(CRL_FILE, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    return crl


def create_empty_crl(ca):
    """CA mới tạo phát hành một CRL rỗng (chưa thu hồi chứng chỉ nào), ghi đè CRL cũ."""
    ca_key, ca_cert = ca
    return _write_crl(ca_key, ca_cert, [])


def revoke_certificate(cert_serial, reason=x509.ReasonFlags.key_compromise, ca=None):
    """Thêm cert_serial vào CRL và ký lại CRL bằng khoá của CA phát hành.

    ca = (ca_key, ca_cert); mặc định dùng Intermediate CA trong certs/.
    """
    ca_key, ca_cert = ca or load_ca()
    entries = []
    old = _load_crl()
    # Chỉ giữ lại danh sách cũ nếu CRL cũ do chính CA này ký (tránh chép CRL của CA đã tạo lại)
    if old is not None and old.issuer == ca_cert.subject and old.is_signature_valid(ca_cert.public_key()):
        entries = list(old)
    if not any(e.serial_number == cert_serial for e in entries):
        entries.append(x509.RevokedCertificateBuilder()
                       .serial_number(cert_serial)
                       .revocation_date(utcnow())
                       .add_extension(x509.CRLReason(reason), critical=False)
                       .build())
    return _write_crl(ca_key, ca_cert, entries)


def check_ocsp_status(cert_serial, issuer_cert=None):
    """Trả về GOOD / REVOKED / UNKNOWN cho serial cần tra."""
    issuer_cert = issuer_cert or load_cert(INTER_CERT_FILE)
    crl = _load_crl()
    if crl is None:
        return GOOD   # CA chưa thu hồi chứng chỉ nào
    # CRL giả mạo / của CA khác -> không tin được -> UNKNOWN
    if crl.issuer != issuer_cert.subject or not crl.is_signature_valid(issuer_cert.public_key()):
        return UNKNOWN
    if crl.next_update_utc is not None and utcnow() > crl.next_update_utc:
        return UNKNOWN   # CRL đã quá hạn, cần CA phát hành CRL mới
    entry = crl.get_revoked_certificate_by_serial_number(cert_serial)
    return REVOKED if entry is not None else GOOD
