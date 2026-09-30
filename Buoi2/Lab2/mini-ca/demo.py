"""Chạy toàn bộ quy trình Mini CA trên terminal."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ca_utils import (create_intermediate_ca, create_root_ca, describe, generate_key,
                      issue_certificate, verify_certificate_chain)
from revoke_utils import CRL_FILE, check_ocsp_status, create_empty_crl, revoke_certificate

USER_INFO = {
    "common_name": "Le_Viet_Huy",
    "org": "UEF - Truong Dai hoc Kinh te - Tai chinh TP.HCM",
    "country": "VN",
}


def fake_root_same_name(real_root):
    """Kẻ tấn công tự tạo Root CA trùng tên (subject) với Root thật nhưng khác khoá."""
    key = generate_key()
    return (x509.CertificateBuilder()
            .subject_name(real_root.subject).issuer_name(real_root.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(real_root.not_valid_before_utc)
            .not_valid_after(real_root.not_valid_after_utc)
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(real_root.extensions.get_extension_for_class(x509.KeyUsage).value,
                           critical=True)
            .sign(key, hashes.SHA256()))


def step(title):
    print(f"\n=== {title} ===")


def main():
    step("1. Tạo Root CA")
    root_ca = create_root_ca()
    print(describe(root_ca[1]))

    step("2. Tạo Intermediate CA (Root ký)")
    inter_ca = create_intermediate_ca(root_ca)
    print(describe(inter_ca[1]))
    create_empty_crl(inter_ca)
    print(f"Phát hành CRL rỗng: {CRL_FILE}")

    step("3. Phát hành chứng chỉ người dùng cuối (Intermediate ký)")
    _, user_cert = issue_certificate(inter_ca, USER_INFO)
    print(describe(user_cert))

    step("4. Xác thực chuỗi chứng chỉ")
    chain = [inter_ca[1], root_ca[1]]
    print("User -> Intermediate -> Root :", verify_certificate_chain(user_cert, chain))
    print("Thiếu Intermediate (User -> Root):")
    print("  =>", verify_certificate_chain(user_cert, [root_ca[1]], verbose=True))
    print("Root giả mạo trùng tên Root thật:")
    print("  =>", verify_certificate_chain(user_cert, [inter_ca[1], fake_root_same_name(root_ca[1])],
                                           verbose=True))

    step("5. Kiểm tra trạng thái (OCSP) trước khi thu hồi")
    print(f"serial {hex(user_cert.serial_number)[:14]}... ->", check_ocsp_status(user_cert.serial_number))

    step("6. Thu hồi chứng chỉ người dùng (lý do: key_compromise)")
    crl = revoke_certificate(user_cert.serial_number, x509.ReasonFlags.key_compromise, ca=inter_ca)
    print(f"Đã cập nhật CRL: {CRL_FILE} ({len(list(crl))} chứng chỉ bị thu hồi)")

    step("7. Kiểm tra trạng thái (OCSP) sau khi thu hồi")
    print(f"serial {hex(user_cert.serial_number)[:14]}... ->", check_ocsp_status(user_cert.serial_number))


if __name__ == "__main__":
    main()
