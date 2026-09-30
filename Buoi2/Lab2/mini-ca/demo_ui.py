"""Giao diện Tkinter cho Mini CA: 5 nút tương ứng 5 bước của quy trình."""
import os
import tkinter as tk
from tkinter import messagebox, scrolledtext

from cryptography import x509

from ca_utils import (CERTS_DIR, INTER_CERT_FILE, ROOT_CERT_FILE, create_intermediate_ca,
                      create_root_ca, describe, issue_certificate, load_ca, load_cert,
                      verify_certificate_chain)
from revoke_utils import GOOD, REVOKED, check_ocsp_status, create_empty_crl, revoke_certificate

USER_INFO = {
    "common_name": "Le_Viet_Huy",
    "org": "UEF - Truong Dai hoc Kinh te - Tai chinh TP.HCM",
    "country": "VN",
}
USER_CERT_FILE = os.path.join(CERTS_DIR, f"{USER_INFO['common_name']}_cert.pem")

STATUS_TEXT = {GOOD: "Hợp lệ (GOOD)", REVOKED: "Đã thu hồi (REVOKED)"}


class MiniCAApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mini CA Demo")
        self.geometry("960x480")
        tk.Label(self, text="Mini CA – Root → Intermediate → User",
                 font=("Segoe UI", 14, "bold")).pack(pady=(10, 4))
        self.log_box = scrolledtext.ScrolledText(self, height=15, width=128, state="disabled",
                                                 font=("Consolas", 9), bg="#f7f7f7")
        self.log_box.pack(padx=10, pady=6)

        bar = tk.Frame(self)
        bar.pack(pady=6)
        buttons = [
            ("1. Tạo Root & Intermediate CA", self.setup_ca),
            ("2. Phát hành User Cert", self.issue_cert),
            ("3. Kiểm tra chuỗi Cert", self.verify_chain),
            ("4. Thu hồi User Cert", self.revoke_cert),
            ("5. Kiểm tra trạng thái OCSP", self.ocsp_check),
        ]
        for i, (text, cmd) in enumerate(buttons):
            span = 2 if i == len(buttons) - 1 else 1   # nút cuối nằm giữa hàng
            tk.Button(bar, text=text, width=28, command=cmd).grid(row=i // 2, column=i % 2,
                                                                  columnspan=span, padx=6, pady=4)

    # ------------------------------------------------------------------ helpers
    def log(self, msg):
        self.log_box.config(state="normal")
        self.log_box.insert(tk.END, msg + "\n")
        self.log_box.see(tk.END)
        self.log_box.config(state="disabled")

    def _need(self, paths, msg):
        if all(os.path.exists(p) for p in paths):
            return True
        messagebox.showerror("Lỗi", msg)
        return False

    # ------------------------------------------------------------------ actions
    def setup_ca(self):
        self.log("Tạo Root CA (RSA 4096)...")
        root_ca = create_root_ca()
        self.log("  " + describe(root_ca[1]))
        self.log("Tạo Intermediate CA (RSA 2048, Root ký)...")
        inter_ca = create_intermediate_ca(root_ca)
        self.log("  " + describe(inter_ca[1]))
        create_empty_crl(inter_ca)
        self.log("Phát hành CRL rỗng cho Intermediate CA")
        messagebox.showinfo("Thông báo", "Đã tạo Root CA và Intermediate CA thành công!")

    def issue_cert(self):
        if not self._need([INTER_CERT_FILE], "Phải tạo CA (nút 1) trước khi phát hành chứng chỉ!"):
            return
        self.log(f"Phát hành chứng chỉ cho {USER_INFO['common_name']}...")
        _, cert = issue_certificate(load_ca(), USER_INFO)
        self.log("  " + describe(cert))
        messagebox.showinfo("Thông báo", f"Phát hành chứng chỉ thành công!\nSerial: {hex(cert.serial_number)}")

    def verify_chain(self):
        if not self._need([USER_CERT_FILE, INTER_CERT_FILE, ROOT_CERT_FILE],
                          "Chưa có chứng chỉ user để kiểm tra (nút 2)!"):
            return
        cert = load_cert(USER_CERT_FILE)
        chain = [load_cert(INTER_CERT_FILE), load_cert(ROOT_CERT_FILE)]
        ok = verify_certificate_chain(cert, chain)
        self.log(f"Kiểm tra chuỗi User -> Intermediate -> Root: {ok}")
        messagebox.showinfo("Kết quả", f"Chuỗi chứng chỉ hợp lệ: {ok}")

    def revoke_cert(self):
        if not self._need([USER_CERT_FILE], "Chưa có chứng chỉ user để thu hồi!"):
            return
        cert = load_cert(USER_CERT_FILE)
        crl = revoke_certificate(cert.serial_number, x509.ReasonFlags.key_compromise)
        self.log(f"Thu hồi serial {hex(cert.serial_number)[:14]}... (key_compromise) "
                 f"-> CRL có {len(list(crl))} mục")
        messagebox.showinfo("Thông báo", "Chứng chỉ đã được thu hồi!")

    def ocsp_check(self):
        if not self._need([USER_CERT_FILE], "Chưa có chứng chỉ user để kiểm tra!"):
            return
        cert = load_cert(USER_CERT_FILE)
        status = check_ocsp_status(cert.serial_number)
        text = STATUS_TEXT.get(status, status)
        self.log(f"Trạng thái OCSP của serial {hex(cert.serial_number)[:14]}...: {text}")
        messagebox.showinfo("Kết quả OCSP", f"Trạng thái: {text}")


if __name__ == "__main__":
    MiniCAApp().mainloop()
