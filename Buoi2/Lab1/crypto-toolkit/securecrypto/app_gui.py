"""Giao diện Tkinter cho securecrypto: nhập mật khẩu, chọn file để mã hoá / giải mã."""
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox

try:
    from securecrypto import aes_utils
except ImportError:  # chạy trực tiếp "python securecrypto/app_gui.py" khi chưa pip install -e .
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from securecrypto import aes_utils

from cryptography.exceptions import InvalidTag


class SecureCryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureCrypto GUI")
        self.geometry("700x250")
        self.resizable(False, False)

        tk.Label(self, text="SecureCrypto – AES-256-GCM",
                 font=("Segoe UI", 13, "bold")).pack(pady=(12, 6))

        row = tk.Frame(self)
        row.pack(pady=4)
        tk.Label(row, text="Mật khẩu / Key:").pack(side=tk.LEFT, padx=(0, 6))
        self.password = tk.Entry(row, show="*", width=56)
        self.password.pack(side=tk.LEFT)

        buttons = tk.Frame(self)
        buttons.pack(pady=10)
        tk.Button(buttons, text="Encrypt", width=12, command=self.encrypt).pack(side=tk.LEFT, padx=8)
        tk.Button(buttons, text="Decrypt", width=12, command=self.decrypt).pack(side=tk.LEFT, padx=8)

        self.result = tk.Label(self, text="", wraplength=660, justify=tk.LEFT, fg="#0b5394")
        self.result.pack(pady=6, padx=12)

    def _secret(self):
        value = self.password.get().strip()
        if not value:
            messagebox.showwarning("Thiếu mật khẩu", "Hãy nhập mật khẩu (hoặc Key) trước.")
        return value

    def encrypt(self):
        secret = self._secret()
        if not secret:
            return
        path = filedialog.askopenfilename(title="Chọn file cần mã hoá")
        if not path:
            return
        path = os.path.normpath(path)
        key = aes_utils.encrypt_file_aes(path, secret)
        # Label không bôi đen được nên đưa Key vào clipboard để dán khi giải mã
        self.clipboard_clear()
        self.clipboard_append(key)
        self.result.config(text=f"Đã mã hoá -> {path}.enc\nKey (đã copy vào clipboard): {key}")

    def decrypt(self):
        secret = self._secret()
        if not secret:
            return
        path = filedialog.askopenfilename(title="Chọn file .enc cần giải mã",
                                          filetypes=[("Encrypted file", "*.enc"), ("All files", "*.*")])
        if not path:
            return
        path = os.path.normpath(path)
        try:
            out = aes_utils.decrypt_file_aes(path, secret)
        except InvalidTag:
            messagebox.showerror("Giải mã thất bại", "Sai mật khẩu/Key hoặc file đã bị sửa.")
            return
        self.result.config(text=f"Đã giải mã -> {out}")


if __name__ == "__main__":
    SecureCryptoApp().mainloop()
