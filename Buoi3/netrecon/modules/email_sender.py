"""Gửi kết quả quét qua Gmail SMTP (SMTP_SSL cổng 465).

Dùng SMTP_USER / SMTP_PASS lấy từ file .env — SMTP_PASS là *mật khẩu ứng dụng*
16 ký tự của Google, KHÔNG phải mật khẩu đăng nhập Gmail. File .env không commit.
"""
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()


def send_email(receiver_email, subject, body, smtp_user, smtp_pass):
    if not smtp_user or not smtp_pass:
        print("[-] Bo qua gui email: chua cau hinh SMTP_USER/SMTP_PASS trong .env")
        return
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = receiver_email
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(smtp_user, smtp_pass)
            smtp.send_message(msg)
        print(f"[+] Email sent to {receiver_email}")
    except Exception as e:
        print(f"[-] Email failed: {e}")
