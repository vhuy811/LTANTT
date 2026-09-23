# SecureValidator — Làm sạch & Kiểm tra Dữ liệu Đầu vào

> Bài 1 — Lab 1: Cơ sở lập trình bảo mật, kiểm tra đầu vào
> Môn: An toàn Web và Cơ sở dữ liệu (UEF)
> Sinh viên: **Lê Viết Huy** — MSSV **2387700020** — Lớp **23DATA1**

## 1. Mục tiêu

Xây dựng thư viện **SecureValidator** gồm các hàm kiểm tra và làm sạch dữ liệu đầu vào, tích hợp vào ứng dụng web Flask có giao diện nhập liệu, kèm phân tích bảo mật của chính thư viện đó.

## 2. Chức năng

| Hàm | Nhiệm vụ |
|-----|----------|
| `validate_email(email)` | Kiểm tra định dạng email bằng regex |
| `validate_url(url)` | Kiểm tra URL hợp lệ (scheme http/https + có netloc) |
| `validate_filename(filename)` | Chặn path traversal (`..`, `/`, `\`) |
| `sanitize_sql_input(input_str)` | Lọc ký tự/từ khóa SQL nhằm giảm SQL Injection |
| `sanitize_html_input(html_str)` | Escape HTML nhằm giảm XSS |

## 3. Cấu trúc thư mục

```
Lab1/
├── app.py                    # Flask: form nhập & hiển thị kết quả kiểm tra
├── requirements.txt          # Flask, gunicorn
├── securevalidator/
│   ├── __init__.py
│   └── core.py               # 5 hàm validate/sanitize
├── templates/
│   └── index.html            # Giao diện nhập liệu
├── tests/
│   └── test_validators.py    # Unit test
└── BaoCao_Audit_secure-validator-lab.md   # Báo cáo đánh giá bảo mật
```

## 4. Cài đặt & chạy

```bash
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
python -m unittest tests/test_validators.py   # chạy unit test
```

Nhập email / url / filename / SQL / HTML vào form, ứng dụng trả kết quả kiểm tra và chuỗi đã làm sạch.

## 5. Phân tích bảo mật (tóm tắt báo cáo)

Thư viện dùng cách tiếp cận **blacklist/escape đơn giản** nên còn nhiều điểm yếu — chi tiết trong `BaoCao_Audit_secure-validator-lab.md`. Các phát hiện chính:

- **`sanitize_sql_input` bị bypass:** neo `\b` khiến từ khóa dán liền số/chữ lọt qua (`1OR1=1`); thiếu `||`, `LIKE`, `IN`...; payload `1 || 1=1` vượt lọc và là tautology. Cách vá đúng: **parameterized query**, không dùng blacklist.
- **`sanitize_html_input` chỉ an toàn ngữ cảnh HTML text:** thủng ở URL (`javascript:`), attribute không dấu nháy, `<script>`/JS, CSS. Cần escape theo ngữ cảnh.
- **`validate_url` không chống SSRF** dù docstring nói có (cho qua `127.0.0.1`, `169.254.169.254`...).
- **`validate_filename`** bỏ sót null byte, tên thiết bị Windows (`CON`, `NUL`...), ADS.
- **`validate_email`** regex vừa lọt sai (chấm liên tiếp) vừa từ chối email hợp lệ có `+`.

## 6. Ghi chú

- Source giữ đúng theo bản của giáo trình (đây cũng là đối tượng để phân tích ở báo cáo).
- Đây là môi trường học tập; các điểm yếu nêu trên là bài học minh hoạ, không dùng cho production.
