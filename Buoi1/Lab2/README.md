# GitSecure — Pre-commit Hook Bảo mật

> Bài thực hành 1.4 — Bảo mật trước khi commit
> Môn: An toàn Web và Cơ sở dữ liệu (UEF)
> Sinh viên: **Lê Viết Huy** — MSSV **2387700020** — Lớp **23DATA1**

## 1. Mục tiêu

Thiết kế và triển khai một hệ thống **pre-commit hook** ("GitSecure") tự động kiểm tra mã nguồn **trước khi** thực hiện `git commit`, nhằm phát hiện và ngăn chặn các rủi ro bảo mật lọt vào repository.

## 2. Chức năng

| Chức năng | Mô tả | Hàm |
|-----------|-------|-----|
| Quét thông tin nhạy cảm | Phát hiện API key, mật khẩu, token bị hardcode | `scan_sensitive` |
| Kiểm tra quyền file | Cảnh báo file `world-writable` (Unix) | `check_permissions` |
| Quét lỗ hổng | Chạy `bandit`, chặn nếu có mức **High** | `run_bandit` |
| Ghi log | Lưu chi tiết phát hiện vào `gitsecure.log` | `log` |
| Chặn commit | `sys.exit(1)` nếu có bất kỳ phát hiện nào | `main` |

Các mẫu nhận diện secret (`SENSITIVE_PATTERNS`):

```python
r"apikey\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]"
r"secret\s*=\s*['\"][A-Za-z0-9_\-]{8,}['\"]"
r"password\s*=\s*['\"][^'\"]{4,}['\"]"
r"token\s*=\s*['\"][A-Za-z0-9]{10,}['\"]"
r"(AKIA|ASIA)[A-Z0-9]{16}"      # AWS access key
```

## 3. Cấu trúc thư mục

```
gitsecure-lab/
├── .githooks/
│   └── pre-commit            # Script hook (Python)
├── pre-commit-hook-test/
│   └── bad.py                # File test chứa secret (password = "123456")
├── requirements.txt          # bandit
├── .gitignore
└── README.md
```

## 4. Cài đặt & sử dụng

Mở **Git Bash** hoặc **PowerShell** tại thư mục repo:

```bash
# 1. Cài phụ thuộc
pip install -r requirements.txt

# 2. Khởi tạo git (nếu chưa) và trỏ Git tới thư mục hook
git init
git config core.hooksPath .githooks

# 3. Cấp quyền thực thi cho hook (Git Bash / Linux / macOS)
chmod +x .githooks/pre-commit

# 4. Thử commit file dính secret -> hook sẽ CHẶN
git add pre-commit-hook-test/bad.py
git commit -m "test"
```

## 5. Kết quả kiểm chứng

Chạy `scan_sensitive` trên các file mẫu:

| File | Nội dung | Kết quả |
|------|----------|---------|
| `pre-commit-hook-test/bad.py` | `password = "123456"` | ⛔ Phát hiện (pattern `password`) |
| file chứa `apikey = "ABCD1234abcd5678ZZ"` | API key | ⛔ Phát hiện (pattern `apikey`) |
| file chứa `AKIAIOSFODNN7EXAMPLE` | AWS key | ⛔ Phát hiện (pattern `AKIA`) |
| `requirements.txt` | `bandit` | ✅ An toàn (`None`) |

Khi commit `bad.py`, kết quả mong đợi:

```
COMMIT BLOCKED by GitSecure:
 - Sensitive info found in pre-commit-hook-test/bad.py: pattern password\s*=\s*['"][^'"]{4,}['"]
```

Log được ghi vào `gitsecure.log`:

```
[2026-09-23 ...] Sensitive info found in pre-commit-hook-test/bad.py: pattern password...
```

## 6. Bằng chứng chạy thực tế

Sau khi `git init` + `git config core.hooksPath .githooks`, thử commit file `bad.py` (chứa `password = "123456"`):

![Commit bị GitSecure chặn](images/01_commit_blocked.png)

Hook đã **chặn commit** (`COMMIT BLOCKED by GitSecure`) với 2 phát hiện:
- `Sensitive info found in pre-commit-hook-test/bad.py: pattern password...`
- `File pre-commit-hook-test/bad.py is world-writable!`

→ Đúng mục tiêu: mã có rủi ro bảo mật không lọt được vào repo.

## 7. Ghi chú kỹ thuật

- **Windows:** `check_permissions` dùng đúng bản chính của giáo trình (trang 23). Trên Windows,
  `stat.S_IWOTH` gần như không bao giờ bật nên hàm trả `None` — chạy bình thường, không lỗi.
  Giáo trình (trang 25) có gợi ý thêm nhánh `platform.system() == "Windows"` nếu muốn bỏ qua hẳn
  bước này trên Windows; source ở đây giữ bản chính.
- **`gitsecure.log`** đã được đưa vào `.gitignore` để không commit chính file log (đúng khuyến nghị của bài).
- Hook chỉ kích hoạt sau khi đã `git config core.hooksPath .githooks` và cấp quyền `chmod +x`.
