# Báo cáo đánh giá bảo mật — `secure-validator-lab`

**Môn học:** Lập trình an ninh thông tin (UEF)
**Sinh viên:** Lê Viết Huy — MSSV 2387700020 — Lớp 23DATA1
**Ngày:** 23/09/2026
**Đối tượng audit:** Ứng dụng Flask `secure-validator-lab` (thư viện `securevalidator` + `app.py`)
**Phương pháp:** Đọc mã nguồn tĩnh (white-box) toàn bộ file + kiểm chứng động bằng cách import chính hàm của lab và chạy payload.

---

## 1. Tóm tắt cho người quản lý (Executive Summary)

Thư viện `securevalidator` tự nhận là bộ "validator/sanitizer an toàn", nhưng **cả 5 hàm đều dựa trên cách tiếp cận sai về nguyên tắc** (blacklist / regex vá lỗi bề mặt) hoặc **có docstring hứa hẹn khả năng bảo vệ mà code không thực hiện**. Rủi ro lớn nhất không nằm ở một payload cụ thể, mà ở chỗ thư viện tạo **cảm giác an toàn giả** (false sense of security): lập trình viên tin rằng đã "làm sạch" đầu vào nên bỏ qua các biện pháp phòng thủ đúng đắn (parameterized query, allowlist, thư viện chuẩn).

Tổng cộng **12 phát hiện**: 4 mức Cao, 4 mức Trung bình, 4 mức Thấp.

> **Lưu ý phạm vi (quan trọng, trung thực):** Bản thân `app.py` **không thực thi câu lệnh SQL nào** — nó chỉ gọi hàm làm sạch rồi in kết quả ra màn hình. Do đó nhiều lỗ hổng ở đây là **lỗ hổng của thư viện** (sẽ nguy hiểm khi được dùng trong ứng dụng thật), chứ chưa phải khai thác chiếm dữ liệu trực tiếp trên chính lab này. Báo cáo phân biệt rõ hai điều này ở từng mục.

---

## 2. Bảng tổng hợp phát hiện

| # | Thành phần | Phát hiện | Mức độ | Loại |
|---|-----------|-----------|--------|------|
| F-01 | `sanitize_sql_input` | Blacklist bị bypass bằng nhiều kỹ thuật; sai về nguyên tắc | **Cao** | Thiết kế/SQLi |
| F-02 | `validate_url` | Không hề chống SSRF dù docstring khẳng định có | **Cao** | SSRF / tài liệu sai |
| F-03 | `app.py` | `debug=True` → Werkzeug console (nguy cơ RCE) + lộ stack trace | **Cao** | Cấu hình |
| F-04 | `requirements.txt` | `gunicorn==21.2.0` dính CVE-2024-1135 (request smuggling) | **Cao** | Dependency |
| F-05 | `validate_filename` | Bỏ sót null byte, tên thiết bị Windows, ADS | **Trung bình** | Path traversal |
| F-06 | `sanitize_html_input` | Chỉ an toàn ngữ cảnh HTML text; thủng ở URL/attribute/JS/CSS (5 bug H-01→H-05) | **Trung bình** | XSS |
| F-07 | `tests/` | Test tạo "bảo đảm giả": chỉ kiểm 1 payload cổ điển | **Trung bình** | Quy trình |
| F-08 | `app.py` | Không có CSRF token cho form POST | **Trung bình** | CSRF |
| F-09 | `validate_email` | Regex vừa lọt sai (double dot...) vừa từ chối email hợp lệ (`+`) | **Thấp** | Correctness |
| F-10 | `requirements.txt` | Flask 2.3.3 cũ; Werkzeug không ghim phiên bản | **Thấp** | Dependency |
| F-11 | `templates/index.html` | Nạp CSS từ CDN unpkg không có SRI | **Thấp** | Supply-chain |
| F-12 | `app.py` | `request.form["x"]` gây KeyError/400 khi thiếu field | **Thấp** | Robustness |

---

## 3. Chi tiết phát hiện

### F-01 — `sanitize_sql_input`: bộ lọc blacklist bị bypass (Cao)

```python
def sanitize_sql_input(input_str: str) -> str:
    sanitized = re.sub(r"(--|;|'|\"|#)", "", input_str)
    sanitized = re.sub(r"\b(OR|AND|SELECT|INSERT|DELETE|UPDATE|DROP|UNION|WHERE)\b",
                       "", sanitized, flags=re.IGNORECASE)
    return sanitized.strip()
```

Đây là lỗi **nguyên tắc**: chống SQLi bằng cách "xóa ký tự/từ khóa xấu" (blacklist) không bao giờ đầy đủ. Các điểm yếu cụ thể đã kiểm chứng trên chính hàm này:

**(a) Neo `\b` (word-boundary) thất bại khi từ khóa dán liền ký tự chữ/số.**
`\bOR\b` chỉ khớp khi `OR` đứng riêng như một "từ". Dán vào số/chữ là lọt nguyên vẹn:

| Input | Output sau lọc | Ghi chú |
|-------|----------------|---------|
| `1OR1=1` | `1OR1=1` | `OR` không bị xóa |
| `id2AND3=3` | `id2AND3=3` | `AND` không bị xóa |
| `1UNION2` | `1UNION2` | `UNION` không bị xóa |

**(b) Danh sách từ khóa thiếu.** Không chặn `||` (toán tử OR logic), `LIKE`, `IN`, `BETWEEN`, `REGEXP`, `XOR`, `/**/`...

| Input | Output sau lọc |
|-------|----------------|
| `1 \|\| 1=1` | `1 \|\| 1=1` |
| `1 LIKE 1` | `1 LIKE 1` |
| `1 IN (1)` | `1 IN (1)` |
| `1 REGEXP 1` | `1 REGEXP 1` |

**(c) Xóa dấu nháy trở nên vô nghĩa trong ngữ cảnh số.** Payload cổ điển `' OR 1=1 --` bị lọc thành `1=1`, nhưng nếu điểm tiêm nằm ở cột số (`WHERE id = <input>`) thì không cần dấu nháy ngay từ đầu.

**(d) Lọc một lượt, không đệ quy.** Với các bộ lọc kiểu `replace`, thủ thuật viết lồng (`SESELECTLECT`) thường tái tạo từ khóa sau khi lọc; ở đây `\b` khiến chuỗi lồng cũng lọt thẳng — nghĩa là bộ lọc thất bại theo cả hai hướng.

**(e) Không xử lý mã hóa** (URL-encode, Unicode, hex `0x...`, `CHAR()`), vốn là các vector SQLi phổ biến.

**Payload đại diện tốt nhất:** `1 || 1=1` — vừa vượt qua bộ lọc nguyên vẹn, vừa là một tautology (luôn đúng) hợp lệ trong MySQL/SQLite.

**Khai thác đạt được gì:** *Trên chính lab này* — chỉ chứng minh chuỗi injection sống sót qua bộ lọc (bypass thành công). *Nếu output này bị ghép vào truy vấn thật* ở cột số, ví dụ:
```sql
SELECT * FROM users WHERE id = 1 || 1=1   -- điều kiện luôn TRUE → trả toàn bộ bảng
```
thì trở thành authentication bypass / trích xuất dữ liệu hàng loạt.

**Cách vá đúng — không dùng blacklist mà dùng truy vấn tham số hóa:**
```python
# SAI: ghép chuỗi (dù đã "làm sạch")
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")

# ĐÚNG: parameterized query — dữ liệu tách khỏi lệnh
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
```
Bổ sung: validate theo **allowlist** (ID phải là số → `int(user_input)`), dùng ORM, cấp quyền tối thiểu (least-privilege) cho tài khoản DB.

---

### F-02 — `validate_url`: docstring hứa chống SSRF nhưng không làm gì (Cao)

```python
def validate_url(url: str) -> bool:
    """Validate URL and prevent basic SSRF vectors."""
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
```

Hàm chỉ kiểm tra scheme là `http/https` và có netloc — **không có bất kỳ cơ chế chống SSRF nào**. Các URL sau đều được coi là "hợp lệ":

- `http://169.254.169.254/latest/meta-data/` (metadata cloud — AWS/GCP)
- `http://127.0.0.1:8080/admin`, `http://localhost/`
- `http://[::1]/`, `http://0.0.0.0/`
- `http://10.0.0.5/`, `http://192.168.1.1/` (dải nội bộ)
- `http://internal-service/` (hostname nội bộ)

**Tác hại:** nếu URL này được server dùng để `requests.get()`, kẻ tấn công có thể quét/đọc dịch vụ nội bộ, đánh cắp credential metadata cloud.

**Cách vá:** resolve hostname → chặn IP thuộc dải private/loopback/link-local (dùng `ipaddress`), chặn redirect ngầm, ưu tiên allowlist domain. Đồng thời sửa docstring cho đúng khả năng thực tế.

---

### F-03 — `app.py`: `debug=True` (Cao)

```python
if __name__ == "__main__":
    app.run(debug=True)
```

Werkzeug debugger khi bật `debug=True` cung cấp **interactive console** ngay trong trang lỗi; kết hợp với việc lộ mã PIN hoặc bypass PIN, đây là con đường **thực thi mã từ xa (RCE)** kinh điển. Ngoài ra mọi exception sẽ **lộ stack trace, đường dẫn, biến môi trường**.

**Cách vá:** không bao giờ chạy `debug=True` ngoài máy phát triển cá nhân; production dùng WSGI server (gunicorn) với `debug` tắt và biến môi trường `FLASK_DEBUG=0`.

---

### F-04 — `gunicorn==21.2.0`: CVE-2024-1135 (Cao)

`gunicorn` 21.2.0 dính **CVE-2024-1135** — xử lý sai `Transfer-Encoding` dẫn đến **HTTP Request Smuggling**, có thể vượt hạn chế truy cập front-end, đầu độc cache, hoặc truy cập endpoint nội bộ. Đã được vá ở **gunicorn 22.0.0**.

**Cách vá:** nâng lên `gunicorn>=22.0.0`.

---

### F-05 — `validate_filename`: bỏ sót nhiều vector (Trung bình)

```python
def validate_filename(filename: str) -> bool:
    if ".." in filename or "/" in filename or "\\" in filename:
        return False
    return os.path.basename(filename) == filename
```

Chặn được path traversal cơ bản (`../`), nhưng bỏ sót:

- **Null byte:** `report.pdf\x00.exe` — có thể cắt chuỗi ở tầng thấp (C libs).
- **Tên thiết bị Windows dành riêng:** `CON`, `PRN`, `NUL`, `AUX`, `COM1`–`COM9`, `LPT1`–`LPT9` — gây lỗi/DoS trên Windows.
- **Alternate Data Streams (Windows):** `file.txt:hidden`.
- **File ẩn / dấu chấm đầu (Unix):** `.bashrc`, `.htaccess` vẫn qua được.
- **Phụ thuộc nền tảng:** `os.path.basename` cho kết quả khác nhau giữa Windows/Linux → cùng một input có thể hợp lệ ở nền này, nguy hiểm ở nền kia.

**Cách vá:** dùng allowlist ký tự (`^[A-Za-z0-9._-]+$`), chặn null byte, chặn danh sách tên dành riêng của Windows, và luôn nối file vào thư mục gốc rồi kiểm tra bằng `os.path.realpath` nằm trong thư mục cho phép.

---

### F-06 — `sanitize_html_input`: chỉ an toàn 1 ngữ cảnh, thủng 4 ngữ cảnh còn lại (Trung bình)

```python
def sanitize_html_input(html_str: str) -> str:
    return html.escape(html_str)
```

`html.escape` chỉ escape 5 ký tự `& < > " '`. Nó **chỉ an toàn khi output nằm trong thân HTML (text content)** — đúng một ngữ cảnh. Docstring "prevent XSS" là tuyên bố quá rộng. Đã kiểm chứng động (import chạy thử) 5 bug:

| Mã | Ngữ cảnh chèn | Payload | Vì sao thủng |
|----|---------------|---------|--------------|
| **H-01** | URL `href`/`src` | `javascript:alert(document.cookie)` | Không ký tự nào bị escape → click là XSS; `html.escape` không chặn scheme `javascript:`/`data:` |
| **H-02** | Attribute **không** dấu nháy `value={{..}}` | `x onmouseover=alert(1)` · `1 autofocus onfocus=alert(1)` | Space và `=` không được escape → thoát ra tiêm event handler, `onfocus` tự kích hoạt |
| **H-03** | Trong `<script>` / JS | `\'; alert(1); //` · `` `+alert(1)+` `` · `${alert(1)}` | Không escape backslash `\`, backtick `` ` ``, `${}` → phá chuỗi / template literal JS |
| **H-04** | CSS `style="{{..}}"` | `x:expression(alert(1))` | Cú pháp CSS đi thẳng qua |
| **H-05** | (Bug hiển thị trong chính app) | `<b>hi</b>` | `core.py` escape rồi Jinja2 `{{ results.html }}` escape **lần hai** → người dùng thấy `&amp;lt;b&amp;gt;hi&amp;lt;/b&amp;gt;` |

Bằng chứng H-01/H-02 — escape trả lại **y nguyên** payload:
```
javascript:alert(document.cookie)  -> javascript:alert(document.cookie)
x onmouseover=alert(1)             -> x onmouseover=alert(1)
```

**Ghi chú phạm vi (trung thực):** trong `app.py` hiện tại, field `html` được in vào thân HTML (`<code>{{ results.html }}</code>`) — đúng ngữ cảnh an toàn duy nhất, lại có thêm Jinja2 auto-escape — nên **field này hiện KHÔNG bị XSS** (chỉ dính bug hiển thị H-05). H-01→H-04 là lỗ hổng **của thư viện** `sanitize_html_input`: sẽ bùng phát khi lập trình viên tin nó "chống XSS" rồi tái dùng ở href/attribute/script/CSS — đúng bẫy "false sense of security".

**Cách vá:**
- Escape theo **đúng ngữ cảnh**, không dùng một hàm cho mọi chỗ: URL → validate chỉ cho `http/https`; attribute → luôn bọc dấu nháy rồi escape; JS → `json.dumps()`; CSS → allowlist.
- HTML người dùng nhập tự do → dùng `bleach` với allowlist thẻ.
- Trong Flask, để Jinja2 auto-escape đảm nhiệm và **bỏ** `html.escape` thủ công trong `core.py` để hết escape hai lần (H-05).
- Sửa docstring cho đúng: hàm chỉ escape cho ngữ cảnh HTML text, không phải chống XSS tổng quát.

---

### F-07 — Test suite tạo "bảo đảm giả" (Trung bình)

`test_sanitize_sql_input_injection` chỉ kiểm đúng payload `' OR 1=1 --`. Test **pass** khiến người đọc tin bộ lọc "chống SQLi", trong khi hàng loạt bypass ở F-01 không hề được kiểm. Đây là rủi ro quy trình: test yếu → niềm tin sai.

**Cách vá:** bổ sung test cho các bypass đã biết (`1 || 1=1`, `1OR1=1`, `1 LIKE 1`...) — và tốt hơn là test rằng tầng dữ liệu dùng parameterized query, thay vì test bộ lọc.

---

### F-08 — Thiếu CSRF token (Trung bình)

Form POST ở `/` không có CSRF token. Ứng dụng thật có thay đổi trạng thái cần bảo vệ bằng `Flask-WTF`/CSRF token.

---

### F-09 — `validate_email`: regex sai hai chiều (Thấp)

```python
pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
```

- **Lọt sai (false positive):** chấp nhận `a..b@c.com` (chấm liên tiếp), `-@-.a`, `_@_.a`.
- **Từ chối sai (false negative):** loại bỏ email hợp lệ chứa `+` như `user+tag@example.com`.

**Cách vá:** dùng thư viện `email-validator` thay vì regex tự chế; nếu cần regex, bám RFC chặt hơn và chuẩn hóa trước.

---

### F-10 — Dependency cũ, không ghim đủ (Thấp)

`Flask==2.3.3` đã cũ; `Werkzeug` (kéo theo, quyết định hành vi debugger/security) **không được ghim phiên bản** → build không tái lập, dễ dính lỗ hổng transitive.

**Cách vá:** nâng Flask lên bản ổn định mới, ghim toàn bộ dependency (kể cả transitive) qua `pip-tools`/`requirements.lock`, quét định kỳ bằng `pip-audit`.

---

### F-11 — CDN không có SRI (Thấp)

```html
<link rel="stylesheet" href="https://unpkg.com/@picocss/pico@1.*/css/pico.min.css">
```

Nạp tài nguyên bên thứ ba với version range `1.*` và **không có Subresource Integrity (SRI)** → nếu CDN bị chèn mã độc, trình duyệt nạp thẳng. Đây là supply-chain risk.

**Cách vá:** ghim phiên bản chính xác + thêm thuộc tính `integrity` và `crossorigin`, hoặc tự host file.

---

### F-12 — Truy cập field thô gây lỗi (Thấp)

`request.form["email"]` dùng `[]` → thiếu field sẽ ném `KeyError` (HTTP 400). Kết hợp `debug=True` (F-03) sẽ lộ stack trace.

**Cách vá:** dùng `request.form.get("email", "")`.

---

## 4. Tổng hợp khuyến nghị (ưu tiên theo thứ tự)

1. **Ngừng dựa vào `sanitize_sql_input`.** Thay bằng parameterized query + allowlist tại tầng dữ liệu. (F-01)
2. **Tắt `debug=True`; nâng `gunicorn>=22.0.0`.** (F-03, F-04)
3. **Cài đặt chống SSRF thực sự cho `validate_url`** hoặc sửa docstring, đừng để tuyên bố sai. (F-02)
4. **Củng cố `validate_filename`** bằng allowlist + chặn null byte/tên dành riêng. (F-05)
5. **Escape theo ngữ cảnh cho HTML**, giao cho Jinja2 auto-escape, tránh escape hai lần. (F-06)
6. **Viết lại test** để phản ánh bypass thực tế và kiểm tầng dữ liệu. (F-07)
7. Bổ sung CSRF, sửa regex email, ghim dependency, thêm SRI, dùng `.get()`. (F-08→F-12)

**Bài học cốt lõi:** *sanitize/validate đầu vào là lớp phòng thủ bổ trợ, không thay thế được biện pháp đúng tại đúng tầng* — SQLi phải chặn bằng parameterized query, SSRF bằng kiểm tra IP đích, XSS bằng escape theo ngữ cảnh.

---

## 5. Phụ lục — Script kiểm chứng (PoC)

Đặt file cùng thư mục `securevalidator/`, chạy `PYTHONPATH=. python3 poc.py`:

```python
# -*- coding: utf-8 -*-
from securevalidator import sanitize_sql_input as s, validate_url as u, validate_filename as f

# F-01: bypass bộ lọc SQL
for p in ["' OR 1=1 --", "1 || 1=1", "1OR1=1", "id2AND3=3", "1 LIKE 1", "1 IN (1)"]:
    print(f"{p!r:18} -> {s(p)!r}")

# F-02: validate_url không chặn SSRF
for p in ["http://169.254.169.254/", "http://127.0.0.1:8080/admin", "http://192.168.1.1/"]:
    print(f"{p!r:34} -> hợp lệ? {u(p)}")   # đều True

# F-05: validate_filename bỏ sót
for p in ["report.pdf\x00.exe", "CON", "file.txt:hidden", ".bashrc"]:
    print(f"{p!r:22} -> hợp lệ? {f(p)}")
```

Kiểm chứng F-06 (XSS theo ngữ cảnh) — `PYTHONPATH=. python3 poc_html.py`:

```python
# -*- coding: utf-8 -*-
from securevalidator import sanitize_html_input as h

cases = {
    "H-01 URL href":        "javascript:alert(document.cookie)",
    "H-02 attr khong nhay":  "x onmouseover=alert(1)",
    "H-03 script backslash": r"\'; alert(1); //",
    "H-03 template literal":  "${alert(1)}",
    "H-04 CSS":               "x:expression(alert(1))",
}
for ctx, p in cases.items():
    print(f"{ctx:22} | {p!r:34} -> {h(p)!r}")

# H-05: escape hai lan (core.py + Jinja2)
import html
once = h("<b>hi</b>"); twice = html.escape(once)
print("H-05 escape 2 lan     |", twice)   # &amp;lt;b&amp;gt;hi&amp;lt;/b&amp;gt;
```

---

## 6. Ghi chú về tính đầy đủ (trung thực)

Báo cáo này là kết quả rà soát tĩnh + kiểm chứng động toàn bộ mã nguồn hiện có trong thư mục lab (`app.py`, `securevalidator/core.py`, `templates/index.html`, `tests/test_validators.py`, `requirements.txt`). Đã bao phủ cả 5 validator và tầng ứng dụng/hạ tầng. Tuy vậy, **không có audit nào tuyên bố tuyệt đối "đã tìm hết"** — các vector phụ thuộc ngữ cảnh triển khai thật (DB engine cụ thể, reverse proxy, cấu hình OS) chỉ bộc lộ khi kiểm thử động trên hệ thống hoàn chỉnh. Nếu Minh cung cấp đề bài chính thức của môn, có thể chỉnh trọng tâm báo cáo cho khớp yêu cầu chấm điểm.
