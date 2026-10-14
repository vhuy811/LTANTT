# Buổi 4 – Bảo mật Web App và API

Họ và tên: **Lê Viết Huy**
Lớp: **23DATA1**
MSSV: **2387700020**

---

## Tổng quan

Buổi 4 gồm hai phần thực hành và một phần lý thuyết:

| Mục | Nội dung | Thư mục |
|---|---|---|
| **4.2** | Web Vulnerability Scanner – quét XSS, SQLi, CSRF, SSRF | [`web-vuln-scanner/`](web-vuln-scanner/README.md) |
| **4.3** | Lý thuyết JWT & OAuth 2.0, vòng đời token | *(trình bày bên dưới)* |
| **4.4** | JWTSecure – bộ công cụ bảo mật JWT | [`jwt-security-tools/`](jwt-security-tools/README.md) |

---

## 4.3. Lý thuyết JWT và OAuth 2.0

### 4.3.1. Cấu trúc JWT và các lỗ hổng phổ biến

**JWT (JSON Web Token)** là chuỗi token gồm 3 phần ngăn cách bằng dấu chấm:

```
<Header>.<Payload>.<Signature>
```

**1. Header** – khai báo thuật toán ký và loại token:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**2. Payload** – chứa thông tin (claims):

```json
{
  "sub": "user123",
  "role": "admin",
  "exp": 1719820800
}
```

Các claim phổ biến:
- `sub`: Subject (định danh người dùng).
- `iat`: Issued at (thời điểm phát hành).
- `exp`: Expiration time (hết hạn).
- `iss`: Issuer (bên phát hành).

**3. Signature** – xác minh tính toàn vẹn của token. Ví dụ với HMAC SHA-256:

```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

**Các lỗ hổng phổ biến trong JWT:**

| Lỗ hổng | Mô tả |
|---|---|
| `alg=none` | Một số JWT library chấp nhận `alg=none`, cho phép attacker bỏ qua chữ ký. |
| Key confusion (HS256 vs RS256) | Chuyển từ asymmetric (RS256) sang symmetric (HS256) để giả mạo token bằng public key. |
| Brute force secret | Nếu khóa bí mật quá yếu, có thể bị dò bằng từ điển. |
| Token replay | Dùng lại token đã hết hạn hoặc đánh cắp từ trình duyệt. |
| Lỗi trong xác thực thời gian (`exp`, `iat`) | Không kiểm tra kỹ `exp` → cho phép token dùng vô hạn. |
| Thông tin nhạy cảm trong Payload | Vì payload không mã hóa (chỉ base64) → có thể đọc được nếu bị đánh cắp. |

### 4.3.2. OAuth 2.0 Flows và các vấn đề bảo mật

**OAuth 2.0** là giao thức ủy quyền truy cập cho phép ứng dụng bên thứ ba truy cập vào tài nguyên người dùng mà không cần chia sẻ mật khẩu. Thay vào đó, hệ thống sử dụng các access token được cấp sau quá trình ủy quyền.

Các luồng OAuth phổ biến (Authorization Flows):

| Luồng | Mô tả | Sử dụng cho |
|---|---|---|
| **Authorization Code Flow** | Người dùng xác thực → nhận mã code → app đổi mã lấy access token | Ứng dụng server-side |
| **Implicit Flow** *(deprecated)* | Token trả về trực tiếp qua URL | Ứng dụng frontend (SPA) |
| **Client Credentials Flow** | Client xác thực trực tiếp với Authorization Server | Machine-to-machine (M2M) |
| **Resource Owner Password Flow** *(không khuyến nghị)* | Người dùng cung cấp trực tiếp username/password cho app | Ứng dụng tin cậy cao |
| **Device Authorization Flow** | Dành cho thiết bị không có trình duyệt (TV, IoT) | Device-based apps |

Trong phần thực hành 4.4, `OAuthClient` triển khai **Authorization Code Flow** – luồng an toàn và phổ biến nhất cho ứng dụng server-side.

### 4.3.3. Quản lý vòng đời Token

**Token** là chuỗi đại diện quyền truy cập, được cấp bởi hệ thống ủy quyền (Authorization Server), dùng để chứng thực các yêu cầu truy cập tài nguyên. Có 2 loại phổ biến:

- **Access Token**: Dùng để truy cập API – thường có hạn sử dụng ngắn (5–15 phút).
- **Refresh Token**: Dùng để lấy access token mới – có thể có thời hạn dài hơn.

Cơ chế này giúp giảm rủi ro: nếu access token bị lộ, nó cũng nhanh chóng hết hạn; khi đó client dùng refresh token để xin access token mới mà không bắt người dùng đăng nhập lại. Trong phần 4.4, lớp `TokenManager` hiện thực hóa đúng mô hình này (`access_exp = 15` phút, `refresh_exp = 24` giờ, kèm hàm `refresh_access_token`).

---

## Cách chạy từng phần

- **4.2 – Web Vulnerability Scanner:** xem hướng dẫn chi tiết trong [`web-vuln-scanner/README.md`](web-vuln-scanner/README.md).
- **4.4 – JWTSecure:** xem hướng dẫn chi tiết trong [`jwt-security-tools/README.md`](jwt-security-tools/README.md).

Tất cả ảnh chụp màn hình kết quả là **ảnh chụp thật** khi chạy trên máy, đặt trong thư mục `images/` của từng phần.
