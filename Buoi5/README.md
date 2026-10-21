# Buổi 5 – Phân tích và kiểm thử bảo mật

Họ và tên: **Lê Viết Huy**
Lớp: **23DATA1**
MSSV: **2387700020**

---

## Tổng quan

Buổi 5 gồm hai kỹ thuật kiểm thử bảo mật bổ sung cho nhau, mỗi kỹ thuật có một phần lý thuyết và một công cụ thực hành:

| Mục | Nội dung | Thư mục |
|---|---|---|
| **5.1** | Lý thuyết SAST (phân tích tĩnh) | *(trình bày bên dưới)* |
| **5.2** | `sast-tool` – phân tích tĩnh mã Python, xuất SARIF | [`sast-tool/`](sast-tool/README.md) |
| **5.3** | Lý thuyết DAST (phân tích động) | *(trình bày bên dưới)* |
| **5.4** | `dast-tool` – giám sát hành vi runtime + Flask API | [`dast-tool/`](dast-tool/README.md) |

- **SAST (Static Analysis)**: phân tích **mã nguồn** khi chưa chạy → phát hiện lỗ hổng sớm, ngay trong lúc phát triển.
- **DAST (Dynamic Analysis)**: quan sát **hành vi khi thực thi** → phát hiện lỗ hổng chỉ lộ ra lúc chạy (bộ nhớ, mạng, tiến trình).

---

## 5.1. Lý thuyết SAST

### 5.1.1. Cây cú pháp trừu tượng (AST)

**AST (Abstract Syntax Tree)** là biểu diễn dạng cây của cấu trúc cú pháp mã nguồn, mỗi nút là một cấu trúc ngôn ngữ (biểu thức, lệnh gán, hàm, điều kiện). AST bỏ qua chi tiết thừa (dấu ngoặc, thụt dòng), chỉ giữ cấu trúc logic. Trong SAST, duyệt AST cho phép phân tích mã **mà không cần chạy**, giúp xác định:

- Các mẫu mã nguy hiểm (gọi `eval`, thao tác trực tiếp với input người dùng).
- Các cấu trúc thiếu an toàn (thiếu kiểm tra xác thực, vòng lặp vô hạn).
- Những hành vi tiềm ẩn rủi ro khi triển khai thực tế.

Python cung cấp thư viện `ast` để phân tích cú pháp và xây dựng trình kiểm tra lỗ hổng theo rule (duyệt `ast.walk` tìm `ast.Call` có `func.id == 'eval'`...).

### 5.1.2. Pattern Matching

**Pattern Matching** là kỹ thuật tìm các cấu trúc mã cụ thể thường gắn với lỗ hổng. Thay vì chỉ tìm từ khóa, nó phân tích **ngữ cảnh và cấu trúc** để nhận diện hành vi đáng ngờ (SQL Injection, XSS, Insecure Deserialization). Phân loại pattern:

- **Literal pattern**: tìm trực tiếp chuỗi cụ thể (vd `os.system`, `eval`).
- **Structural pattern**: dựa vào cấu trúc mã (biểu thức, cây AST).
- **Semantic pattern**: dựa vào hành vi tiềm ẩn (nhập người dùng → xử lý → thực thi).

### 5.1.3. Đánh giá chất lượng mã

**Code Quality Metrics** đo mức độ "sạch", "ổn định", "an toàn" của mã; mã kém chất lượng thường dễ lỗi và tiềm ẩn lỗ hổng. Một số chỉ số:

- **Cyclomatic Complexity**: số nhánh điều kiện trong hàm – cao thì khó kiểm thử, dễ lỗi.
- **Function Length**: hàm quá dài dễ chồng chéo logic, bỏ sót lỗ hổng.
- **Nested Depth**: lồng if/else, loop nhiều lớp làm mờ luồng điều khiển.
- **Dependency Count**: dùng nhiều thư viện ngoài → tăng bề mặt tấn công.
- **Security Smell Density**: tần suất "mùi nguy hiểm" như `eval()`, hardcoded credentials, `os.system`.

---

## 5.3. Lý thuyết DAST

### 5.3.1. Runtime Security Testing

**Runtime Security Testing (RST)** theo dõi và phân tích hành vi phần mềm **trong khi chạy** để phát hiện hoạt động nguy hiểm, lỗi bảo mật tiềm ẩn hoặc hành vi bất thường – thứ mà phân tích tĩnh (làm trên mã nguồn) không thấy được. Các thành phần chính của RST:

| Thành phần | Mô tả chức năng |
|---|---|
| RuntimeMonitor | Ghi nhận và log các hành vi quan trọng khi chạy: I/O, gọi API, tiến trình con... |
| MemoryAnalyzer | Kiểm tra vùng bộ nhớ cấp phát động để phát hiện rò rỉ, truy cập sai vùng, tràn buffer. |
| NetworkTrafficAnalyzer | Phân tích lưu lượng mạng: kết nối mở, dữ liệu gửi/nhận, tên miền, phát hiện C2/exfiltration. |
| SecurityBehaviorChecker | So khớp hành vi runtime với mẫu đã học để phát hiện keylogging, tải shellcode, tự nhân bản. |
| VirtualSandbox | Môi trường cách ly để chạy thử phần mềm độc hại mà không ảnh hưởng hệ điều hành thật. |

### 5.3.2. Phân tích hành vi

**Behavioral Analysis** quan sát và đánh giá hành vi của chương trình khi thực thi. Khác với dựa trên chữ ký (signature-based), nó không cần biết trước mẫu mã độc mà phát hiện hành vi bất thường qua giám sát thời gian thực. Các kỹ thuật phổ biến:

- **Rule-based detection**: so khớp hành vi với luật định sẵn (vd: đọc `/etc/passwd` và mở socket ra ngoài → cảnh báo).
- **Heuristic Analysis**: áp dụng tập tiêu chí để đánh giá nhanh, không cần chính xác tuyệt đối.
- **Anomaly Detection**: dùng thống kê/AI để phát hiện hành vi lệch baseline.
- **ML-based detection**: trích đặc trưng hành vi và huấn luyện mô hình phân biệt "bình thường" và "nghi ngờ".

### 5.3.3. Phân tích trong hộp cát

**Sandbox Analysis** thực thi phần mềm trong môi trường ảo hoá/cô lập để quan sát hành vi mà không ảnh hưởng hệ thống thật – đặc biệt hữu ích với phần mềm chưa rõ nguồn gốc. Các loại sandbox:

| Loại | Mô tả | Ví dụ |
|---|---|---|
| VM-based | Dùng máy ảo (VirtualBox, QEMU, VMware) mô phỏng OS thật | Cuckoo Sandbox |
| Container-based | Dùng Docker/LXC – nhanh, nhẹ nhưng ít cô lập hơn | Firejail, Sysdig Falco |
| Bare-metal | Chạy trên máy thật, giám sát bằng phần cứng/hypervisor | Joe Sandbox Bare Metal |
| In-memory/emulator | Mô phỏng CPU/memory (QEMU, Unicorn) để quan sát cấp thấp | PANDA, Intel PIN |

---

Chi tiết cài đặt, cách chạy và kết quả của từng công cụ xem trong [`sast-tool/README.md`](sast-tool/README.md) và [`dast-tool/README.md`](dast-tool/README.md). Ảnh trong báo cáo là ảnh chụp màn hình thật khi chạy trên máy.
