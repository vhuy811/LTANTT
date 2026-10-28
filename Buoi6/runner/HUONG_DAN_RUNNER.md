# Chạy GitLab Runner bằng Docker Desktop (không cần thẻ Visa)

GitLab.com yêu cầu xác minh thẻ chỉ để dùng *shared runner*. Runner do chính bạn đăng ký cho project thì không cần.

## 1. Tắt shared runner, tạo project runner
1. Project `devsecops-lab` → **Settings > CI/CD > Runners**.
2. Tắt **Enable instance runners for this project**.
3. Bấm **New project runner** → tick **Run untagged jobs** → **Create runner**.
4. Copy token dạng `glrt-...` (chỉ hiện 1 lần).

## 2. Khởi động runner (PowerShell, trong thư mục `runner`)
```powershell
docker compose up -d
docker exec -it gitlab-runner gitlab-runner register `
  --non-interactive `
  --url https://gitlab.com `
  --token glrt-DAN_TOKEN_CUA_BAN `
  --executor docker `
  --docker-image alpine:latest `
  --description "runner-local-docker"
```
Quay lại trang Runners: thấy chấm xanh (online) là xong. Chụp **Hình A** ở đây.

## 3. Chạy Lab 6.2.1
1. Tạo file `.gitlab-ci.yml` ở gốc project với nội dung `lab-6.2.1-basic/.gitlab-ci.yml` → **Commit changes**.
2. **Build > Pipelines** → chụp danh sách pipeline (Hình 3), bấm ID pipeline chụp sơ đồ 3 stage (Hình 4), bấm `deploy-prod` chụp log (Hình 5).

## 4. Chạy Lab 6.2.2
1. Copy toàn bộ nội dung `lab06-docusaurus/` (kể cả `.gitlab-ci.yml`, `package-lock.json`) vào gốc project, thay `vhuy811` trong `docusaurus.config.ts` bằng username GitLab thật rồi push.
2. Pipeline có `build-job` → `pages` → `pages:deploy`. Chụp log build (Hình 6), mục artifacts Browse (Hình 7).
3. **Deploy > Pages** lấy URL, mở site và chụp (Hình 8, 9).

Nếu `npm ci` lỗi "docker: permission" hoặc job treo ở "pending": kiểm tra runner đã **Run untagged jobs** và instance runner đã tắt.
