# LAN Vulnerability Service

Service Python nhận yêu cầu đánh giá thiết bị/dịch vụ LAN qua RabbitMQ, chuẩn hóa thông tin phần mềm thành CPE và đối
chiếu CVE từ NVD. Kết quả và cache NVD được lưu trong PostgreSQL; API Flask cung cấp health check và truy vấn findings
theo `scan_id`.

Pipeline gồm CVE matching, kiểm tra cấu hình và chấm điểm rủi ro. Hiện hai bước cuối mới có khung xử lý, chưa triển khai
logic đánh giá.

## Chạy trên local

Yêu cầu: Python 3.12, PostgreSQL, RabbitMQ và kết nối Internet để tra cứu NVD. Chạy các lệnh từ thư mục gốc dự án.

### 1. Cài đặt thư viện

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Trên Linux/macOS, kích hoạt môi trường bằng `source .venv/bin/activate`.

### 2. Cấu hình

Tạo hoặc cập nhật file `.env` ở thư mục gốc với cấu hình phù hợp:

```dotenv
# DB dùng của tôi cũng được
DATABASE_URL=postgresql+psycopg://<USERNAME>:<PASSWD>@postgres.thong.stream:5432/vuln
RABBITMQ_URL=amqp://<USERNAME>:<PASSWD>@rabbitmq.thong.stream:5672/%2F
SCOPE_CHECK_URL=http://localhost:8080/api/v1/scope/check # TỰ khởi chạy lấy 1 con Platform Orchestrator
NVD_API_KEY=
FLASK_HOST=127.0.0.1
FLASK_PORT=8082
```

Tạo database `vuln`, user PostgreSQL và user RabbitMQ tương ứng trước khi chạy. User RabbitMQ cần quyền
configure/read/write trên vhost `/`. `SCOPE_CHECK_URL` là cấu hình bắt buộc khi khởi tạo client NVD; thay bằng URL của
hệ thống tích hợp (hiện chưa được gọi trong luồng xử lý). `NVD_API_KEY` có thể để trống.

Khởi tạo bảng bằng `psql` (URL này dùng dạng PostgreSQL thông thường, không có `+psycopg`):

```powershell
psql "postgresql://vuln:vuln_password@localhost:5432/lan_vuln" -v ON_ERROR_STOP=1 -f sql/schema.sql
```

### 3. Khởi chạy

Khởi tạo exchange/queue RabbitMQ, sau đó chạy worker:

```powershell
python -m app.common.messaging.setup
python -m app.run_service
```

Worker chờ sự kiện `platform.assessment.stage.requested` và phát sự kiện hoàn thành từng bước/giai đoạn. Để truy vấn kết
quả, mở terminal khác, kích hoạt cùng môi trường ảo và chạy API:

```powershell
python -m app.api
```

- Health check: `http://localhost:8082/health` (trả HTTP 503 nếu không kết nối được database).
- Findings: `http://localhost:8082/api/v1/findings/<scan_id>`.

## Chạy bằng Docker

Yêu cầu Docker đang hoạt động, PostgreSQL và RabbitMQ đã sẵn sàng; khởi tạo database bằng `sql/schema.sql` như trên.
Image chỉ chứa service, các dịch vụ phụ thuộc chạy riêng.

### 1. Build image

```powershell
docker build -t lan-vuln-service .
```

### 2. Cấu hình kết nối

Tạo file `.env.docker` với các biến như `.env`. Nếu PostgreSQL/RabbitMQ chạy trên máy host và dùng Docker Desktop, đổi
`localhost` thành `host.docker.internal` trong các URL:

```dotenv
DATABASE_URL=postgresql+psycopg://vuln:vuln_password@host.docker.internal:5432/lan_vuln
RABBITMQ_URL=amqp://vuln:vuln_password@host.docker.internal:5672/%2F
SCOPE_CHECK_URL=http://host.docker.internal:8080/api/v1/scope/check
NVD_API_KEY=
FLASK_HOST=0.0.0.0
FLASK_PORT=8082
```

Nếu các dịch vụ phụ thuộc chạy trong container cùng Docker network, dùng tên container làm hostname và thêm
`--network <ten-network>` vào các lệnh `docker run`. Trên Linux Docker Engine, khi kết nối về host, thêm
`--add-host host.docker.internal:host-gateway`; các dịch vụ trên host cần lắng nghe trên địa chỉ mà container truy cập
được.

### 3. Chạy worker

```powershell
docker run -d --name lan-vuln-worker --env-file .env.docker lan-vuln-service
```

Chạy API bằng cùng image, ghi đè lệnh mặc định, chưa cần chạy thì thôi:

```powershell
docker run -d --name lan-vuln-api --env-file .env.docker -e FLASK_HOST=0.0.0.0 -e FLASK_PORT=8082 -p 127.0.0.1:8082:8082 lan-vuln-service python -m app.api
```

Truy cập API tại `http://localhost:8082/health`. API dùng Flask development server, phù hợp để chạy thử local.

Xem log và dừng/xóa container:

```powershell
docker logs -f lan-vuln-worker
docker stop lan-vuln-worker lan-vuln-api
docker rm lan-vuln-worker lan-vuln-api
```
