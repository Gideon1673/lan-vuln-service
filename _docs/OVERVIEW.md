# LAN Vulnerability Service

## RabbitMQ: assessment completion

After CVE matching saves its findings, the service publishes
`assessment.step.completed` to the `lan_scanner` topic exchange.
The `platform.inbox` queue receives assessment events through the
`assessment.#` binding.

Initialize this topology before starting the worker:

```powershell
uv run --locked python -m app.common.messaging.setup
```

The exchange name and type use `RABBITMQ_EXCHANGE=lan_scanner` and
`RABBITMQ_EXCHANGE_TYPE=topic`. The worker consumes requests from its
separate `RABBITMQ_QUEUE` (default: `assessment.inbox`).

Từ dữ liệu thiết bị/dịch vụ do Discovery Service thu thập, đối chiếu với cơ sở dữ liệu lỗ hổng công khai và các quy tắc
cấu hình an toàn, phát hiện điểm yếu, chấm điểm rủi ro và đưa ra khuyến nghị khắc phục mà không khai thác thật.

Service được chia thành ba module bắt buộc:

| Module | Tên nghiệp vụ                    | Chức năng                                                    |
|--------|----------------------------------|--------------------------------------------------------------|
| F1     | CVE Matching Engine              | Nhận diện phần mềm/firmware có khả năng bị ảnh hưởng bởi CVE |
| F2     | Configuration & Hardening Checks | Phát hiện cấu hình yếu hoặc không an toàn                    |
| F3     | Risk Scoring & Verification      | Đánh giá rủi ro, xác minh và phê duyệt kết quả               |

Vulnerability Service phải có khả năng xử lý dữ liệu, đối chiếu thông tin và thực hiện các bước xác minh không phá hoại
theo giới hạn nghiệp vụ

Kiểm tra cấu hình dựa trên thông tin đã thu thập, có bước phê duyệt thủ công và không thực hiện tự động khai thác hoặc
khắc phục lỗ hổng

Vulnerability trả lời câu hỏi sau:

`Những thiết bị/dịch vụ đó có thể tồn tại lỗ hổng nào, cấu hình nào không an toàn, mức độ rủi ro ra sao?`

Vulnerability Service phải xử lý theo các bước:

* Xác định sản phẩm: OpenSSH.
* Chuẩn hóa phiên bản: 8.2p1, đồng thời giữ thông tin bản vá của Ubuntu nếu có.
* Xác định CPE tương ứng (ví dụ một CPE ứng viên của OpenSSH).
* Tìm các CVE có điều kiện ảnh hưởng phù hợp.
* Kiểm tra phiên bản, điều kiện nền tảng và bằng chứng.
* Tạo bản ghi phát hiện cùng mức độ tin cậy.

Không được kết luận có lỗ hổng chỉ vì phiên bản nằm trong một khoảng CVE. Ví dụ Ubuntu có thể đã backport bản vá bảo mật
mà không thay đổi số phiên bản upstream hiển thị qua SSH banner.

## Module F1 — CVE Matching Engine

Đây là module quan trọng nhất về mặt kỹ thuật, bởi đề bài yêu cầu tự xây dựng engine chuẩn hóa tên/phiên bản thành CPE
và đối chiếu CVE, thay vì đơn thuần gọi Nmap hoặc một vulnerability scanner có sẵn.

Trong hệ thống quét phát hiện lỗ hổng cho node mạng LAN (Router/PC), F1 là module chịu trách nhiệm xác định một phần
mềm, hệ điều hành hoặc firmware đang chạy trên thiết bị có khả năng bị ảnh hưởng bởi các lỗ hổng bảo mật đã được công bố
hay không.

CVE Matching không đơn giản là lấy tên phần mềm, phiên bản rồi tìm kiếm CVE. Một engine chính xác còn phải chuẩn hóa sản
phẩm, nhận diện CPE, kiểm tra khoảng phiên bản và đánh giá các điều kiện áp dụng của CVE.

### Yêu cầu bắt buộc của F1 theo đề bài

| Thành phần   | Yêu cầu                                                                                |
|--------------|----------------------------------------------------------------------------------------|
| Input        | `device.service.identified` chứa tên và phiên bản phần mềm/firmware                    |
| Core Engine  | Chuẩn hóa tên/phiên bản thành CPE                                                      |
| CVE Database | Tra cứu và đồng bộ định kỳ với nguồn CVE công khai, ví dụ NVD                          |
| Output       | `vuln.cve.matched` chứa CPE, CVE ID, severity theo CVSS và nguồn tham chiếu            |
| Testing      | Unit test bộ chuẩn hóa phiên bản, tối thiểu 5 cặp phần mềm/phiên bản được tra cứu đúng |
| Ràng buộc    | Không triển khai tự động khai thác lỗ hổng                                             |

### Hiểu rõ CVE, CPE, CVSS và NVD

* **CVE**: Mã định danh lỗ hổng bảo mật công khai - Xác định lỗ hổng
* **CPE**: Chuẩn định danh sản phẩm, hệ điều hành và phần cứng - Xác định sản phẩm bị ảnh hưởng
* **CVSS**: Hệ thống chấm điểm mức độ nghiêm trọng lỗ hổng - Cung cấp severity
* **NVD**: Cơ sở dữ liệu lỗ hổng của NIST - Cung cấp dữ liệu CVE, CPE applicability và CVSS

Ví dụ giả định:

- Discovery nhận diện ExampleServer 2.4.8.
- F1 xác định sản phẩm tương ứng với example_vendor:example_server.
- Một CVE có điều kiện ảnh hưởng tới các phiên bản từ 2.4.0 đến trước 2.4.10.
- F1 xác định 2.4.8 nằm trong khoảng ảnh hưởng.
- F1 tạo một CVE finding, nhưng vẫn phải đánh giá các điều kiện bổ sung nếu có.

```Mermaid
flowchart TD
    A["Discovered Software"] --> B["CPE Identification"]
    B --> C["CVE Applicability Matching"]
    D["NVD CVE Database"] --> C
    E["NVD CPE Dictionary"] --> B
    C --> F["Matched CVE Candidates"]
    F --> G["Evidence Evaluation"]
    G --> H["CVE Findings"]
    D --> I["CVSS Metrics"]
    I --> H
```

CPE được thiết kế để định danh lớp sản phẩm, còn NVD sử dụng Applicability Statements để diễn tả những sản phẩm và môi
trường nào thuộc phạm vi ảnh hưởng của CVE

### Nghiệp vụ 1 — Nhận dữ liệu từ Discovery Service

#### Discovery phải cung cấp dữ liệu gì?

F1 phụ thuộc trực tiếp vào kết quả Service Fingerprinting và OS Fingerprinting. Ví dụ một sự kiện:

```json
{
  "event": "device.service.identified",
  "scan_id": "scan-001",
  "timestamp": "2026-10-13T08:00:00Z",
  "data": {
    "host": "192.168.56.101",
    "port": 22,
    "protocol": "tcp",
    "service": "ssh",
    "product": "OpenSSH",
    "version": "8.2p1",
    "os": "Ubuntu",
    "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"
  }
}
```

Kết quả Fingerprinting không phải lúc nào cũng đầy đủ. Vì vậy, nên phân biệt:

- **RAW**: thông tin nguyên bản từ Discovery.
- **NORMALIZED**: thông tin đã được chuẩn hóa.
- **RESOLVED**: thông tin đã gắn với CPE ứng viên.
- **MATCHED**: thông tin đã đối chiếu với dữ liệu CVE.

### Nghiệp vụ 2 — Software Identification & Normalization

#### Vấn đề khi nhận diện phần mềm

Cùng một phần mềm có thể xuất hiện dưới nhiều cách viết:

```
OpenSSH 8.2p1
OpenSSH_8.2p1
OpenSSH Server 8.2
openssh-server 1:8.2p1-4ubuntu0.11
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
```

Nếu chỉ dùng so sánh chuỗi đơn giản, engine có thể hiểu đây là nhiều phần mềm khác nhau. Do đó cần xây dựng
SoftwareNormalizer - Tức là nhận biết các cách viết có cùng 1 phần mềm hay không

#### Thuật toán normalization

Có thể chia thành các bước:

1. **Parse**: Trích xuất tên sản phẩm và phiên bản từ dữ liệu fingerprint.
2. **Canonicalize**: Chuẩn hóa cách viết, chữ hoa/thường và alias sản phẩm.
3. **Vendor Resolution**: Xác định nhà cung cấp sản phẩm.
4. **Version Normalization**: Phân tách upstream version, package revision, build metadata.
5. **Confidence Assessment**: Đánh giá mức tin cậy của kết quả nhận diện.

Các mapping vendor/product phải được đối chiếu với dữ liệu CPE thật; không nên xây dựng chỉ bằng cách chuyển chữ thường
và thay dấu cách thành dấu gạch dưới.

### Nghiệp vụ 3 — CPE Resolution

Sau khi có tên phần mềm và phiên bản, F1 cần tìm CPE phù hợp.

#### Cấu trúc CPE 2.3

```
cpe:2.3:<part>:<vendor>:<product>:<version>:
<update>:<edition>:<language>:<sw_edition>:
<target_sw>:<target_hw>:<other>

Ví dụ: cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*
```

#### Không nên tạo CPE bằng nối chuỗi thuần túy

Ví dụ như tạo chuỗi kiểu này:

```
String cpe = "cpe:2.3:a:"
    + vendor + ":"
    + product + ":"
    + version + ":*:*:*:*:*:*:*";
```

Đoạn mã có thể tạo ra một chuỗi đúng hình thức nhưng không bảo đảm đó là định danh sản phẩm phù hợp trong NVD.
Thay vào đó, CpeResolver nên:

- Tra cứu CPE Dictionary.
- Tìm các CPE có vendor/product tương ứng.
- Xếp hạng ứng viên theo alias và dữ liệu fingerprint.
- Kiểm tra part và platform.
- Trả về tập ứng viên cùng confidence.

#### CPE Name và CPE Match Criteria

* **CPE Name**: định danh một sản phẩm/nền tảng.
* **CPE Match Criteria**: mô tả điều kiện sản phẩm phù hợp với một CVE, có thể bao gồm các khoảng phiên bản.

Một CPE Match Criteria có thể áp dụng cho nhiều CPE Name khác nhau. NVD cung cấp API riêng để truy xuất loại dữ liệu này

### Nghiệp vụ 4 — CVE Matching Algorithm

Đây là phần lõi của Module F1. Sau khi tìm được CPE phù hợp, engine phải xác định CVE nào có điều kiện áp dụng cho sản
phẩm và phiên bản đã phát hiện.

#### Không chỉ so sánh CPE bằng chuỗi
Giả sử F1 nhận diện sản phẩm giả định:
```
Vendor: example
Product: web_server
Version: 2.4.8
```

CVE database chứa:
```
{
  "cveId": "CVE-EXAMPLE-001",
  "criteria": "cpe:2.3:a:example:web_server:*:*:*:*:*:*:*:*",
  "versionStartIncluding": "2.4.0",
  "versionEndExcluding": "2.4.10"
}
```

Phép kiểm tra: $2.4.0 \leq 2.4.8 < 2.4.10$

Kết quả: phiên bản 2.4.8 thỏa mãn điều kiện về phiên bản.
Nhưng vẫn cần kiểm tra các điều kiện nền tảng hoặc cấu hình bổ sung trước khi kết luận sản phẩm bị ảnh hưởng.

#### Bốn loại điều kiện phiên bản
NVD hỗ trợ các thuộc tính sau trong CPE Match Criteria

#### Matching các điều kiện AND/OR

## Module F2 - Configuration Checks

## Module F3 - Risk Scoring & Verification
