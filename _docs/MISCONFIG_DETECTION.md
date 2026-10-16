# Mô tả về MISCONFIG_DETECTION

## 1. MISCONFIG_DETECTION là gì?

Misconfiguration Detection (Phát hiện cấu hình không an toàn) là quá trình thu thập thông tin cấu hình của thiết bị, hệ
điều hành hoặc dịch vụ, sau đó đối chiếu với những quy tắc và tiêu chuẩn bảo mật nhằm phát hiện các thiết lập có thể làm
gia tăng nguy cơ mất an toàn thông tin.

Ví dụ:

- Router bật Telnet để quản trị từ xa.
- Website quản trị chỉ hỗ trợ HTTP thay vì HTTPS.
- SNMPv1/v2c cho phép đọc thông tin bằng community mặc định public.
- UPnP cho phép một số hoạt động điều khiển không phù hợp với chính sách mạng.
- SSH Server cho phép các thuật toán mã hóa hoặc trao đổi khóa yếu.
- Giao diện quản trị được truy cập từ vùng mạng không được phép.

Vai trò của MISCONFIG_DETECTION trong hệ thông này:

| Thành phần               | Chức năng                                                                   |
|--------------------------|-----------------------------------------------------------------------------|
| Discovery Service        | Thu thập host, port, service, OS và configuration snapshots                 |
| CVE_MATCHING (F1)        | Tìm CVE tiềm năng dựa trên sản phẩm, phiên bản và điều kiện ảnh hưởng       |
| MISCONFIG_DETECTION (F2) | Phát hiện các thiết lập dịch vụ hoặc thiết bị không đáp ứng quy tắc bảo mật |
| RISK_SCORING (F3)        | Tổng hợp kết quả F1 và F2 để đánh giá, xếp hạng rủi ro                      |
| Platform Service         | Điều phối và hiển thị kết quả assessment                                    |

Ví dụ, một máy chủ không có CVE được tìm thấy vẫn có thể sử dụng Telnet hoặc công khai một giao diện quản trị không cần
thiết. F1 không được thiết kế để phát hiện đầy đủ những vấn đề đó, nhưng F2 có thể phát hiện khi có đủ bằng chứng.

## 2. Các cơ sở lý thuyết liên quan

### 2.1. Security Configuration Baseline

Security Baseline là tập hợp những giá trị và thiết lập bảo mật được chấp thuận cho một nhóm thiết bị hoặc hệ thống

Ví dụ:

- Router Management: Ưu tiên SSH/HTTPS, hạn chế giao thức quản trị không mã hóa
- SNMP: Ưu tiên SNMPv3 với cơ chế bảo mật thích hợp
- SSH: Không cho phép thuật toán yếu theo chính sách được áp dụng
- Firewall: Chỉ cho phép những luồng kết nối cần thiết
- UPnP: Chỉ bật khi có nhu cầu và phạm vi truy cập phù hợp

CIS Controls v8 Control 4 yêu cầu thiết lập và duy trì cấu hình an toàn cho thiết bị và phần mềm; Control 12 đề cập quản
lý an toàn hạ tầng mạng. (https://www.cisecurity.org/controls/cis-controls-navigator/v8)

### 2.2. Rule-based Detection

Đây là cơ sở thuật toán chính tôi đề xuất cho F2. Một quy tắc bảo mật bao gồm:
$$Rule=(Condition,\ Evidence,\ Severity,\ Recommendation)$$

Trong đó:

* Condition: điều kiện xác định cấu hình không an toàn.
* Evidence: dữ liệu thực tế chứng minh điều kiện.
* Severity: mức độ nghiêm trọng theo chính sách.
* Recommendation: hướng khắc phục.

Ví dụ:

```
Rule ID: TELNET_ENABLED

Condition:
  protocol = tcp
  AND service = telnet
  AND port.state = open

Result:
  Finding = INSECURE_MANAGEMENT_PROTOCOL
```

Quy tắc nên lưu dưới dạng YAML/JSON thay vì hardcode trực tiếp trong các câu lệnh if/else của Python. Điều này hỗ trợ bổ
sung kiểm tra mới mà không sửa thuật toán lõi.

### 2.3. Configuration Compliance Checking

Đây là quá trình so sánh trạng thái thực tế của thiết bị với cấu hình chuẩn.

```
Observed Configuration
          |
          v
Security Baseline
          |
          v
Compliance Evaluation
          |
     +----+----+
     |         |
  Compliant  Non-compliant
```

Trong hệ thống quét không có quyền quản trị, cần thêm trạng thái UNKNOWN hoặc NOT_EVALUATED khi chưa có đủ bằng chứng để
đưa ra kết luận. Ví dụ, chỉ phát hiện cổng UDP 161 không có nghĩa community SNMP là public. Phải có bằng chứng Discovery
thực sự nhận được phản hồi phù hợp.

### 2.4. Least Privilege và Attack Surface Reduction

Hai nguyên tắc quan trọng:

* Least Privilege: Chỉ cấp những quyền và khả năng truy cập cần thiết.
* Attack Surface Reduction: Giảm số lượng giao diện, dịch vụ và chức năng có thể bị tấn công.

Ví dụ, thiết bị Router chỉ cần quản trị từ VLAN nội bộ thì không nên để giao diện quản trị truy cập rộng hơn mức cần
thiết.

CISA cũng đưa ra hướng dẫn giảm nguy cơ từ các giao diện quản trị bị phơi lộ ra Internet. Tuy nhiên, khả năng truy cập
trong một mạng LAN không đủ để kết luận giao diện bị phơi lộ ra Internet; cần có bằng chứng về routing, firewall hoặc
một phép kiểm tra từ vị trí phù hợp.

### 2.5. Evidence-based Detection

Mọi cảnh báo cấu hình nên đi kèm bằng chứng cụ thể, ví dụ:

```
{
  "rule_id": "HTTP_MANAGEMENT",
  "host": "192.168.56.12",
  "port": 80,
  "evidence": {
    "http_status": 200,
    "html_title": "Router Administration",
    "management_interface": true
  }
}
```

Đây là ví dụ dữ liệu mong muốn. Trong thực tế, tiêu đề trang chỉ là một dấu hiệu; cần tiêu chí nhận diện giao diện quản
trị có thể kiểm chứng trước khi kết luận.

Nguyên tắc quan trọng của F2 là không có bằng chứng không đồng nghĩa với cấu hình an toàn.