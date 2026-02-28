📑 TÀI LIỆU KIẾN TRÚC: NGINX LOG ANALYZER (PROTOTYPE)

1. Vấn đề giải quyết (Problem Statement)
Các quản trị viên hệ thống thường đối mặt với lượng lớn dữ liệu log từ Nginx mà không có công cụ phân tích bảo mật nhanh gọn. Vấn đề cốt lõi dự án giải quyết là:

Phát hiện tấn công tự động: Nhận diện các hành vi dò quét lỗ hổng (CVE-2024-36401, LFI, SQLi) ngay lập tức thay vì kiểm tra thủ công.

Lọc nhiễu dữ liệu: Phân loại mức độ đe dọa (LOW, MEDIUM, HIGH) để tập trung vào các IP thực sự nguy hiểm.

Cảnh báo thời gian thực: Đưa thông tin tình báo bảo mật từ API quốc tế (AbuseIPDB) trực tiếp đến điện thoại qua Telegram.

2. Tech Stack & Công cụ lựa chọn
Ngôn ngữ Python: Lựa chọn hàng đầu cho xử lý chuỗi và phân tích dữ liệu nhờ thư viện phong phú.

Rich & Click: Dùng để xây dựng giao diện CLI (Command Line Interface) chuyên nghiệp, cung cấp Dashboard trực quan ngay trên Terminal.

AbuseIPDB API: Cung cấp dữ liệu uy tín IP toàn cầu, giúp xác thực các cuộc tấn công từ botnet hoặc proxy độc hại.

Multi-threading (concurrent.futures): Tối ưu hóa hiệu suất khi truy vấn API cho nhiều IP cùng lúc mà không làm nghẽn luồng xử lý chính.

3. Luồng hoạt động chính (System Flow)
Dưới đây là sơ đồ luồng dữ liệu của hệ thống:

Input: Nhận file access.log từ Nginx và blacklist.csv từ người dùng.

Parsing: Module parser.py sử dụng Regex để bóc tách dữ liệu, có cơ chế "salvage" để cứu vãn các dòng log malformed (không đúng chuẩn HTTP).

Statistics: Module stats.py tính toán các thông số tổng quan như Bandwidth, Top IP, và phân phối Status Code.

Security Scoring: Module filter.py chấm điểm IP dựa trên 6 tín hiệu (Signals): Blacklist, Malformed, 4xx/5xx threshold, Sensitive Paths và AbuseIPDB Score.

Enrichment: Module checker.py gọi API AbuseIPDB để lấy thông tin ISP và Country Code.

Output: * Hiển thị Dashboard Rich trên Terminal.

Gửi cảnh báo HTML đến Telegram nếu phát hiện mức HIGH.

4. Thiết kế Modular
Dự án được tổ chức theo cấu trúc package giúp dễ dàng bảo trì và mở rộng:

analyzer/: Chứa toàn bộ logic xử lý dữ liệu.

notifiers/: Quản lý các kênh thông báo đầu ra.

tests/: Hệ thống Unit Test đảm bảo tính ổn định của từng module.