# nginx-log-analyzer
🔍 Nginx Log Analyzer (Security SIEM Prototype)
Nginx Log Analyzer là một công cụ phân tích log Web Server tập trung vào bảo mật, được thiết kế để phát hiện sớm các hành vi tấn công, quét lỗ hổng và cảnh báo tức thời. Đây là một nguyên mẫu (Prototype) cho hệ thống SIEM thu nhỏ, giúp quản trị viên phản ứng nhanh với các mối đe dọa.

✨ Tính năng chính
Bóc tách log thông minh (Parsing & Salvaging): Tự động phân tích các trường log chuẩn và có khả năng cứu vãn dữ liệu từ các dòng log lỗi định dạng (malformed) để không bỏ sót các kỹ thuật quét ẩn danh.

Phân tích thống kê (Insights): Tổng hợp trực quan lưu lượng truy cập, băng thông, danh sách Top IP và phân phối mã trạng thái (2xx, 4xx, 5xx).

Chấm điểm đe dọa đa tầng (Multi-layer Scoring):
Local Blacklist: Đối soát nhanh với danh sách chặn nội bộ.

Heuristic Analysis: Nhận diện các hành vi dò quét lỗ hổng phổ biến (GeoServer RCE, Path Traversal, SQLi, Login Probing).

AbuseIPDB Integration: Truy vấn thời gian thực tới cơ sở dữ liệu quốc tế để lấy điểm tin cậy lạm dụng (Confidence Score).

Dashboard hiện đại: Giao diện Terminal chuyên nghiệp, trực quan sử dụng thư viện Rich.

Cảnh báo Telegram: Tự động gửi báo cáo chi tiết định dạng HTML qua Telegram Bot khi phát hiện các IP có mức độ đe dọa HIGH.

📂 Cấu trúc dự án
nginx-log-analyzer/
│
├── main.py                  ← Entry point CLI (click + rich dashboard)
├── config.py                ← Singleton settings đọc từ .env
├── requirements.txt         ← click, rich, requests, python-dotenv
├── .env                     ← Biến môi trường thật (không commit lên git)
├── .env.example             ← Template cấu hình để tham khảo
├── .gitignore
├── LICENSE
├── README.md
│
├── analyzer/                ← Toàn bộ logic phân tích log
│   ├── __init__.py
│   ├── parser.py            ← Parse Combined Log Format; salvage malformed lines
│   ├── stats.py             ← Tính toán thống kê tổng hợp (Counter-based)
│   ├── filter.py            ← Chấm điểm đe dọa 6 tín hiệu + AbuseIPDB
│   └── checker.py           ← AbuseIPDB v2 API client (batch + concurrent)
│
├── notifiers/               ← Kênh gửi cảnh báo ra ngoài
│   ├── __init__.py
│   └── telegram.py          ← Gửi HTML alert qua Telegram Bot API
│
├── data/                    ← Dữ liệu vận hành (không phải code)
│   ├── access.log           ← File log Nginx để phân tích
│   └── blacklist.csv        ← IP blacklist nội bộ (ip,reason,added_date)
│
└── tests/                   ← Unit tests — không cần mạng, không cần API key
    ├── test_parser.py        ← 40 tests: regex, salvage, key schema
    ├── test_filter.py        ← 60 tests: 6 signals, AbuseIPDB mock, sorting
    └── test_stats.py         ← 53 tests: bandwidth, top IPs/paths, timestamps

🚀 Hướng dẫn cài đặt và sử dụng

1. Yêu cầu hệ thống
Python 3.9 trở lên.
API Key từ AbuseIPDB.
Telegram Bot Token & Chat ID (tạo qua @BotFather).

2.  Clone repository (bash)
git clone https://github.com/SANG01022005/nginx-log-analyzer.git
cd nginx-log-analyzer

3. Cài đặt thư viện 
pip install rich requests python-dotenv click

4. Cấu hình môi trường
Sao chép file mẫu: cp .env.example .env
Mở file .env và điền các thông số chính xác.

5. Chạy chương trình:
Phân tích file log mặc định kèm blacklist:
python main.py --help
python main.py --log data/access.log --blacklist data/blacklist.csv

6. Kiểm thử (Unit Test)
Để đảm bảo các module hoạt động chính xác:
python tests/test_parser.py -v
python tests/test_filter.py -v
python tests/test_stats.py -v

🛡️ Bảo mật
File .env chứa thông tin nhạy cảm đã được cấu hình trong .gitignore để không bị lộ khi đẩy lên GitHub.
Hệ thống sử dụng các thư viện chuẩn để xử lý yêu cầu HTTP và quản lý dữ liệu.

📝 Vibe Coding Insights
Dự án này được phát triển thông qua phương thức Pair-programming với AI, tập trung vào việc giải quyết các bài toán thực tế:
Sử dụng ThreadPoolExecutor để tối ưu hóa tốc độ gọi API AbuseIPDB.
Xử lý các lỗi lồng nhau về đường dẫn sys.path để đảm bảo tính modular.
Tối ưu hóa giao diện Terminal bằng cơ chế ratio và soft_wrap của Rich để tránh chồng lấn văn bản.

Author: NGÔ VĂN SANG

Project: Open Vibe Coding Challenge Prototype