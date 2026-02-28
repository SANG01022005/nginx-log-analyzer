Nhật ký "Vibe Coding" — Nginx Log Analyzer
Lịch sử các prompt quan trọng với Claude AI

https://claude.ai/share/0a5a9f7c-8f97-4f2e-93ed-5e33f4eaf2b5

Tổng kết quá trình Vibe Coding
Những gì AI làm tốt

Thiết kế kiến trúc: Đề xuất module separation rõ ràng, giải thích trade-off.
Boilerplate code: Viết nhanh dataclass, regex, error handling.
Debug logic: Phân tích lỗi từ traceback và source code, chỉ ra đúng nguyên nhân gốc rễ.
Edge cases: Tự đề xuất các trường hợp biên mà tôi chưa nghĩ đến (ThreadPoolExecutor exception handling, status_code=None cho salvage failure...).

Những gì cần intervention thủ công

Business requirements: AI không tự biết ngưỡng nào là "hợp lý" cho từng signal (5xx_for_high=5 hay 10?). Cần người dùng quyết định.
Test fixture accuracy: Lần đầu AI viết fixture theo assumption, không đọc source. Phải prompt lại rõ: "đọc source trước khi viết test".
API quota management: Quyết định use_abuseipdb=False là default phải do người dùng đề xuất — AI không biết free tier giới hạn 1.000 req/ngày là nhiều hay ít cho usecase cụ thể.

Prompt pattern hiệu quả nhất
"Hãy đọc lại [file.py] trước, sau đó [yêu cầu].
Đặc biệt chú ý đến [điểm cụ thể cần chú ý]."
Việc yêu cầu AI đọc source code thật trước khi viết test/documentation đã loại bỏ hầu hết các lỗi do assumption sai.
