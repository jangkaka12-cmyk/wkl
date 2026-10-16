# Frontend: giao diện CryptoShield

Giao diện web viết bằng Streamlit, gồm một tệp `app.py`. Giao diện không tự cài thuật toán nào mà chỉ gọi lại code của cả nhóm:

| Trang | Gọi code của |
| --- | --- |
| Tổng quan | Sơ đồ luồng xử lý + số liệu chính lấy từ `Benchmark/ket_qua/` |
| Gửi / nhận tệp | Alice: `sender_establish` của Thắng + `seal_file` của Tân. Bob: chống phát lại theo `message_id`, rồi `receiver_establish` của Thắng + `open_file` của Tân |
| Key Inspector | `ThangV2/hybrid_kex.py`: xem từng khóa trong một lần trao đổi khóa |
| Attack Lab | `Dang_Attack_Lab/attack_lab.py` của Đăng: chạy 5 demo, hiện kết quả lên trang |
| Benchmark | `Benchmark/benchmark.py`: xem bảng, biểu đồ, chạy lại phép đo |

Nếu máy báo `Python was not found`, hãy gõ `py` thay cho `python` trong mọi lệnh bên dưới.

## Chạy giao diện

1. Mở terminal và `cd` vào thư mục `P256_MLKEM768`.
2. Cài thư viện (chỉ cần làm lần đầu):
   ```
   python -m pip install cryptography -r Frontend/requirements.txt
   ```
3. Chạy giao diện:
   ```
   python -m streamlit run Frontend/app.py
   ```
4. Trình duyệt sẽ tự mở trang `http://localhost:8501`. Nếu không tự mở, hãy tự gõ địa chỉ đó vào trình duyệt.
5. Chọn trang ở cột bên trái.
6. Muốn tắt giao diện thì quay lại terminal và nhấn **Ctrl+C**.

Alice và Bob chạy trên cùng một máy. Khóa của hai bên được tạo mới mỗi lần tải lại trang (F5).
