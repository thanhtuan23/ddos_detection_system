#!/bin/bash
# src/ddos_detection_system/install.sh

echo "Cài đặt hệ thống phát hiện và ngăn chặn DDoS..."

# Kiểm tra python3.12 đã cài chưa
if ! command -v python3.12 &> /dev/null
then
    echo "Lỗi: python3.12 chưa được cài. Vui lòng cài đặt Python 3.12 trước."
    exit 1
fi

# Tạo môi trường Python ảo bằng Python 3.12
echo "Tạo môi trường Python ảo với Python 3.12..."
python3.12 -m venv venv

# Kích hoạt môi trường ảo
source venv/bin/activate

# Cài đặt các gói phụ thuộc
echo "Cài đặt các gói phụ thuộc..."
python -m ensurepip --upgrade
pip install --upgrade pip
pip install -r requirements.txt

# Kiểm tra quyền root cho iptables
if [ "$EUID" -ne 0 ]; then
    echo "Cảnh báo: Script không chạy với quyền root. Một số tính năng iptables có thể không hoạt động."
    echo "Hãy chạy lại với sudo nếu cần tính năng ngăn chặn DDoS."
fi

# Tạo thư mục logs nếu chưa tồn tại
mkdir -p logs

# Cấu hình hệ thống
echo "Cấu hình hệ thống..."
if [ ! -f config/config.ini ]; then
    cp config/config.ini.example config/config.ini
    echo "Hãy chỉnh sửa tệp tin config/config.ini với cấu hình của bạn"
fi

# Kiểm tra mô hình ML
if [ ! -f ml/models/random_forest_model.pkl ]; then
    echo "Cảnh báo: Không tìm thấy tệp tin mô hình ML."
    echo "Hãy đặt tệp tin mô hình đã huấn luyện vào thư mục ml/models/"
fi

echo "Cài đặt hoàn tất!"
echo "Để khởi động hệ thống: sudo python main.py"
