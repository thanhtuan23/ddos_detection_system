# src/ddos_detection_system/utils/ddos_logger.py
import os
import logging
import csv
from typing import Dict, Any
import time
from datetime import datetime

class DDoSLogger:
    """Lớp ghi log chuyên dụng cho các cuộc tấn công DDoS."""
    
    def __init__(self, log_file: str = 'logs/ddos_attacks.log'):
        """
        Khởi tạo logger DDoS.
        
        Args:
            log_file: Đường dẫn đến file log
        """
        # Đảm bảo thư mục logs tồn tại
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Kiểm tra xem file log có tồn tại không
        file_exists = os.path.exists(log_file)
        
        # Mở file ở chế độ append
        self.log_file = log_file
        self.log_handler = open(log_file, 'a')
        self.csv_writer = csv.writer(self.log_handler)
        
        # Viết header nếu file không tồn tại
        if not file_exists:
            self.csv_writer.writerow([
                'timestamp', 'attack_type', 'src_ip', 'dst_ip', 
                'confidence', 'protocol', 'packet_rate', 'byte_rate'
            ])
            self.log_handler.flush()
    
    def log_attack(self, attack_info: Dict[str, Any]):
        """
        Ghi thông tin về một cuộc tấn công DDoS vào file log.
        
        Args:
            attack_info: Thông tin về cuộc tấn công
        """
        try:
            # Trích xuất thông tin
            attack_type = attack_info.get('attack_type', 'Unknown')
            confidence = attack_info.get('confidence', 0)
            timestamp = attack_info.get('timestamp', time.time())
            flow_key = attack_info.get('flow_key', '')
            details = attack_info.get('details', {})
            
            # Trích xuất IP từ flow_key
            src_ip = dst_ip = "Unknown"
            if flow_key and '-' in flow_key:
                parts = flow_key.split('-')
                if ':' in parts[0]:
                    src_ip = parts[0].split(':')[0]
                if ':' in parts[1]:
                    dst_ip = parts[1].split(':')[0]
            
            # Thông tin bổ sung
            protocol = details.get('Protocol', 'Unknown')
            packet_rate = details.get('Packet Rate', 0)
            byte_rate = details.get('Byte Rate', 0)
            
            # Định dạng timestamp
            ts_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            # Ghi vào file CSV
            self.csv_writer.writerow([
                ts_str, attack_type, src_ip, dst_ip, 
                f"{confidence:.2f}", protocol, f"{packet_rate:.2f}", f"{byte_rate:.2f}"
            ])
            self.log_handler.flush()
            
            # In thông báo ngắn gọn ra console
            print(f"[CẢNH BÁO DDOS] {ts_str} - {attack_type} từ {src_ip} (độ tin cậy: {confidence:.2f})")
            
        except Exception as e:
            print(f"Lỗi khi ghi log tấn công: {e}")
    
    def close(self):
        """Đóng file log."""
        if self.log_handler:
            self.log_handler.close()

# Khởi tạo logger toàn cục
ddos_logger = DDoSLogger()

def log_attack(attack_info: Dict[str, Any]):
    """
    Hàm tiện ích để ghi log tấn công.
    
    Args:
        attack_info: Thông tin về cuộc tấn công
    """
    ddos_logger.log_attack(attack_info)