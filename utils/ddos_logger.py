# src/ddos_detection_system/utils/ddos_logger.py
import os
import csv
import time
from datetime import datetime
from typing import Dict, Any, List

class DDoSLogger:
    """Logger chuyên dụng cho các cuộc tấn công DDoS."""
    
    def __init__(self, log_dir: str = 'logs'):
        """
        Khởi tạo logger DDoS.
        
        Args:
            log_dir: Thư mục chứa các file log
        """
        # Đảm bảo thư mục logs tồn tại
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # File log cho các cuộc tấn công
        self.attack_log_file = os.path.join(log_dir, 'ddos_attacks.log')
        
        # File log cho danh sách IP tấn công
        self.ip_log_file = os.path.join(log_dir, 'ddos_ips.log')
        
        # Khởi tạo các file nếu chưa tồn tại
        self._initialize_log_files()
        
        # Lưu trữ các IP đã log để tránh trùng lặp
        self.logged_ips = set()
        self._load_existing_ips()
    
    def _initialize_log_files(self):
        """Khởi tạo các file log nếu chưa tồn tại."""
        # Khởi tạo file log tấn công
        if not os.path.exists(self.attack_log_file):
            with open(self.attack_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'attack_type', 'src_ip', 'dst_ip', 
                    'confidence', 'protocol', 'packet_rate', 'byte_rate'
                ])
        
        # Khởi tạo file log IP
        if not os.path.exists(self.ip_log_file):
            with open(self.ip_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'ip', 'first_seen', 'last_seen', 'attack_count', 'attack_types', 
                    'confidence_avg', 'blocked'
                ])
    
    def _load_existing_ips(self):
        """Tải danh sách IP đã có trong file log IP."""
        if os.path.exists(self.ip_log_file):
            try:
                with open(self.ip_log_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    next(reader)  # Bỏ qua header
                    for row in reader:
                        if row and len(row) > 0:
                            self.logged_ips.add(row[0])  # IP ở cột đầu tiên
            except Exception as e:
                print(f"Lỗi khi tải danh sách IP đã có: {e}")
    
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
            
            # Ghi vào file log tấn công
            with open(self.attack_log_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    ts_str, attack_type, src_ip, dst_ip, 
                    f"{confidence:.2f}", protocol, f"{packet_rate:.2f}", f"{byte_rate:.2f}"
                ])
            
            # Ghi vào file log IP
            # Chỉ ghi các IP hợp lệ và khác "Unknown"
            if src_ip != "Unknown" and self._is_valid_ip(src_ip):
                self._log_ip(src_ip, ts_str, attack_type, confidence)
            
            # In thông báo ngắn gọn ra console
            print(f"[CẢNH BÁO DDOS] {ts_str} - {attack_type} từ {src_ip} (độ tin cậy: {confidence:.2f})")
            
        except Exception as e:
            print(f"Lỗi khi ghi log tấn công: {e}")
    
    def _log_ip(self, ip: str, timestamp: str, attack_type: str, confidence: float):
        """
        Ghi thông tin về một IP tấn công vào file log IP.
        
        Args:
            ip: Địa chỉ IP tấn công
            timestamp: Thời gian phát hiện
            attack_type: Loại tấn công
            confidence: Độ tin cậy của phát hiện
        """
        # Tải dữ liệu IP hiện có
        ip_data = {}
        if os.path.exists(self.ip_log_file):
            with open(self.ip_log_file, 'r', newline='') as f:
                reader = csv.reader(f)
                header = next(reader)  # Đọc header
                
                for row in reader:
                    if len(row) >= 7:
                        curr_ip = row[0]
                        ip_data[curr_ip] = {
                            'first_seen': row[1],
                            'last_seen': row[2],
                            'attack_count': int(row[3]),
                            'attack_types': row[4],
                            'confidence_avg': float(row[5]),
                            'blocked': row[6] == 'True'
                        }
        
        # Cập nhật hoặc thêm mới thông tin IP
        if ip in ip_data:
            # Cập nhật IP đã có
            data = ip_data[ip]
            data['last_seen'] = timestamp
            data['attack_count'] += 1
            
            # Cập nhật danh sách loại tấn công
            attack_types = set(data['attack_types'].split(','))
            attack_types.add(attack_type)
            data['attack_types'] = ','.join(attack_types)
            
            # Cập nhật độ tin cậy trung bình
            old_avg = data['confidence_avg']
            old_count = data['attack_count'] - 1
            data['confidence_avg'] = (old_avg * old_count + confidence) / data['attack_count']
        else:
            # Thêm IP mới
            ip_data[ip] = {
                'first_seen': timestamp,
                'last_seen': timestamp,
                'attack_count': 1,
                'attack_types': attack_type,
                'confidence_avg': confidence,
                'blocked': False
            }
            self.logged_ips.add(ip)
        
        # Ghi lại tất cả dữ liệu vào file
        with open(self.ip_log_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'first_seen', 'last_seen', 'attack_count', 'attack_types', 'confidence_avg', 'blocked'])
            
            for curr_ip, data in ip_data.items():
                writer.writerow([
                    curr_ip,
                    data['first_seen'],
                    data['last_seen'],
                    data['attack_count'],
                    data['attack_types'],
                    f"{data['confidence_avg']:.4f}",
                    data['blocked']
                ])
    
    def update_ip_blocked_status(self, ip: str, blocked: bool):
        """
        Cập nhật trạng thái chặn của một IP.
        
        Args:
            ip: Địa chỉ IP
            blocked: True nếu IP bị chặn, False nếu không
        """
        if not os.path.exists(self.ip_log_file):
            return
        
        ip_data = {}
        with open(self.ip_log_file, 'r', newline='') as f:
            reader = csv.reader(f)
            header = next(reader)  # Đọc header
            
            for row in reader:
                if len(row) >= 7:
                    curr_ip = row[0]
                    ip_data[curr_ip] = {
                        'first_seen': row[1],
                        'last_seen': row[2],
                        'attack_count': int(row[3]),
                        'attack_types': row[4],
                        'confidence_avg': float(row[5]),
                        'blocked': row[6] == 'True'
                    }
        
        # Chỉ cập nhật nếu IP tồn tại trong danh sách
        if ip in ip_data:
            ip_data[ip]['blocked'] = blocked
            
            # Ghi lại tất cả dữ liệu vào file
            with open(self.ip_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ip', 'first_seen', 'last_seen', 'attack_count', 'attack_types', 'confidence_avg', 'blocked'])
                
                for curr_ip, data in ip_data.items():
                    writer.writerow([
                        curr_ip,
                        data['first_seen'],
                        data['last_seen'],
                        data['attack_count'],
                        data['attack_types'],
                        f"{data['confidence_avg']:.4f}",
                        data['blocked']
                    ])
    
    def get_all_attack_ips(self) -> List[Dict[str, Any]]:
        """
        Lấy danh sách tất cả các IP tấn công.
        
        Returns:
            Danh sách các IP tấn công với thông tin chi tiết
        """
        ip_list = []
        
        if not os.path.exists(self.ip_log_file):
            return ip_list
        
        with open(self.ip_log_file, 'r', newline='') as f:
            reader = csv.reader(f)
            header = next(reader)  # Đọc header
            
            for row in reader:
                if len(row) >= 7:
                    ip_list.append({
                        'ip': row[0],
                        'first_seen': row[1],
                        'last_seen': row[2],
                        'attack_count': int(row[3]),
                        'attack_types': row[4],
                        'confidence_avg': float(row[5]),
                        'blocked': row[6] == 'True'
                    })
        
        return ip_list
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Kiểm tra xem một chuỗi có phải là địa chỉ IP hợp lệ không.
        
        Args:
            ip: Chuỗi cần kiểm tra
            
        Returns:
            True nếu là IP hợp lệ, False nếu không
        """
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        
        return True

# Tạo instance logger toàn cục
ddos_logger = DDoSLogger()

def log_attack(attack_info: Dict[str, Any]):
    """
    Hàm tiện ích để ghi log tấn công.
    
    Args:
        attack_info: Thông tin về cuộc tấn công
    """
    ddos_logger.log_attack(attack_info)

def update_ip_blocked_status(ip: str, blocked: bool):
    """
    Hàm tiện ích để cập nhật trạng thái chặn của một IP.
    
    Args:
        ip: Địa chỉ IP
        blocked: True nếu IP bị chặn, False nếu không
    """
    ddos_logger.update_ip_blocked_status(ip, blocked)

def get_all_attack_ips() -> List[Dict[str, Any]]:
    """
    Hàm tiện ích để lấy danh sách tất cả các IP tấn công.
    
    Returns:
        Danh sách các IP tấn công với thông tin chi tiết
    """
    return ddos_logger.get_all_attack_ips()