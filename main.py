# src/ddos_detection_system/main.py
import os
import sys
import time
import queue
import threading
import logging
import logging.config
import configparser
from typing import Dict, Any

# Cấu hình logging sớm để giảm bớt thông báo không cần thiết
logging.config.fileConfig('config/logging.conf')

werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.WARNING)

# Bỏ qua cảnh báo sklearn về feature names
import warnings
warnings.filterwarnings('ignore', message='X does not have valid feature names')

# Thêm thư mục gốc vào sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import các module
from core.packet_capture import PacketCapture
from core.feature_extraction import FeatureExtractor
from core.detection_engine import DetectionEngine
from core.prevention_engine import PreventionEngine
from core.notification_service import NotificationService
from ml.model_loader import ModelLoader
from ui.app import run_webapp, register_callbacks, on_attack_detected
from ui.app import update_detection_stats, update_blocked_ips, update_system_info

class DDoSDetectionSystem:
    """
    Lớp chính quản lý toàn bộ hệ thống phát hiện và ngăn chặn DDoS.
    """
    
    def __init__(self, config_path: str):
        """
        Khởi tạo hệ thống.
        
        Args:
            config_path: Đường dẫn đến tệp tin cấu hình
        """
        # Thiết lập logging
        logging.config.fileConfig('config/logging.conf')
        self.logger = logging.getLogger(__name__)
        
        # Đọc cấu hình
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
        
        # Khởi tạo các thành phần
        self.packet_queue = queue.Queue()
        self.setup_components()
        
        # Trạng thái hệ thống
        self.running = False
        self.stats_thread = None
    
    def setup_components(self):
        """Thiết lập các thành phần của hệ thống."""
        try:
            # Tải mô hình
            model_path = self.config.get('Detection', 'model_path')
            model_loader = ModelLoader(model_path)
            self.model, feature_columns = model_loader.load_model()
            
            # Thiết lập các thành phần
            interface = self.config.get('Network', 'interface')
            capture_filter = self.config.get('Network', 'capture_filter')
            self.packet_capture = PacketCapture(interface, self.packet_queue, capture_filter)
            
            self.feature_extractor = FeatureExtractor(feature_columns)
            
            # Thiết lập dịch vụ thông báo
            email_config = {
                'smtp_server': self.config.get('Notification', 'smtp_server'),
                'smtp_port': self.config.getint('Notification', 'smtp_port'),
                'sender_email': self.config.get('Notification', 'sender_email'),
                'password': self.config.get('Notification', 'password'),
                'recipients': [r.strip() for r in self.config.get('Notification', 'recipients').split(',')]
            }
            cooldown_period = self.config.getint('Notification', 'cooldown_period')
            self.notification_service = NotificationService(email_config, cooldown_period)
            
            # Đăng ký callback để nhận thông báo tấn công
            self.notification_service.register_callback('attack_detected', on_attack_detected)
            
            # Thiết lập engine phát hiện
            detection_threshold = self.config.getfloat('Detection', 'detection_threshold')
            check_interval = self.config.getfloat('Detection', 'check_interval')
            batch_size = self.config.getint('Detection', 'batch_size')
            self.detection_engine = DetectionEngine(
                self.model, 
                self.feature_extractor, 
                self.notification_service.notify,
                self.packet_queue,
                detection_threshold,
                check_interval,
                batch_size
            )
            
            # Thiết lập engine ngăn chặn
            block_duration = self.config.getint('Prevention', 'block_duration')
            whitelist = [ip.strip() for ip in self.config.get('Prevention', 'whitelist').split(',')]
            self.prevention_engine = PreventionEngine(block_duration, whitelist)
            
            # Đăng ký callbacks cho WebUI
            self._register_ui_callbacks()
            
            self.logger.info("Đã thiết lập thành công tất cả các thành phần hệ thống")
            
        except Exception as e:
            self.logger.error(f"Lỗi khi thiết lập các thành phần: {e}")
            raise
    
    def _register_ui_callbacks(self):
        """Đăng ký các callbacks cho WebUI."""
        callbacks = {
            'start_detection_callback': self.start_detection,
            'stop_detection_callback': self.stop_detection,
            'start_prevention_callback': self.start_prevention,
            'stop_prevention_callback': self.stop_prevention,
            'unblock_ip_callback': self.prevention_engine.unblock_ip,
            'update_config_callback': self.update_config
        }
        register_callbacks(callbacks)
    
    def start_all(self):
        """Khởi động tất cả các thành phần của hệ thống."""
        try:
            self.logger.info("Khởi động hệ thống phát hiện và ngăn chặn DDoS...")
            
            # Khởi động từng thành phần
            self.notification_service.start()
            self.prevention_engine.start()
            self.packet_capture.start_capture()
            self.detection_engine.start_detection()
            
            # Khởi động thread cập nhật thống kê
            self.running = True
            self.stats_thread = threading.Thread(target=self._update_stats_loop)
            self.stats_thread.daemon = True
            self.stats_thread.start()
            
            self.logger.info("Hệ thống đã khởi động thành công")
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi khởi động hệ thống: {e}")
            self.stop_all()
            return False
    
    def stop_all(self):
        """Dừng tất cả các thành phần của hệ thống."""
        try:
            self.logger.info("Dừng hệ thống phát hiện và ngăn chặn DDoS...")
            
            # Dừng thread cập nhật thống kê
            self.running = False
            if self.stats_thread:
                self.stats_thread.join(timeout=2.0)
            
            # Dừng từng thành phần theo thứ tự ngược lại
            self.detection_engine.stop_detection()
            self.packet_capture.stop_capture()
            self.prevention_engine.stop()
            self.notification_service.stop()
            
            self.logger.info("Hệ thống đã dừng thành công")
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi dừng hệ thống: {e}")
            return False
    
    def start_detection(self):
        """Khởi động thành phần phát hiện tấn công."""
        try:
            if not self.packet_capture.running:
                self.packet_capture.start_capture()
            self.detection_engine.start_detection()
            self.logger.info("Đã khởi động thành phần phát hiện tấn công")
            return True
        except Exception as e:
            self.logger.error(f"Lỗi khi khởi động thành phần phát hiện: {e}")
            return False
    
    def stop_detection(self):
        """Dừng thành phần phát hiện tấn công."""
        try:
            self.detection_engine.stop_detection()
            if self.packet_capture.running:
                self.packet_capture.stop_capture()
            self.logger.info("Đã dừng thành phần phát hiện tấn công")
            return True
        except Exception as e:
            self.logger.error(f"Lỗi khi dừng thành phần phát hiện: {e}")
            return False
    
    def start_prevention(self):
        """Khởi động thành phần ngăn chặn tấn công."""
        try:
            self.prevention_engine.start()
            self.logger.info("Đã khởi động thành phần ngăn chặn tấn công")
            return True
        except Exception as e:
            self.logger.error(f"Lỗi khi khởi động thành phần ngăn chặn: {e}")
            return False
    
    def stop_prevention(self):
        """Dừng thành phần ngăn chặn tấn công."""
        try:
            self.prevention_engine.stop()
            self.logger.info("Đã dừng thành phần ngăn chặn tấn công")
            return True
        except Exception as e:
            self.logger.error(f"Lỗi khi dừng thành phần ngăn chặn: {e}")
            return False
    
    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """
        Cập nhật cấu hình hệ thống.
        
        Args:
            new_config: Dict chứa cấu hình mới
            
        Returns:
            True nếu cập nhật thành công, False nếu không
        """
        try:
            # Cập nhật cấu hình phát hiện
            if 'detection_threshold' in new_config:
                threshold = float(new_config['detection_threshold'])
                self.detection_engine.detection_threshold = threshold
                self.config.set('Detection', 'detection_threshold', str(threshold))
            
            if 'block_duration' in new_config:
                duration = int(new_config['block_duration'])
                self.prevention_engine.block_duration = duration
                self.config.set('Prevention', 'block_duration', str(duration))
            
            if 'whitelist' in new_config and isinstance(new_config['whitelist'], list):
                whitelist = new_config['whitelist']
                self.prevention_engine.whitelist = set(whitelist)
                self.config.set('Prevention', 'whitelist', ','.join(whitelist))
            
            # Lưu cấu hình vào tệp tin
            with open('config/config.ini', 'w') as f:
                self.config.write(f)
                
            self.logger.info("Đã cập nhật cấu hình hệ thống")
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi cập nhật cấu hình: {e}")
            return False
    
    def _update_stats_loop(self):
        """Thread cập nhật thống kê hệ thống định kỳ."""
        while self.running:
            try:
                # Cập nhật thống kê phát hiện
                detection_stats = self.detection_engine.get_detection_stats()
                update_detection_stats(detection_stats)
                
                # Cập nhật danh sách IP bị chặn
                blocked_ips = self.prevention_engine.get_blocked_ips()
                update_blocked_ips(blocked_ips)
                
                # Cập nhật thông tin hệ thống
                system_info = self._get_system_info()
                update_system_info(system_info)
                
            except Exception as e:
                self.logger.error(f"Lỗi khi cập nhật thống kê: {e}")
                
            time.sleep(5)  # Cập nhật mỗi 5 giây
    
    def _get_system_info(self) -> Dict[str, Any]:
        """
        Thu thập thông tin về hệ thống.
        
        Returns:
            Dict chứa thông tin hệ thống
        """
        import psutil
        
        return {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'packet_queue_size': self.packet_queue.qsize(),
            'uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0
        }
    
    def run(self):
        """Khởi động hệ thống và chạy WebUI."""
        try:
            # Lưu thời gian bắt đầu
            self.start_time = time.time()
            
            # Khởi động hệ thống
            if not self.start_all():
                self.logger.error("Không thể khởi động hệ thống. Hệ thống sẽ thoát.")
                return
            
            # Chạy WebUI
            host = self.config.get('WebUI', 'host')
            port = self.config.getint('WebUI', 'port')
            debug = self.config.getboolean('WebUI', 'debug')
            
            self.logger.info(f"Khởi động WebUI tại http://{host}:{port}")
            run_webapp(host, port, debug)
            
        except KeyboardInterrupt:
            self.logger.info("Đã nhận tín hiệu thoát. Dừng hệ thống...")
            self.stop_all()
        except Exception as e:
            self.logger.critical(f"Lỗi không xử lý được: {e}")
            self.stop_all()

if __name__ == "__main__":
    # Đường dẫn mặc định đến tệp tin cấu hình
    config_path = "config/config.ini"
    
    # Cho phép chỉ định tệp tin cấu hình từ dòng lệnh
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    
    # Khởi tạo và chạy hệ thống
    system = DDoSDetectionSystem(config_path)
    system.run()