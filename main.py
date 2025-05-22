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
            'block_ip_callback': self.prevention_engine.block_ip,  # Thêm callback này
            'update_config_callback': self.update_config
        }
        register_callbacks(callbacks)
    
    def start_all(self):
        """Khởi động tất cả các thành phần của hệ thống."""
        try:
            self.logger.info("Khởi động hệ thống phát hiện và ngăn chặn DDoS...")
            
            # Khởi động các dịch vụ cơ bản
            self.notification_service.start()
            
            # THAY ĐỔI: Không tự động khởi động engine phát hiện và ngăn chặn
            # self.prevention_engine.start()
            # self.packet_capture.start_capture()
            # self.detection_engine.start_detection()
            
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
    
    def update_config(self, config_data: Dict[str, Any]) -> bool:
        """
        Cập nhật cấu hình hệ thống.
        
        Args:
            config_data: Dict chứa section và cấu hình mới
            
        Returns:
            True nếu cập nhật thành công, False nếu không
        """
        try:
            section = config_data.get('section', '').lower()
            config = config_data.get('config', {})
            
            # Kiểm tra xem có cần khởi động lại thành phần nào không
            need_restart_detection = False
            need_restart_prevention = False
            need_restart_notification = False
            
            # Lưu trạng thái hiện tại
            detection_was_running = self.detection_engine.running if hasattr(self.detection_engine, 'running') else False
            prevention_was_running = self.prevention_engine.running if hasattr(self.prevention_engine, 'running') else False
            notification_was_running = self.notification_service.running if hasattr(self.notification_service, 'running') else False
            
            # Xử lý cấu hình Detection
            if section == 'detection':
                # Tham số yêu cầu khởi động lại
                restart_params = ['batch_size', 'model_path']
                for param in restart_params:
                    if param in config:
                        need_restart_detection = True
                        break
                
                # Dừng detection engine nếu cần khởi động lại
                if need_restart_detection and detection_was_running:
                    self.logger.info("Dừng engine phát hiện tạm thời để áp dụng thay đổi...")
                    self.detection_engine.stop_detection()
                    if self.packet_capture.running:
                        self.packet_capture.stop_capture()
                
                # Cập nhật các tham số khởi động lại
                if 'batch_size' in config:
                    self.detection_engine.batch_size = int(config['batch_size'])
                    
                if 'model_path' in config:
                    # Tải lại mô hình
                    try:
                        model_loader = ModelLoader(config['model_path'])
                        self.model, feature_columns = model_loader.load_model()
                        self.detection_engine.model = self.model
                        # Cập nhật feature_extractor nếu cần
                        self.feature_extractor.feature_columns = feature_columns
                    except Exception as model_error:
                        self.logger.error(f"Lỗi khi tải mô hình mới: {model_error}")
                        # Vẫn tiếp tục với các cập nhật khác
                
                # Cập nhật các tham số không yêu cầu khởi động lại
                if 'detection_threshold' in config:
                    self.detection_engine.detection_threshold = float(config['detection_threshold'])
                    
                if 'check_interval' in config:
                    self.detection_engine.check_interval = float(config['check_interval'])
            
            # Xử lý cấu hình Network
            elif section == 'network':
                network_restart_params = ['interface', 'capture_filter']
                for param in network_restart_params:
                    if param in config:
                        need_restart_detection = True
                        break
                
                # Dừng detection engine nếu cần khởi động lại
                if need_restart_detection and detection_was_running:
                    self.logger.info("Dừng engine phát hiện tạm thời để áp dụng thay đổi giao diện mạng...")
                    self.detection_engine.stop_detection()
                    if self.packet_capture.running:
                        self.packet_capture.stop_capture()
                
                # Cập nhật các tham số
                if 'interface' in config:
                    # Cần tạo lại PacketCapture với giao diện mới
                    interface = config['interface']
                    capture_filter = self.packet_capture.capture_filter
                    if 'capture_filter' in config:
                        capture_filter = config['capture_filter']
                    
                    # Tạo PacketCapture mới
                    self.packet_queue = queue.Queue()  # Tạo queue mới
                    self.packet_capture = PacketCapture(interface, self.packet_queue, capture_filter)
                    
                    # Cập nhật queue trong detection_engine
                    self.detection_engine.packet_queue = self.packet_queue
            
            # Xử lý cấu hình Prevention
            elif section == 'prevention':
                # Tham số yêu cầu khởi động lại
                if 'enable_auto_block' in config:
                    need_restart_prevention = True
                
                # Dừng prevention engine nếu cần
                if need_restart_prevention and prevention_was_running:
                    self.logger.info("Dừng engine ngăn chặn tạm thời để áp dụng thay đổi...")
                    self.prevention_engine.stop()
                
                # Cập nhật các tham số không yêu cầu khởi động lại
                if 'block_duration' in config:
                    self.prevention_engine.block_duration = int(config['block_duration'])
                    
                if 'whitelist' in config and isinstance(config['whitelist'], list):
                    self.prevention_engine.whitelist = set(config['whitelist'])
            
            # Xử lý cấu hình Notification
            elif section == 'notification':
                # Tham số yêu cầu khởi động lại
                if 'enable_notifications' in config:
                    need_restart_notification = True
                
                # Dừng notification service nếu cần
                if need_restart_notification and notification_was_running:
                    self.logger.info("Dừng dịch vụ thông báo tạm thời để áp dụng thay đổi...")
                    self.notification_service.stop()
                
                # Cập nhật cấu hình email
                if all(k in config for k in ['smtp_server', 'smtp_port', 'sender_email']):
                    # Tạo cấu hình email mới
                    email_config = {
                        'smtp_server': config['smtp_server'],
                        'smtp_port': int(config['smtp_port']),
                        'sender_email': config['sender_email'],
                        'password': config.get('password', self.notification_service.email_sender.password),
                        'recipients': config.get('recipients', self.notification_service.email_sender.recipients)
                    }
                    
                    # Cập nhật email_sender
                    from utils.email_sender import EmailSender
                    self.notification_service.email_sender = EmailSender(**email_config)
                
                # Cập nhật thời gian cooldown
                if 'cooldown_period' in config:
                    self.notification_service.cooldown_period = int(config['cooldown_period'])
                    
                # Cập nhật danh sách người nhận
                if 'recipients' in config and isinstance(config['recipients'], list):
                    self.notification_service.email_sender.recipients = config['recipients']
            
            # Khởi động lại các thành phần nếu cần
            if need_restart_detection and detection_was_running:
                self.logger.info("Khởi động lại engine phát hiện với cấu hình mới...")
                # Khởi động lại packet capture nếu cần
                if not self.packet_capture.running:
                    self.packet_capture.start_capture()
                # Khởi động lại detection engine
                self.detection_engine.start_detection()
            
            if need_restart_prevention and prevention_was_running:
                self.logger.info("Khởi động lại engine ngăn chặn với cấu hình mới...")
                self.prevention_engine.start()
            
            if need_restart_notification and notification_was_running:
                self.logger.info("Khởi động lại dịch vụ thông báo với cấu hình mới...")
                self.notification_service.start()
            
            self.logger.info(f"Đã cập nhật cấu hình {section}")
            
            # Lưu cấu hình vào file
            self._save_config_to_file(section, config)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi cập nhật cấu hình: {e}")
            return False

    def _save_config_to_file(self, section: str, config: Dict[str, Any]):
        """Lưu cấu hình vào file config.ini."""
        try:
            # Map section name
            section_map = {
                'detection': 'Detection',
                'prevention': 'Prevention',
                'notification': 'Notification',
                'network': 'Network',
                'webui': 'WebUI'
            }
            
            section_name = section_map.get(section.lower(), section.capitalize())
            
            # Đọc file cấu hình hiện tại
            config_path = 'config/config.ini'
            config_parser = configparser.ConfigParser()
            config_parser.read(config_path)
            
            # Đảm bảo section tồn tại
            if section_name not in config_parser:
                config_parser[section_name] = {}
            
            # Cập nhật các giá trị
            for key, value in config.items():
                # Xử lý các kiểu dữ liệu đặc biệt
                if isinstance(value, list):
                    config_parser[section_name][key] = ', '.join(str(item) for item in value)
                else:
                    config_parser[section_name][key] = str(value)
            
            # Lưu file
            with open(config_path, 'w') as f:
                config_parser.write(f)
                
        except Exception as e:
            self.logger.error(f"Lỗi khi lưu cấu hình vào file: {e}")
    
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
    def update_config(self, config_data: Dict[str, Any]) -> bool:
        """
        Cập nhật cấu hình hệ thống.
        
        Args:
            config_data: Dict chứa section và cấu hình mới
            
        Returns:
            True nếu cập nhật thành công, False nếu không
        """
        try:
            section = config_data.get('section', '').lower()
            config = config_data.get('config', {})
            
            if section == 'detection':
                # Cập nhật cấu hình phát hiện
                if 'detection_threshold' in config:
                    self.detection_engine.detection_threshold = float(config['detection_threshold'])
                    
                if 'batch_size' in config:
                    # batch_size chỉ có thể thay đổi khi khởi động lại engine
                    self.logger.info(f"Cập nhật batch_size thành {config['batch_size']}. Sẽ có hiệu lực sau khi khởi động lại.")
                    
                if 'check_interval' in config:
                    self.detection_engine.check_interval = float(config['check_interval'])
                    
            elif section == 'prevention':
                # Cập nhật cấu hình ngăn chặn
                if 'block_duration' in config:
                    self.prevention_engine.block_duration = int(config['block_duration'])
                    
                if 'whitelist' in config and isinstance(config['whitelist'], list):
                    self.prevention_engine.whitelist = set(config['whitelist'])
                    
                # Thêm xử lý enable_auto_block nếu cần
                    
            elif section == 'notification':
                # Cập nhật cấu hình thông báo
                if 'recipients' in config and isinstance(config['recipients'], list):
                    self.notification_service.email_sender.recipients = config['recipients']
                    
                if 'cooldown_period' in config:
                    self.notification_service.cooldown_period = int(config['cooldown_period'])
                    
                # Cập nhật các cấu hình email khác nếu cần
                if all(k in config for k in ['smtp_server', 'smtp_port', 'sender_email', 'password']):
                    # Tạo email sender mới với cấu hình mới
                    from utils.email_sender import EmailSender
                    self.notification_service.email_sender = EmailSender(
                        smtp_server=config['smtp_server'],
                        smtp_port=int(config['smtp_port']),
                        sender_email=config['sender_email'],
                        password=config['password'],
                        recipients=config['recipients']
                    )
            
            self.logger.info(f"Đã cập nhật cấu hình {section}")
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi cập nhật cấu hình: {e}")
            return False
        
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