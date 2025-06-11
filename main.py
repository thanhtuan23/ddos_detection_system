# src/ddos_detection_system/main.py
import os
import sys
import time
import queue
import threading
import logging
import logging.config
import configparser
from typing import Dict, Any, List, Optional

# Cấu hình logging sớm để giảm bớt thông báo không cần thiết
logging.config.fileConfig('config/logging.conf')

werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.WARNING)

# Bỏ qua cảnh báo sklearn về feature names
import warnings
warnings.filterwarnings('ignore', message='X does not have valid feature names')

# Thêm thư mục gốc vào sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import tất cả module cần thiết
import psutil
from core.packet_capture import PacketCapture
from core.feature_extraction import FeatureExtractor
from core.detection_engine import DetectionEngine
from core.prevention_engine import PreventionEngine
from core.notification_service import NotificationService
from ml.model_loader import ModelLoader
from utils.email_sender import EmailSender
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

        self.prevention_engine = PreventionEngine()
        self.prevention_engine.start()

        # Trạng thái hệ thống
        self.running = False
        self.stats_thread = None
        self.start_time = 0
    
    def setup_components(self):
        """Thiết lập các thành phần của hệ thống."""
        try:
            # Tải mô hình
            model_path = self.config.get('Detection', 'model_path')
            model_loader = ModelLoader(model_path)
            self.model, feature_columns, scaler, label_encoder, label_mapping = model_loader.load_model()
            
            # Thiết lập các thành phần
            interface = self.config.get('Network', 'interface')
            capture_filter = self.config.get('Network', 'capture_filter')
            self.packet_capture = PacketCapture(interface, self.packet_queue, capture_filter)
            
            # Truyền config cho feature_extractor
            self.feature_extractor = FeatureExtractor(feature_columns, self.config)
            
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
            
            # Đọc cấu hình streaming services và ngưỡng false positive (để tham khảo sau này)
            self.streaming_services = self.config.get('Detection', 'streaming_services', 
                                                    fallback='youtube,netflix').split(',')
            self.streaming_services = [s.strip() for s in self.streaming_services]
            
            self.false_positive_threshold = self.config.getfloat('Detection', 
                                                          'false_positive_threshold', 
                                                          fallback=0.8)
            
            # Khởi tạo detection engine KHÔNG truyền các tham số chưa được hỗ trợ
            self.detection_engine = DetectionEngine(
                self.model, 
                self.feature_extractor, 
                self.notification_service.notify,
                self.packet_queue,
                detection_threshold,
                check_interval,
                batch_size,
                config=self.config,  # Truyền config để có thể sử dụng trong feature_extractor
                prevention_engine=self.prevention_engine,
                label_encoder=label_encoder
                # streaming_services và false_positive_threshold bị loại bỏ
            )
            
            # Lưu các tham số này vào thuộc tính của detection_engine (nếu engine hỗ trợ)
            try:
                self.detection_engine.streaming_services = self.streaming_services
                self.detection_engine.false_positive_threshold = self.false_positive_threshold
                self.logger.info(f"Đã cài đặt thông tin dịch vụ streaming: {len(self.streaming_services)} dịch vụ")
            except AttributeError:
                self.logger.warning("Detection Engine không hỗ trợ nhận diện dịch vụ streaming tự động")
            
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
        callbacks = {
            'start_detection_callback': self.start_detection,
            'stop_detection_callback': self.stop_detection,
            'start_prevention_callback': self.start_prevention,
            'stop_prevention_callback': self.stop_prevention,
            'unblock_ip_callback': self.unblock_ip,
            'block_ip_callback': self.block_ip,
            'update_config_callback': self.update_config_ui,  # Sử dụng hàm đã tối ưu
        }
        register_callbacks(callbacks)

    
    def start_all(self) -> bool:
        """Khởi động tất cả các thành phần của hệ thống."""
        try:
            self.logger.info("Khởi động hệ thống phát hiện và ngăn chặn DDoS...")
            
            # Khởi động dịch vụ thông báo
            self.notification_service.start()
            
            # Khởi động thread cập nhật thống kê
            self.running = True
            self.start_time = time.time()
            self.stats_thread = threading.Thread(target=self._update_stats_loop)
            self.stats_thread.daemon = True
            self.stats_thread.start()
            
            self.logger.info("Hệ thống đã khởi động thành công")
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi khởi động hệ thống: {e}")
            self.stop_all()
            return False
    
    def stop_all(self) -> bool:
        """Dừng tất cả các thành phần của hệ thống."""
        try:
            self.logger.info("Dừng hệ thống phát hiện và ngăn chặn DDoS...")
            
            # Dừng thread cập nhật thống kê
            self.running = False
            if self.stats_thread and self.stats_thread.is_alive():
                self.stats_thread.join(timeout=2.0)
            
            # Dừng từng thành phần theo thứ tự ngược lại
            if hasattr(self, 'detection_engine'):
                self.detection_engine.stop_detection()
            if hasattr(self, 'packet_capture'):
                self.packet_capture.stop_capture()
            if hasattr(self, 'prevention_engine'):
                self.prevention_engine.stop()
            if hasattr(self, 'notification_service'):
                self.notification_service.stop()
            
            self.logger.info("Hệ thống đã dừng thành công")
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi dừng hệ thống: {e}")
            return False
    
    def start_detection(self) -> bool:
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
    
    def stop_detection(self) -> bool:
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
    
    def start_prevention(self) -> bool:
        """Khởi động thành phần ngăn chặn tấn công."""
        try:
            self.prevention_engine.start()
            self.logger.info("Đã khởi động thành phần ngăn chặn tấn công")
            return True
        except Exception as e:
            self.logger.error(f"Lỗi khi khởi động thành phần ngăn chặn: {e}")
            return False
    
    def stop_prevention(self) -> bool:
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
            component_status = {
                'detection': {'running': False, 'restarted': False},
                'prevention': {'running': False, 'restarted': False},
                'notification': {'running': False, 'restarted': False}
            }
            
            # Lưu trạng thái các thành phần trước khi cập nhật
            if hasattr(self, 'detection_engine'):
                component_status['detection']['running'] = self.detection_engine.is_running
            if hasattr(self, 'prevention_engine'):
                component_status['prevention']['running'] = self.prevention_engine.is_running
            if hasattr(self, 'notification_service'):
                component_status['notification']['running'] = self.notification_service.is_running
            
            # Xử lý cấu hình Detection
            if section == 'detection':
                self._update_detection_config(config, component_status)
                
            # Xử lý cấu hình Network
            elif section == 'network':
                self._update_network_config(config, component_status)
                
            # Xử lý cấu hình Prevention
            elif section == 'prevention':
                self._update_prevention_config(config, component_status)
                
            # Xử lý cấu hình Notification
            elif section == 'notification':
                self._update_notification_config(config, component_status)
            
            # Khởi động lại các thành phần nếu cần
            if component_status['detection']['restarted'] and component_status['detection']['running']:
                self.logger.info("Khởi động lại engine phát hiện với cấu hình mới...")
                self.start_detection()
            
            if component_status['prevention']['restarted'] and component_status['prevention']['running']:
                self.logger.info("Khởi động lại engine ngăn chặn với cấu hình mới...")
                self.start_prevention()
            
            if component_status['notification']['restarted'] and component_status['notification']['running']:
                self.logger.info("Khởi động lại dịch vụ thông báo với cấu hình mới...")
                self.notification_service.start()
            
            self.logger.info(f"Đã cập nhật cấu hình {section}")
            
            # Lưu cấu hình vào file
            self._save_config_to_file(section, config)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi cập nhật cấu hình: {e}")
            return False
    
    def _update_detection_config(self, config: Dict[str, Any], component_status: Dict[str, Dict[str, bool]]):
        """Cập nhật cấu hình detection engine."""
        need_restart = False
        
        # Tham số yêu cầu khởi động lại
        restart_params = ['batch_size', 'model_path']
        for param in restart_params:
            if param in config:
                need_restart = True
                break
        
        # Dừng detection engine nếu cần khởi động lại
        if need_restart and component_status['detection']['running']:
            self.logger.info("Dừng engine phát hiện tạm thời để áp dụng thay đổi...")
            self.detection_engine.stop_detection()
            if self.packet_capture.running:
                self.packet_capture.stop_capture()
            component_status['detection']['restarted'] = True
        
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
        
        # Cập nhật các tham số không yêu cầu khởi động lại
        if 'detection_threshold' in config:
            self.detection_engine.detection_threshold = float(config['detection_threshold'])
        
        if 'check_interval' in config:
            self.detection_engine.check_interval = float(config['check_interval'])
            
        # Cập nhật cấu hình streaming services
        if 'streaming_services' in config and isinstance(config['streaming_services'], list):
            self.detection_engine.streaming_services = config['streaming_services']
            self.logger.info(f"Đã cập nhật danh sách streaming services: {config['streaming_services']}")
        
        # Cập nhật ngưỡng false positive
        if 'false_positive_threshold' in config:
            self.detection_engine.false_positive_threshold = float(config['false_positive_threshold'])
            self.logger.info(f"Đã cập nhật ngưỡng false positive: {config['false_positive_threshold']}")
    
    def _update_network_config(self, config: Dict[str, Any], component_status: Dict[str, Dict[str, bool]]):
        """Cập nhật cấu hình network."""
        need_restart = False
        
        # Tham số yêu cầu khởi động lại
        network_restart_params = ['interface', 'capture_filter']
        for param in network_restart_params:
            if param in config:
                need_restart = True
                break
        
        # Dừng detection engine nếu cần khởi động lại
        if need_restart and component_status['detection']['running']:
            self.logger.info("Dừng engine phát hiện tạm thời để áp dụng thay đổi giao diện mạng...")
            self.detection_engine.stop_detection()
            if self.packet_capture.running:
                self.packet_capture.stop_capture()
            component_status['detection']['restarted'] = True
        
        # Cập nhật cấu hình network
        if 'interface' in config or 'capture_filter' in config:
            # Cập nhật giao diện mạng
            interface = config.get('interface', self.packet_capture.interface)
            capture_filter = config.get('capture_filter', self.packet_capture.capture_filter)
            
            # Tạo lại packet capture nếu cần
            if self.packet_capture.interface != interface or self.packet_capture.capture_filter != capture_filter:
                self.packet_capture = PacketCapture(interface, self.packet_queue, capture_filter)
                self.logger.info(f"Đã cập nhật cấu hình mạng: interface={interface}, filter={capture_filter}")
    
    def _update_prevention_config(self, config: Dict[str, Any], component_status: Dict[str, Dict[str, bool]]):
        """Cập nhật cấu hình prevention engine."""
        need_restart = False
        
        # Tham số yêu cầu khởi động lại
        if 'enable_auto_block' in config:
            need_restart = True
        
        # Dừng prevention engine nếu cần
        if need_restart and component_status['prevention']['running']:
            self.logger.info("Dừng engine ngăn chặn tạm thời để áp dụng thay đổi...")
            self.prevention_engine.stop()
            component_status['prevention']['restarted'] = True
        
        # Cập nhật cấu hình prevention
        if 'whitelist' in config and isinstance(config['whitelist'], list):
            self.prevention_engine.whitelist = set(config['whitelist'])
            self.logger.info(f"Đã cập nhật whitelist: {len(config['whitelist'])} IPs")
        
        if 'block_duration' in config:
            self.prevention_engine.block_duration = int(config['block_duration'])
            self.logger.info(f"Đã cập nhật thời gian chặn: {config['block_duration']} giây")
    
    def _update_notification_config(self, config: Dict[str, Any], component_status: Dict[str, Dict[str, bool]]):
        """Cập nhật cấu hình notification service."""
        need_restart = False
        
        # Tham số yêu cầu khởi động lại
        if 'enable_notifications' in config:
            need_restart = True
        
        # Dừng notification service nếu cần
        if need_restart and component_status['notification']['running']:
            self.logger.info("Dừng dịch vụ thông báo tạm thời để áp dụng thay đổi...")
            self.notification_service.stop()
            component_status['notification']['restarted'] = True
        
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
            self.notification_service.email_sender = EmailSender(**email_config)
            self.logger.info("Đã cập nhật cấu hình email")
        
        # Cập nhật thời gian cooldown
        if 'cooldown_period' in config:
            self.notification_service.cooldown_period = int(config['cooldown_period'])
            self.logger.info(f"Đã cập nhật thời gian cooldown: {config['cooldown_period']} giây")
            
        # Cập nhật danh sách người nhận
        if 'recipients' in config and isinstance(config['recipients'], list):
            self.notification_service.email_sender.recipients = config['recipients']
            self.logger.info(f"Đã cập nhật danh sách người nhận: {len(config['recipients'])} địa chỉ")

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
                
            self.logger.info(f"Đã lưu cấu hình vào file {config_path}")
                
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
        return {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'packet_queue_size': self.packet_queue.qsize(),
            'uptime': time.time() - self.start_time if self.start_time > 0 else 0
        }
    
    def block_ip(self, ip, attack_info=None):
        if self.prevention_engine:
            result = self.prevention_engine.block_ip(ip, attack_info or {"attack_type": "Manual"})
            update_blocked_ips(self.prevention_engine.get_blocked_ips())
            return result
        return False

    def unblock_ip(self, ip):
        if self.prevention_engine:
            result = self.prevention_engine.unblock_ip(ip)
            update_blocked_ips(self.prevention_engine.get_blocked_ips())
            return result
        return False

    # Đừng overwrite hàm update_config gốc! Thay vào đó:
    def update_config_ui(self, config_data: Dict[str, Any]) -> bool:
        # Gọi update_config thực sự
        result = self.update_config(config_data)
        # Sau đó update lại UI
        update_blocked_ips(self.prevention_engine.get_blocked_ips())
        update_detection_stats(self.detection_engine.get_detection_stats())
        update_system_info(self._get_system_info())
        return result



    def run(self):
        """Khởi động hệ thống và chạy WebUI."""
        try:
            # Hiển thị cấu hình streaming services
            streaming_services = self.config.get('Detection', 'streaming_services', fallback='youtube,netflix')
            self.logger.info(f"Hỗ trợ nhận diện tự động các dịch vụ streaming: {streaming_services}")
            
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