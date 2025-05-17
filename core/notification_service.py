# src/ddos_detection_system/core/notification_service.py
import time
import threading
import queue
import logging
from typing import Dict, Any, List, Callable
from utils.email_sender import EmailSender

class NotificationService:
    """
    Dịch vụ gửi thông báo khi phát hiện các cuộc tấn công DDoS.
    """
    
    def __init__(self, email_config: Dict[str, str], cooldown_period: int = 300):
        """
        Khởi tạo dịch vụ thông báo.
        
        Args:
            email_config: Cấu hình email (SMTP server, credentials, etc.)
            cooldown_period: Thời gian chờ giữa các thông báo (giây)
        """
        self.email_sender = EmailSender(**email_config)
        self.cooldown_period = cooldown_period
        self.notification_queue = queue.Queue()
        self.last_notification_time = {}  # Lưu thời gian thông báo cuối cùng theo loại tấn công
        self.running = False
        self.notification_thread = None
        self.logger = logging.getLogger("ddos_notification")
        
        # Đăng ký các callback cho các sự kiện
        self.event_callbacks = {}
    
    def start(self):
        """Bắt đầu dịch vụ thông báo."""
        self.running = True
        self.notification_thread = threading.Thread(target=self._process_notifications)
        self.notification_thread.daemon = True
        self.notification_thread.start()
        self.logger.info("Dịch vụ thông báo đã bắt đầu")
    
    def stop(self):
        """Dừng dịch vụ thông báo."""
        self.running = False
        if self.notification_thread:
            self.notification_thread.join(timeout=2.0)
        self.logger.info("Dịch vụ thông báo đã dừng")
    
    def notify(self, attack_info: Dict[str, Any]):
        """
        Thêm một thông báo tấn công vào hàng đợi.
        
        Args:
            attack_info: Thông tin về cuộc tấn công DDoS
        """
        self.notification_queue.put(attack_info)
        
        # Kích hoạt callback nếu đã đăng ký
        event_type = "attack_detected"
        if event_type in self.event_callbacks:
            for callback in self.event_callbacks[event_type]:
                try:
                    callback(attack_info)
                except Exception as e:
                    self.logger.error(f"Lỗi khi gọi callback {callback}: {e}")
    
    def register_callback(self, event_type: str, callback: Callable):
        """
        Đăng ký một hàm callback cho một loại sự kiện.
        
        Args:
            event_type: Loại sự kiện ('attack_detected', 'notification_sent', etc.)
            callback: Hàm callback được gọi khi sự kiện xảy ra
        """
        if event_type not in self.event_callbacks:
            self.event_callbacks[event_type] = []
        self.event_callbacks[event_type].append(callback)
    
    def _process_notifications(self):
        """Xử lý các thông báo trong hàng đợi."""
        while self.running:
            try:
                # Lấy một thông báo từ hàng đợi (timeout để cho phép kiểm tra định kỳ self.running)
                try:
                    attack_info = self.notification_queue.get(block=True, timeout=1.0)
                except queue.Empty:
                    continue
                    
                # Xử lý thông báo
                self._handle_notification(attack_info)
                self.notification_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Lỗi khi xử lý thông báo: {e}")
                time.sleep(1)  # Ngăn loop lỗi liên tục
    
    def _handle_notification(self, attack_info: Dict[str, Any]):
        """
        Xử lý một thông báo tấn công.
        
        Args:
            attack_info: Thông tin về cuộc tấn công DDoS
        """
        attack_type = attack_info.get('attack_type', 'Unknown')
        flow_key = attack_info.get('flow_key', '')
        current_time = time.time()
        
        # Kiểm tra xem đã đến lúc gửi thông báo mới chưa
        notification_key = f"{attack_type}_{flow_key.split('-')[0] if flow_key else 'unknown'}"
        last_time = self.last_notification_time.get(notification_key, 0)
        
        if current_time - last_time >= self.cooldown_period:
            # Gửi email thông báo
            success = self._send_email_notification(attack_info)
            
            if success:
                self.last_notification_time[notification_key] = current_time
                
                # Kích hoạt callback nếu đã đăng ký
                if "notification_sent" in self.event_callbacks:
                    for callback in self.event_callbacks["notification_sent"]:
                        try:
                            callback(attack_info)
                        except Exception as e:
                            self.logger.error(f"Lỗi khi gọi callback notification_sent: {e}")
    
    def _send_email_notification(self, attack_info: Dict[str, Any]) -> bool:
        """
        Gửi email thông báo về cuộc tấn công DDoS.
        
        Args:
            attack_info: Thông tin về cuộc tấn công
            
        Returns:
            True nếu gửi thành công, False nếu không
        """
        try:
            attack_type = attack_info.get('attack_type', 'Unknown')
            confidence = attack_info.get('confidence', 0)
            timestamp = attack_info.get('timestamp', time.time())
            flow_key = attack_info.get('flow_key', '')
            details = attack_info.get('details', {})
            
            # Tách thông tin từ flow_key
            src_ip = dst_ip = "Unknown"
            if flow_key and '-' in flow_key:
                parts = flow_key.split('-')
                if ':' in parts[0]:
                    src_ip = parts[0].split(':')[0]
                if ':' in parts[1]:
                    dst_ip = parts[1].split(':')[0]
            
            # Tạo nội dung email
            subject = f"[CẢNH BÁO DDOS] Phát hiện tấn công {attack_type}"
            
            body = f"""
            <html>
            <body>
            <h2>Cảnh báo: Phát hiện tấn công DDoS</h2>
            <p>Hệ thống đã phát hiện một cuộc tấn công DDoS tiềm ẩn.</p>
            
            <h3>Chi tiết cuộc tấn công:</h3>
            <ul>
                <li><strong>Loại tấn công:</strong> {attack_type}</li>
                <li><strong>Độ tin cậy:</strong> {confidence:.2f}</li>
                <li><strong>Thời gian phát hiện:</strong> {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}</li>
                <li><strong>IP nguồn:</strong> {src_ip}</li>
                <li><strong>IP đích:</strong> {dst_ip}</li>
            </ul>
            
            <h3>Thông tin gói tin:</h3>
            <ul>
            """
            
            # Thêm chi tiết về gói tin
            for key, value in details.items():
                if key != 'Flow Key' and key != 'Protocol':  # Đã hiển thị ở trên
                    body += f"<li><strong>{key}:</strong> {value}</li>\n"
            
            body += """
            </ul>
            
            <p>Vui lòng kiểm tra hệ thống của bạn và áp dụng các biện pháp thích hợp.</p>
            </body>
            </html>
            """
            
            # Gửi email
            success = self.email_sender.send_email(
                subject=subject,
                body=body,
                is_html=True
            )
            
            if success:
                self.logger.info(f"Đã gửi thông báo email về tấn công {attack_type}")
            else:
                self.logger.error(f"Không thể gửi thông báo email về tấn công {attack_type}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Lỗi khi gửi email thông báo: {e}")
            return False