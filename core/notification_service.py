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
            
            # Đánh giá mức độ nghiêm trọng dựa trên độ tin cậy
            severity = "TRUNG BÌNH"
            if confidence > 0.8:
                severity = "CAO"
            elif confidence < 0.6:
                severity = "THẤP"
                
            # Tính toán tốc độ gói và băng thông
            packet_rate = details.get('Packet Rate', 0)
            byte_rate = details.get('Byte Rate', 0)
            
            # Chuyển đổi byte_rate thành MB/s
            mbps = byte_rate * 8 / 1000000
            
            # Tạo nội dung email
            subject = f"[CẢNH BÁO DDOS] Phát hiện tấn công {attack_type} - Mức độ: {severity}"
            
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #f0ad4e; border-left: 5px solid #d9534f;">
                    <h2 style="color: #d9534f; margin-top: 0;">⚠️ CẢNH BÁO: PHÁT HIỆN TẤN CÔNG DDOS</h2>
                    
                    <div style="background-color: #f8f8f8; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                        <table style="width: 100%">
                            <tr>
                                <td style="font-weight: bold; padding: 8px 0;">Loại tấn công:</td>
                                <td>{attack_type}</td>
                            </tr>
                            <tr>
                                <td style="font-weight: bold; padding: 8px 0;">Mức độ nghiêm trọng:</td>
                                <td style="color: {'#d9534f' if severity == 'CAO' else '#f0ad4e' if severity == 'TRUNG BÌNH' else '#5bc0de'};">
                                    {severity} (Độ tin cậy: {confidence:.0%})
                                </td>
                            </tr>
                            <tr>
                                <td style="font-weight: bold; padding: 8px 0;">Thời gian phát hiện:</td>
                                <td>{time.strftime('%H:%M:%S %d/%m/%Y', time.localtime(timestamp))}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <h3 style="margin-bottom: 10px;">Thông tin cơ bản:</h3>
                    <div style="background-color: #f8f8f8; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                        <table style="width: 100%">
                            <tr>
                                <td style="font-weight: bold; padding: 8px 0; width: 170px;">IP nguồn:</td>
                                <td>{src_ip}</td>
                            </tr>
                            <tr>
                                <td style="font-weight: bold; padding: 8px 0;">IP đích:</td>
                                <td>{dst_ip}</td>
                            </tr>
                            <tr>
                                <td style="font-weight: bold; padding: 8px 0;">Tốc độ:</td>
                                <td>{packet_rate:.0f} gói/giây ({mbps:.2f} Mbps)</td>
                            </tr>
                        </table>
                    </div>
                    
                    <div style="background-color: #d9edf7; padding: 15px; margin: 25px 0; border-radius: 4px;">
                        <h3 style="margin-top: 0; color: #31708f;">Hành động đề xuất:</h3>
                        <ul style="margin-bottom: 0;">
                            <li>Kiểm tra tình trạng máy chủ và dịch vụ mạng</li>
                            <li>Xác minh lưu lượng mạng bất thường từ IP nguồn</li>
                            <li>Cân nhắc chặn IP nguồn nếu xác nhận đây là cuộc tấn công</li>
                        </ul>
                    </div>
                    
                    <p style="font-size: 12px; color: #777; margin-top: 30px;">
                        Email này được gửi tự động từ hệ thống phát hiện DDoS. Vui lòng không trả lời email này.
                    </p>
                </div>
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