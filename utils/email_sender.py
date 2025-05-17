# src/ddos_detection_system/utils/email_sender.py
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import List, Optional

class EmailSender:
    """
    Tiện ích gửi email thông báo.
    """
    
    def __init__(self, smtp_server: str, smtp_port: int, sender_email: str, 
                 password: str, recipients: List[str]):
        """
        Khởi tạo tiện ích gửi email.
        
        Args:
            smtp_server: Địa chỉ máy chủ SMTP
            smtp_port: Cổng của máy chủ SMTP
            sender_email: Địa chỉ email người gửi
            password: Mật khẩu hoặc mã ứng dụng của email người gửi
            recipients: Danh sách địa chỉ email người nhận
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.password = password
        self.recipients = recipients
        self.logger = logging.getLogger("email_sender")
    
    def send_email(self, subject: str, body: str, is_html: bool = False) -> bool:
        """
        Gửi email.
        
        Args:
            subject: Tiêu đề email
            body: Nội dung email
            is_html: True nếu nội dung là HTML, False nếu là text
            
        Returns:
            True nếu gửi thành công, False nếu không
        """
        try:
            # Tạo tin nhắn
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.sender_email
            message["To"] = ", ".join(self.recipients)
            
            # Thêm phần nội dung vào tin nhắn
            if is_html:
                message.attach(MIMEText(body, "html"))
            else:
                message.attach(MIMEText(body, "plain"))
            
            # Tạo kết nối an toàn với máy chủ SMTP
            context = ssl.create_default_context()
            
            # Kết nối và gửi email
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context) as server:
                server.login(self.sender_email, self.password)
                server.sendmail(self.sender_email, self.recipients, message.as_string())
                
            self.logger.info(f"Đã gửi email '{subject}' đến {len(self.recipients)} người nhận")
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi gửi email: {e}")
            return False