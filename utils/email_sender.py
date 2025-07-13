# utils/email_sender.py
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional

class EmailSender:
    """
    Utility for sending email notifications.
    """
    
    def __init__(self, smtp_server: str, smtp_port: int, sender_email: str, 
                 password: str, recipients: List[str]):
        """
        Initialize the email sender.
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP server port
            sender_email: Sender email address
            password: Sender email password
            recipients: List of recipient email addresses
        """
        self.logger = logging.getLogger("ddos_detection_system.utils.email_sender")
        
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.password = password
        self.recipients = recipients
        
        self.logger.info(f"Email sender initialized for {smtp_server}:{smtp_port}")
    
    def send_email(self, subject: str, body: str, is_html: bool = False) -> bool:
        """
        Send an email.
        
        Args:
            subject: Email subject
            body: Email body
            is_html: Whether the body is HTML
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.recipients:
            self.logger.warning("No recipients specified, skipping email")
            return False
        
        try:
            # Create message
            message = MIMEMultipart()
            message['From'] = self.sender_email
            message['To'] = ', '.join(self.recipients)
            message['Subject'] = subject
            
            # Attach body
            content_type = 'html' if is_html else 'plain'
            message.attach(MIMEText(body, content_type))
            
            # Connect to server and send
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.password)
                server.send_message(message)
            
            self.logger.info(f"Sent email to {len(self.recipients)} recipients: {subject}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending email: {e}", exc_info=True)
            return False
    
    def test_connection(self) -> bool:
        """
        Test the SMTP connection.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.password)
            
            self.logger.info("SMTP connection test successful")
            return True
            
        except Exception as e:
            self.logger.error(f"SMTP connection test failed: {e}", exc_info=True)
            return False