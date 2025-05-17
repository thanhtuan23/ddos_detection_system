# src/ddos_detection_system/utils/logging_util.py
import os
import logging
import logging.handlers
from typing import Optional, Dict, Any, Union
import time
from datetime import datetime

class LoggingUtil:
    """
    Tiện ích để cấu hình và quản lý logging trong hệ thống phát hiện DDoS.
    Cung cấp các phương thức để thiết lập bộ xử lý log, định dạng và mức độ log.
    """
    
    @staticmethod
    def setup_logging(log_dir: str = 'logs', 
                      log_level: Union[int, str] = logging.INFO,
                      log_format: Optional[str] = None,
                      console_output: bool = True,
                      file_output: bool = True,
                      max_file_size: int = 10 * 1024 * 1024,  # 10MB
                      backup_count: int = 5) -> logging.Logger:
        """
        Thiết lập cấu hình logging cho hệ thống.
        
        Args:
            log_dir: Thư mục để lưu trữ tệp log
            log_level: Mức độ log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_format: Định dạng tin nhắn log, None để sử dụng mặc định
            console_output: Có ghi log ra console không
            file_output: Có ghi log vào tệp không
            max_file_size: Kích thước tối đa của mỗi tệp log (byte)
            backup_count: Số lượng tệp log backup tối đa cần giữ
            
        Returns:
            Logger đã được cấu hình
        """
        # Tạo thư mục log nếu chưa tồn tại
        if file_output and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Chuyển đổi log_level từ string sang int nếu cần
        if isinstance(log_level, str):
            log_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Sử dụng định dạng log mặc định nếu không có
        if log_format is None:
            log_format = '%(asctime)s [%(levelname)s] [%(name)s] - %(message)s'
        
        # Tạo định dạng log
        formatter = logging.Formatter(log_format)
        
        # Tạo logger gốc
        logger = logging.getLogger()
        logger.setLevel(log_level)
        
        # Xóa các bộ xử lý hiện có để tránh ghi log trùng lặp
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Thêm bộ xử lý console nếu cần
        if console_output:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(log_level)
            logger.addHandler(console_handler)
        
        # Thêm bộ xử lý file nếu cần
        if file_output:
            timestamp = datetime.now().strftime("%Y%m%d")
            log_file = os.path.join(log_dir, f'ddos_detection_{timestamp}.log')
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, 
                maxBytes=max_file_size,
                backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            logger.addHandler(file_handler)
        
        return logger
    
    @staticmethod
    def get_attack_logger() -> logging.Logger:
        """
        Trả về logger chuyên dụng cho việc ghi lại các cuộc tấn công.
        Các cuộc tấn công được ghi vào một tệp riêng biệt để dễ dàng phân tích.
        
        Returns:
            Logger chuyên dụng cho các cuộc tấn công
        """
        # Tạo thư mục log nếu chưa tồn tại
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Tạo logger chuyên dụng
        logger = logging.getLogger('attack_log')
        
        # Nếu logger đã có bộ xử lý, trả về logger
        if logger.handlers:
            return logger
        
        logger.setLevel(logging.INFO)
        
        # Định dạng CSV để dễ dàng phân tích: timestamp,attack_type,src_ip,dst_ip,confidence
        formatter = logging.Formatter('%(asctime)s,%(message)s')
        
        # Tạo tệp log cho các cuộc tấn công, mỗi tháng một tệp
        timestamp = datetime.now().strftime("%Y%m")
        log_file = os.path.join(log_dir, f'attack_log_{timestamp}.csv')
        
        # Sử dụng RotatingFileHandler để kiểm soát kích thước
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=10
        )
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        
        # Thêm tiêu đề CSV nếu tệp mới
        if os.path.getsize(log_file) == 0:
            logger.info("timestamp,attack_type,src_ip,dst_ip,confidence,packet_count,byte_rate")
            
        return logger
    
    @staticmethod
    def log_attack(attack_info: Dict[str, Any]):
        """
        Ghi thông tin về một cuộc tấn công vào log.
        
        Args:
            attack_info: Thông tin về cuộc tấn công DDoS
        """
        logger = LoggingUtil.get_attack_logger()
        
        attack_type = attack_info.get('attack_type', 'Unknown')
        confidence = attack_info.get('confidence', 0)
        flow_key = attack_info.get('flow_key', '')
        details = attack_info.get('details', {})
        
        # Trích xuất IP nguồn và đích từ flow_key
        src_ip = dst_ip = "Unknown"
        if flow_key and '-' in flow_key:
            parts = flow_key.split('-')
            if ':' in parts[0]:
                src_ip = parts[0].split(':')[0]
            if ':' in parts[1]:
                dst_ip = parts[1].split(':')[0]
        
        # Tạo bản ghi CSV
        packet_count = details.get('Total Packets', 0)
        byte_rate = details.get('Byte Rate', 0)
        
        log_entry = f"{attack_type},{src_ip},{dst_ip},{confidence:.4f},{packet_count},{byte_rate:.2f}"
        logger.info(log_entry)
    
    @staticmethod
    def get_performance_logger() -> logging.Logger:
        """
        Trả về logger chuyên dụng cho các số liệu hiệu suất.
        
        Returns:
            Logger chuyên dụng cho hiệu suất
        """
        # Tạo thư mục log nếu chưa tồn tại
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Tạo logger chuyên dụng
        logger = logging.getLogger('performance_log')
        
        # Nếu logger đã có bộ xử lý, trả về logger
        if logger.handlers:
            return logger
        
        logger.setLevel(logging.INFO)
        
        # Định dạng CSV: timestamp,cpu_usage,memory_usage,packet_queue_size,detection_rate
        formatter = logging.Formatter('%(asctime)s,%(message)s')
        
        # Tạo tệp log cho hiệu suất, mỗi tháng một tệp
        timestamp = datetime.now().strftime("%Y%m")
        log_file = os.path.join(log_dir, f'performance_log_{timestamp}.csv')
        
        # Sử dụng RotatingFileHandler để kiểm soát kích thước
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=20 * 1024 * 1024,  # 20MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        
        # Thêm tiêu đề CSV nếu tệp mới
        if os.path.getsize(log_file) == 0:
            logger.info("timestamp,cpu_usage,memory_usage,packet_queue_size,detection_rate,avg_processing_time_ms")
            
        return logger
    
    @staticmethod
    def log_performance(cpu_usage: float, memory_usage: float, 
                       packet_queue_size: int, detection_rate: float,
                       avg_processing_time_ms: float):
        """
        Ghi thông tin hiệu suất hệ thống vào log.
        
        Args:
            cpu_usage: Mức sử dụng CPU (%)
            memory_usage: Mức sử dụng bộ nhớ (%)
            packet_queue_size: Kích thước hàng đợi gói tin
            detection_rate: Tỷ lệ phát hiện tấn công
            avg_processing_time_ms: Thời gian xử lý trung bình (ms)
        """
        logger = LoggingUtil.get_performance_logger()
        
        # Tạo bản ghi CSV
        log_entry = f"{cpu_usage:.2f},{memory_usage:.2f},{packet_queue_size},{detection_rate:.4f},{avg_processing_time_ms:.2f}"
        logger.info(log_entry)