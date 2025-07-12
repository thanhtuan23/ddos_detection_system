# core/detection_engine.py
import time
import threading
import logging
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from core.classification_system import ClassificationSystem

class DetectionEngine:
    """
    Engine phát hiện tấn công DDoS sử dụng mô hình học máy.
    """
    
    def __init__(self, model, feature_extractor, notification_callback, packet_queue, 
                 detection_threshold=0.7, check_interval=1.0, batch_size=10, 
                 config=None, label_encoder=None, prevention_engine=None, 
                 secondary_model=None, secondary_feature_extractor=None, 
                 secondary_label_encoder=None):
        """
        Khởi tạo engine phát hiện.
        
        Args:
            model: Mô hình chính (CIC-DDoS)
            feature_extractor: Trình trích xuất đặc trưng cho mô hình chính
            notification_callback: Callback khi phát hiện tấn công
            packet_queue: Hàng đợi gói tin
            detection_threshold: Ngưỡng phát hiện
            check_interval: Khoảng thời gian kiểm tra (giây)
            batch_size: Kích thước lô xử lý
            config: Cấu hình hệ thống
            label_encoder: Bộ mã hóa nhãn cho mô hình chính
            prevention_engine: Engine ngăn chặn
            secondary_model: Mô hình phụ (Suricata)
            secondary_feature_extractor: Trình trích xuất đặc trưng cho mô hình phụ
            secondary_label_encoder: Bộ mã hóa nhãn cho mô hình phụ
        """
        self.model = model
        self.feature_extractor = feature_extractor
        self.notification_callback = notification_callback
        self.packet_queue = packet_queue
        self.detection_threshold = detection_threshold
        self.check_interval = check_interval
        self.batch_size = batch_size
        self.config = config
        self.label_encoder = label_encoder
        self.prevention_engine = prevention_engine
        
        # Các thuộc tính cho mô hình phụ
        self.secondary_model = secondary_model
        self.secondary_feature_extractor = secondary_feature_extractor
        self.secondary_label_encoder = secondary_label_encoder
        
        # Khởi tạo các thông tin mô hình
        models = []
        feature_extractors = []
        
        # Thêm mô hình chính
        primary_model_info = {
            'model': model,
            'label_encoder': label_encoder,
            'model_type': 'cicddos',
            'label_mapping': {i: c for i, c in enumerate(label_encoder.classes_)} if label_encoder else {}
        }
        models.append(primary_model_info)
        feature_extractors.append(feature_extractor)
        
        # Thêm mô hình phụ nếu có
        if secondary_model is not None:
            secondary_model_info = {
                'model': secondary_model,
                'label_encoder': secondary_label_encoder,
                'model_type': 'suricata',
                'label_mapping': {0: 'DDoS'} if secondary_label_encoder is None else {i: c for i, c in enumerate(secondary_label_encoder.classes_)}
            }
            models.append(secondary_model_info)
            feature_extractors.append(secondary_feature_extractor)
        
        # Khởi tạo hệ thống phân loại
        self.classification_system = ClassificationSystem(models, config)
        self.feature_extractors = feature_extractors
        
        # Thông tin về phương pháp kết hợp mô hình
        self.has_secondary_model = secondary_model is not None
        
        # Danh sách IP whitelist để tránh false positive
        self.whitelist_ip = set()
        self.whitelist_port = set()
        
        # Nếu có cấu hình whitelist từ file config
        if config and config.has_section('Prevention'):
            if config.has_option('Prevention', 'whitelist'):
                whitelist_str = config.get('Prevention', 'whitelist')
                self.whitelist_ip = set([ip.strip() for ip in whitelist_str.split(',')])
        
        if config and config.has_section('Network'):
            if config.has_option('Network', 'whitelist_ports'):
                ports_str = config.get('Network', 'whitelist_ports')
                self.whitelist_port = set([int(port.strip()) for port in ports_str.split(',')])
        
        # Thread và trạng thái
        self.running = False
        self.is_running = False
        self.detection_thread = None
        
        # Thống kê
        self.total_flows_analyzed = 0
        self.total_attacks_detected = 0
        self.processing_times = []
        self.start_time = time.time()
        
        # Logging
        self.logger = logging.getLogger("ddos_detection_system.core.detection_engine")
        self.logger.info(f"Engine phát hiện DDoS đã khởi tạo với {len(models)} mô hình")
    
    def start_detection(self):
        """Bắt đầu engine phát hiện trong một thread riêng biệt."""
        self.running = True
        self.is_running = True
        self.detection_thread = threading.Thread(target=self._detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        self.logger.info("Engine phát hiện DDoS đã bắt đầu")
    
    def stop_detection(self):
        """Dừng engine phát hiện."""
        self.running = False
        if self.detection_thread and self.detection_thread.is_alive():
            self.detection_thread.join(timeout=5.0)
        self.is_running = False
        self.logger.info("Engine phát hiện DDoS đã dừng")
    
    def is_legitimate_service(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """
        Kiểm tra xem luồng có phải là dịch vụ hợp pháp không.
        
        Args:
            src_ip: Địa chỉ IP nguồn
            dst_ip: Địa chỉ IP đích
            src_port: Cổng nguồn
            dst_port: Cổng đích
            protocol: Giao thức
            
        Returns:
            True nếu là dịch vụ hợp pháp, False nếu không
        """
        # Kiểm tra IP whitelist
        if src_ip in self.whitelist_ip or dst_ip in self.whitelist_ip:
            return True
        
        # Kiểm tra port whitelist
        if src_port in self.whitelist_port or dst_port in self.whitelist_port:
            return True
        
        # Kiểm tra các dịch vụ streaming nếu có cấu hình
        if hasattr(self, 'streaming_services') and hasattr(self, 'false_positive_threshold'):
            # Triển khai logic nhận diện dịch vụ streaming ở đây nếu cần
            pass
        
        return False
    
    def _detection_loop(self):
        """Vòng lặp chính của engine phát hiện."""
        while self.running:
            try:
                # Lấy số lượng flows cần xử lý
                batch_size = min(self.batch_size, self.packet_queue.qsize())
                
                if batch_size > 0:
                    flows = []
                    flow_keys = []
                    
                    # Lấy batch_size flows từ hàng đợi
                    for _ in range(batch_size):
                        if not self.packet_queue.empty():
                            flow_data = self.packet_queue.get()
                            flow_key = flow_data.get('flow_key', 'unknown')
                            flows.append(flow_data)
                            flow_keys.append(flow_key)
                    
                    # Xử lý các flows
                    if flows:
                        self._process_flows(flows, flow_keys)
                
                # Ngủ một khoảng thời gian
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Lỗi trong vòng lặp phát hiện: {e}", exc_info=True)
    
    def _process_flows(self, flows, flow_keys):
        """
        Xử lý một batch các luồng dữ liệu.
        
        Args:
            flows: Danh sách dữ liệu luồng
            flow_keys: Danh sách khóa luồng tương ứng
        """
        start_time = time.time()
        
        for i, flow in enumerate(flows):
            flow_key = flow_keys[i]
            
            try:
                # Kiểm tra whitelist trước khi phân tích
                src_ip = flow.get('src_ip', '')
                dst_ip = flow.get('dst_ip', '')
                src_port = flow.get('src_port', 0)
                dst_port = flow.get('dst_port', 0)
                protocol = flow.get('protocol', '')
                
                if self.is_legitimate_service(src_ip, dst_ip, src_port, dst_port, protocol):
                    self.logger.debug(f"Bỏ qua flow hợp pháp: {flow_key}")
                    continue
                
                # Phân tích flow
                is_attack, confidence, attack_type, _ = self.analyze_flow(flow)
                
                # Cập nhật thống kê
                self.total_flows_analyzed += 1
                
                # Nếu là tấn công và vượt ngưỡng
                if is_attack and confidence >= self.detection_threshold:
                    self.total_attacks_detected += 1
                    
                    # Tạo thông tin chi tiết về tấn công
                    attack_details = {
                        'flow_rate': flow.get('flow_rate', 0),
                        'packet_rate': flow.get('packet_rate', 0),
                        'byte_rate': flow.get('byte_rate', 0),
                        'packet_count': flow.get('packet_count', 0),
                        'flow_duration': flow.get('flow_duration', 0),
                        'protocol': protocol
                    }
                    
                    # Log tấn công
                    self._log_attack(flow_key, attack_type, confidence, attack_details)
                    
                    # Tạo thông tin tấn công để thông báo
                    attack_info = {
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'flow_key': flow_key,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'attack_type': attack_type,
                        'confidence': confidence,
                        'details': attack_details
                    }
                    
                    # Gửi thông báo tấn công
                    if self.notification_callback:
                        self.notification_callback(attack_info)
                    
                    # Tự động chặn nếu cấu hình cho phép
                    if self.prevention_engine and self.config:
                        try:
                            auto_block = self.config.getboolean('Prevention', 'auto_block', fallback=False)
                            if auto_block:
                                self.prevention_engine.block_ip(src_ip, attack_type, confidence)
                        except Exception as block_error:
                            self.logger.error(f"Lỗi khi chặn IP: {block_error}")
                
            except Exception as e:
                self.logger.error(f"Lỗi khi xử lý flow {flow_key}: {e}", exc_info=True)
        
        # Tính thời gian xử lý
        processing_time = (time.time() - start_time) * 1000  # ms
        self.processing_times.append(processing_time / max(1, len(flows)))
        
        # Giới hạn số lượng thời gian xử lý lưu trữ
        if len(self.processing_times) > 100:
            self.processing_times = self.processing_times[-100:]
    
    def analyze_flow(self, flow) -> Tuple[bool, float, str, Optional[int]]:
        """
        Phân tích một luồng dữ liệu để phát hiện tấn công.
        
        Args:
            flow: Dữ liệu luồng
            
        Returns:
            Tuple (is_attack, confidence, attack_type, attack_class)
        """
        try:
            # Thử suy luận các đặc trưng thiếu trước khi phân tích
            if hasattr(self.feature_extractor, 'infer_features'):
                flow = self.feature_extractor.infer_features(flow)
            
            # Sử dụng hệ thống phân loại
            is_attack, confidence, attack_type, details = self.classification_system.classify_flow(
                flow, self.feature_extractors
            )
            
            # Kiểm tra và ghi log nếu có đặc trưng bị thiếu
            if 'missing_features' in details:
                self.logger.warning(f"Đặc trưng thiếu khi phân tích: {details['missing_features']}")
                
            # Sử dụng hệ thống phân loại
            is_attack, confidence, attack_type, details = self.classification_system.classify_flow(
                flow, self.feature_extractors
            )
            
            # Lưu thêm thông tin vào chi tiết để sử dụng sau này
            flow_key = flow.get('flow_key', 'unknown')
            src_ip = flow.get('src_ip', '')
            dst_ip = flow.get('dst_ip', '')
            
            # Thêm mô tả loại tấn công
            attack_description = self.classification_system.get_attack_type_description(attack_type)
            confidence_level = self.classification_system.get_detection_confidence_level(confidence)
            
            # Log chi tiết hơn về kết quả phân loại
            if is_attack:
                self.logger.info(
                    f"Phát hiện tấn công {attack_type} (tin cậy: {confidence:.4f}, mức: {confidence_level}) "
                    f"từ {src_ip} đến {dst_ip}"
                )
                if self.config and self.config.getboolean('Advanced', 'detailed_traffic_logging', fallback=False):
                    self.logger.debug(f"Chi tiết phân loại: {details}")
            
            # Trả về kết quả phân tích
            return is_attack, confidence, attack_type, None  # Loại bỏ attack_class vì không còn cần thiết
            
        except Exception as e:
            self.logger.error(f"Lỗi khi phân tích luồng: {e}", exc_info=True)
            return False, 0.0, "Error", None
    
    def _log_attack(self, flow_key, attack_type, confidence, details):
        """
        Ghi log tấn công.
        
        Args:
            flow_key: Khóa luồng
            attack_type: Loại tấn công
            confidence: Độ tin cậy
            details: Chi tiết bổ sung
        """
        # Tách thông tin từ flow_key
        src_ip = dst_ip = src_port = dst_port = "Unknown"
        if '-' in flow_key:
            parts = flow_key.split('-')
            if ':' in parts[0]:
                src_parts = parts[0].split(':')
                src_ip = src_parts[0]
                src_port = src_parts[1] if len(src_parts) > 1 else "Unknown"
            if ':' in parts[1]:
                dst_parts = parts[1].split(':')
                dst_ip = dst_parts[0]
                dst_port = dst_parts[1] if len(dst_parts) > 1 else "Unknown"
        
        # Log thông tin chi tiết
        self.logger.warning(
            f"Phát hiện tấn công: {attack_type} từ {src_ip}:{src_port} đến {dst_ip}:{dst_port} "
            f"(độ tin cậy: {confidence:.2f})"
        )
        
        # Ghi log sử dụng DDoSLogger nếu có
        try:
            from utils.ddos_logger import log_attack
            
            attack_info = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': details.get('protocol', 'Unknown'),
                'attack_type': attack_type,
                'confidence': confidence,
                'blocked': False,
                'details': details
            }
            
            log_attack(attack_info)
            
        except ImportError:
            self.logger.debug("Không thể import DDoSLogger")
    
    def get_detection_stats(self):
        """
        Lấy thống kê về engine phát hiện.
        
        Returns:
            Dict chứa thống kê
        """
        # Tính thời gian xử lý trung bình
        avg_processing_time = 0
        if self.processing_times:
            avg_processing_time = sum(self.processing_times) / len(self.processing_times)
        
        # Tính tỷ lệ phát hiện
        detection_rate = 0
        if self.total_flows_analyzed > 0:
            detection_rate = self.total_attacks_detected / self.total_flows_analyzed
        
        # Xác định trạng thái phát hiện
        detection_status = "Active" if self.is_running else "Inactive"
        
        # Xác định trạng thái ngăn chặn
        prevention_status = "Unknown"
        if self.prevention_engine:
            prevention_status = "Active" if self.prevention_engine.running else "Inactive"
        
        return {
            'total_flows_analyzed': self.total_flows_analyzed,
            'total_attacks_detected': self.total_attacks_detected,
            'detection_rate': detection_rate,
            'avg_processing_time_ms': avg_processing_time,
            'detection_status': detection_status,
            'prevention_status': prevention_status,
            'uptime': time.time() - self.start_time,
            'models_count': len(self.feature_extractors),
            'has_secondary_model': self.has_secondary_model
        }