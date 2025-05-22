# src/ddos_detection_system/core/detection_engine.py
import time
import queue
import threading
import numpy as np
import pandas as pd
from typing import Dict, List, Callable, Any, Optional
from sklearn.base import BaseEstimator
from utils.ddos_logger import log_attack

class DetectionEngine:
    """
    Module phát hiện DDoS sử dụng mô hình ML để phân tích luồng mạng.
    """
    
    def __init__(self, model: BaseEstimator, feature_extractor, notification_callback: Callable,
                 packet_queue: queue.Queue, detection_threshold: float = 0.7,
                 check_interval: float = 1.0, batch_size: int = 10):
        """
        Khởi tạo engine phát hiện DDoS.
        
        Args:
            model: Mô hình ML đã được huấn luyện để phát hiện DDoS
            feature_extractor: Bộ trích xuất đặc trưng
            notification_callback: Hàm callback khi phát hiện tấn công
            packet_queue: Queue chứa các gói tin để phân tích
            detection_threshold: Ngưỡng xác suất để coi là tấn công DDoS
            check_interval: Khoảng thời gian (giây) giữa các lần kiểm tra
            batch_size: Số lượng luồng cần phân tích mỗi lần
        """
        self.model = model
        self.feature_extractor = feature_extractor
        self.notification_callback = notification_callback
        self.packet_queue = packet_queue
        self.detection_threshold = detection_threshold
        self.check_interval = check_interval
        self.batch_size = batch_size
        
        self.attack_log = {}  # Nhật ký các cuộc tấn công
        self.running = False
        self.detection_thread = None
        
        # Lưu các chỉ số hiệu suất
        self.processing_times = []
        self.detection_counts = {
            'total_flows': 0,
            'attack_flows': 0,
            'last_reset_time': time.time()
        }
        
        # Mapping các loại tấn công 
        self.attack_types = {
            0: "Benign",
            1: "UDP",
            2: "UDPLag",
            3: "MSSQL",
            4: "LDAP",
            5: "NetBIOS", 
            6: "Syn"
        }
    
    def start_detection(self):
        """Bắt đầu engine phát hiện trong một thread riêng biệt."""
        self.running = True
        self.detection_thread = threading.Thread(target=self._detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        print("Engine phát hiện DDoS đã bắt đầu")
    
    def stop_detection(self):
        """Dừng engine phát hiện."""
        self.running = False
        if self.detection_thread:
            self.detection_thread.join(timeout=2.0)
        print("Engine phát hiện DDoS đã dừng")
    
    def _detection_loop(self):
        """Vòng lặp chính để phát hiện các cuộc tấn công DDoS."""
        while self.running:
            try:
                # Thu thập một batch các luồng mạng để phân tích
                flows = []
                flow_keys = []
                
                for _ in range(self.batch_size):
                    try:
                        flow_data = self.packet_queue.get(block=True, timeout=0.1)
                        flow_keys.append(flow_data.get('Flow Key', 'unknown'))
                        flows.append(flow_data)
                        self.packet_queue.task_done()
                    except queue.Empty:
                        break
                
                if not flows:
                    time.sleep(self.check_interval)
                    continue
                
                # Xử lý và phát hiện
                start_time = time.time()
                self._process_flows(flows, flow_keys)
                end_time = time.time()
                
                # Lưu thời gian xử lý để tính hiệu suất
                self.processing_times.append(end_time - start_time)
                if len(self.processing_times) > 100:
                    self.processing_times.pop(0)
                
                # Reset các bộ đếm sau mỗi giờ
                current_time = time.time()
                if current_time - self.detection_counts['last_reset_time'] > 3600:
                    self.detection_counts = {
                        'total_flows': 0,
                        'attack_flows': 0,
                        'last_reset_time': current_time
                    }
                
                # Nghỉ một chút để giảm tải CPU
                time.sleep(0.01)
                
            except Exception as e:
                print(f"Lỗi trong vòng lặp phát hiện: {e}")
                time.sleep(1)  # Tránh loop liên tục nếu có lỗi
    
    def _process_flows(self, flows: List[Dict[str, Any]], flow_keys: List[str]):
        """
        Xử lý một batch các luồng mạng để phát hiện các cuộc tấn công DDoS.
        
        Args:
            flows: Danh sách các luồng mạng để phân tích
            flow_keys: Danh sách các khóa luồng tương ứng
        """
        if not flows:
            return
        
        # Trích xuất đặc trưng cho mỗi luồng
        features_list = [self.feature_extractor.extract_features(flow) for flow in flows]
        
        # Chuẩn bị đặc trưng cho mô hình
        X = self.feature_extractor.prepare_features_for_model(features_list)
        
        # Dự đoán với mô hình
        try:
            y_pred = self.model.predict(X)
            y_prob = self.model.predict_proba(X)
            
            # Cập nhật bộ đếm
            self.detection_counts['total_flows'] += len(flows)
            
            # Phân tích kết quả
            for i, (pred, probs, flow_key) in enumerate(zip(y_pred, y_prob, flow_keys)):
                if pred != 0:  # Nếu không phải benign (dự đoán là tấn công)
                    attack_type = self.attack_types.get(pred, "Unknown")
                    attack_prob = probs[pred]
                    
                    # === LOGIC KIỂM TRA LƯỚI LƯỢNG HỢP PHÁP ===
                    # Kiểm tra các dịch vụ phổ biến (YouTube, streaming, etc.)
                    is_legitimate_service = False
                    service_name = "Unknown"
                    
                    # Trích xuất IP và port từ flow_key
                    src_ip = dst_ip = src_port = dst_port = ""
                    protocol = flows[i].get('Protocol', 'Unknown')
                    
                    if flow_key and '-' in flow_key:
                        parts = flow_key.split('-')
                        if ':' in parts[0]:
                            src_ip, src_port = parts[0].split(':')
                        if ':' in parts[1]:
                            dst_ip, dst_port = parts[1].split(':')
                    
                    # 1. Kiểm tra các IP của Google/YouTube
                    youtube_patterns = ["142.250.", "172.217.", "74.125.", "216.58."]
                    if any(dst_ip.startswith(pattern) for pattern in youtube_patterns):
                        is_legitimate_service = True
                        service_name = "YouTube/Google"
                    
                    # 2. Kiểm tra các IP của Netflix
                    netflix_patterns = ["52.222.", "108.175.", "192.173.", "198.38."]
                    if any(dst_ip.startswith(pattern) for pattern in netflix_patterns):
                        is_legitimate_service = True
                        service_name = "Netflix"
                    
                    # 3. Kiểm tra các IP nội bộ - thường là an toàn
                    local_network_patterns = ["192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."]
                    if any(src_ip.startswith(pattern) for pattern in local_network_patterns):
                        if attack_prob < 0.95:  # Yêu cầu độ tin cậy rất cao cho mạng nội bộ
                            is_legitimate_service = True
                            service_name = "Local Network"
                    
                    # 4. Kiểm tra các đặc trưng lưu lượng streaming
                    # - Các streaming có kích thước gói lớn và ổn định
                    # - Thường có tỷ lệ PSH/ACK cao với TCP
                    packet_length_mean = flows[i].get('Packet Length Mean', 0)
                    packet_length_std = flows[i].get('Packet Length Std', 0)
                    
                    if attack_type in ["UDPLag", "MSSQL"] and packet_length_mean > 1000 and packet_length_std < 300:
                        if protocol == "UDP" or (protocol == "TCP" and dst_port in ["80", "443", "8080"]):
                            confidence_threshold = 0.98  # Yêu cầu độ tin cậy rất cao cho streaming
                            if attack_prob < confidence_threshold:
                                is_legitimate_service = True
                                service_name = "Streaming Service"
                    
                    # 5. Điều chỉnh ngưỡng phát hiện dựa trên loại tấn công
                    attack_specific_threshold = self.detection_threshold
                    
                    # Tăng ngưỡng cho các loại tấn công thường gây false positive
                    if attack_type == "UDPLag":
                        attack_specific_threshold = max(self.detection_threshold, 0.9)
                    elif attack_type == "MSSQL" and not (src_port == "1433" or dst_port == "1433"):
                        # MSSQL thực sự sử dụng port 1433, tăng ngưỡng nếu không dùng port này
                        attack_specific_threshold = max(self.detection_threshold, 0.92)
                    
                    # 6. Kiểm tra số lượng gói tin - tấn công thực thường có rất nhiều gói
                    packet_count = flows[i].get('Total Packets', 0)
                    if packet_count < 20 and attack_prob < 0.98:  # Ít gói, có thể là false positive
                        attack_specific_threshold = max(attack_specific_threshold, 0.9)
                    
                    # 7. Ghi log chi tiết cho debug
                    self.logger.debug(f"Flow: {flow_key}, Attack: {attack_type}, Prob: {attack_prob:.4f}, "
                                    f"Threshold: {attack_specific_threshold:.4f}, "
                                    f"Service: {service_name}, Legitimate: {is_legitimate_service}")
                    
                    # Chỉ xử lý các luồng không được xác định là dịch vụ hợp pháp hoặc có độ tin cậy rất cao
                    if not is_legitimate_service or attack_prob > 0.98:
                        if attack_prob >= attack_specific_threshold:
                            # Ghi lại cuộc tấn công
                            self.detection_counts['attack_flows'] += 1
                            self._log_attack(flow_key, attack_type, attack_prob, flows[i])
                            
                            # Ghi log với utils.ddos_logger nếu có
                            try:
                                from utils.ddos_logger import log_attack
                                log_attack({
                                    'flow_key': flow_key,
                                    'attack_type': attack_type,
                                    'confidence': attack_prob,
                                    'timestamp': time.time(),
                                    'details': flows[i]
                                })
                            except ImportError:
                                pass  # Bỏ qua nếu không có module ddos_logger
                            
                            # Kiểm tra xem đã thông báo về cuộc tấn công này gần đây chưa
                            current_time = time.time()
                            if (flow_key not in self.attack_log or 
                                current_time - self.attack_log[flow_key]['last_notification'] > 60):
                                # Cập nhật thời gian thông báo cuối cùng
                                self.attack_log[flow_key]['last_notification'] = current_time
                                
                                # Thêm thông tin về dịch vụ và ngưỡng được áp dụng
                                notification_data = {
                                    'flow_key': flow_key,
                                    'attack_type': attack_type,
                                    'confidence': attack_prob,
                                    'timestamp': current_time,
                                    'details': flows[i],
                                    'threshold_applied': attack_specific_threshold,
                                    'service_detected': service_name if is_legitimate_service else "None"
                                }
                                
                                # Gửi thông báo
                                self.notification_callback(notification_data)
        
        except Exception as e:
            self.logger.error(f"Lỗi khi dự đoán: {e}")
            print(f"Lỗi khi dự đoán: {e}")
    
    def _log_attack(self, flow_key: str, attack_type: str, confidence: float, details: Dict[str, Any]):
        """
        Ghi lại thông tin về cuộc tấn công phát hiện được.
        
        Args:
            flow_key: Khóa nhận diện luồng
            attack_type: Loại tấn công DDoS
            confidence: Độ tin cậy của dự đoán
            details: Chi tiết về luồng bị tấn công
        """
        current_time = time.time()
        
        if flow_key not in self.attack_log:
            self.attack_log[flow_key] = {
                'first_detected': current_time,
                'last_detected': current_time,
                'attack_type': attack_type,
                'detection_count': 1,
                'avg_confidence': confidence,
                'last_notification': 0,  # Chưa có thông báo nào
                'details': details
            }
        else:
            log_entry = self.attack_log[flow_key]
            log_entry['last_detected'] = current_time
            log_entry['detection_count'] += 1
            # Cập nhật độ tin cậy trung bình
            log_entry['avg_confidence'] = ((log_entry['avg_confidence'] * (log_entry['detection_count'] - 1)) 
                                          + confidence) / log_entry['detection_count']
            log_entry['details'] = details  # Cập nhật thông tin chi tiết mới nhất
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """
        Trả về thống kê hiện tại về việc phát hiện.
        
        Returns:
            Dict chứa các thống kê phát hiện
        """
        avg_processing_time = sum(self.processing_times) / len(self.processing_times) if self.processing_times else 0
        
        # Lọc các cuộc tấn công đang diễn ra (phát hiện trong 5 phút qua)
        current_time = time.time()
        active_attacks = {k: v for k, v in self.attack_log.items() 
                          if current_time - v['last_detected'] < 300}
        
        # Phân loại các cuộc tấn công theo loại
        attack_types_count = {}
        for attack in active_attacks.values():
            attack_type = attack['attack_type']
            if attack_type in attack_types_count:
                attack_types_count[attack_type] += 1
            else:
                attack_types_count[attack_type] = 1
        
        return {
            'total_flows_analyzed': self.detection_counts['total_flows'],
            'total_attacks_detected': self.detection_counts['attack_flows'],
            'active_attack_count': len(active_attacks),
            'attack_types_distribution': attack_types_count,
            'avg_processing_time_ms': avg_processing_time * 1000,
            'detection_rate': self.detection_counts['attack_flows'] / self.detection_counts['total_flows'] 
                              if self.detection_counts['total_flows'] > 0 else 0
        }