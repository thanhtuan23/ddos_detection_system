# src/ddos_detection_system/core/detection_engine.py
import logging
import time
import queue
import threading
import numpy as np
import pandas as pd
from typing import Dict, List, Callable, Any, Optional
from sklearn.base import BaseEstimator


class DetectionEngine:
    def __init__(self, model, feature_extractor, notification_callback: Callable,
                 packet_queue: queue.Queue, detection_threshold: float = 0.7,
                 check_interval: float = 1.0, batch_size: int = 10, config=None):
        self.model = model
        self.feature_extractor = feature_extractor
        self.running = False
        self.is_running = False
        self.notification_callback = notification_callback
        self.packet_queue = packet_queue
        self.detection_threshold = detection_threshold
        self.check_interval = check_interval
        self.batch_size = batch_size
        self.logger = logging.getLogger("DetectionEngine")

        self.attack_log = {}
        self.detection_thread = None

        self.processing_times = []
        self.detection_counts = {'total_flows': 0, 'attack_flows': 0, 'last_reset_time': time.time()}
        self.attack_types = {
            0: "Benign",
            1: "UDP",
            2: "UDPLag",
            3: "MSSQL",
            4: "LDAP",
            5: "NetBIOS", 
            6: "Syn"
        }

        # === Bổ sung: load whitelist IP/port từ config ===
        self.whitelist_ip, self.whitelist_port = self.load_whitelist_from_config(config)

    def load_whitelist_from_config(self, config):
        if config is None:
            return set(), set()
        ip_list = config.get('Detection', 'whitelist_ip', fallback='').split(',')
        port_list = config.get('Detection', 'whitelist_port', fallback='').split(',')
        ip_list = [x.strip() for x in ip_list if x.strip()]
        port_list = [int(x.strip()) for x in port_list if x.strip() and x.strip().isdigit()]
        return set(ip_list), set(port_list)

    def start_detection(self):
        """Bắt đầu engine phát hiện trong một thread riêng biệt."""
        self.running = True
        self.is_running = True
        self.detection_thread = threading.Thread(target=self._detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        print("Engine phát hiện DDoS đã bắt đầu")
    
    def stop_detection(self):
        """Dừng engine phát hiện."""
        self.running = False
        self.is_running = False
        if self.detection_thread:
            self.detection_thread.join(timeout=2.0)
        print("Engine phát hiện DDoS đã dừng")

    def is_legitimate_service(self, src_ip, dst_ip, src_port, dst_port, protocol, flow=None):
        # Check whitelist IP/port trước tiên
        if src_ip in self.whitelist_ip or dst_ip in self.whitelist_ip:
            return True, "Whitelist IP"
        if src_port and int(src_port) in self.whitelist_port:
            if protocol == "TCP" and flow is not None:
                syn_rate = flow.get('SYN Flag Rate', 0)
                ack_rate = flow.get('ACK Flag Rate', 0)
                # Nếu là SYN Flood thì KHÔNG skip (để alert)
                if syn_rate > 0.8 and ack_rate < 0.2:
                    return False, ""
                if flow.get('ACK Flood Indicator', 0) == 1:
                    return False, ""
            # Nếu là UDP Flood thì KHÔNG skip (để alert)
            if protocol == "UDP" and flow is not None:
                if flow.get('UDP Flood Indicator', 0) == 1:
                    return False, ""
            return True, "Whitelist Port"

        if dst_port and int(dst_port) in self.whitelist_port:
            if protocol == "TCP" and flow is not None:
                syn_rate = flow.get('SYN Flag Rate', 0)
                ack_rate = flow.get('ACK Flag Rate', 0)
                if syn_rate > 0.8 and ack_rate < 0.2:
                    return False, ""
                if flow.get('ACK Flood Indicator', 0) == 1:
                    return False, ""
            if protocol == "UDP" and flow is not None:
                if flow.get('UDP Flood Indicator', 0) == 1:
                    return False, ""
            return True, "Whitelist Port"

        # Các pattern IP Google, Youtube, Facebook, CDN lớn
        big_cdn_patterns = [
            "142.250.", "172.217.", "74.125.", "216.58.",    # Google/Youtube
            "52.222.", "108.175.", "192.173.", "198.38.",    # Netflix
            "31.13.", "157.240.", "104.244.",                # Facebook
            "13.35.", "35.186.",                             # AWS/GCP
            "203.113.", "8.8.8."                             # VNPT, Google DNS
        ]
        if any(dst_ip.startswith(pat) for pat in big_cdn_patterns):
            return True, "BigCDN/Streaming"

        # Dải IP local network
        local_patterns = ["192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."]
        if any(src_ip.startswith(pat) for pat in local_patterns):
            return True, "Local Network"
        if any(dst_ip.startswith(pat) for pat in local_patterns):
            return True, "Local Network"

        # Port web phổ biến (ngay cả khi không nằm trong whitelist)
        if str(dst_port) in ["80", "443", "8080", "1935", "33000", "33001"]:
            return True, "Web/Streaming Port"

        # Có thể mở rộng thêm logic nhận biết các service khác ở đây
        return False, ""
    
    def _detection_loop(self):
        while self.running:
            try:
                flows, flow_keys = [], []
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

                start_time = time.time()
                self._process_flows(flows, flow_keys)
                end_time = time.time()
                self.processing_times.append(end_time - start_time)
                if len(self.processing_times) > 100:
                    self.processing_times.pop(0)

                current_time = time.time()
                if current_time - self.detection_counts['last_reset_time'] > 3600:
                    self.detection_counts = {
                        'total_flows': 0,
                        'attack_flows': 0,
                        'last_reset_time': current_time
                    }
                time.sleep(0.01)
            except Exception as e:
                print(f"Lỗi trong vòng lặp phát hiện: {e}")
                time.sleep(1)
    
    def _process_flows(self, flows: List[Dict[str, Any]], flow_keys: List[str]):
        if not flows:
            return
        features_list = [self.feature_extractor.extract_features(flow) for flow in flows]
        X = self.feature_extractor.prepare_features_for_model(features_list)

        try:
            y_pred = self.model.predict(X)
            y_prob = self.model.predict_proba(X)
            self.detection_counts['total_flows'] += len(flows)
            for i, (pred, probs, flow_key) in enumerate(zip(y_pred, y_prob, flow_keys)):
                if pred == 0:
                    continue  # Benign

                attack_type = self.attack_types.get(pred, "Unknown")
                attack_prob = probs[pred]

                # ==== Tách src/dst/port từ flow_key ====
                src_ip, dst_ip, src_port, dst_port = "", "", "", ""
                if flow_key and '-' in flow_key:
                    parts = flow_key.split('-')
                    if ':' in parts[0]:
                        src_ip, src_port = parts[0].split(':')
                    if ':' in parts[1]:
                        dst_ip, dst_port = parts[1].split(':')

                # ==== Lấy protocol đúng kiểu string ====
                protocol_num = flows[i].get('Protocol', 3)
                protocol_map = {0: "TCP", 1: "UDP", 2: "ICMP", 3: "Unknown"}
                try:
                    protocol = protocol_map[int(protocol_num)]
                except Exception:
                    protocol = "Unknown"

                # ========== 1. BỘ LỌC WHITELIST + DỊCH VỤ HỢP PHÁP ==========
                is_legit, legit_reason = self.is_legitimate_service(
                    src_ip, dst_ip, src_port, dst_port, protocol, flows[i]
                )
                if is_legit:
                    self.logger.info(
                        f"SKIP: {flow_key} ({legit_reason}) - attack_prob={attack_prob:.2f}, attack_type={attack_type}"
                    )
                    continue  # Không alert nếu là traffic hợp pháp!

                # ========== 2. TĂNG THRESHOLD CẢNH BÁO CHO PORT/ATTACK CỤ THỂ ==========
                attack_specific_threshold = self.detection_threshold
                # Tăng ngưỡng cho UDP/Streaming/MSSQL
                if attack_type in ["UDPLag"]:
                    attack_specific_threshold = max(attack_specific_threshold, 0.9)
                elif attack_type == "MSSQL" and not (src_port == "1433" or dst_port == "1433"):
                    attack_specific_threshold = max(attack_specific_threshold, 0.92)
                # Tăng ngưỡng nếu port phổ biến
                if str(dst_port) in ["80", "443", "8080"]:
                    attack_specific_threshold = max(attack_specific_threshold, 0.97)

                # Thêm điều kiện với flow ít packet
                packet_count = flows[i].get('Total Packets', 0)
                if packet_count < 20 and attack_prob < 0.98:
                    attack_specific_threshold = max(attack_specific_threshold, 0.9)

                # Log debug
                self.logger.debug(f"CHECK: {flow_key}, attack_type={attack_type}, prob={attack_prob:.4f}, threshold={attack_specific_threshold}")

                # ========== 3. BÁO ĐỘNG NẾU QUA ĐƯỢC MỌI LỌC ==========
                if attack_prob >= attack_specific_threshold:
                    self.detection_counts['attack_flows'] += 1
                    self._log_attack(flow_key, attack_type, attack_prob, flows[i])
                    # Notification
                    current_time = time.time()
                    if (flow_key not in self.attack_log or
                        current_time - self.attack_log[flow_key]['last_notification'] > 60):
                        self.attack_log[flow_key]['last_notification'] = current_time
                        notification_data = {
                            'flow_key': flow_key,
                            'attack_type': attack_type,
                            'confidence': attack_prob,
                            'timestamp': current_time,
                            'details': flows[i],
                            'threshold_applied': attack_specific_threshold,
                            'service_detected': legit_reason
                        }
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
    
    def analyze_flow(self, flow_features: Dict[str, Any]) -> Dict[str, Any]:
        """Phân tích luồng mạng để phát hiện tấn công DDoS."""
        
        # Chuẩn bị đặc trưng cho mô hình
        features_list = [flow_features]
        X = self.feature_extractor.prepare_features_for_model(features_list)
        
        # Dự đoán
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        
        # Xác định loại tấn công cụ thể
        attack_type = "Normal"
        confidence = float(probabilities[int(prediction)])
        
        # Tạo kết quả phân tích
        result = {
            'flow_key': flow_features.get('Flow Key', ''),
            'source_ip': flow_features.get('Source IP', ''),
            'is_attack': bool(prediction),
            'confidence': confidence,
            'attack_type': attack_type,
            'flow_features': flow_features,
            'timestamp': time.time()
        }
        
        # Nếu hỗ trợ phân tích streaming và có đặc trưng streaming
        if hasattr(self, 'streaming_services') and hasattr(self, 'false_positive_threshold'):
            # Kiểm tra xem có phải là dịch vụ streaming được cho phép không
            is_likely_streaming = flow_features.get('Likely Streaming', 0) == 1
            is_streaming_port = flow_features.get('Streaming Service Port', 0) == 1
            
            # Nếu phát hiện là streaming và confidence thấp hơn ngưỡng false positive
            if is_likely_streaming and is_streaming_port and confidence < self.false_positive_threshold:
                result['is_attack'] = False
                result['attack_type'] = "Normal (Streaming)"
                return result
        
        # Đánh dấu loại tấn công cụ thể nếu là tấn công
        if result['is_attack']:
            protocol = flow_features.get('Protocol', 3)
            
            # Xác định loại tấn công
            if protocol == 0:  # TCP
                if flow_features.get('SYN Flag Rate', 0) > 0.8:
                    attack_type = "SYN Flood"
                
            elif protocol == 1:  # UDP
                if flow_features.get('UDP Flood Indicator', 0) == 1:
                    attack_type = "UDP Flood"
                
            # Phát hiện MSSQL Attack nếu có đặc trưng liên quan
            mssql_port = flow_features.get('MSSQL Port Indicator', 0) == 1
            dst_port = flow_features.get('Destination Port', 0)
            src_port = flow_features.get('Source Port', 0)
            ssl_pattern = (dst_port == 443 or src_port == 443) and protocol == 'TCP'
            high_packet_rate = flow_features.get('Packet Rate', 0) > 1000
            
            if mssql_port:
                # Nếu là cổng MSSQL thực sự, có thể là tấn công
                if high_packet_rate:
                    attack_type = "MSSQL Attack"
            else:
                # Nếu không phải cổng MSSQL, cần thận trọng hơn khi phân loại
                # Tránh nhầm lẫn với SSL/TLS
                if ssl_pattern and flow_features.get('Packet Length Mean', 0) > 800:
                    # Gói lớn qua SSL/TLS thường là video/streaming
                    result['is_attack'] = False
                    result['attack_type'] = "Normal (HTTPS Traffic)"
        
        result['attack_type'] = attack_type
        
        # Xử lý đặc biệt cho lưu lượng HTTPS
        if flow_features.get('HTTPS Traffic', 0) == 1:
            # Lưu lượng HTTPS đã được xác nhận thường không phải là tấn công
            if result['is_attack'] and confidence < 0.9:
                # Chỉ ghi đè kết quả nếu độ tin cậy không quá cao
                result['is_attack'] = False
                result['attack_type'] = "Normal (HTTPS Traffic)"
                result['original_confidence'] = confidence
                result['confidence'] = 0.2  # Giảm độ tin cậy là tấn công
                return result
        
        # Xử lý MSSQL Attack
        if result['is_attack'] and flow_features.get('MSSQL Port Indicator', 0) == 1:
            attack_type = "MSSQL Attack"
            
            # Sử dụng thêm xác suất tấn công nếu có
            if 'MSSQL Attack Probability' in flow_features:
                # Điều chỉnh độ tin cậy dựa trên phân tích sâu hơn
                mssql_attack_prob = flow_features['MSSQL Attack Probability']
                result['confidence'] = (result['confidence'] + mssql_attack_prob) / 2
        
        return result