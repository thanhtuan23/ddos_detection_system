# src/ddos_detection_system/core/detection_engine.py

import time
import queue
import threading
import numpy as np
import pandas as pd
import ipaddress
import re
import socket
import logging
from typing import Dict, List, Callable, Any, Optional, Set, Tuple
from sklearn.base import BaseEstimator
from utils.ddos_logger import log_attack
from config import whitelist  # Giả sử whitelist được định nghĩa trong file config.py

class DetectionEngine:
    """
    Module phát hiện DDoS sử dụng mô hình ML để phân tích luồng mạng.
    """
    
    def __init__(self, model: BaseEstimator, feature_extractor, notification_callback: Callable,
                 packet_queue: queue.Queue, detection_threshold: float = 0.7,
                 check_interval: float = 1.0, batch_size: int = 10,
                 config: Optional[Dict[str, Any]] = None):
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
            config: Cấu hình bổ sung từ file config.ini
        """
        self.model = model
        self.feature_extractor = feature_extractor
        self.notification_callback = notification_callback
        self.packet_queue = packet_queue
        self.detection_threshold = detection_threshold
        self.check_interval = check_interval
        self.batch_size = batch_size
        self.config = config or {}
        self.whitelist = whitelist or set()  # Danh sách IP được tin cậy
        
        self.attack_log = {}  # Nhật ký các cuộc tấn công
        self.running = False
        self.detection_thread = None
        
        # Lưu các chỉ số hiệu suất
        self.processing_times = []
        self.detection_counts = {
            'total_flows': 0,
            'attack_flows': 0,
            'false_positives': 0,
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
        
        # Ngược lại, từ tên đến index
        self.attack_type_indices = {v: k for k, v in self.attack_types.items()}
        
        # Tải cấu hình bổ sung
        self.udp_flood_min_rate = float(self.config.get('udp_flood_min_rate', 1000))
        self.syn_flood_min_rate = float(self.config.get('syn_flood_min_rate', 100))
        self.ignore_streaming = self.config.get('ignore_streaming', 'true').lower() == 'true'
        
        # Tải danh sách dịch vụ đáng tin cậy
        self.streaming_services = self._load_trusted_services()
        
        # Tải danh sách whitelist IP
        self.whitelist_networks = self._parse_whitelist()
        
        self.logger = logging.getLogger("detection_engine")
        self.logger.info(f"Khởi tạo engine phát hiện với ngưỡng {detection_threshold}, "
                       f"batch size {batch_size}, và ignore_streaming={self.ignore_streaming}")
    
    def _load_trusted_services(self) -> Set[str]:
        """Tải danh sách các dịch vụ đáng tin cậy từ cấu hình."""
        trusted_services = set()
        
        if hasattr(self.config, 'get'):
            # Thêm các dịch vụ streaming
            streaming_services = self.config.get('streaming_services', '')
            if streaming_services:
                trusted_services.update([s.strip() for s in streaming_services.split(',')])
                
            # Thêm các dịch vụ hosting video
            video_hosting = self.config.get('video_hosting', '')
            if video_hosting:
                trusted_services.update([s.strip() for s in video_hosting.split(',')])
                
            # Thêm các mạng CDN
            cdn_networks = self.config.get('cdn_networks', '')
            if cdn_networks:
                trusted_services.update([s.strip() for s in cdn_networks.split(',')])
        
        # Thêm các dịch vụ phổ biến nếu chưa có
        default_services = {
            'youtube.com', 'googlevideo.com', 'netflix.com', 'spotify.com',
            'akamaihd.net', 'cloudfront.net', 'fastly.net', 'twitch.tv'
        }
        trusted_services.update(default_services)
        
        return trusted_services
    
    def _parse_whitelist(self) -> List[Tuple[ipaddress.IPv4Network, str]]:
        """Phân tích danh sách whitelist từ cấu hình."""
        whitelist_networks = []
        
        # Lấy danh sách whitelist từ cấu hình
        whitelist_str = self.config.get('whitelist', '')
        if not whitelist_str:
            return whitelist_networks
            
        # Phân tích từng mục
        for entry in whitelist_str.split(','):
            entry = entry.strip()
            if not entry:
                continue
                
            try:
                # Xử lý dạng CIDR (ví dụ: 192.168.1.0/24)
                if '/' in entry:
                    network = ipaddress.IPv4Network(entry, strict=False)
                    whitelist_networks.append((network, entry))
                else:
                    # Đơn IP
                    network = ipaddress.IPv4Network(f"{entry}/32", strict=False)
                    whitelist_networks.append((network, entry))
            except ValueError:
                self.logger.warning(f"Không thể phân tích địa chỉ IP/network: {entry}")
                
        return whitelist_networks
    
    def _is_whitelisted(self, ip: str) -> bool:
        """
        Kiểm tra xem một IP có trong danh sách whitelist không.
        
        Args:
            ip: Địa chỉ IP cần kiểm tra
            
        Returns:
            True nếu IP nằm trong whitelist, False nếu không
        """
        if not ip or ip == "Unknown":
            return False
            
        # Kiểm tra trực tiếp trong whitelist (danh sách IP đơn)
        if hasattr(self, 'whitelist') and ip in self.whitelist:
            self.logger.debug(f"IP {ip} được tìm thấy trong whitelist đơn giản")
            return True
            
        # Kiểm tra trong whitelist_networks (dạng CIDR)
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            
            # Kiểm tra danh sách network
            if hasattr(self, 'whitelist_networks'):
                for network, network_str in self.whitelist_networks:
                    if ip_obj in network:
                        self.logger.debug(f"IP {ip} thuộc mạng whitelist {network_str}")
                        return True
                        
            # Thử phân giải tên miền và kiểm tra
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                domain = '.'.join(hostname.split('.')[-2:])  # Lấy tên miền cấp 2
                
                # Kiểm tra tên miền với danh sách trusted_services
                if hasattr(self, 'streaming_services') and domain in self.streaming_services:
                    self.logger.debug(f"IP {ip} thuộc dịch vụ tin cậy {domain}")
                    return True
            except (socket.herror, socket.gaierror):
                pass
                
        except ValueError as e:
            self.logger.debug(f"Lỗi xác thực IP {ip}: {e}")
            return False
            
        return False
    
    def _is_trusted_service(self, ip: str) -> bool:
        """
        Kiểm tra xem một IP có thuộc về dịch vụ đáng tin cậy không.
        
        Args:
            ip: Địa chỉ IP cần kiểm tra
            
        Returns:
            True nếu IP thuộc về dịch vụ đáng tin cậy, False nếu không
        """
        if not ip or ip == "Unknown" or not self.ignore_streaming:
            return False
            
        try:
            # Thử phân giải tên miền từ IP
            hostname = socket.gethostbyaddr(ip)[0]
            
            # Kiểm tra xem tên miền có chứa dịch vụ đáng tin cậy nào không
            for service in self.streaming_services:
                if service in hostname:
                    self.logger.debug(f"IP {ip} thuộc dịch vụ đáng tin cậy: {service} ({hostname})")
                    return True
        except (socket.herror, socket.gaierror):
            # Không thể phân giải tên miền, kiểm tra theo mẫu IP
            
            # Kiểm tra mẫu IP phổ biến cho các dịch vụ Google/YouTube
            youtube_patterns = ["142.250.", "172.217.", "74.125.", "216.58."]
            if any(ip.startswith(pattern) for pattern in youtube_patterns):
                return True
            
            # Kiểm tra mẫu IP phổ biến cho các dịch vụ Netflix
            netflix_patterns = ["52.41.", "52.84.", "54.187."]
            if any(ip.startswith(pattern) for pattern in netflix_patterns):
                return True
                
        return False
    
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
                        'false_positives': 0,
                        'last_reset_time': current_time
                    }
                
                # Nghỉ một chút để giảm tải CPU
                time.sleep(0.01)
                
            except Exception as e:
                self.logger.error(f"Lỗi trong vòng lặp phát hiện: {e}")
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
                    
                    # Kiểm tra whitelist và dịch vụ đáng tin cậy
                    src_ip = dst_ip = "Unknown"
                    if flow_key and '-' in flow_key:
                        parts = flow_key.split('-')
                        if ':' in parts[0]:
                            src_ip = parts[0].split(':')[0]
                        if ':' in parts[1]:
                            dst_ip = parts[1].split(':')[0]
                    
                    # Kiểm tra whitelist cho IP nguồn và đích
                    if self._is_whitelisted(src_ip) or self._is_whitelisted(dst_ip):
                        self.logger.debug(f"Bỏ qua cảnh báo cho IP trong whitelist: {src_ip} -> {dst_ip}")
                        self.detection_counts['false_positives'] += 1
                        continue
                    
                    # Kiểm tra các dịch vụ đáng tin cậy
                    if self._is_trusted_service(src_ip) or self._is_trusted_service(dst_ip):
                        self.logger.debug(f"Bỏ qua cảnh báo cho dịch vụ đáng tin cậy: {src_ip} -> {dst_ip}")
                        self.detection_counts['false_positives'] += 1
                        continue
                    
                    # Áp dụng kiểm tra đặc biệt cho từng loại tấn công
                    is_valid_attack = self._validate_attack(attack_type, flows[i])
                    if not is_valid_attack:
                        self.logger.debug(f"Bỏ qua cảnh báo không hợp lệ cho {attack_type}: {src_ip} -> {dst_ip}")
                        self.detection_counts['false_positives'] += 1
                        continue
                    
                    # Áp dụng ngưỡng phát hiện
                    if attack_prob >= self.detection_threshold:
                        # Ghi lại cuộc tấn công
                        self.detection_counts['attack_flows'] += 1
                        self._log_attack(flow_key, attack_type, attack_prob, flows[i])
                        
                        # Ghi log tấn công với logger chuyên dụng
                        log_attack({
                            'flow_key': flow_key,
                            'attack_type': attack_type,
                            'confidence': attack_prob,
                            'timestamp': time.time(),
                            'details': flows[i]
                        })
                        
                        # Kiểm tra xem đã thông báo về cuộc tấn công này gần đây chưa
                        current_time = time.time()
                        if (flow_key not in self.attack_log or 
                            current_time - self.attack_log[flow_key]['last_notification'] > 60):
                            # Cập nhật thời gian thông báo cuối cùng
                            self.attack_log[flow_key]['last_notification'] = current_time
                            
                            # Gửi thông báo
                            self.notification_callback({
                                'flow_key': flow_key,
                                'attack_type': attack_type,
                                'confidence': attack_prob,
                                'timestamp': current_time,
                                'details': flows[i]
                            })
        
        except Exception as e:
            self.logger.error(f"Lỗi khi dự đoán: {e}")
    
    def _validate_attack(self, attack_type: str, flow_data: Dict[str, Any]) -> bool:
        """
        Kiểm tra tính hợp lệ của một cuộc tấn công dựa trên loại tấn công và dữ liệu luồng.
        
        Args:
            attack_type: Loại tấn công được dự đoán
            flow_data: Dữ liệu luồng mạng
            
        Returns:
            True nếu cuộc tấn công có vẻ hợp lệ, False nếu không
        """
        # Lấy các đặc trưng quan trọng
        packet_rate = flow_data.get('Packet Rate', 0)
        byte_rate = flow_data.get('Byte Rate', 0)
        protocol = flow_data.get('Protocol', 'Unknown')
        syn_flag_rate = flow_data.get('SYN Flag Rate', 0)
        syn_flag_count = flow_data.get('SYN Flag Count', 0)
        ack_flag_rate = flow_data.get('ACK Flag Rate', 0)
        
        # Kiểm tra tùy chỉnh cho từng loại tấn công
        if attack_type == "UDP" or attack_type == "UDPLag":
            # UDP Flood cần tốc độ gói cao
            if packet_rate < self.udp_flood_min_rate:
                return False
                
            # Kiểm tra xem đây có phải là video streaming không
            packet_length_mean = flow_data.get('Packet Length Mean', 0)
            packet_length_std = flow_data.get('Packet Length Std', 0)
            
            # Video streaming thường có gói lớn (> 1000) và độ lệch chuẩn thấp (< 200)
            if packet_length_mean > 1000 and packet_length_std < 200:
                # Có thể là video streaming, kiểm tra thêm
                # Video streaming có tỷ lệ gói/byte khá ổn định
                packets_bytes_ratio = packet_rate / byte_rate if byte_rate > 0 else 0
                if 0.0001 < packets_bytes_ratio < 0.001:  # Tỷ lệ điển hình cho video streaming
                    return False
        
        elif attack_type == "Syn":
            # SYN Flood cần nhiều cờ SYN và tỷ lệ ACK thấp
            if syn_flag_count < 5 or syn_flag_rate < 0.5 or packet_rate < self.syn_flood_min_rate:
                return False
        
        elif attack_type == "MSSQL":
            # MSSQL thực sự phải có port 1433
            src_port = dst_port = 0
            if flow_data.get('Flow Key', ''):
                try:
                    parts = flow_data['Flow Key'].split('-')
                    src_port = int(parts[0].split(':')[1]) if ':' in parts[0] else 0
                    dst_port = int(parts[1].split(':')[1]) if ':' in parts[1] else 0
                except (IndexError, ValueError):
                    pass
            
            # Kiểm tra xem luồng có sử dụng port MSSQL không
            is_mssql_port = (src_port == 1433 or dst_port == 1433)
            
            # Kiểm tra protocol và tốc độ gói
            if protocol != 'TCP' or not is_mssql_port:
                return False
        
        elif attack_type == "LDAP":
            # LDAP thực sự phải có port 389
            src_port = dst_port = 0
            if flow_data.get('Flow Key', ''):
                try:
                    parts = flow_data['Flow Key'].split('-')
                    src_port = int(parts[0].split(':')[1]) if ':' in parts[0] else 0
                    dst_port = int(parts[1].split(':')[1]) if ':' in parts[1] else 0
                except (IndexError, ValueError):
                    pass
            
            # Kiểm tra xem luồng có sử dụng port LDAP không
            is_ldap_port = (src_port == 389 or dst_port == 389)
            
            # Kiểm tra protocol và tốc độ gói
            if not is_ldap_port:
                return False
        
        # Mặc định, tin tưởng mô hình
        return True
    
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
            'false_positives_avoided': self.detection_counts['false_positives'],
            'active_attack_count': len(active_attacks),
            'attack_types_distribution': attack_types_count,
            'avg_processing_time_ms': avg_processing_time * 1000,
            'detection_rate': self.detection_counts['attack_flows'] / self.detection_counts['total_flows'] 
                              if self.detection_counts['total_flows'] > 0 else 0
        }