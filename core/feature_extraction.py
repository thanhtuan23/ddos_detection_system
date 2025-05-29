# src/ddos_detection_system/core/feature_extraction.py
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple

class FeatureExtractor:
    """Trích xuất và chuẩn hóa các đặc trưng từ dữ liệu luồng mạng."""
    
    def __init__(self, feature_columns: List[str], config=None):
        """
        Khởi tạo bộ trích xuất đặc trưng.
        
        Args:
            feature_columns: Danh sách các cột đặc trưng mà mô hình cần
            config: Đối tượng cấu hình để đọc các tham số
        """
        self.feature_columns = feature_columns
        self.config = config
        self.protocol_mappings = {
            'TCP': 0, 
            'UDP': 1, 
            'ICMP': 2,
            'Unknown': 3
        }

    def extract_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trích xuất đặc trưng từ dữ liệu luồng thô.
        
        Args:
            flow_data: Dữ liệu luồng thô từ module thu thập gói tin
            
        Returns:
            Dict chứa các đặc trưng đã được xử lý
        """
        features = {}
        
        # Xử lý Protocol
        protocol = flow_data.get('Protocol', 'Unknown')
        features['Protocol'] = self.protocol_mappings.get(protocol, 3)
        
        # Lấy cổng đích và nguồn
        dst_port = flow_data.get('Destination Port', 0)
        src_port = flow_data.get('Source Port', 0)
        dst_ip = flow_data.get('Destination IP', '')
        
        # Các đặc trưng cơ bản
        features['Flow Duration'] = flow_data.get('Flow Duration', 0)
        features['Total Packets'] = flow_data.get('Total Packets', 0)
        features['Total Bytes'] = flow_data.get('Total Bytes', 0)
        features['Packet Rate'] = flow_data.get('Packet Rate', 0)
        features['Byte Rate'] = flow_data.get('Byte Rate', 0)
        
        # Đặc trưng kích thước gói tin
        features['Packet Length Mean'] = flow_data.get('Packet Length Mean', 0)
        features['Packet Length Std'] = flow_data.get('Packet Length Std', 0)
        features['Packet Length Min'] = flow_data.get('Packet Length Min', 0)
        features['Packet Length Max'] = flow_data.get('Packet Length Max', 0)
        
        # Đặc trưng TCP Flag (nếu có)
        features['SYN Flag Count'] = flow_data.get('SYN Flag Count', 0)
        features['FIN Flag Count'] = flow_data.get('FIN Flag Count', 0)
        features['RST Flag Count'] = flow_data.get('RST Flag Count', 0)
        features['PSH Flag Count'] = flow_data.get('PSH Flag Count', 0)
        features['ACK Flag Count'] = flow_data.get('ACK Flag Count', 0)
        features['URG Flag Count'] = flow_data.get('URG Flag Count', 0)
        features['SYN Flag Rate'] = flow_data.get('SYN Flag Rate', 0)
        features['ACK Flag Rate'] = flow_data.get('ACK Flag Rate', 0)
        
        # Đặc trưng nâng cao
        # Tính IAT (Inter-Arrival Time)
        if 'Packet Times' in flow_data and len(flow_data['Packet Times']) > 1:
            packet_times = flow_data['Packet Times']
            iats = [packet_times[i+1] - packet_times[i] for i in range(len(packet_times)-1)]
            features['IAT Mean'] = np.mean(iats) if iats else 0
            features['IAT Std'] = np.std(iats) if iats else 0
            features['IAT Min'] = min(iats) if iats else 0
            features['IAT Max'] = max(iats) if iats else 0
        else:
            features['IAT Mean'] = 0
            features['IAT Std'] = 0
            features['IAT Min'] = 0
            features['IAT Max'] = 0
        
        # Thêm đặc trưng nhận biết SYN Flood
        if protocol == 'TCP':
            features['SYN Flood Indicator'] = 1 if features['SYN Flag Rate'] > 0.8 and features['ACK Flag Rate'] < 0.2 else 0
        else:
            features['SYN Flood Indicator'] = 0
        
        # Cải thiện đặc trưng nhận dạng MSSQL 
        is_mssql_port = (dst_port == 1433 or src_port == 1433)
        # MSSQL thường có kích thước gói nhỏ, đồng nhất và số lượng nhiều
        is_mssql_pattern = False

        # Kiểm tra MSSQL thực sự bằng phương thức mới
        is_real_mssql = self._is_real_mssql_traffic(flow_data)
        
        if is_real_mssql:
            # Đây là MSSQL thật - có thể là lưu lượng bình thường
            features['MSSQL Port Indicator'] = 1
        elif is_mssql_port:
            # Sử dụng cổng MSSQL nhưng không có đặc điểm MSSQL -> có thể là tấn công
            features['MSSQL Port Indicator'] = 1
            features['MSSQL Attack Probability'] = 0.7  # Thêm đặc trưng xác suất tấn công
        else:
            # Kiểm tra các đặc điểm khác để xác định MSSQL
            packet_sizes = flow_data.get('packet_sizes', [])
            if packet_sizes and len(packet_sizes) > 10:
                packet_size_mean = np.mean(packet_sizes)
                packet_size_std = np.std(packet_sizes)
                
                # MSSQL amplification attack pattern
                is_mssql_pattern = (
                    packet_size_mean < 300 and  # Gói nhỏ
                    packet_size_std < 50 and    # Kích thước đồng nhất
                    features['Packet Rate'] > 100  # Tốc độ cao
                )
            
            features['MSSQL Port Indicator'] = 1 if is_mssql_pattern else 0
            if is_mssql_pattern:
                features['MSSQL Attack Probability'] = 0.9  # Cao hơn vì đây là mẫu tấn công
    
        # Kiểm tra nếu lưu lượng là HTTPS/TLS
        is_https = self._is_likely_https_traffic(features)
        features['HTTPS Traffic'] = 1 if is_https else 0
        
        # Giảm khả năng nhầm lẫn HTTPS với tấn công
        if is_https:
            # Nếu là HTTPS, giảm khả năng là MSSQL attack
            features['MSSQL Port Indicator'] = 0
            # Tăng khả năng là streaming
            if features.get('Packet Length Mean', 0) > 800:
                features['Likely Streaming'] = 1
    
        # Phân tích UDP để phân biệt tấn công với streaming
        if protocol == 'UDP':
            packet_sizes = flow_data.get('packet_sizes', [])
            
            # Nhận diện YouTube và các dịch vụ streaming
            is_common_video_port = (dst_port == 443) or (src_port == 443)  # QUIC (YouTube)
            is_netflix_port = (dst_port in [443, 33000, 33001]) or (src_port in [443, 33000, 33001])
            is_streaming_port = is_common_video_port or is_netflix_port
            
            features['Streaming Service Port'] = 1 if is_streaming_port else 0
            
            if packet_sizes and len(packet_sizes) > 5:
                packet_size_std = np.std(packet_sizes)
                packet_size_mean = np.mean(packet_sizes)
                
                # Tính toán tỷ lệ gói tin nhỏ (< 200 bytes) so với tổng số gói tin
                small_packets = [size for size in packet_sizes if size < 200]
                small_packets_ratio = len(small_packets) / len(packet_sizes) if packet_sizes else 0
                
                # Đánh dấu mẫu lưu lượng video streaming
                is_streaming_pattern = (
                    packet_size_mean > 800 and  # Gói tin lớn
                    small_packets_ratio < 0.4 and  # Ít gói nhỏ
                    features['Packet Rate'] < 2000  # Tốc độ không quá cao
                )
                
                # Đánh dấu mẫu lưu lượng tấn công
                is_attack_pattern = (
                    packet_size_std < 100 and  # Kích thước đồng nhất
                    features['Packet Rate'] > 2000 and  # Tốc độ rất cao
                    small_packets_ratio > 0.7  # Chủ yếu là gói tin nhỏ
                )
                
                # Lưu các đặc trưng để phân biệt
                features['Likely Streaming'] = 1 if is_streaming_pattern else 0
                features['UDP Flood Indicator'] = 1 if is_attack_pattern else 0
                
                # Đặc trưng nâng cao: tỷ lệ kích thước gói lớn/nhỏ
                features['Size Uniformity'] = packet_size_std / packet_size_mean if packet_size_mean > 0 else 0
                features['Small Packet Ratio'] = small_packets_ratio
            else:
                # Không đủ dữ liệu để phân tích mẫu
                features['Likely Streaming'] = 0 if features['Packet Rate'] > 2000 else 1
                features['UDP Flood Indicator'] = 0
                features['Size Uniformity'] = 0
                features['Small Packet Ratio'] = 0
        else:
            features['Likely Streaming'] = 0
            features['UDP Flood Indicator'] = 0
            features['Size Uniformity'] = 0 
            features['Small Packet Ratio'] = 0
            features['Streaming Service Port'] = 0
            
        # Xác định dòng lưu lượng
        dst_port = flow_data.get('Destination Port', 0)
        src_port = flow_data.get('Source Port', 0)
        dst_ip = flow_data.get('Destination IP', '')
        
        # Tải danh sách port từ cấu hình
        streaming_ports_str = self._get_config_value('Detection', 'streaming_ports', '443,33000,33001')
        streaming_ports = [int(p) for p in streaming_ports_str.split(',')]
        
        local_service_ports_str = self._get_config_value('Detection', 'local_service_ports', '80,443,8080')
        local_service_ports = [int(p) for p in local_service_ports_str.split(',')]
        
        # Logic phân biệt streaming và dịch vụ local
        is_streaming_port = (dst_port in streaming_ports) or (src_port in streaming_ports)
        is_local_service = False
        
        # Kiểm tra nếu đây là dịch vụ nội bộ 
        if (dst_port in local_service_ports or src_port in local_service_ports):
            # Kiểm tra nếu IP đích là IP private/local
            is_local_service = self._is_private_ip(dst_ip)
        
        # Đánh dấu là streaming chỉ nếu:
        # 1. Sử dụng streaming port và 
        # 2. Không phải dịch vụ nội bộ
        features['Streaming Service Port'] = 1 if (is_streaming_port and not is_local_service) else 0
        
        return features

    def _is_private_ip(self, ip: str) -> bool:
        """Kiểm tra xem một địa chỉ IP có phải là private không."""
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return False
            
            # Kiểm tra các dải private IP phổ biến
            if octets[0] == '10': 
                return True
            if octets[0] == '172' and 16 <= int(octets[1]) <= 31:
                return True
            if octets[0] == '192' and octets[1] == '168':
                return True
            if octets[0] == '127':
                return True
                
            return False
        except:
            return False

    def prepare_features_for_model(self, features_list: List[Dict[str, Any]]) -> np.ndarray:
        """
        Chuẩn bị đặc trưng để sử dụng với mô hình ML.
        
        Args:
            features_list: Danh sách các từ điển đặc trưng đã trích xuất
            
        Returns:
            Mảng numpy chứa đặc trưng đã được xử lý để cung cấp cho mô hình
        """
        # Chuyển đổi danh sách dict thành DataFrame
        df = pd.DataFrame(features_list)
        
        # Chỉ giữ lại các cột mà mô hình cần
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0  # Thêm cột bị thiếu với giá trị mặc định là 0
        
        # Đảm bảo chỉ giữ các cột đặc trưng cần thiết theo thứ tự chính xác
        df = df[self.feature_columns]
        
        return df.values
    
    def _get_config_value(self, section, key, default_value):
        """Lấy giá trị từ config hoặc trả về giá trị mặc định nếu không có config."""
        if self.config is None:
            return default_value
        
        try:
            return self.config.get(section, key, fallback=default_value)
        except:
            return default_value
    
    def _is_likely_https_traffic(self, features: Dict[str, Any]) -> bool:
        """Kiểm tra xem luồng có khả năng là HTTPS/TLS không."""
        # HTTPS có đặc điểm: gói tin lớn, ACK Flag cao, cổng 443
        dst_port = features.get('Destination Port', 0)
        src_port = features.get('Source Port', 0)
        
        if dst_port == 443 or src_port == 443:
            packet_length_mean = features.get('Packet Length Mean', 0)
            packet_length_std = features.get('Packet Length Std', 0)
            ack_flag_rate = features.get('ACK Flag Rate', 0)
            
            # HTTPS/TLS có gói tin lớn, tỷ lệ ACK cao, và kích thước gói biến đổi
            if packet_length_mean > 600 and ack_flag_rate > 0.4 and packet_length_std > 200:
                return True
        
        return False
    
    def _is_real_mssql_traffic(self, flow_data: Dict[str, Any]) -> bool:
        """Kiểm tra xem đây có phải là lưu lượng MSSQL thực hay không."""
        # Kiểm tra cổng
        dst_port = flow_data.get('Destination Port', 0)
        src_port = flow_data.get('Source Port', 0)
        is_mssql_port = (dst_port == 1433 or src_port == 1433)
        
        # Kiểm tra payload nếu có (chỉ áp dụng khi bắt gói tin với payload)
        has_tds_header = False
        payload = flow_data.get('payload_hex', '')
        if payload and len(payload) > 8:
            # TDS header có mẫu nhận dạng đặc trưng
            tds_markers = ['02010000', '04010000', '0701000']
            has_tds_header = any(marker in payload[:16] for marker in tds_markers)
        
        return is_mssql_port and has_tds_header