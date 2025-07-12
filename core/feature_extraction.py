# core/feature_extraction.py
import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Any, Union
import socket
import struct

class FeatureExtractor:
    """
    Lớp trích xuất đặc trưng từ dữ liệu gói tin.
    """
    
    def __init__(self, feature_columns: List[str], config=None, model_type: str = "cicddos"):
        """
        Khởi tạo trình trích xuất đặc trưng.
        
        Args:
            feature_columns: Danh sách các cột đặc trưng
            config: Cấu hình hệ thống
            model_type: Loại mô hình ("suricata" hoặc "cicddos")
        """
        self.feature_columns = feature_columns
        self.config = config
        self.model_type = model_type.lower()
        self.logger = logging.getLogger("ddos_detection_system.core.feature_extraction")
        self.logger.info(f"Khởi tạo FeatureExtractor cho mô hình {model_type} với {len(feature_columns)} đặc trưng")
        
        # Danh sách đặc trưng cần thiết cho từng loại mô hình
        self.cicddos_features = [
            'ACK Flag Count', 'Fwd Packet Length Min', 'Protocol', 'URG Flag Count', 
            'Fwd Packet Length Max', 'Fwd Packet Length Std', 'Init Fwd Win Bytes', 'Bwd Packet Length Max'
        ]
        
        self.suricata_features = [
            'src_port', 'dest_port', 'bytes_toserver', 'bytes_toclient', 'pkts_toserver', 
            'pkts_toclient', 'total_bytes', 'total_pkts', 'avg_bytes_per_pkt', 'bytes_ratio', 
            'pkts_ratio', 'is_wellknown_port', 'proto_tcp', 'proto_udp', 'proto_ipv6-icmp', 
            'proto_icmp', 'proto_ICMP', 'proto_IPv6-ICMP', 'proto_TCP', 'proto_UDP'
        ]
        
        # Ánh xạ giao thức sang số
        self.protocol_map = {
            'tcp': 6, 'TCP': 6,
            'udp': 17, 'UDP': 17, 
            'icmp': 1, 'ICMP': 1,
            'ipv6-icmp': 58, 'IPv6-ICMP': 58
        }
        
        # Các giá trị mặc định cho trường hợp thiếu đặc trưng
        self.default_values = self._create_default_values()
        
        # Kiểm tra và ghi log nếu có đặc trưng không được hỗ trợ
        self._validate_features()
    
    def _create_default_values(self) -> Dict[str, Any]:
        """
        Tạo giá trị mặc định cho các đặc trưng.
        
        Returns:
            Dict các giá trị mặc định
        """
        defaults = {
            # CIC-DDoS features
            'ACK Flag Count': 0,
            'Fwd Packet Length Min': 0,
            'Protocol': 6,  # TCP
            'URG Flag Count': 0,
            'Fwd Packet Length Max': 0,
            'Fwd Packet Length Std': 0,
            'Init Fwd Win Bytes': 0,
            'Bwd Packet Length Max': 0,
            
            # Suricata features
            'src_port': 0,
            'dest_port': 0,
            'bytes_toserver': 0,
            'bytes_toclient': 0,
            'pkts_toserver': 0,
            'pkts_toclient': 0,
            'total_bytes': 0,
            'total_pkts': 0,
            'avg_bytes_per_pkt': 0,
            'bytes_ratio': 1.0,
            'pkts_ratio': 1.0,
            'is_wellknown_port': 0
        }
        
        # Mặc định cho các giao thức
        for proto in ['tcp', 'udp', 'ipv6-icmp', 'icmp', 'ICMP', 'IPv6-ICMP', 'TCP', 'UDP']:
            defaults[f'proto_{proto}'] = 0
        
        return defaults
    
    def _validate_features(self):
        """Kiểm tra và ghi log nếu có đặc trưng không được hỗ trợ."""
        required_features = self.cicddos_features if self.model_type == "cicddos" else self.suricata_features
        missing_features = [f for f in required_features if f not in self.feature_columns]
        
        if missing_features:
            self.logger.warning(f"Các đặc trưng sau không có trong feature_columns: {missing_features}")
            self.logger.warning("Sẽ sử dụng giá trị mặc định cho các đặc trưng này")
    
    def extract_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trích xuất đặc trưng từ dữ liệu luồng.
        
        Args:
            flow_data: Dữ liệu luồng mạng
            
        Returns:
            Dict chứa các đặc trưng đã trích xuất
        """
        # Chọn phương thức trích xuất đặc trưng phù hợp với loại mô hình
        if self.model_type == "suricata":
            return self._extract_suricata_features(flow_data)
        else:
            return self._extract_cicddos_features(flow_data)
    
    def prepare_features_df(self, features_dict: Dict[str, Any]) -> pd.DataFrame:
        """
        Chuẩn bị DataFrame chứa đặc trưng để đưa vào mô hình.
        
        Args:
            features_dict: Dict chứa các đặc trưng đã trích xuất
            
        Returns:
            DataFrame chứa các đặc trưng đã được sắp xếp
        """
        # Tạo DataFrame với các cột đặc trưng cần thiết
        df = pd.DataFrame([features_dict])
        
        # Đảm bảo tất cả các cột cần thiết đều có trong DataFrame
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = self.default_values.get(col, 0)  # Sử dụng giá trị mặc định
        
        # Chỉ giữ lại các cột cần thiết theo thứ tự yêu cầu
        df = df[self.feature_columns]
        
        return df
    
    def _extract_suricata_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trích xuất đặc trưng cho mô hình Suricata.
        
        Args:
            flow_data: Dữ liệu luồng mạng
            
        Returns:
            Dict chứa các đặc trưng Suricata
        """
        features = {}
        
        try:
            # Trích xuất thông tin cổng
            src_port = flow_data.get('src_port', self.default_values['src_port'])
            dst_port = flow_data.get('dst_port', self.default_values['dest_port'])
            features['src_port'] = src_port
            features['dest_port'] = dst_port
            
            # Trích xuất thông tin về bytes và packets
            bytes_toserver = flow_data.get('bytes_toserver', 0)
            if bytes_toserver is None:
                bytes_toserver = flow_data.get('fwd_bytes', 0)
            
            bytes_toclient = flow_data.get('bytes_toclient', 0)
            if bytes_toclient is None:
                bytes_toclient = flow_data.get('bwd_bytes', 0)
            
            pkts_toserver = flow_data.get('pkts_toserver', 0)
            if pkts_toserver is None:
                pkts_toserver = flow_data.get('fwd_packets', 0)
            
            pkts_toclient = flow_data.get('pkts_toclient', 0)
            if pkts_toclient is None:
                pkts_toclient = flow_data.get('bwd_packets', 0)
            
            features['bytes_toserver'] = bytes_toserver
            features['bytes_toclient'] = bytes_toclient
            features['pkts_toserver'] = pkts_toserver
            features['pkts_toclient'] = pkts_toclient
            
            # Tính toán các đặc trưng tổng hợp
            total_bytes = bytes_toserver + bytes_toclient
            total_pkts = pkts_toserver + pkts_toclient
            
            features['total_bytes'] = total_bytes
            features['total_pkts'] = total_pkts
            
            # Tránh chia cho 0
            features['avg_bytes_per_pkt'] = total_bytes / max(1, total_pkts)
            
            # Tính tỷ lệ
            features['bytes_ratio'] = bytes_toserver / max(1, bytes_toclient) if bytes_toclient > 0 else bytes_toserver
            features['pkts_ratio'] = pkts_toserver / max(1, pkts_toclient) if pkts_toclient > 0 else pkts_toserver
            
            # Kiểm tra cổng phổ biến
            features['is_wellknown_port'] = 1 if (src_port < 1024 or dst_port < 1024) else 0
            
            # Mã hóa one-hot cho giao thức
            protocol = flow_data.get('protocol', 'tcp').lower()
            for proto in ['tcp', 'udp', 'ipv6-icmp', 'icmp', 'ICMP', 'IPv6-ICMP', 'TCP', 'UDP']:
                features[f'proto_{proto}'] = 1 if proto.lower() == protocol.lower() else 0
            
        except Exception as e:
            self.logger.error(f"Lỗi khi trích xuất đặc trưng Suricata: {e}", exc_info=True)
            # Điền các giá trị mặc định cho các đặc trưng còn thiếu
            for feature in self.suricata_features:
                if feature not in features:
                    features[feature] = self.default_values.get(feature, 0)
        
        return features
    
    def _extract_cicddos_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trích xuất đặc trưng cho mô hình CIC-DDoS.
        
        Args:
            flow_data: Dữ liệu luồng mạng
            
        Returns:
            Dict chứa các đặc trưng CIC-DDoS
        """
        features = {}
        
        try:
            # Trích xuất Flag Count
            tcp_flags = flow_data.get('tcp_flags', {})
            if not isinstance(tcp_flags, dict):
                tcp_flags = {}
            
            features['ACK Flag Count'] = tcp_flags.get('ACK', 0)
            if features['ACK Flag Count'] is None:
                # Thử trích xuất từ nguồn khác
                features['ACK Flag Count'] = flow_data.get('ack_flag_count', 0)
            
            features['URG Flag Count'] = tcp_flags.get('URG', 0)
            if features['URG Flag Count'] is None:
                # Thử trích xuất từ nguồn khác
                features['URG Flag Count'] = flow_data.get('urg_flag_count', 0)
            
            # Trích xuất thông tin về kích thước gói tin
            packet_lengths = flow_data.get('packet_lengths', {})
            if not isinstance(packet_lengths, dict):
                packet_lengths = {'forward': [], 'backward': []}
            
            fwd_packet_lengths = packet_lengths.get('forward', [])
            if not fwd_packet_lengths and 'fwd_pkt_len_list' in flow_data:
                # Thử trích xuất từ nguồn khác
                fwd_packet_lengths = flow_data.get('fwd_pkt_len_list', [0])
            
            bwd_packet_lengths = packet_lengths.get('backward', [])
            if not bwd_packet_lengths and 'bwd_pkt_len_list' in flow_data:
                # Thử trích xuất từ nguồn khác
                bwd_packet_lengths = flow_data.get('bwd_pkt_len_list', [0])
            
            # Đảm bảo có ít nhất một phần tử trong danh sách
            if not fwd_packet_lengths:
                fwd_packet_lengths = [0]
            if not bwd_packet_lengths:
                bwd_packet_lengths = [0]
            
            # Tính toán các đặc trưng kích thước gói tin
            features['Fwd Packet Length Min'] = min(fwd_packet_lengths)
            features['Fwd Packet Length Max'] = max(fwd_packet_lengths)
            features['Fwd Packet Length Std'] = np.std(fwd_packet_lengths) if len(fwd_packet_lengths) > 1 else 0
            features['Bwd Packet Length Max'] = max(bwd_packet_lengths)
            
            # Trích xuất thông tin về Window bytes
            features['Init Fwd Win Bytes'] = flow_data.get('init_win_bytes_forward', 0)
            if features['Init Fwd Win Bytes'] is None:
                # Thử trích xuất từ nguồn khác
                features['Init Fwd Win Bytes'] = flow_data.get('init_fwd_win_bytes', 0)
            
            # Mã hóa giao thức
            protocol = flow_data.get('protocol', 'tcp').lower()
            features['Protocol'] = self._get_protocol_number(protocol)
            
        except Exception as e:
            self.logger.error(f"Lỗi khi trích xuất đặc trưng CIC-DDoS: {e}", exc_info=True)
            # Điền các giá trị mặc định cho các đặc trưng còn thiếu
            for feature in self.cicddos_features:
                if feature not in features:
                    features[feature] = self.default_values.get(feature, 0)
        
        return features
    
    def _get_protocol_number(self, proto: str) -> int:
        """
        Chuyển đổi tên giao thức thành số.
        
        Args:
            proto: Tên giao thức
            
        Returns:
            Số tương ứng với giao thức
        """
        return self.protocol_map.get(proto.lower(), 0)
    
    def extract_all_possible_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trích xuất tất cả các đặc trưng có thể từ dữ liệu luồng.
        Hữu ích khi cần trích xuất đặc trưng cho nhiều mô hình.
        
        Args:
            flow_data: Dữ liệu luồng mạng
            
        Returns:
            Dict chứa tất cả các đặc trưng đã trích xuất
        """
        # Trích xuất đặc trưng cho cả hai loại mô hình
        cicddos_features = self._extract_cicddos_features(flow_data)
        suricata_features = self._extract_suricata_features(flow_data)
        
        # Kết hợp hai bộ đặc trưng
        all_features = {**cicddos_features, **suricata_features}
        
        return all_features
    def infer_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Cố gắng suy luận các đặc trưng thiếu từ các đặc trưng có sẵn.
        
        Args:
            flow_data: Dữ liệu luồng mạng
            
        Returns:
            Dict chứa các đặc trưng đã được suy luận
        """
        features = flow_data.copy()
        
        # 1. Suy luận đặc trưng liên quan đến giao thức
        if 'protocol' in features:
            protocol = features['protocol']
            # Đảm bảo các đặc trưng giao thức one-hot tồn tại
            for proto in ['tcp', 'udp', 'ipv6-icmp', 'icmp', 'ICMP', 'IPv6-ICMP', 'TCP', 'UDP']:
                features[f'proto_{proto}'] = 1 if proto.lower() == protocol.lower() else 0
            
            # Đảm bảo Protocol number tồn tại
            features['Protocol'] = self._get_protocol_number(protocol)
        
        # 2. Suy luận đặc trưng liên quan đến kích thước gói tin
        if 'fwd_bytes' in features and 'bytes_toserver' not in features:
            features['bytes_toserver'] = features['fwd_bytes']
        
        if 'bwd_bytes' in features and 'bytes_toclient' not in features:
            features['bytes_toclient'] = features['bwd_bytes']
        
        if 'fwd_packets' in features and 'pkts_toserver' not in features:
            features['pkts_toserver'] = features['fwd_packets']
        
        if 'bwd_packets' in features and 'pkts_toclient' not in features:
            features['pkts_toclient'] = features['bwd_packets']
        
            # 3. Suy luận các đặc trưng tổng hợp
        if 'bytes_toserver' in features and 'bytes_toclient' in features:
            features['total_bytes'] = features['bytes_toserver'] + features['bytes_toclient']
        
        if 'pkts_toserver' in features and 'pkts_toclient' in features:
            features['total_pkts'] = features['pkts_toserver'] + features['pkts_toclient']
        
        if 'total_bytes' in features and 'total_pkts' in features and features['total_pkts'] > 0:
            features['avg_bytes_per_pkt'] = features['total_bytes'] / features['total_pkts']
        
        # 4. Suy luận đặc trưng tỷ lệ
        if 'bytes_toserver' in features and 'bytes_toclient' in features and features['bytes_toclient'] > 0:
            features['bytes_ratio'] = features['bytes_toserver'] / features['bytes_toclient']
        elif 'bytes_toserver' in features:
            features['bytes_ratio'] = features['bytes_toserver']
        
        if 'pkts_toserver' in features and 'pkts_toclient' in features and features['pkts_toclient'] > 0:
            features['pkts_ratio'] = features['pkts_toserver'] / features['pkts_toclient']
        elif 'pkts_toserver' in features:
            features['pkts_ratio'] = features['pkts_toserver']
        
        # 5. Suy luận đặc trưng cổng well-known
        if 'src_port' in features and 'dst_port' in features:
            features['is_wellknown_port'] = 1 if (features['src_port'] < 1024 or features['dst_port'] < 1024) else 0
        
        # 6. Suy luận đặc trưng CIC-DDoS từ các nguồn khác
        if 'packet_lengths' in features and isinstance(features['packet_lengths'], dict):
            packet_lengths = features['packet_lengths']
            fwd_lengths = packet_lengths.get('forward', [])
            bwd_lengths = packet_lengths.get('backward', [])
            
            if fwd_lengths:
                features['Fwd Packet Length Min'] = min(fwd_lengths)
                features['Fwd Packet Length Max'] = max(fwd_lengths)
                features['Fwd Packet Length Std'] = np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0
            
            if bwd_lengths:
                features['Bwd Packet Length Max'] = max(bwd_lengths)
        
        # 7. Suy luận đặc trưng TCP flags
        if 'tcp_flags' in features and isinstance(features['tcp_flags'], dict):
            tcp_flags = features['tcp_flags']
            features['ACK Flag Count'] = tcp_flags.get('ACK', 0)
            features['URG Flag Count'] = tcp_flags.get('URG', 0)
        
        return features