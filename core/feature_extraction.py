# core/feature_extraction.py
import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional

class FeatureExtractor:
    """
    Extracts features from network flows for ML model input.
    """
    
    def __init__(self, feature_columns: List[str], config=None, model_type: str = "cicddos"):
        """
        Initialize the feature extractor.
        
        Args:
            feature_columns: List of feature names required by the model
            config: Configuration object
            model_type: Type of model ("cicddos" or "suricata")
        """
        self.logger = logging.getLogger("ddos_detection_system.core.feature_extraction")
        self.feature_columns = feature_columns
        self.config = config
        self.model_type = model_type.lower()
        
        # Define feature sets for different model types
        self.cicddos_features = [
            'ACK Flag Count', 'Fwd Packet Length Min', 'Protocol', 'URG Flag Count',
            'Fwd Packet Length Max', 'Fwd Packet Length Std', 'Init Fwd Win Bytes',
            'Bwd Packet Length Max'
        ]
        
        self.suricata_features = [
            'src_port', 'dest_port', 'bytes_toserver', 'bytes_toclient',
            'pkts_toserver', 'pkts_toclient', 'total_bytes', 'total_pkts',
            'avg_bytes_per_pkt', 'bytes_ratio', 'pkts_ratio', 'is_wellknown_port',
            'proto_tcp', 'proto_udp', 'proto_ipv6-icmp', 'proto_icmp',
            'proto_ICMP', 'proto_IPv6-ICMP', 'proto_TCP', 'proto_UDP'
        ]
        
        # Create default values for missing features
        self.default_values = self._create_default_values()
        
        # Validate required features
        self._validate_features()
        
        self.logger.info(f"Feature extractor initialized for {model_type} model with {len(feature_columns)} features")
    
    def _create_default_values(self) -> Dict[str, Any]:
        """
        Create default values for features that might be missing.
        
        Returns:
            Dict with default values for all possible features
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
        
        # One-hot encoding for protocols
        for proto in ['tcp', 'udp', 'ipv6-icmp', 'icmp', 'ICMP', 'IPv6-ICMP', 'TCP', 'UDP']:
            defaults[f'proto_{proto}'] = 0
        
        return defaults
    
    def _validate_features(self):
        """Check and log if any required features are missing."""
        required_features = self.cicddos_features if self.model_type == "cicddos" else self.suricata_features
        missing_features = [f for f in required_features if f not in self.feature_columns]
        
        if missing_features:
            self.logger.warning(f"The following features are missing from feature_columns: {missing_features}")
            self.logger.warning("Default values will be used for these features")
    
    def extract_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from flow data based on model type.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dict with extracted features
        """        
        # Select the appropriate extraction method based on model type
        if self.model_type == "suricata":
            return self._extract_suricata_features(flow_data)
        else:
            return self._extract_cicddos_features(flow_data)
    
    def _extract_cicddos_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract CIC-DDoS2019 features from flow data.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dict with extracted features
        """
        # Khởi tạo với các giá trị mặc định
        features = {
            'ACK Flag Count': 0,
            'Fwd Packet Length Min': 0,
            'Protocol': 0,
            'URG Flag Count': 0,
            'Fwd Packet Length Max': 0,
            'Fwd Packet Length Std': 0,
            'Init Fwd Win Bytes': 0,
            'Bwd Packet Length Max': 0
        }
        
        # Trích xuất đặc trưng từ flow_data
        try:
            # Kiểm tra cấu trúc tcp_flags
            if 'tcp_flags' in flow_data:
                # Ghi log để kiểm tra kiểu dữ liệu
                self.logger.debug(f"TCP flags type: {type(flow_data['tcp_flags'])}, value: {flow_data['tcp_flags']}")
                
                if isinstance(flow_data['tcp_flags'], int):
                    # Nếu tcp_flags là số nguyên, xử lý như trước
                    flags = flow_data['tcp_flags']
                    if flags & 0x10:  # ACK flag
                        features['ACK Flag Count'] = 1
                    if flags & 0x20:  # URG flag
                        features['URG Flag Count'] = 1
                elif isinstance(flow_data['tcp_flags'], dict):
                    # Nếu tcp_flags là dictionary, tìm các key liên quan
                    flags_dict = flow_data['tcp_flags']
                    if flags_dict.get('ACK', False) or flags_dict.get('ack', False):
                        features['ACK Flag Count'] = 1
                    if flags_dict.get('URG', False) or flags_dict.get('urg', False):
                        features['URG Flag Count'] = 1
                elif isinstance(flow_data['tcp_flags'], str):
                    # Nếu tcp_flags là string, kiểm tra từng flag
                    flags_str = flow_data['tcp_flags'].upper()
                    if 'ACK' in flags_str:
                        features['ACK Flag Count'] = 1
                    if 'URG' in flags_str:
                        features['URG Flag Count'] = 1
            
            # Đặc trưng Protocol
            if 'protocol' in flow_data:
                protocol_value = flow_data['protocol']
                if isinstance(protocol_value, str):
                    # Chuyển đổi tên protocol thành số
                    protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
                    features['Protocol'] = protocol_map.get(protocol_value.upper(), 0)
                else:
                    features['Protocol'] = int(protocol_value)
            
            # Đặc trưng kích thước gói tin
            if 'fwd_packet_lengths' in flow_data and flow_data['fwd_packet_lengths']:
                fwd_lengths = flow_data['fwd_packet_lengths']
                if isinstance(fwd_lengths, list) and len(fwd_lengths) > 0:
                    features['Fwd Packet Length Min'] = min(fwd_lengths)
                    features['Fwd Packet Length Max'] = max(fwd_lengths)
                    features['Fwd Packet Length Std'] = np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0
                elif 'fwd_pkt_len_min' in flow_data:
                    # Tìm các key thay thế
                    features['Fwd Packet Length Min'] = flow_data.get('fwd_pkt_len_min', 0)
                    features['Fwd Packet Length Max'] = flow_data.get('fwd_pkt_len_max', 0)
                    features['Fwd Packet Length Std'] = flow_data.get('fwd_pkt_len_std', 0)
            
            # Đặc trưng Window size
            if 'init_win_bytes_forward' in flow_data:
                features['Init Fwd Win Bytes'] = flow_data['init_win_bytes_forward']
            elif 'init_fwd_win_bytes' in flow_data:
                features['Init Fwd Win Bytes'] = flow_data['init_fwd_win_bytes']
            
            # Đặc trưng kích thước gói tin ngược
            if 'bwd_packet_lengths' in flow_data and flow_data['bwd_packet_lengths']:
                bwd_lengths = flow_data['bwd_packet_lengths']
                if isinstance(bwd_lengths, list) and len(bwd_lengths) > 0:
                    features['Bwd Packet Length Max'] = max(bwd_lengths)
                elif 'bwd_pkt_len_max' in flow_data:
                    features['Bwd Packet Length Max'] = flow_data.get('bwd_pkt_len_max', 0)
                    
        except Exception as e:
            self.logger.error(f"Error extracting CIC-DDoS features: {e}", exc_info=True)
            # Ghi log thông tin flow_data để debug
            self.logger.debug(f"Flow data: {flow_data}")
        
        return features

    def _extract_suricata_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract Suricata-compatible features from flow data.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dict with extracted features
        """
        # Khởi tạo với các giá trị mặc định cho các đặc trưng Suricata
        features = {
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
            'is_wellknown_port': 0,
            'proto_tcp': 0,
            'proto_udp': 0,
            'proto_ipv6-icmp': 0,
            'proto_icmp': 0,
            'proto_ICMP': 0,
            'proto_IPv6-ICMP': 0,
            'proto_TCP': 0,
            'proto_UDP': 0
        }
        
        try:
            # Trích xuất đặc trưng cổng
            if 'src_port' in flow_data:
                features['src_port'] = flow_data['src_port']
            if 'dst_port' in flow_data:
                features['dest_port'] = flow_data['dst_port']
            
            # Các đặc trưng về byte
            if 'bytes_toserver' in flow_data:
                features['bytes_toserver'] = flow_data['bytes_toserver']
            if 'bytes_toclient' in flow_data:
                features['bytes_toclient'] = flow_data['bytes_toclient']
            
            # Các đặc trưng về gói tin
            if 'pkts_toserver' in flow_data:
                features['pkts_toserver'] = flow_data['pkts_toserver']
            if 'pkts_toclient' in flow_data:
                features['pkts_toclient'] = flow_data['pkts_toclient']
            
            # Tính tổng số byte và gói tin
            features['total_bytes'] = features['bytes_toserver'] + features['bytes_toclient']
            features['total_pkts'] = features['pkts_toserver'] + features['pkts_toclient']
            
            # Tính trung bình byte trên mỗi gói tin
            if features['total_pkts'] > 0:
                features['avg_bytes_per_pkt'] = features['total_bytes'] / features['total_pkts']
            
            # Tính tỷ lệ byte và gói tin
            if features['bytes_toclient'] > 0:
                features['bytes_ratio'] = features['bytes_toserver'] / features['bytes_toclient']
            if features['pkts_toclient'] > 0:
                features['pkts_ratio'] = features['pkts_toserver'] / features['pkts_toclient']
            
            # Kiểm tra cổng well-known
            well_known_ports = [80, 443, 53, 22, 25, 110, 143, 993, 995, 21]
            if features['src_port'] in well_known_ports or features['dest_port'] in well_known_ports:
                features['is_wellknown_port'] = 1
            
            # Xác định giao thức
            if 'protocol' in flow_data:
                protocol = flow_data['protocol']
                if isinstance(protocol, str):
                    protocol = protocol.upper()
                    if protocol == 'TCP':
                        features['proto_tcp'] = 1
                        features['proto_TCP'] = 1
                    elif protocol == 'UDP':
                        features['proto_udp'] = 1
                        features['proto_UDP'] = 1
                    elif protocol == 'ICMP':
                        features['proto_icmp'] = 1
                        features['proto_ICMP'] = 1
                    elif protocol == 'IPV6-ICMP':
                        features['proto_ipv6-icmp'] = 1
                        features['proto_IPv6-ICMP'] = 1
                elif isinstance(protocol, int):
                    if protocol == 6:  # TCP
                        features['proto_tcp'] = 1
                        features['proto_TCP'] = 1
                    elif protocol == 17:  # UDP
                        features['proto_udp'] = 1
                        features['proto_UDP'] = 1
                    elif protocol == 1:  # ICMP
                        features['proto_icmp'] = 1
                        features['proto_ICMP'] = 1
        
        except Exception as e:
            self.logger.error(f"Error extracting Suricata features: {e}", exc_info=True)
        
        return features
    
    def _get_protocol_number(self, proto: Any) -> int:
        """
        Convert protocol to numeric value.
        
        Args:
            proto: Protocol value (might be number, string, or None)
            
        Returns:
            Numeric protocol value
        """
        if isinstance(proto, int):
            return proto
        
        if isinstance(proto, str):
            proto = proto.lower()
            if proto == 'tcp':
                return 6
            elif proto == 'udp':
                return 17
            elif proto == 'icmp':
                return 1
            elif proto == 'icmpv6' or proto == 'ipv6-icmp':
                return 58
            
            try:
                return int(proto)
            except ValueError:
                pass
        
        return 0
    
    def prepare_features_df(self, features_dict: Dict[str, Any]) -> pd.DataFrame:
        """
        Prepare features as a DataFrame ready for model input.
        
        Args:
            features_dict: Dictionary of features
            
        Returns:
            DataFrame with properly formatted features
        """
        # Ensure all required columns are present
        for col in self.feature_columns:
            if col not in features_dict:
                features_dict[col] = self.default_values.get(col, 0)
        
        # Create DataFrame with only the required columns in the right order
        df = pd.DataFrame({col: [features_dict.get(col, self.default_values.get(col, 0))] 
                           for col in self.feature_columns})
        
        return df
    
    def extract_all_possible_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract all possible features from flow data.
        Useful for extracting features for multiple models at once.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dict with all extracted features
        """
        # Extract features for both model types
        cicddos_features = self._extract_cicddos_features(flow_data)
        suricata_features = self._extract_suricata_features(flow_data)
        
        # Combine all features
        all_features = {}
        all_features.update(cicddos_features)
        all_features.update(suricata_features)
        
        return all_features
    
    def infer_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Infer which features are available in the flow data.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dict with inferred features
        """
        # Check which model type fits better with the data
        cicddos_matches = sum(1 for f in self.cicddos_features if f in flow_data)
        suricata_matches = sum(1 for f in self.suricata_features if f in flow_data)
        
        if cicddos_matches >= suricata_matches:
            self.logger.debug("Inferred CIC-DDoS features from flow data")
            return self._extract_cicddos_features(flow_data)
        else:
            self.logger.debug("Inferred Suricata features from flow data")
            return self._extract_suricata_features(flow_data)