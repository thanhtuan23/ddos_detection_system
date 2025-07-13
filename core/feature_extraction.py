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
        Extract features for CIC-DDoS model.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dict with extracted CIC-DDoS features
        """
        features = {}
        
        # Copy default values for all required features
        for feature in self.feature_columns:
            features[feature] = self.default_values.get(feature, 0)
        
        # Update with actual values where available
        for feature in self.cicddos_features:
            if feature in flow_data:
                features[feature] = flow_data[feature]
        
        # Handle special cases
        
        # Ensure TCP flags are present
        if 'ACK Flag Count' in self.feature_columns and 'tcp_flags' in flow_data:
            features['ACK Flag Count'] = flow_data['tcp_flags'].get('ACK', 0)
        
        if 'URG Flag Count' in self.feature_columns and 'tcp_flags' in flow_data:
            features['URG Flag Count'] = flow_data['tcp_flags'].get('URG', 0)
        
        # Handle packet length features
        if 'packet_lengths' in flow_data:
            fwd_lengths = flow_data['packet_lengths'].get('forward', [])
            if fwd_lengths:
                if 'Fwd Packet Length Min' in self.feature_columns:
                    features['Fwd Packet Length Min'] = min(fwd_lengths)
                
                if 'Fwd Packet Length Max' in self.feature_columns:
                    features['Fwd Packet Length Max'] = max(fwd_lengths)
                
                if 'Fwd Packet Length Std' in self.feature_columns and len(fwd_lengths) > 1:
                    features['Fwd Packet Length Std'] = np.std(fwd_lengths)
            
            bwd_lengths = flow_data['packet_lengths'].get('backward', [])
            if bwd_lengths and 'Bwd Packet Length Max' in self.feature_columns:
                features['Bwd Packet Length Max'] = max(bwd_lengths)
        
        # Handle protocol
        if 'Protocol' in self.feature_columns and 'protocol' in flow_data:
            protocol = flow_data['protocol']
            if protocol == 6:  # TCP
                features['Protocol'] = 6
            elif protocol == 17:  # UDP
                features['Protocol'] = 17
            elif protocol == 1 or protocol == 58:  # ICMP or ICMPv6
                features['Protocol'] = 1
            else:
                features['Protocol'] = 0
        
        # Handle window size
        if 'Init Fwd Win Bytes' in self.feature_columns:
            features['Init Fwd Win Bytes'] = flow_data.get('init_win_bytes_forward', 0)
        
        return features
    
    def _extract_suricata_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features for Suricata model.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dict with extracted Suricata features
        """
        features = {}
        
        # Copy default values for all required features
        for feature in self.feature_columns:
            features[feature] = self.default_values.get(feature, 0)
        
        # Update with actual values where available
        for feature in self.suricata_features:
            if feature in flow_data:
                features[feature] = flow_data[feature]
        
        # Handle ports
        if 'src_port' in self.feature_columns:
            features['src_port'] = flow_data.get('src_port', 0) or 0
        
        if 'dest_port' in self.feature_columns:
            features['dest_port'] = flow_data.get('dst_port', 0) or 0
        
        # Handle byte and packet counts
        if 'bytes_toserver' in self.feature_columns:
            features['bytes_toserver'] = flow_data.get('fwd_bytes', 0)
        
        if 'bytes_toclient' in self.feature_columns:
            features['bytes_toclient'] = flow_data.get('bwd_bytes', 0)
        
        if 'pkts_toserver' in self.feature_columns:
            features['pkts_toserver'] = flow_data.get('fwd_packets', 0)
        
        if 'pkts_toclient' in self.feature_columns:
            features['pkts_toclient'] = flow_data.get('bwd_packets', 0)
        
        if 'total_bytes' in self.feature_columns:
            features['total_bytes'] = flow_data.get('bytes', 0)
        
        if 'total_pkts' in self.feature_columns:
            features['total_pkts'] = flow_data.get('packets', 0)
        
        # Calculate average bytes per packet
        if 'avg_bytes_per_pkt' in self.feature_columns:
            packets = flow_data.get('packets', 0)
            bytes_total = flow_data.get('bytes', 0)
            features['avg_bytes_per_pkt'] = bytes_total / packets if packets > 0 else 0
        
        # Calculate ratios
        if 'bytes_ratio' in self.feature_columns:
            fwd_bytes = flow_data.get('fwd_bytes', 0)
            bwd_bytes = flow_data.get('bwd_bytes', 0)
            features['bytes_ratio'] = fwd_bytes / bwd_bytes if bwd_bytes > 0 else 1.0
        
        if 'pkts_ratio' in self.feature_columns:
            fwd_packets = flow_data.get('fwd_packets', 0)
            bwd_packets = flow_data.get('bwd_packets', 0)
            features['pkts_ratio'] = fwd_packets / bwd_packets if bwd_packets > 0 else 1.0
        
        # Handle protocol one-hot encoding
        protocol = self._get_protocol_number(flow_data.get('protocol', 0))
        
        for proto_name in ['tcp', 'udp', 'ipv6-icmp', 'icmp', 'ICMP', 'IPv6-ICMP', 'TCP', 'UDP']:
            proto_feature = f'proto_{proto_name}'
            if proto_feature in self.feature_columns:
                features[proto_feature] = 0
        
        # Set appropriate protocol flags
        if protocol == 6:  # TCP
            if 'proto_tcp' in self.feature_columns:
                features['proto_tcp'] = 1
            if 'proto_TCP' in self.feature_columns:
                features['proto_TCP'] = 1
        elif protocol == 17:  # UDP
            if 'proto_udp' in self.feature_columns:
                features['proto_udp'] = 1
            if 'proto_UDP' in self.feature_columns:
                features['proto_UDP'] = 1
        elif protocol == 1:  # ICMP
            if 'proto_icmp' in self.feature_columns:
                features['proto_icmp'] = 1
            if 'proto_ICMP' in self.feature_columns:
                features['proto_ICMP'] = 1
        elif protocol == 58:  # ICMPv6
            if 'proto_ipv6-icmp' in self.feature_columns:
                features['proto_ipv6-icmp'] = 1
            if 'proto_IPv6-ICMP' in self.feature_columns:
                features['proto_IPv6-ICMP'] = 1
        
        # Handle well-known port check
        if 'is_wellknown_port' in self.feature_columns:
            src_port = flow_data.get('src_port', 0) or 0
            dst_port = flow_data.get('dst_port', 0) or 0
            
            is_wellknown = 0
            wellknown_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
            if src_port in wellknown_ports or dst_port in wellknown_ports:
                is_wellknown = 1
            
            features['is_wellknown_port'] = is_wellknown
        
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