import numpy as np
import pandas as pd
from collections import Counter
from scipy.stats import entropy as calc_entropy
from typing import Dict, Any, List

class FeatureExtractor:
    """Trích xuất và chuẩn hóa các đặc trưng từ dữ liệu luồng mạng."""

    def __init__(self, feature_columns: List[str], config=None):
        self.feature_columns = feature_columns
        self.config = config
        self.protocol_mappings = {
            'TCP': 0, 
            'UDP': 1, 
            'ICMP': 2,
            'Unknown': 3
        }

    def extract_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        features = {}

        # ----------- PROTOCOL & PORT -----------
        protocol = flow_data.get('Protocol', 'Unknown')
        features['Protocol'] = self.protocol_mappings.get(protocol, 3)
        dst_port = int(flow_data.get('Destination Port', 0) or 0)
        src_port = int(flow_data.get('Source Port', 0) or 0)
        dst_ip = flow_data.get('Destination IP', '')
        src_ip = flow_data.get('Source IP', '')

        # ----------- BASIC FLOW STATS -----------
        features['Flow Duration'] = flow_data.get('Flow Duration', 0)
        features['Total Packets'] = flow_data.get('Total Packets', 0)
        features['Total Bytes'] = flow_data.get('Total Bytes', 0)
        features['Packet Rate'] = flow_data.get('Packet Rate', 0)
        features['Byte Rate'] = flow_data.get('Byte Rate', 0)

        # ----------- PACKET LENGTH STATS -----------
        packet_lengths = flow_data.get('Packet Lengths', [])
        features['Packet Length Mean'] = np.mean(packet_lengths) if packet_lengths else 0
        features['Packet Length Std'] = np.std(packet_lengths) if packet_lengths else 0
        features['Packet Length Min'] = np.min(packet_lengths) if packet_lengths else 0
        features['Packet Length Max'] = np.max(packet_lengths) if packet_lengths else 0

        # ----------- TCP FLAG STATS -----------
        features['SYN Flag Count'] = flow_data.get('SYN Flag Count', 0)
        features['FIN Flag Count'] = flow_data.get('FIN Flag Count', 0)
        features['RST Flag Count'] = flow_data.get('RST Flag Count', 0)
        features['PSH Flag Count'] = flow_data.get('PSH Flag Count', 0)
        features['ACK Flag Count'] = flow_data.get('ACK Flag Count', 0)
        features['URG Flag Count'] = flow_data.get('URG Flag Count', 0)
        total_packets = features['Total Packets']
        features['SYN Flag Rate'] = features['SYN Flag Count'] / total_packets if total_packets else 0
        features['ACK Flag Rate'] = features['ACK Flag Count'] / total_packets if total_packets else 0

        # ----------- INTER-ARRIVAL TIME (IAT) -----------
        packet_times = flow_data.get('Packet Times', [])
        if packet_times and len(packet_times) > 1:
            iats = [packet_times[i+1] - packet_times[i] for i in range(len(packet_times)-1)]
            features['IAT Mean'] = np.mean(iats)
            features['IAT Std'] = np.std(iats)
            features['IAT Min'] = np.min(iats)
            features['IAT Max'] = np.max(iats)
        else:
            features['IAT Mean'] = features['IAT Std'] = features['IAT Min'] = features['IAT Max'] = 0

        # ----------- ENTROPY, BURST, ROLLING STD (Tăng khả năng phân biệt attack/benign/streaming) -----------
        if packet_lengths and len(packet_lengths) > 1:
            value_counts = Counter(packet_lengths)
            probs = np.array(list(value_counts.values())) / len(packet_lengths)
            features['PktLen Entropy'] = float(calc_entropy(probs, base=2))
            features['PktLen RollingStd'] = float(np.mean([np.std(packet_lengths[i:i+5]) for i in range(len(packet_lengths)-4)])) if len(packet_lengths) >= 5 else features['Packet Length Std']
        else:
            features['PktLen Entropy'] = features['PktLen RollingStd'] = 0

        # ----------- BURST COUNT -----------
        burst_count = 0
        if packet_times and len(packet_times) > 2:
            time_diffs = np.diff(packet_times)
            burst_count = int(np.sum(time_diffs < 0.01))
        features['Burst Count'] = burst_count

        # ----------- SYN FLOOD INDICATOR -----------
        features['SYN Flood Indicator'] = 1 if protocol == 'TCP' and features['SYN Flag Rate'] > 0.8 and features['ACK Flag Rate'] < 0.2 else 0

        # ----------- MSSQL DETECTION -----------
        is_mssql_port = (dst_port == 1433 or src_port == 1433)
        is_mssql_pattern = False
        packet_size_list = flow_data.get('packet_sizes', packet_lengths)
        is_real_mssql = self._is_real_mssql_traffic(flow_data)
        if is_real_mssql:
            features['MSSQL Port Indicator'] = 1
        elif is_mssql_port:
            features['MSSQL Port Indicator'] = 1
            features['MSSQL Attack Probability'] = 0.7
        else:
            if packet_size_list and len(packet_size_list) > 10:
                packet_size_mean = np.mean(packet_size_list)
                packet_size_std = np.std(packet_size_list)
                is_mssql_pattern = (packet_size_mean < 300 and packet_size_std < 50 and features['Packet Rate'] > 100)
            features['MSSQL Port Indicator'] = 1 if is_mssql_pattern else 0
            if is_mssql_pattern:
                features['MSSQL Attack Probability'] = 0.9

        # ----------- HTTPS & STREAMING DETECTION -----------
        is_https = self._is_likely_https_traffic(features, dst_port, src_port)
        features['HTTPS Traffic'] = 1 if is_https else 0
        if is_https:
            features['MSSQL Port Indicator'] = 0
            if features.get('Packet Length Mean', 0) > 800:
                features['Likely Streaming'] = 1

        # ----------- UDP FLOOD / STREAMING -----------
        if protocol == 'UDP':
            is_common_video_port = dst_port in [443, 33000, 33001] or src_port in [443, 33000, 33001]
            features['Streaming Service Port'] = 1 if is_common_video_port else 0
            small_packets = [size for size in packet_size_list if size < 200] if packet_size_list else []
            small_packets_ratio = len(small_packets) / len(packet_size_list) if packet_size_list else 0
            packet_size_std = np.std(packet_size_list) if packet_size_list else 0
            packet_size_mean = np.mean(packet_size_list) if packet_size_list else 0

            is_streaming_pattern = packet_size_mean > 800 and small_packets_ratio < 0.4 and features['Packet Rate'] < 2000
            is_attack_pattern = packet_size_std < 100 and features['Packet Rate'] > 2000 and small_packets_ratio > 0.7

            features['Likely Streaming'] = 1 if is_streaming_pattern else 0
            features['UDP Flood Indicator'] = 1 if is_attack_pattern else 0
            features['Size Uniformity'] = packet_size_std / packet_size_mean if packet_size_mean > 0 else 0
            features['Small Packet Ratio'] = small_packets_ratio
        else:
            features['Likely Streaming'] = 0
            features['UDP Flood Indicator'] = 0
            features['Size Uniformity'] = 0 
            features['Small Packet Ratio'] = 0
            features['Streaming Service Port'] = 0

        # ----------- LOGIC PHÂN BIỆT STREAMING/LOCAL SERVICE (TỪ CONFIG) -----------
        streaming_ports_str = self._get_config_value('Detection', 'streaming_ports', '443,33000,33001')
        streaming_ports = [int(p) for p in streaming_ports_str.split(',') if p.strip().isdigit()]
        local_service_ports_str = self._get_config_value('Detection', 'local_service_ports', '80,443,8080')
        local_service_ports = [int(p) for p in local_service_ports_str.split(',') if p.strip().isdigit()]
        is_streaming_port = (dst_port in streaming_ports) or (src_port in streaming_ports)
        is_local_service = (dst_port in local_service_ports or src_port in local_service_ports) and self._is_private_ip(dst_ip)
        features['Streaming Service Port'] = 1 if (is_streaming_port and not is_local_service) else 0

        return features

    def prepare_features_for_model(self, features_list: List[Dict[str, Any]]) -> np.ndarray:
        df = pd.DataFrame(features_list)
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        df = df[self.feature_columns]
        return df.values

    def _get_config_value(self, section, key, default_value):
        if self.config is None:
            return default_value
        try:
            return self.config.get(section, key, fallback=default_value)
        except:
            return default_value

    def _is_likely_https_traffic(self, features: Dict[str, Any], dst_port: int, src_port: int) -> bool:
        if dst_port == 443 or src_port == 443:
            if features.get('Packet Length Mean', 0) > 600 and features.get('ACK Flag Rate', 0) > 0.4 and features.get('Packet Length Std', 0) > 200:
                return True
        return False

    def _is_real_mssql_traffic(self, flow_data: Dict[str, Any]) -> bool:
        dst_port = flow_data.get('Destination Port', 0)
        src_port = flow_data.get('Source Port', 0)
        is_mssql_port = (dst_port == 1433 or src_port == 1433)
        payload = flow_data.get('payload_hex', '')
        has_tds_header = False
        if payload and len(payload) > 8:
            tds_markers = ['02010000', '04010000', '0701000']
            has_tds_header = any(marker in payload[:16] for marker in tds_markers)
        return is_mssql_port and has_tds_header

    def _is_private_ip(self, ip: str) -> bool:
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return False
            if octets[0] == '10': return True
            if octets[0] == '172' and 16 <= int(octets[1]) <= 31: return True
            if octets[0] == '192' and octets[1] == '168': return True
            if octets[0] == '127': return True
            return False
        except: return False
