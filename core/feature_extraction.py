# src/ddos_detection_system/core/feature_extraction.py
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple

class FeatureExtractor:
    """Trích xuất và chuẩn hóa các đặc trưng từ dữ liệu luồng mạng."""
    
    def __init__(self, feature_columns: List[str]):
        """
        Khởi tạo bộ trích xuất đặc trưng.
        
        Args:
            feature_columns: Danh sách các cột đặc trưng mà mô hình cần
        """
        self.feature_columns = feature_columns
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
            
        # Thêm đặc trưng nhận biết UDP Flood
        if protocol == 'UDP':
            features['UDP Flood Indicator'] = 1 if features['Packet Rate'] > 100 else 0
        else:
            features['UDP Flood Indicator'] = 0


        features['Flow Bytes/s'] = features['Byte Rate']  # Có thể là bản sao của Byte Rate
        features['Flow Packets/s'] = features['Packet Rate']  # Có thể là bản sao của Packet Rate
        features['Fwd Packets/s'] = features['Packet Rate'] / 2  # Ước tính
        features['Bwd Packets/s'] = features['Packet Rate'] / 2  # Ước tính
        features['Min Packet Length'] = features['Packet Length Min']  # Bản sao
        features['Max Packet Length'] = features['Packet Length Max']  # Bản sao
        features['Packet Length Variance'] = features['Packet Length Std'] ** 2  # Phái sinh
        features['Average Packet Size'] = features['Packet Length Mean']  # Bản sao 
                   
        return features
    
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