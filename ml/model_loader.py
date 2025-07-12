from typing import Dict, List, Any, Union, Tuple, Optional
import os
import pickle
import numpy as np
import pandas as pd
import logging
import joblib
from sklearn.ensemble import RandomForestClassifier
import time

class ModelLoader:
    """
    Lớp tải mô hình phát hiện tấn công DDoS.
    """
    
    def __init__(self, model_paths: Union[str, List[str]]):
        """
        Khởi tạo ModelLoader.
        
        Args:
            model_paths: Đường dẫn tới (các) file mô hình
        """
        self.model_paths = [model_paths] if isinstance(model_paths, str) else model_paths
        self.logger = logging.getLogger("ddos_detection_system.ml.model_loader")
        self.logger.info(f"Khởi tạo ModelLoader với {len(self.model_paths)} mô hình")
    
    def load_model(self) -> Tuple:
        """
        Tải mô hình mặc định (mô hình đầu tiên).
        
        Returns:
            Tuple chứa (model, feature_columns, scaler, label_encoder, label_mapping)
        """
        if not self.model_paths:
            raise ValueError("Không có đường dẫn mô hình nào được cung cấp")
        
        # Tải mô hình đầu tiên
        return self.load_model_by_index(0)
    
    def load_model_by_index(self, index: int = 0) -> Tuple:
        """
        Tải mô hình theo chỉ số.
        
        Args:
            index: Chỉ số của mô hình cần tải
            
        Returns:
            Tuple chứa (model, feature_columns, scaler, label_encoder, label_mapping)
        """
        if index < 0 or index >= len(self.model_paths):
            raise ValueError(f"Chỉ số mô hình không hợp lệ: {index}")
        
        model_path = self.model_paths[index]
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Không tìm thấy file mô hình: {model_path}")
        
        # Xác định loại mô hình dựa vào tên file
        model_type = self._determine_model_type(model_path)
        
        # Tải mô hình
        try:
            with open(model_path, 'rb') as f:
                model_info = pickle.load(f)
            
            if not isinstance(model_info, dict):
                raise ValueError(f"Định dạng mô hình không hợp lệ: {model_path} không chứa dictionary")
            
            # Trích xuất model từ thông tin
            model = model_info.get('model')
            if model is None:
                raise ValueError(f"Không tìm thấy 'model' trong file: {model_path}")
            
            # Trích xuất scaler và label_encoder
            scaler = model_info.get('scaler')
            label_encoder = model_info.get('label_encoder')
            
            # Trích xuất và xử lý label_mapping dựa trên định dạng
            label_mapping = model_info.get('label_mapping')
            if label_mapping is None and label_encoder is not None:
                # Nếu không có label_mapping nhưng có label_encoder
                label_mapping = {i: c for i, c in enumerate(label_encoder.classes_)}
            elif label_mapping is None:
                # Nếu không có cả hai, tạo mapping mặc định dựa trên loại mô hình
                if model_type == "suricata":
                    label_mapping = {0: 'DDoS'}
                else:  # cicddos hoặc default
                    label_mapping = {
                        0: 'Benign', 
                        1: 'LDAP', 
                        2: 'MSSQL', 
                        3: 'NetBIOS', 
                        4: 'Syn', 
                        5: 'UDP', 
                        6: 'UDPLag'
                    }
            
            # Trích xuất feature_columns dựa trên định dạng
            if model_type == "suricata":
                # Cho mô hình Suricata
                if 'original_features' in model_info:
                    feature_columns = model_info['original_features']
                elif 'selected_features' in model_info:
                    feature_columns = model_info['selected_features']
                else:
                    # Danh sách đặc trưng mặc định cho Suricata
                    feature_columns = [
                        'src_port', 'dest_port', 'bytes_toserver', 'bytes_toclient', 'pkts_toserver', 
                        'pkts_toclient', 'total_bytes', 'total_pkts', 'avg_bytes_per_pkt', 'bytes_ratio', 
                        'pkts_ratio', 'is_wellknown_port', 'proto_tcp', 'proto_udp', 'proto_ipv6-icmp', 
                        'proto_icmp', 'proto_ICMP', 'proto_IPv6-ICMP', 'proto_TCP', 'proto_UDP'
                    ]
            else:
                # Cho mô hình CIC-DDoS
                if 'features' in model_info:
                    feature_columns = model_info['features']
                elif hasattr(model, 'feature_names_in_'):
                    feature_columns = model.feature_names_in_.tolist()
                else:
                    # Danh sách đặc trưng mặc định cho CIC-DDoS
                    feature_columns = [
                        'ACK Flag Count', 'Fwd Packet Length Min', 'Protocol', 'URG Flag Count', 
                        'Fwd Packet Length Max', 'Fwd Packet Length Std', 'Init Fwd Win Bytes', 
                        'Bwd Packet Length Max'
                    ]
            
            # Log thông tin mô hình
            self._log_model_info(model_info, model_type, feature_columns, label_mapping)
            
            return model, feature_columns, scaler, label_encoder, label_mapping
            
        except Exception as e:
            self.logger.error(f"Lỗi khi tải mô hình {model_path}: {e}", exc_info=True)
            raise
    
    def load_all_models(self) -> List[Dict[str, Any]]:
        """
        Tải tất cả các mô hình.
        
        Returns:
            Danh sách các dict chứa thông tin mô hình
        """
        models = []
        for i in range(len(self.model_paths)):
            try:
                model_path = self.model_paths[i]
                model_type = self._determine_model_type(model_path)
                
                # Tải mô hình
                model_data = self.load_model_by_index(i)
                model, feature_columns, scaler, label_encoder, label_mapping = model_data
                
                # Đóng gói thông tin mô hình
                model_info = {
                    'model': model,
                    'feature_columns': feature_columns,
                    'scaler': scaler,
                    'label_encoder': label_encoder,
                    'label_mapping': label_mapping,
                    'model_type': model_type,
                    'model_path': model_path
                }
                
                models.append(model_info)
                
            except Exception as e:
                self.logger.error(f"Lỗi khi tải mô hình thứ {i}: {e}", exc_info=True)
        
        return models
    
    def _determine_model_type(self, model_path: str) -> str:
        """
        Xác định loại mô hình dựa vào tên file.
        
        Args:
            model_path: Đường dẫn tới file mô hình
            
        Returns:
            Loại mô hình dự đoán
        """
        filename = os.path.basename(model_path).lower()
        
        if "suricata" in filename:
            return "suricata"
        elif "cicddos" in filename or "cic" in filename or "ddos_model" in filename:
            return "cicddos"
        else:
            return "standard_sklearn"
    
    def _log_model_info(self, model_info: Dict[str, Any], model_type: str, feature_columns: List[str], label_mapping: Dict[int, str]):
        """
        Ghi log thông tin về mô hình.
        
        Args:
            model_info: Dictionary chứa thông tin mô hình
            model_type: Loại mô hình (suricata, cicddos, ...)
            feature_columns: Danh sách các cột đặc trưng
            label_mapping: Ánh xạ từ số lớp sang tên lớp
        """
        # Trích xuất thông tin từ model_info
        model = model_info.get('model')
        model_name = type(model).__name__
        n_features = len(feature_columns)
        
        # Thông tin siêu tham số
        hyperparams = {}
        if 'hyperparameters' in model_info:
            hyperparams = model_info['hyperparameters']
        elif 'best_parameters' in model_info:
            hyperparams = model_info['best_parameters']
        elif hasattr(model, 'get_params'):
            hyperparams = model.get_params()
        
        # Thông tin hiệu suất
        performance = model_info.get('performance', {})
        
        # Thông tin ngày tạo
        creation_date = model_info.get('creation_date') or model_info.get('training_date')
        
        # Thông tin phiên bản
        model_version = model_info.get('model_version', 'N/A')
        
        # Log thông tin
        self.logger.info(f"=====================================")
        self.logger.info(f"Thông tin mô hình đã lưu: {model_type}")
        self.logger.info(f"Loại mô hình: {model_name}")
        self.logger.info(f"Siêu tham số: {hyperparams}")
        self.logger.info(f"Số lượng đặc trưng: {n_features}")
        self.logger.info(f"Ánh xạ nhãn: {label_mapping}")
        self.logger.info(f"Các đặc trưng: {feature_columns}")
        
        if creation_date:
            self.logger.info(f"Ngày tạo: {creation_date}")
        
        if model_version != 'N/A':
            self.logger.info(f"Phiên bản: {model_version}")
        
        if performance:
            self.logger.info(f"Hiệu suất: {performance}")
        
        self.logger.info(f"=====================================")