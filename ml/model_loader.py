# src/ddos_detection_system/ml/model_loader.py
import pickle
import os
import logging
from typing import Tuple, List, Dict, Any
import numpy as np
from sklearn.base import BaseEstimator

class ModelLoader:
    """
    Tải và quản lý mô hình ML đã được huấn luyện.
    """
    
    def __init__(self, model_path: str):
        """
        Khởi tạo model loader.
        
        Args:
            model_path: Đường dẫn đến tệp tin mô hình đã lưu
        """
        self.model_path = model_path
        self.model = None
        self.feature_columns = []
        self.logger = logging.getLogger("model_loader")
        
    def load_model(self) -> Tuple[BaseEstimator, List[str]]:
        """
        Tải mô hình ML từ tệp tin.
        
        Returns:
            Tuple của (model, feature_columns)
        """
        try:
            if not os.path.exists(self.model_path):
                self.logger.error(f"Tệp tin mô hình không tồn tại: {self.model_path}")
                raise FileNotFoundError(f"Tệp tin mô hình không tồn tại: {self.model_path}")
                
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
                
            self.logger.info(f"Đã tải mô hình từ {self.model_path}")
            
            # Lấy thông tin feature columns (có thể lưu riêng hoặc cùng với mô hình)
            # Trong trường hợp này, sử dụng danh sách các đặc trưng đã biết từ model
            self._extract_feature_columns()
            
            return self.model, self.feature_columns
            
        except Exception as e:
            self.logger.error(f"Lỗi khi tải mô hình: {e}")
            raise
    
    def _extract_feature_columns(self):
        """Trích xuất danh sách cột đặc trưng từ mô hình."""
        # Đối với RandomForest, có thể lấy danh sách đặc trưng từ feature_names_in_
        if hasattr(self.model, 'feature_names_in_'):
            self.feature_columns = list(self.model.feature_names_in_)
        else:
            # Sử dụng danh sách đặc trưng mặc định nếu không tìm thấy
            self.feature_columns = [
                'Protocol', 'Flow Duration', 'Total Packets', 'Total Bytes',
                'Packet Rate', 'Byte Rate', 'Packet Length Mean', 'Packet Length Std',
                'Packet Length Min', 'Packet Length Max', 'SYN Flag Count',
                'FIN Flag Count', 'RST Flag Count', 'PSH Flag Count',
                'ACK Flag Count', 'URG Flag Count', 'SYN Flag Rate', 'ACK Flag Rate'
            ]
        
        self.logger.info(f"Đặc trưng mô hình: {', '.join(self.feature_columns)}")