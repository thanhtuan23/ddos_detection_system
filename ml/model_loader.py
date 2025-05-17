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
                loaded_data = pickle.load(f)
                
            # Kiểm tra xem có phải là đối tượng mô hình đơn thuần hay mô hình có metadata
            if isinstance(loaded_data, dict) and 'model' in loaded_data:
                # Đây là mô hình có metadata
                self.model = loaded_data['model']
                self.feature_columns = loaded_data['features']
                
                # Log thông tin chi tiết về mô hình từ metadata
                self.logger.info(f"Đã tải mô hình có metadata từ {self.model_path}")
                self.logger.info(f"Loại mô hình: {loaded_data.get('model_type', type(self.model).__name__)}")
                self.logger.info(f"Số lượng đặc trưng: {loaded_data.get('n_features', len(self.feature_columns))}")
                
                if 'label_mapping' in loaded_data:
                    label_map = loaded_data['label_mapping']
                    self.logger.info(f"Ánh xạ nhãn: {label_map}")
                    
            else:
                # Đây là mô hình đơn thuần (cũ)
                self.model = loaded_data
                
                # Trích xuất tên đặc trưng từ mô hình nếu có
                self._extract_feature_columns()
                self.logger.info(f"Đã tải mô hình đơn thuần từ {self.model_path}")
            
            # In thông tin về số lượng đặc trưng được tìm thấy
            self.logger.info(f"Tổng số đặc trưng được tải: {len(self.feature_columns)}")
            if len(self.feature_columns) < 10:
                # Nếu số lượng đặc trưng nhỏ, hiển thị tất cả
                self.logger.info(f"Danh sách đặc trưng: {self.feature_columns}")
            else:
                # Nếu nhiều hơn, chỉ hiển thị 5 đặc trưng đầu tiên
                self.logger.info(f"5 đặc trưng đầu tiên: {self.feature_columns[:5]}...")
                
            return self.model, self.feature_columns
            
        except Exception as e:
            self.logger.error(f"Lỗi khi tải mô hình: {e}")
            raise
    
    def _extract_feature_columns(self):
        """Trích xuất danh sách cột đặc trưng từ mô hình."""
        # Đối với RandomForest, có thể lấy danh sách đặc trưng từ feature_names_in_
        if hasattr(self.model, 'feature_names_in_'):
            self.feature_columns = list(self.model.feature_names_in_)
            self.logger.info(f"Đặc trưng mô hình: {', '.join(self.feature_columns)}")
        else:
            # Sử dụng danh sách đặc trưng mặc định nếu không tìm thấy
            self.feature_columns = [
                'Protocol', 'Flow Duration', 'Total Packets', 'Total Bytes',
                'Packet Rate', 'Byte Rate', 'Packet Length Mean', 'Packet Length Std',
                'Packet Length Min', 'Packet Length Max', 'SYN Flag Count',
                'FIN Flag Count', 'RST Flag Count', 'PSH Flag Count',
                'ACK Flag Count', 'URG Flag Count', 'SYN Flag Rate', 'ACK Flag Rate'
            ]
            self.logger.info(f"Sử dụng danh sách đặc trưng mặc định: {', '.join(self.feature_columns)}")
        
        # Thêm kiểm tra số lượng đặc trưng để debug
        if hasattr(self.model, 'n_features_in_'):
            self.logger.info(f"Mô hình cần {self.model.n_features_in_} đặc trưng")
            if len(self.feature_columns) != self.model.n_features_in_:
                self.logger.warning(f"Cảnh báo: Số lượng đặc trưng không khớp! " 
                                  f"Mô hình cần {self.model.n_features_in_}, "
                                  f"nhưng đã tìm thấy {len(self.feature_columns)}")