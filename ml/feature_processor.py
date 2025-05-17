# src/ddos_detection_system/ml/feature_processor.py
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from sklearn.preprocessing import MinMaxScaler

class FeatureProcessor:
    """
    Xử lý và chuẩn hóa đặc trưng cho mô hình học máy.
    """
    
    def __init__(self, feature_columns: List[str]):
        """
        Khởi tạo bộ xử lý đặc trưng.
        
        Args:
            feature_columns: Danh sách các cột đặc trưng cần thiết cho mô hình
        """
        self.feature_columns = feature_columns
        self.scaler = MinMaxScaler()
        self.scaler_fitted = False
        
    def fit_scaler(self, X: np.ndarray):
        """
        Đào tạo bộ chuẩn hóa MinMaxScaler với dữ liệu.
        
        Args:
            X: Dữ liệu để đào tạo bộ chuẩn hóa
        """
        self.scaler.fit(X)
        self.scaler_fitted = True
        
    def process_features(self, features: Dict[str, Any]) -> np.ndarray:
        """
        Xử lý một từ điển đặc trưng thành một vector đặc trưng.
        
        Args:
            features: Từ điển chứa các đặc trưng
            
        Returns:
            Vector đặc trưng đã được xử lý
        """
        # Tạo DataFrame với một hàng từ từ điển đặc trưng
        df = pd.DataFrame([features])
        
        # Đảm bảo tất cả các cột cần thiết đều có mặt
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0  # Thêm cột thiếu với giá trị mặc định
        
        # Chỉ giữ lại các cột đặc trưng cần thiết theo thứ tự chính xác
        df = df[self.feature_columns]
        
        # Chuyển đổi thành mảng numpy
        X = df.values
        
        # Chuẩn hóa đặc trưng nếu bộ chuẩn hóa đã được đào tạo
        if self.scaler_fitted:
            X = self.scaler.transform(X)
            
        return X
    
    def process_batch(self, features_list: List[Dict[str, Any]]) -> np.ndarray:
        """
        Xử lý một batch các từ điển đặc trưng.
        
        Args:
            features_list: Danh sách các từ điển đặc trưng
            
        Returns:
            Mảng đặc trưng đã được xử lý
        """
        # Tạo DataFrame từ danh sách các từ điển
        df = pd.DataFrame(features_list)
        
        # Đảm bảo tất cả các cột cần thiết đều có mặt
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Chỉ giữ lại các cột đặc trưng cần thiết theo thứ tự chính xác
        df = df[self.feature_columns]
        
        # Chuyển đổi thành mảng numpy
        X = df.values
        
        # Chuẩn hóa đặc trưng nếu bộ chuẩn hóa đã được đào tạo
        if self.scaler_fitted:
            X = self.scaler.transform(X)
            
        return X