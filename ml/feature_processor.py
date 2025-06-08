import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from sklearn.preprocessing import MinMaxScaler
import logging

class FeatureProcessor:
    """
    Xử lý và chuẩn hóa đặc trưng cho mô hình học máy.
    """
    def __init__(self, feature_columns: List[str], scaler: MinMaxScaler = None):
        """
        Khởi tạo bộ xử lý đặc trưng.
        Args:
            feature_columns: Danh sách các cột đặc trưng cần thiết cho mô hình
            scaler: Bộ chuẩn hóa đã fit từ lúc train (nếu có)
        """
        self.feature_columns = feature_columns
        self.scaler = scaler if scaler is not None else MinMaxScaler()
        self.scaler_fitted = scaler is not None
        self.logger = logging.getLogger("feature_processor")
        self.required_feature_count = len(feature_columns)
        self.logger.info(f"Khởi tạo bộ xử lý đặc trưng với {len(feature_columns)} đặc trưng mong đợi")

    def fit_scaler(self, X: np.ndarray):
        """
        Đào tạo bộ chuẩn hóa MinMaxScaler với dữ liệu.
        Args:
            X: Dữ liệu để đào tạo bộ chuẩn hóa
        """
        self.scaler.fit(X)
        self.scaler_fitted = True
        self.logger.info("Đã đào tạo bộ chuẩn hóa MinMaxScaler")

    def process_features(self, features: Dict[str, Any]) -> np.ndarray:
        """
        Xử lý một từ điển đặc trưng thành một vector đặc trưng cho model.
        Args:
            features: Dict chứa các đặc trưng
        Returns:
            Numpy array 1 dòng, đúng thứ tự, đúng số lượng feature_columns
        """
        df = pd.DataFrame([features])
        missing_features = set(self.feature_columns) - set(df.columns)
        if missing_features:
            for feature in missing_features:
                df[feature] = 0
        # Chỉ giữ đúng cột, đúng thứ tự
        df = df[self.feature_columns]
        X = df.values
        # Apply scaler nếu đã fit
        if self.scaler_fitted:
            try:
                X = self.scaler.transform(X)
            except Exception as e:
                self.logger.error(f"Lỗi khi chuẩn hóa đặc trưng: {e}")
        return X

    def process_batch(self, features_list: List[Dict[str, Any]]) -> np.ndarray:
        if not features_list:
            self.logger.warning("Danh sách đặc trưng trống")
            return np.zeros((0, len(self.feature_columns)))
        df = pd.DataFrame(features_list)
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        df = df[self.feature_columns]
        X = df.values
        if self.scaler_fitted:
            try:
                X = self.scaler.transform(X)
            except Exception as e:
                self.logger.error(f"Lỗi khi chuẩn hóa batch đặc trưng: {e}")
        return X

    def prepare_features_for_model(self, features_list: List[Dict[str, Any]]) -> np.ndarray:
        """
        Chuẩn bị đặc trưng để sử dụng với mô hình ML.
        Args:
            features_list: Danh sách dict đặc trưng đã trích xuất
        Returns:
            Mảng numpy đã chuẩn hóa, đúng số/thứ tự feature
        """
        return self.process_batch(features_list)
