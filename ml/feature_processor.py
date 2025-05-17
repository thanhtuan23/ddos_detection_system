# src/ddos_detection_system/ml/feature_processor.py
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from sklearn.preprocessing import MinMaxScaler
import logging

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
        self.logger = logging.getLogger("feature_processor")
        
        # Đặc trưng cần có để khớp với mô hình
        self.required_feature_count = 32
        
        # Log thông tin về đặc trưng mong đợi
        self.logger.info(f"Khởi tạo bộ xử lý đặc trưng với {len(feature_columns)} đặc trưng mong đợi")
        if len(feature_columns) < 10:
            self.logger.info(f"Danh sách đặc trưng mong đợi: {feature_columns}")
        
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
        Xử lý một từ điển đặc trưng thành một vector đặc trưng.
        
        Args:
            features: Từ điển chứa các đặc trưng
            
        Returns:
            Vector đặc trưng đã được xử lý
        """
        # Tạo DataFrame với một hàng từ từ điển đặc trưng
        df = pd.DataFrame([features])
        
        # Log các đặc trưng đầu vào
        self.logger.debug(f"Số lượng đặc trưng đầu vào: {len(df.columns)}")
        
        # Xử lý sự không khớp giữa đặc trưng đầu vào và đặc trưng mô hình
        missing_features = set(self.feature_columns) - set(df.columns)
        extra_features = set(df.columns) - set(self.feature_columns)
        
        if missing_features:
            self.logger.debug(f"Đặc trưng thiếu: {missing_features}")
            # Thêm các đặc trưng thiếu với giá trị mặc định là 0
            for feature in missing_features:
                df[feature] = 0
        
        if extra_features:
            self.logger.debug(f"Đặc trưng thừa: {extra_features}")
            # Có thể loại bỏ các đặc trưng thừa, tùy vào chiến lược của bạn
        
        # Xác định số lượng đặc trưng cần thêm để đạt đủ 32 đặc trưng
        current_feature_count = len(self.feature_columns)
        dummy_features_needed = max(0, self.required_feature_count - current_feature_count)
        
        # Thêm các đặc trưng giả nếu cần
        if dummy_features_needed > 0:
            self.logger.info(f"Thêm {dummy_features_needed} đặc trưng giả để đạt đủ {self.required_feature_count} đặc trưng")
            dummy_feature_names = [f"dummy_feature_{i}" for i in range(dummy_features_needed)]
            
            # Thêm các đặc trưng giả vào DataFrame
            for feature in dummy_feature_names:
                df[feature] = 0
            
            # Thêm các đặc trưng giả vào danh sách đặc trưng
            self.feature_columns.extend(dummy_feature_names)
        
        # Đảm bảo tất cả các cột cần thiết đều có mặt
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Chỉ giữ lại các cột đặc trưng cần thiết theo thứ tự chính xác
        df = df[self.feature_columns]
        
        # Kiểm tra lại số lượng đặc trưng
        actual_feature_count = df.shape[1]
        if actual_feature_count != self.required_feature_count:
            self.logger.warning(f"Cảnh báo: Vẫn không đủ đặc trưng. Cần {self.required_feature_count}, hiện có {actual_feature_count}")
        else:
            self.logger.debug(f"Đã chuẩn bị đủ {actual_feature_count} đặc trưng")
        
        # Chuyển đổi thành mảng numpy
        X = df.values
        
        # Chuẩn hóa đặc trưng nếu bộ chuẩn hóa đã được đào tạo
        if self.scaler_fitted:
            try:
                X = self.scaler.transform(X)
            except Exception as e:
                self.logger.error(f"Lỗi khi chuẩn hóa đặc trưng: {e}")
                # Trong trường hợp lỗi, trả về mảng không chuẩn hóa
        
        return X
    
    def process_batch(self, features_list: List[Dict[str, Any]]) -> np.ndarray:
        """
        Xử lý một batch các từ điển đặc trưng.
        
        Args:
            features_list: Danh sách các từ điển đặc trưng
            
        Returns:
            Mảng đặc trưng đã được xử lý
        """
        if not features_list:
            self.logger.warning("Danh sách đặc trưng trống")
            # Tạo mảng rỗng với đúng số cột
            return np.zeros((0, len(self.feature_columns)))
        
        # Tạo DataFrame từ danh sách các từ điển
        df = pd.DataFrame(features_list)
        
        # Log thông tin về batch
        self.logger.debug(f"Xử lý batch với {len(features_list)} mẫu, {len(df.columns)} đặc trưng")
        
        # Xử lý sự không khớp giữa đặc trưng đầu vào và đặc trưng mô hình
        missing_features = set(self.feature_columns) - set(df.columns)
        extra_features = set(df.columns) - set(self.feature_columns)
        
        if missing_features:
            self.logger.debug(f"Đặc trưng thiếu trong batch: {missing_features}")
            # Thêm các đặc trưng thiếu với giá trị mặc định là 0
            for feature in missing_features:
                df[feature] = 0
        
        if extra_features:
            self.logger.debug(f"Đặc trưng thừa trong batch: {extra_features}")
            # Có thể loại bỏ các đặc trưng thừa
        
        # Xác định số lượng đặc trưng cần thêm để đạt đủ 32 đặc trưng
        current_feature_count = len(self.feature_columns)
        dummy_features_needed = max(0, self.required_feature_count - current_feature_count)
        
        # Thêm các đặc trưng giả nếu cần
        if dummy_features_needed > 0:
            self.logger.info(f"Thêm {dummy_features_needed} đặc trưng giả vào batch để đạt đủ {self.required_feature_count} đặc trưng")
            dummy_feature_names = [f"dummy_feature_{i}" for i in range(dummy_features_needed)]
            
            # Thêm các đặc trưng giả vào DataFrame
            for feature in dummy_feature_names:
                df[feature] = 0
            
            # Thêm các đặc trưng giả vào danh sách đặc trưng
            self.feature_columns.extend(dummy_feature_names)
        
        # Đảm bảo tất cả các cột cần thiết đều có mặt
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Chỉ giữ lại các cột đặc trưng cần thiết theo thứ tự chính xác
        df = df[self.feature_columns]
        
        # Kiểm tra lại số lượng đặc trưng
        actual_feature_count = df.shape[1]
        if actual_feature_count != self.required_feature_count:
            self.logger.warning(f"Cảnh báo: Batch vẫn không đủ đặc trưng. Cần {self.required_feature_count}, hiện có {actual_feature_count}")
        
        # Chuyển đổi thành mảng numpy
        X = df.values
        
        # Chuẩn hóa đặc trưng nếu bộ chuẩn hóa đã được đào tạo
        if self.scaler_fitted:
            try:
                X = self.scaler.transform(X)
            except Exception as e:
                self.logger.error(f"Lỗi khi chuẩn hóa batch đặc trưng: {e}")
                # Trong trường hợp lỗi, trả về mảng không chuẩn hóa
        
        return X

    def prepare_features_for_model(self, features_list: List[Dict[str, Any]]) -> np.ndarray:
        """
        Chuẩn bị đặc trưng để sử dụng với mô hình ML.
        
        Args:
            features_list: Danh sách các từ điển đặc trưng đã trích xuất
            
        Returns:
            Mảng numpy chứa đặc trưng đã được xử lý để cung cấp cho mô hình
        """
        # Đây là phương thức chính để chuẩn bị đặc trưng cho mô hình
        return self.process_batch(features_list)