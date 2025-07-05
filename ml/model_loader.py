import pickle
import os
import logging
from typing import Tuple, List, Dict, Any, Optional
from sklearn.base import BaseEstimator

class ModelLoader:
    """
    Tải và quản lý mô hình ML đã được huấn luyện.
    """

    def __init__(self, model_path: str):
        self.model_path = model_path
        self.model = None
        self.feature_columns: List[str] = []
        self.scaler = None
        self.label_encoder = None
        self.label_mapping = None
        self.logger = logging.getLogger("model_loader")

    def load_model(self) -> Tuple[BaseEstimator, List[str], Optional[Any], Optional[Any], Optional[Dict]]:
        """
        Tải mô hình ML từ tệp tin.

        Returns:
            Tuple của (model, feature_columns, scaler, label_encoder, label_mapping)
        """
        try:
            if not os.path.exists(self.model_path):
                self.logger.error(f"Tệp tin mô hình không tồn tại: {self.model_path}")
                raise FileNotFoundError(f"Tệp tin mô hình không tồn tại: {self.model_path}")

            with open(self.model_path, 'rb') as f:
                loaded_data = pickle.load(f)

            if isinstance(loaded_data, dict) and 'model' in loaded_data:
                self.model = loaded_data['model']
                self.feature_columns = loaded_data.get('features', [])
                self.scaler = loaded_data.get('scaler')
                self.label_encoder = loaded_data.get('label_encoder')
                self.label_mapping = loaded_data.get('label_mapping', None)
                self.logger.info(f"Đã tải mô hình có metadata từ {self.model_path}")
                self.logger.info(f"Loại mô hình: {loaded_data.get('model_type', type(self.model).__name__)}")
                self.logger.info(f"Số lượng đặc trưng: {loaded_data.get('n_features', len(self.feature_columns))}")
                if self.label_mapping:
                    self.logger.info(f"Ánh xạ nhãn: {self.label_mapping}")
            else:
                # Trường hợp model cũ
                self.model = loaded_data
                self._extract_feature_columns()
                self.logger.info(f"Đã tải mô hình đơn thuần từ {self.model_path}")

            self.logger.info(f"Tổng số đặc trưng: {len(self.feature_columns)}")
            if len(self.feature_columns) <= 10:
                self.logger.info(f"Danh sách đặc trưng: {self.feature_columns}")
            else:
                self.logger.info(f"5 đặc trưng đầu tiên: {self.feature_columns[:5]}...")

            if hasattr(self.model, 'n_features_in_'):
                n_expected = self.model.n_features_in_
                if len(self.feature_columns) != n_expected:
                    self.logger.warning(f"Cảnh báo: Số lượng đặc trưng không khớp! "
                                        f"Mô hình cần {n_expected}, nhưng đã tìm thấy {len(self.feature_columns)}")

            return self.model, self.feature_columns, self.scaler, self.label_encoder, self.label_mapping

        except Exception as e:
            self.logger.error(f"Lỗi khi tải mô hình: {e}")
            raise

    def _extract_feature_columns(self):
        """Trích xuất danh sách cột đặc trưng từ mô hình hoặc từ file pickle."""
        if hasattr(self.model, 'feature_names_in_'):
            self.feature_columns = list(self.model.feature_names_in_)
            self.logger.info(f"Đặc trưng từ model.feature_names_in_: {self.feature_columns}")
        elif self.loaded_data and 'features' in self.loaded_data:
            # Ưu tiên lấy từ file model.pkl nếu có
            self.feature_columns = self.loaded_data['features']
            self.logger.info(f"Đặc trưng từ file model.pkl: {self.feature_columns}")
        else:
            # Chỉ fallback nếu hoàn toàn không có thông tin
            self.feature_columns = [
                'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packets Length Total', 
                'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Std', 
                'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 
                'Flow IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd Header Length', 
                'Bwd Header Length', 'Bwd Packets/s', 'SYN Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 
                'Down/Up Ratio', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Fwd Act Data Packets', 'Active Mean', 'Active Std', 
                'Idle Std'
            ]
            self.logger.warning("Không tìm thấy thông tin đặc trưng — sử dụng danh sách mặc định (top 8 feature)")
