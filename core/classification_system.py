# core/classification_system.py
import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Tuple, Any, Optional
import time

class ClassificationSystem:
    """
    Hệ thống phân loại tấn công DDoS sử dụng kết hợp nhiều mô hình.
    """
    
    def __init__(self, models: List[Dict[str, Any]], config=None):
        """
        Khởi tạo hệ thống phân loại.
        
        Args:
            models: Danh sách các dict chứa thông tin mô hình (model, feature_columns, ...)
            config: Cấu hình hệ thống
        """
        self.models = models
        self.config = config
        self.logger = logging.getLogger("ddos_detection_system.core.classification_system")
        
        # Đọc cấu hình kết hợp
        self.combination_method = "max_confidence"  # Mặc định
        self.model_weights = [0.6, 0.4]  # Mặc định cho 2 mô hình, model 1 có trọng số cao hơn
        
        if config and config.has_section('Detection'):
            if config.has_option('Detection', 'combination_method'):
                self.combination_method = config.get('Detection', 'combination_method')
            
            if config.has_option('Detection', 'model_weights'):
                weights_str = config.get('Detection', 'model_weights')
                try:
                    weights = [float(w.strip()) for w in weights_str.split(',')]
                    if len(weights) >= len(models) and abs(sum(weights[:len(models)]) - 1.0) < 0.01:
                        self.model_weights = weights[:len(models)]
                    else:
                        # Tạo trọng số đồng đều nếu số lượng không khớp
                        self.model_weights = [1.0/len(models)] * len(models)
                except:
                    # Tạo trọng số đồng đều nếu có lỗi
                    self.model_weights = [1.0/len(models)] * len(models)
        
        # Tạo ánh xạ loại tấn công
        self.attack_type_mapping = self._create_attack_type_mapping()
        
        # Lưu lại loại mô hình
        self.model_types = []
        for model_info in models:
            model_type = model_info.get('model_type', 'unknown')
            self.model_types.append(model_type)
        
        self.logger.info(f"Hệ thống phân loại đã được khởi tạo với {len(models)} mô hình")
        self.logger.info(f"Phương pháp kết hợp: {self.combination_method}")
        self.logger.info(f"Trọng số mô hình: {self.model_weights}")
    
    def _create_attack_type_mapping(self) -> Dict[str, str]:
        """
        Tạo ánh xạ từ tên lớp gốc sang tên hiển thị.
        
        Returns:
            Dict ánh xạ tên lớp
        """
        # Ánh xạ mặc định
        mapping = {
            'Benign': 'Normal',
            'LDAP': 'LDAP Amplification',
            'MSSQL': 'MSSQL Amplification',
            'NetBIOS': 'NetBIOS Amplification',
            'Syn': 'SYN Flood',
            'UDP': 'UDP Flood',
            'UDPLag': 'UDP Lag',
            'DDoS': 'Generic DDoS'
        }
        
        # Đọc ánh xạ từ cấu hình nếu có
        if self.config and self.config.has_section('Detection'):
            if self.config.has_option('Detection', 'attack_type_mapping'):
                mapping_str = self.config.get('Detection', 'attack_type_mapping')
                try:
                    # Định dạng: LDAP=LDAP Amplification;MSSQL=MSSQL Amplification;...
                    pairs = mapping_str.split(';')
                    for pair in pairs:
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            mapping[key.strip()] = value.strip()
                except Exception as e:
                    self.logger.warning(f"Lỗi khi đọc ánh xạ loại tấn công: {e}")
        
        return mapping
    
    def classify_flow(self, flow: Dict[str, Any], feature_extractors: List[Any]) -> Tuple[bool, float, str, Dict[str, Any]]:
        """
        Phân loại một luồng dữ liệu.
        
        Args:
            flow: Dữ liệu luồng
            feature_extractors: Danh sách các trình trích xuất đặc trưng tương ứng với các mô hình
            
        Returns:
            Tuple (is_attack, confidence, attack_type, details)
        """
        results = []
        details = {}
        all_missing_features = []
        
        # Đảm bảo số lượng feature_extractors khớp với số lượng mô hình
        if len(feature_extractors) != len(self.models):
            self.logger.error(f"Số lượng feature extractors ({len(feature_extractors)}) không khớp với số lượng mô hình ({len(self.models)})")
            # Sử dụng số lượng tối thiểu
            n_models = min(len(feature_extractors), len(self.models))
        else:
            n_models = len(self.models)
        
        # Lặp qua từng mô hình và phân loại
        for i in range(n_models):
            model_info = self.models[i]
            feature_extractor = feature_extractors[i]
            model_type = self.model_types[i]
            
            # Phân loại với mô hình hiện tại
            result, missing_features = self._classify_with_model(flow, model_info, feature_extractor, model_type)
            results.append(result)
            
            # Lưu danh sách đặc trưng thiếu
            if missing_features:
                all_missing_features.extend(missing_features)
                details[f"model_{i+1}_missing_features"] = missing_features

            # Lưu chi tiết kết quả từng mô hình
            is_attack, confidence, attack_type, class_index = result
            details[f"model_{i+1}"] = {
                "is_attack": is_attack,
                "confidence": confidence,
                "attack_type": attack_type,
                "class_index": class_index,
                "model_type": model_type
            }
        
        # Kết hợp kết quả từ tất cả các mô hình
        final_result = self._combine_results(results)
        is_attack, confidence, attack_type, _ = final_result
        
        # Thêm kết quả cuối cùng vào chi tiết
        details["final_result"] = {
            "is_attack": is_attack,
            "confidence": confidence,
            "attack_type": attack_type,
            "combination_method": self.combination_method
        }
        # Thêm danh sách đặc trưng thiếu vào chi tiết
        if all_missing_features:
            details["missing_features"] = list(set(all_missing_features))
    

        return is_attack, confidence, attack_type, details
    
    def _classify_with_model(self, flow: Dict[str, Any], model_info: Dict[str, Any], 
                             feature_extractor: Any, model_type: str) -> Tuple[bool, float, str, Optional[int]]:
        """
        Phân loại với một mô hình cụ thể.
        
        Args:
            flow: Dữ liệu luồng
            model_info: Thông tin về mô hình
            feature_extractor: Trình trích xuất đặc trưng
            model_type: Loại mô hình
            
        Returns:
            Tuple (is_attack, confidence, attack_type, class_index)
        """
        try:
            start_time = time.time()
            
            # Trích xuất thông tin từ model_info
            model = model_info['model']
            label_encoder = model_info.get('label_encoder')
            label_mapping = model_info.get('label_mapping', {})
            
            # Trích xuất đặc trưng
            features = feature_extractor.extract_features(flow)
            features_df = feature_extractor.prepare_features_df(features)
            
            # Kiểm tra đặc trưng thiếu
            required_features = feature_extractor.feature_columns
            missing_features = [f for f in required_features if f not in features]
            
            # Chuẩn bị DataFrame
            features_df = feature_extractor.prepare_features_df(features)

            # Dự đoán
            prediction_proba = model.predict_proba(features_df)
            predicted_class = np.argmax(prediction_proba, axis=1)[0]
            confidence = np.max(prediction_proba, axis=1)[0]
            
            # Giải mã nhãn
            if label_encoder is not None:
                try:
                    attack_type = label_encoder.inverse_transform([predicted_class])[0]
                except:
                    attack_type = label_mapping.get(predicted_class, f"Class_{predicted_class}")
            else:
                attack_type = label_mapping.get(predicted_class, f"Class_{predicted_class}")
            
            # Áp dụng ánh xạ tên loại tấn công
            attack_type = self.attack_type_mapping.get(attack_type, attack_type)
            
            # Xác định có phải là tấn công không
            is_attack = attack_type != "Normal" and attack_type != "Benign"
            
            # Đối với mô hình Suricata, tất cả dự đoán đều là tấn công với độ tin cậy khác nhau
            if model_type.lower() == "suricata" and self.config:
                is_attack = confidence >= self.config.getfloat('Detection', 'detection_threshold', fallback=0.7)
                attack_type = "Generic DDoS" if is_attack else "Normal"
            
            processing_time = (time.time() - start_time) * 1000  # ms
            self.logger.debug(f"Phân loại với {model_type}: {attack_type} (tin cậy: {confidence:.4f}, thời gian: {processing_time:.2f}ms)")
            
            return (is_attack, confidence, attack_type, predicted_class), missing_features
            
        except Exception as e:
            self.logger.error(f"Lỗi khi phân loại với mô hình {model_type}: {e}", exc_info=True)
            return False, 0.0, "Error", None
    
    def _combine_results(self, results: List[Tuple]) -> Tuple[bool, float, str, Optional[int]]:
        """
        Kết hợp kết quả từ nhiều mô hình.
        
        Args:
            results: Danh sách kết quả từ các mô hình
            
        Returns:
            Tuple (is_attack, confidence, attack_type, class_index)
        """
        # Nếu chỉ có một kết quả, trả về luôn
        if len(results) == 1:
            return results[0]
        
        # Đảm bảo model_weights có cùng kích thước với results
        weights = self.model_weights[:len(results)]
        if len(weights) < len(results):
            weights = weights + [weights[-1]] * (len(results) - len(weights))
        
        # Nếu có nhiều kết quả, kết hợp theo phương pháp đã cấu hình
        if self.combination_method == "voting":
            # Phương pháp bỏ phiếu có trọng số
            vote_sum = 0
            for i, result in enumerate(results):
                is_attack = result[0]
                vote_sum += weights[i] * (1 if is_attack else 0)
            
                        # Kết quả là tấn công nếu tổng phiếu > 0.5
            is_attack = vote_sum > 0.5
            
            # Lấy loại tấn công và độ tin cậy từ mô hình có độ tin cậy cao nhất
            confidences = [r[1] for r in results]
            max_confidence_idx = np.argmax(confidences)
            confidence = results[max_confidence_idx][1]
            attack_type = results[max_confidence_idx][2]
            class_index = results[max_confidence_idx][3]
            
            # Nếu kết quả cuối cùng là không tấn công, ghi đè attack_type
            if not is_attack:
                attack_type = "Normal"
            
        elif self.combination_method == "weighted":
            # Phương pháp kết hợp có trọng số
            weighted_confidences = []
            attack_votes = []
            
            for i, result in enumerate(results):
                is_attack, confidence, _, _ = result
                
                # Nếu là tấn công, lấy độ tin cậy dương, ngược lại âm
                adjusted_confidence = confidence if is_attack else -confidence
                weighted_confidences.append(adjusted_confidence * weights[i])
                attack_votes.append(is_attack)
            
            # Lấy tổng có trọng số
            final_confidence_sum = sum(weighted_confidences)
            is_attack = final_confidence_sum > 0
            
            # Chuẩn hóa độ tin cậy về khoảng [0, 1]
            confidence = min(1.0, abs(final_confidence_sum))
            
            # Nếu là tấn công, chọn loại tấn công chi tiết nhất
            if is_attack:
                # Ưu tiên model CIC-DDoS vì nó có phân loại chi tiết hơn
                for i, result in enumerate(results):
                    if self.model_types[i].lower() == "cicddos" and result[0]:  # Nếu mô hình CIC-DDoS nói là tấn công
                        attack_type = result[2]
                        class_index = result[3]
                        break
                else:
                    # Nếu không có mô hình CIC-DDoS nào phát hiện tấn công, lấy từ mô hình có độ tin cậy cao nhất
                    attack_idx = [i for i, vote in enumerate(attack_votes) if vote]
                    if attack_idx:
                        # Chỉ xét các mô hình nói rằng có tấn công
                        attack_confidences = [results[i][1] for i in attack_idx]
                        max_confidence_idx = attack_idx[np.argmax(attack_confidences)]
                        attack_type = results[max_confidence_idx][2]
                        class_index = results[max_confidence_idx][3]
                    else:
                        # Fallback nếu không có mô hình nào nói là tấn công
                        attack_type = "Generic DDoS"
                        class_index = None
            else:
                attack_type = "Normal"
                class_index = None
            
        else:  # max_confidence (mặc định)
            # Phương pháp lấy kết quả từ mô hình có độ tin cậy cao nhất
            weighted_confidences = [results[i][1] * weights[i] for i in range(len(results))]
            max_confidence_idx = np.argmax(weighted_confidences)
            
            is_attack = results[max_confidence_idx][0]
            confidence = results[max_confidence_idx][1]
            attack_type = results[max_confidence_idx][2]
            class_index = results[max_confidence_idx][3]
            
            # Nếu mô hình có độ tin cậy cao nhất là Suricata và là tấn công,
            # nhưng CIC-DDoS cũng phát hiện tấn công, sử dụng loại tấn công từ CIC-DDoS
            if is_attack and self.model_types[max_confidence_idx].lower() == "suricata":
                for i, result in enumerate(results):
                    if self.model_types[i].lower() == "cicddos" and result[0]:  # Nếu mô hình CIC-DDoS nói là tấn công
                        attack_type = result[2]
                        break
        
        return is_attack, confidence, attack_type, class_index
    
    def get_attack_type_description(self, attack_type: str) -> str:
        """
        Lấy mô tả chi tiết về loại tấn công.
        
        Args:
            attack_type: Tên loại tấn công
            
        Returns:
            Mô tả chi tiết về loại tấn công
        """
        # Mô tả chi tiết về các loại tấn công
        descriptions = {
            "Normal": "Lưu lượng mạng bình thường, không phải tấn công.",
            "Benign": "Lưu lượng mạng bình thường, không phải tấn công.",
            "SYN Flood": "Tấn công bằng cách gửi nhiều gói SYN mà không hoàn tất bắt tay ba bước, làm cạn kiệt tài nguyên máy chủ.",
            "UDP Flood": "Tấn công bằng cách gửi nhiều gói UDP đến các cổng trên máy chủ, gây quá tải.",
            "UDP Lag": "Biến thể của UDP Flood tạo độ trễ cao trên mạng.",
            "LDAP Amplification": "Tấn công khuếch đại sử dụng máy chủ LDAP để tạo ra lưu lượng lớn hơn nhiều lần so với yêu cầu ban đầu.",
            "MSSQL Amplification": "Tấn công khuếch đại sử dụng máy chủ Microsoft SQL để tạo ra lưu lượng lớn.",
            "NetBIOS Amplification": "Tấn công khuếch đại sử dụng giao thức NetBIOS để tạo ra lưu lượng lớn.",
            "Generic DDoS": "Tấn công từ chối dịch vụ phân tán không xác định loại cụ thể.",
            "DNS Amplification": "Tấn công khuếch đại sử dụng máy chủ DNS để tạo ra lưu lượng lớn hơn nhiều lần so với yêu cầu ban đầu."
        }
        
        return descriptions.get(attack_type, f"Không có mô tả cho loại tấn công: {attack_type}")
    
    def get_detection_confidence_level(self, confidence: float) -> str:
        """
        Xác định mức độ tin cậy của phát hiện.
        
        Args:
            confidence: Độ tin cậy từ 0 đến 1
            
        Returns:
            Mức độ tin cậy (High, Medium, Low)
        """
        if confidence >= 0.8:
            return "High"
        elif confidence >= 0.6:
            return "Medium"
        else:
            return "Low"