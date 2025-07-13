# core/classification_system.py
import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional
import configparser

class ClassificationSystem:
    """
    System for classifying DDoS attacks using multiple models.
    """
    
    def __init__(self, models: List[Dict[str, Any]], config=None):
        """
        Initialize the classification system.
        
        Args:
            models: List of model info dictionaries
            config: Configuration object
        """
        self.logger = logging.getLogger("ddos_detection_system.core.classification_system")
        self.models = models
        self.config = config
        
        # Create attack type mapping
        self.attack_type_mapping = self._create_attack_type_mapping()
        
        # Get combination method from config
        self.combination_method = "max_confidence"
        if config and config.has_section('Detection'):
            self.combination_method = config.get(
                'Detection', 'combination_method', fallback='max_confidence'
            )
        
        self.logger.info(f"Classification system initialized with {len(models)} models")
        self.logger.info(f"Using combination method: {self.combination_method}")
    
    def _create_attack_type_mapping(self) -> Dict[str, str]:
        """
        Create mapping from original class names to display names.
        
        Returns:
            Dict mapping class names
        """
        # Default mapping
        mapping = {
            'Benign': 'Normal',
            'LDAP': 'LDAP Amplification',
            'MSSQL': 'MSSQL Amplification',
            'NetBIOS': 'NetBIOS Amplification',
            'Syn': 'SYN Flood',
            'UDP': 'UDP Flood',
            'UDPLag': 'UDP Lag',
        }
        
        # Read mapping from config if available
        if self.config and self.config.has_section('Detection'):
            if self.config.has_option('Detection', 'attack_type_mapping'):
                mapping_str = self.config.get('Detection', 'attack_type_mapping')
                try:
                    # Format: LDAP=LDAP Amplification;MSSQL=MSSQL Amplification;...
                    pairs = mapping_str.split(';')
                    for pair in pairs:
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            mapping[key.strip()] = value.strip()
                except Exception as e:
                    self.logger.warning(f"Error parsing attack type mapping: {e}")
        
        return mapping
    
    def classify_flow(self, flow: Dict[str, Any], feature_extractors: List[Any]) -> Tuple[bool, float, str, Dict[str, Any]]:
        """
        Classify a flow using all available models.
        
        Args:
            flow: Flow data dictionary
            feature_extractors: List of feature extractors for each model
            
        Returns:
            Tuple of (is_attack, confidence, attack_type, details)
        """
        if not self.models or len(self.models) == 0:
            self.logger.error("No models available for classification")
            return False, 0.0, "Unknown", {}
        
        # Ensure we have enough feature extractors
        if len(feature_extractors) < len(self.models):
            self.logger.warning(f"Not enough feature extractors ({len(feature_extractors)}) for models ({len(self.models)})")
            # Pad with the first extractor
            feature_extractors = feature_extractors + [feature_extractors[0]] * (len(self.models) - len(feature_extractors))
        
        # Get classification results from each model
        results = []
        
        for i, (model_info, feature_extractor) in enumerate(zip(self.models, feature_extractors)):
            model_type = model_info.get('model_type', 'cicddos' if i == 0 else 'suricata')
            result = self._classify_with_model(flow, model_info, feature_extractor, model_type)
            
            # Add model weight to result
            weight = model_info.get('weight', 1.0 / len(self.models))
            results.append((*result, weight))
        
        # Combine results
        is_attack, confidence, attack_type, subtype = self._combine_results(results)
        
        # Map attack type to display name
        display_attack_type = self.attack_type_mapping.get(attack_type, attack_type)
        
        # Prepare details
        details = {
            'flow_key': flow.get('flow_key', 'unknown'),
            'src_ip': flow.get('src_ip', 'unknown'),
            'dst_ip': flow.get('dst_ip', 'unknown'),
            'src_port': flow.get('src_port', 0),
            'dst_port': flow.get('dst_port', 0),
            'protocol': flow.get('protocol', 0),
            'packets': flow.get('packets', 0),
            'bytes': flow.get('bytes', 0),
            'duration': flow.get('last_time', 0) - flow.get('start_time', 0),
            'model_results': [
                {
                    'model_type': self.models[i].get('model_type', 'unknown'),
                    'is_attack': r[0],
                    'confidence': r[1],
                    'attack_type': r[2],
                    'weight': r[4]
                }
                for i, r in enumerate(results)
            ],
            'confidence_level': self.get_detection_confidence_level(confidence),
            'attack_description': self.get_attack_type_description(display_attack_type),
        }
        
        # Add flow-specific metrics
        if 'packet_rate' in flow:
            details['packet_rate'] = flow['packet_rate']
        if 'byte_rate' in flow:
            details['byte_rate'] = flow['byte_rate']
        
        return is_attack, confidence, display_attack_type, details
    
    def _classify_with_model(self, flow: Dict[str, Any], model_info: Dict[str, Any], 
                        feature_extractor: Any, model_type: str) -> Tuple[bool, float, str, Optional[int]]:
        try:
            # Ghi log cấu trúc dữ liệu đầu vào
            self.logger.debug(f"Flow data keys: {list(flow.keys())}")
            self.logger.debug(f"Flow data sample: {str(flow)[:200]}...")  # Chỉ hiển thị 200 ký tự đầu
            
            # Trích xuất đặc trưng
            features = feature_extractor.extract_features(flow)
            
            # Ghi log đặc trưng đã trích xuất
            self.logger.debug(f"Extracted features: {features}")
            
            # Chuẩn bị dataframe cho dự đoán
            X = feature_extractor.prepare_features_df(features)
            
            # Lấy mô hình và các thành phần khác
            model = model_info.get('model')
            scaler = model_info.get('scaler')
            
            # Kiểm tra xem model_info có chứa 'features' hay 'selected_features'
            if 'features' in model_info:
                expected_features = model_info['features']
            elif 'selected_features' in model_info:
                expected_features = model_info['selected_features']
            else:
                # Nếu không có thông tin về đặc trưng, sử dụng tất cả các đặc trưng
                expected_features = list(features.keys())
            
            # Ghi log thông tin về đặc trưng
            self.logger.debug(f"Model expects {len(expected_features)} features: {expected_features}")
            self.logger.debug(f"Extracted {len(features)} features: {list(features.keys())}")
            
            # Kiểm tra nếu scaler tồn tại và có n_features_in_
            if scaler and hasattr(scaler, 'n_features_in_'):
                scaler_expected = scaler.n_features_in_
                actual_features = X.shape[1]
                
                # Nếu số lượng đặc trưng không khớp với scaler
                if actual_features != scaler_expected:
                    self.logger.warning(
                        f"Feature count mismatch: model has {len(expected_features)}, "
                        f"scaler expects {scaler_expected}, extracted {actual_features}")
                    
                    # Bỏ qua bước chuẩn hóa
                    X_scaled = X
                    
                    # Chuyển đổi DataFrame thành numpy array nếu cần
                    if hasattr(X_scaled, 'to_numpy'):
                        X_scaled = X_scaled.to_numpy()
                else:
                    # Nếu số lượng đặc trưng khớp, tiếp tục chuẩn hóa
                    try:
                        X_scaled = scaler.transform(X)
                    except Exception as e:
                        self.logger.warning(f"Scaling error: {e}. Using unscaled features.")
                        X_scaled = X
                        if hasattr(X_scaled, 'to_numpy'):
                            X_scaled = X_scaled.to_numpy()
            else:
                # Nếu không có scaler, sử dụng đặc trưng nguyên gốc
                X_scaled = X
                if hasattr(X_scaled, 'to_numpy'):
                    X_scaled = X_scaled.to_numpy()
            
            # Dự đoán với mô hình
            try:
                if hasattr(model, 'predict_proba'):
                    y_proba = model.predict_proba(X_scaled)
                    y_pred = np.argmax(y_proba, axis=1)
                    confidence = np.max(y_proba, axis=1)[0]
                else:
                    y_pred = model.predict(X_scaled)
                    confidence = 1.0
                
                # Xử lý kết quả dự đoán
                original_class = int(y_pred[0]) if len(y_pred) > 0 else None
                
                # Lấy ánh xạ nhãn
                label_mapping = model_info.get('label_mapping', {})
                class_name = label_mapping.get(original_class, f"Unknown-{original_class}")
                
                # Ánh xạ tên hiển thị
                attack_type = self.attack_type_mapping.get(class_name, f"Unknown-{class_name}")
                
                # Xác định xem có phải tấn công không
                is_attack = class_name.lower() != 'benign' and class_name.lower() != 'normal'
                
                return is_attack, confidence, attack_type, original_class
                
            except Exception as e:
                self.logger.error(f"Prediction error: {e}", exc_info=True)
                return False, 0.0, "Unknown", None
                
        except Exception as e:
            self.logger.error(f"Classification error: {e}", exc_info=True)
            return False, 0.0, "Unknown", None
    
    def _combine_results(self, results: List[Tuple]) -> Tuple[bool, float, str, Optional[int]]:
        """
        Combine results from multiple models.
        
        Args:
            results: List of model results with weights
            
        Returns:
            Combined result
        """
        if not results:
            return False, 0.0, "Unknown", None
        
        if len(results) == 1:
            return results[0][:4]  # Return without the weight
        
        # Unpack results
        is_attacks = [r[0] for r in results]
        confidences = [r[1] for r in results]
        attack_types = [r[2] for r in results]
        attack_subtypes = [r[3] for r in results]
        weights = [r[4] for r in results]
        
        # Normalize weights
        total_weight = sum(weights)
        if total_weight > 0:
            weights = [w / total_weight for w in weights]
        else:
            weights = [1.0 / len(results)] * len(results)
        
        # Combine based on method
        if self.combination_method == 'voting':
            # Simple majority vote for attack classification
            attack_votes = sum(1 for is_attack in is_attacks if is_attack)
            is_attack = attack_votes > len(results) / 2
            
            # Count votes for each attack type
            type_votes = {}
            for attack_type, weight in zip(attack_types, weights):
                type_votes[attack_type] = type_votes.get(attack_type, 0) + weight
            
            # Get the most voted attack type
            attack_type = max(type_votes.items(), key=lambda x: x[1])[0]
            
            # Average confidence
            confidence = sum(conf * weight for conf, weight in zip(confidences, weights))
            
            # Use the subtype from the highest confidence result
            max_idx = confidences.index(max(confidences))
            attack_subtype = attack_subtypes[max_idx]
            
        elif self.combination_method == 'weighted':
            # Weighted decision
            attack_score = sum(int(is_attack) * weight for is_attack, weight in zip(is_attacks, weights))
            is_attack = attack_score > 0.5
            
            # Weighted confidence
            confidence = sum(conf * weight for conf, weight in zip(confidences, weights))
            
            # Weighted attack type selection
            type_scores = {}
            for attack_type, conf, weight in zip(attack_types, confidences, weights):
                type_scores[attack_type] = type_scores.get(attack_type, 0) + conf * weight
            
            # Get the highest scoring attack type
            attack_type = max(type_scores.items(), key=lambda x: x[1])[0]
            
            # Use the subtype from the highest confidence result
            max_idx = confidences.index(max(confidences))
            attack_subtype = attack_subtypes[max_idx]
            
        else:  # max_confidence
            # Use the result with the highest confidence
            max_idx = confidences.index(max(confidences))
            is_attack = is_attacks[max_idx]
            confidence = confidences[max_idx]
            attack_type = attack_types[max_idx]
            attack_subtype = attack_subtypes[max_idx]
        
        return is_attack, confidence, attack_type, attack_subtype
    
    def get_attack_type_description(self, attack_type: str) -> str:
        """
        Get a description for an attack type.
        
        Args:
            attack_type: Attack type name
            
        Returns:
            Description of the attack type
        """
        descriptions = {
            'LDAP Amplification': 'Attack that exploits LDAP servers to amplify traffic and overwhelm targets.',
            'MSSQL Amplification': 'Attack that exploits Microsoft SQL servers to generate large amounts of traffic.',
            'NetBIOS Amplification': 'Attack that uses NetBIOS name servers to amplify traffic volume.',
            'SYN Flood': 'Attack that sends a flood of TCP/SYN packets to consume server resources.',
            'UDP Flood': 'Attack that sends a large number of UDP packets to overwhelm target servers.',
            'UDP Lag': 'Attack that sends UDP packets designed to create network latency issues.',
            'Normal': 'Normal network traffic with no attack characteristics.'
        }
        
        return descriptions.get(attack_type, f"Unknown attack type: {attack_type}")
    
    def get_detection_confidence_level(self, confidence: float) -> str:
        """
        Get a textual confidence level based on the confidence score.
        
        Args:
            confidence: Confidence score (0-1)
            
        Returns:
            Confidence level description
        """
        if confidence >= 0.9:
            return "Very High"
        elif confidence >= 0.8:
            return "High"
        elif confidence >= 0.6:
            return "Medium"
        elif confidence >= 0.4:
            return "Low"
        else:
            return "Very Low"