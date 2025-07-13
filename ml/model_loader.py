# ml/model_loader.py
import os
import pickle
import logging
import time
from typing import Dict, Any, List, Tuple, Union, Optional
import numpy as np

class ModelLoader:
    """
    Loads and prepares ML models for DDoS detection.
    """
    
    def __init__(self, model_paths: Union[str, List[str]]):
        """
        Initialize the model loader.
        
        Args:
            model_paths: Path(s) to model file(s)
        """
        self.logger = logging.getLogger("ddos_detection_system.ml.model_loader")
        
        # Convert single path to list
        if isinstance(model_paths, str):
            model_paths = [model_paths]
        
        self.model_paths = model_paths
        self.logger.info(f"Initialized ModelLoader with {len(self.model_paths)} models")
    
    def load_model(self) -> Tuple:
        """
        Load the default model (first model in the list).
        
        Returns:
            Tuple of (model, feature_columns, scaler, label_encoder, label_mapping)
        """
        if not self.model_paths:
            raise ValueError("No model paths provided")
        
        # Load the first model
        return self.load_model_by_index(0)
    
    def load_model_by_index(self, index: int = 0) -> Tuple:
        """
        Load a model by index.
        
        Args:
            index: Model index in the model_paths list
            
        Returns:
            Tuple of (model, feature_columns, scaler, label_encoder, label_mapping)
        """
        if index < 0 or index >= len(self.model_paths):
            raise ValueError(f"Invalid model index: {index}")
        
        model_path = self.model_paths[index]
        self.logger.info(f"Loading model from {model_path}")
        
        try:
            # Load model file
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            # Handle different model formats
            if isinstance(model_data, dict):
                # Modern format with model info dictionary
                model = model_data.get('model')
                
                # Get feature columns
                if 'features' in model_data:
                    feature_columns = model_data['features']
                elif 'feature_columns' in model_data:
                    feature_columns = model_data['feature_columns']
                elif 'selected_features' in model_data:
                    feature_columns = model_data['selected_features']
                else:
                    feature_columns = []
                
                # Get preprocessing components
                scaler = model_data.get('scaler')
                label_encoder = model_data.get('label_encoder')
                
                # Get label mapping
                if 'label_mapping' in model_data:
                    label_mapping = model_data['label_mapping']
                else:
                    label_mapping = {}
                
                # Log model info
                model_type = model_data.get('model_type', type(model).__name__ if model else 'Unknown')
                self._log_model_info(model_data, model_type, feature_columns, label_mapping)
                
            else:
                # Legacy format with just the model
                model = model_data
                feature_columns = []
                scaler = None
                label_encoder = None
                label_mapping = {}
                
                self.logger.warning("Loaded legacy model format without metadata")
            
            return model, feature_columns, scaler, label_encoder, label_mapping
            
        except Exception as e:
            self.logger.error(f"Error loading model from {model_path}: {e}", exc_info=True)
            raise
    
    def load_all_models(self) -> List[Dict[str, Any]]:
        """
        Load all models.
        
        Returns:
            List of model info dictionaries
        """
        models = []
        
        for i in range(len(self.model_paths)):
            try:
                model_path = self.model_paths[i]
                model_type = self._determine_model_type(model_path)
                
                # Load model
                model_data = self.load_model_by_index(i)
                model, feature_columns, scaler, label_encoder, label_mapping = model_data
                
                # Package model info
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
                self.logger.error(f"Error loading model #{i}: {e}", exc_info=True)
        
        return models
    
    def _determine_model_type(self, model_path: str) -> str:
        """
        Determine model type based on filename.
        
        Args:
            model_path: Path to model file
            
        Returns:
            Model type string
        """
        filename = os.path.basename(model_path).lower()
        
        if "suricata" in filename:
            return "suricata"
        elif "cicddos" in filename or "cic" in filename or "ddos_model" in filename:
            return "cicddos"
        else:
            return "standard_sklearn"
    
    def _log_model_info(self, model_info: Dict[str, Any], model_type: str, 
                        feature_columns: List[str], label_mapping: Dict[int, str]):
        """
        Log information about a loaded model.
        
        Args:
            model_info: Model information
            model_type: Type of model
            feature_columns: Feature columns
            label_mapping: Label mapping
        """
        self.logger.info(f"Loaded model: {model_type}")
        self.logger.info(f"Features: {len(feature_columns)} features")
        
        # Log hyperparameters if available
        if 'hyperparameters' in model_info:
            self.logger.info(f"Hyperparameters: {model_info['hyperparameters']}")
        elif 'best_parameters' in model_info:
            self.logger.info(f"Best parameters: {model_info['best_parameters']}")
        
        # Log performance if available
        if 'performance' in model_info:
            perf = model_info['performance']
            if 'test' in perf:
                test_perf = perf['test']
                self.logger.info(f"Test performance: "
                                f"Accuracy={test_perf.get('accuracy', 'N/A'):.4f}, "
                                f"Precision={test_perf.get('precision', 'N/A'):.4f}, "
                                f"Recall={test_perf.get('recall', 'N/A'):.4f}, "
                                f"F1={test_perf.get('f1', 'N/A'):.4f}")
        
        # Log label mapping
        if label_mapping:
            self.logger.info(f"Label mapping: {label_mapping}")