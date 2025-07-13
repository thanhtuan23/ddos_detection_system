# ml/feature_processor.py
import logging
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Union, Optional

class FeatureProcessor:
    """
    Processes features for ML models, including scaling and selection.
    """
    
    def __init__(self, feature_columns: List[str], scaler=None, feature_selector=None):
        """
        Initialize the feature processor.
        
        Args:
            feature_columns: List of feature columns needed for the model
            scaler: Fitted scaler from training time
            feature_selector: Feature selector from training time
        """
        self.logger = logging.getLogger("ddos_detection_system.ml.feature_processor")
        self.feature_columns = feature_columns
        self.scaler = scaler
        self.feature_selector = feature_selector
        
        self.logger.info(f"Initialized feature processor with {len(feature_columns)} expected features")
    
    def process_features(self, features: Union[Dict[str, Any], pd.DataFrame]) -> pd.DataFrame:
        """
        Process features for model input.
        
        Args:
            features: Feature dictionary or DataFrame
            
        Returns:
            Processed DataFrame ready for model input
        """
        try:
            # Convert dictionary to DataFrame if needed
            if isinstance(features, dict):
                df = pd.DataFrame([features])
            else:
                df = features.copy()
            
            # Ensure all required columns exist
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = 0
                    self.logger.debug(f"Added missing column: {col}")
            
            # Select only the required columns in the correct order
            df = df[self.feature_columns]
            
            # Apply scaling if available
            if self.scaler:
                df = pd.DataFrame(
                    self.scaler.transform(df),
                    columns=df.columns
                )
            
            # Apply feature selection if available
            if self.feature_selector:
                df = self.feature_selector.transform(df)
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error processing features: {e}", exc_info=True)
            # Return empty DataFrame with correct columns as fallback
            return pd.DataFrame(columns=self.feature_columns)
    
    def get_feature_importance(self, model) -> Dict[str, float]:
        """
        Get feature importance from a model.
        
        Args:
            model: Trained model
            
        Returns:
            Dictionary mapping feature names to importance values
        """
        try:
            # Check if model has feature_importances_ attribute
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
                
                # Get feature names
                if self.feature_selector:
                    # If feature selector was used, get selected feature indices
                    if hasattr(self.feature_selector, 'get_support'):
                        mask = self.feature_selector.get_support()
                        features = [self.feature_columns[i] for i, selected in enumerate(mask) if selected]
                    else:
                        features = self.feature_columns
                else:
                    features = self.feature_columns
                
                # Ensure length matches
                if len(features) != len(importances):
                    self.logger.warning(f"Feature count mismatch: {len(features)} names vs {len(importances)} importances")
                    # Trim to shorter length
                    min_len = min(len(features), len(importances))
                    features = features[:min_len]
                    importances = importances[:min_len]
                
                # Create dictionary
                return {feature: float(importance) for feature, importance in zip(features, importances)}
            else:
                self.logger.warning("Model does not have feature_importances_ attribute")
                return {}
                
        except Exception as e:
            self.logger.error(f"Error getting feature importance: {e}", exc_info=True)
            return {}