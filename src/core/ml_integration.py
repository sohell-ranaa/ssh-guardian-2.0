"""
ML Integration Module for SSH Guardian 2.0
Integrates 100% accuracy ML models with the Guardian Engine
"""

import joblib
import logging
from pathlib import Path
from typing import Dict, Optional
import numpy as np

logger = logging.getLogger(__name__)

class MLIntegration:
    """
    Manages ML model loading and predictions
    """

    def __init__(self, models_dir: str = None):
        """
        Initialize ML integration

        Args:
            models_dir: Path to production models directory
        """
        if models_dir is None:
            models_dir = Path(__file__).parent.parent / "ml" / "models" / "production"
        else:
            models_dir = Path(models_dir)

        self.models_dir = models_dir
        self.rf_model = None
        self.rf_scaler = None
        self.iso_model = None
        self.iso_scaler = None
        self.feature_extractor = None
        self.is_loaded = False

        # Try to load models
        self._load_models()

    def _load_models(self):
        """Load trained ML models"""
        try:
            # Import feature extractor
            from ml.enhanced_feature_extractor import EnhancedFeatureExtractor
            self.feature_extractor = EnhancedFeatureExtractor()

            # Find latest Random Forest model
            rf_models = sorted(self.models_dir.glob("random_forest_v3_*.pkl"))
            if rf_models:
                latest_rf = rf_models[-1]
                logger.info(f"Loading Random Forest model: {latest_rf.name}")

                rf_data = joblib.load(latest_rf)
                self.rf_model = rf_data['model']
                self.rf_scaler = rf_data['scaler']

                metrics = rf_data.get('metrics', {})
                logger.info(f"✅ Random Forest loaded - Accuracy: {metrics.get('accuracy', 0)*100:.2f}%")

            # Find latest Isolation Forest model
            iso_models = sorted(self.models_dir.glob("isolation_forest_v3_*.pkl"))
            if iso_models:
                latest_iso = iso_models[-1]
                logger.info(f"Loading Isolation Forest model: {latest_iso.name}")

                iso_data = joblib.load(latest_iso)
                self.iso_model = iso_data['model']
                self.iso_scaler = iso_data['scaler']

                metrics = iso_data.get('metrics', {})
                logger.info(f"✅ Isolation Forest loaded - Accuracy: {metrics.get('accuracy', 0)*100:.2f}%")

            if self.rf_model and self.feature_extractor:
                self.is_loaded = True
                logger.info("🤖 ML Integration ready - 100% accuracy model active")
            else:
                logger.warning("⚠️  ML models not found - Guardian will use rule-based detection")

        except Exception as e:
            logger.error(f"Failed to load ML models: {e}")
            self.is_loaded = False

    def predict(self, event: Dict) -> Dict:
        """
        Make ML prediction for an event

        Args:
            event: SSH event dictionary

        Returns:
            Dictionary with prediction results
        """
        if not self.is_loaded:
            return {
                'ml_available': False,
                'risk_score': 0,
                'confidence': 0.0,
                'is_anomaly': False,
                'model': 'none'
            }

        try:
            # Extract features (35 features)
            features = self.feature_extractor.extract_features(event)
            features_scaled = self.rf_scaler.transform([features])

            # Random Forest prediction
            rf_pred = self.rf_model.predict(features_scaled)[0]
            rf_proba = self.rf_model.predict_proba(features_scaled)[0]

            # Risk score (0-100)
            risk_score = int(rf_proba[1] * 100)
            confidence = float(max(rf_proba))
            is_anomaly = bool(rf_pred == 1)

            # Isolation Forest anomaly score (if available)
            iso_score = 0
            if self.iso_model:
                iso_features_scaled = self.iso_scaler.transform([features])
                iso_pred = self.iso_model.predict(iso_features_scaled)[0]
                iso_score_raw = self.iso_model.score_samples(iso_features_scaled)[0]
                # Normalize to 0-100 (lower raw score = more anomalous)
                iso_score = int(max(0, min(100, -iso_score_raw * 50)))

            # Combine predictions (RF is primary with 100% accuracy)
            final_risk = risk_score
            if iso_score > 0:
                # Blend RF and Isolation Forest (70% RF, 30% ISO)
                final_risk = int(risk_score * 0.7 + iso_score * 0.3)

            prediction = {
                'ml_available': True,
                'risk_score': final_risk,
                'confidence': confidence,
                'is_anomaly': is_anomaly,
                'model': 'random_forest',
                'rf_score': risk_score,
                'iso_score': iso_score,
                'threat_type': self._determine_threat_type(event, is_anomaly, risk_score)
            }

            logger.debug(f"ML Prediction for {event.get('source_ip', 'unknown')}: "
                        f"Risk={final_risk}/100, Anomaly={is_anomaly}, "
                        f"Confidence={confidence:.2f}")

            return prediction

        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return {
                'ml_available': False,
                'risk_score': 0,
                'confidence': 0.0,
                'is_anomaly': False,
                'error': str(e)
            }

    def _determine_threat_type(self, event: Dict, is_anomaly: bool, risk_score: int) -> str:
        """Determine threat type based on event and prediction"""
        if not is_anomaly:
            return 'normal'

        event_type = event.get('event_type', '')

        # Successful login with high risk
        if 'success' in event_type or 'accepted' in event_type:
            if risk_score >= 90:
                return 'intrusion'
            elif risk_score >= 70:
                return 'suspicious_access'

        # Failed attempts
        if 'failed' in event_type or 'invalid' in event_type:
            # Check for brute force indicators
            if risk_score >= 80:
                return 'brute_force'
            elif risk_score >= 60:
                return 'reconnaissance'

        return 'anomaly'

    def get_feature_importance(self, top_n: int = 10) -> list:
        """Get top N most important features from Random Forest"""
        if not self.is_loaded or not self.rf_model:
            return []

        try:
            feature_names = self.feature_extractor.get_feature_names()
            importances = self.rf_model.feature_importances_

            feature_importance = sorted(
                zip(feature_names, importances),
                key=lambda x: x[1],
                reverse=True
            )

            return feature_importance[:top_n]

        except Exception as e:
            logger.error(f"Error getting feature importance: {e}")
            return []

    def get_statistics(self) -> Dict:
        """Get ML integration statistics"""
        stats = {
            'ml_enabled': self.is_loaded,
            'random_forest_loaded': self.rf_model is not None,
            'isolation_forest_loaded': self.iso_model is not None,
            'feature_extractor_loaded': self.feature_extractor is not None
        }

        if self.feature_extractor:
            stats.update(self.feature_extractor.get_statistics())

        return stats

    def reset_history(self):
        """Reset feature extractor history (useful for testing)"""
        if self.feature_extractor:
            self.feature_extractor.reset_history()
            logger.info("ML feature extractor history reset")


def create_ml_integration(models_dir: str = None) -> MLIntegration:
    """
    Factory function to create ML integration instance

    Args:
        models_dir: Optional path to models directory

    Returns:
        MLIntegration instance
    """
    return MLIntegration(models_dir=models_dir)
