"""
ML Model Manager
Loads and manages trained models for real-time inference
Handles Random Forest, XGBoost ensemble
"""

import logging
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


class MLModelManager:
    """
    Manages ML models for SSH Guardian
    Loads trained models and performs real-time inference
    """

    def __init__(self, models_dir: Path):
        """
        Initialize ML Model Manager

        Args:
            models_dir: Directory containing saved models
        """
        self.models_dir = Path(models_dir)
        self.models = {}
        self.scalers = {}
        self.feature_names = []

        # Load all available models
        self._load_models()

    def _load_models(self):
        """Load all trained models from disk"""
        logger.info("🤖 Loading ML models...")

        # Look for Random Forest models
        rf_models = list(self.models_dir.glob("random_forest*.pkl"))

        for model_path in rf_models:
            try:
                model_name = model_path.stem
                logger.info(f"   Loading {model_name}...")

                model_data = joblib.load(model_path)

                # Check if it's a dict with model and scaler
                if isinstance(model_data, dict):
                    self.models[model_name] = model_data.get('model')
                    self.scalers[model_name] = model_data.get('scaler')
                    if 'feature_names' in model_data:
                        self.feature_names = model_data['feature_names']
                else:
                    # Just the model
                    self.models[model_name] = model_data

                logger.info(f"   ✅ {model_name} loaded successfully")

            except Exception as e:
                logger.error(f"   ❌ Failed to load {model_path}: {e}")

        # Look for XGBoost models
        xgb_models = list(self.models_dir.glob("xgboost*.pkl"))

        for model_path in xgb_models:
            try:
                model_name = model_path.stem
                logger.info(f"   Loading {model_name}...")

                model_data = joblib.load(model_path)

                if isinstance(model_data, dict):
                    self.models[model_name] = model_data.get('model')
                    self.scalers[model_name] = model_data.get('scaler')
                else:
                    self.models[model_name] = model_data

                logger.info(f"   ✅ {model_name} loaded successfully")

            except Exception as e:
                logger.error(f"   ❌ Failed to load {model_path}: {e}")

        if not self.models:
            logger.warning("⚠️  No ML models found. Using heuristic scoring only.")
        else:
            logger.info(f"✅ Loaded {len(self.models)} ML model(s)")

    def extract_features_for_ml(self, event: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from event for ML prediction

        Args:
            event: SSH event with all enrichment data

        Returns:
            Feature array ready for ML prediction
        """
        features = []

        # Parse timestamp
        timestamp = event.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        # Time features
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        is_weekend = 1 if day_of_week >= 5 else 0
        is_night = 1 if hour < 6 or hour > 22 else 0
        is_business_hours = 1 if 9 <= hour <= 17 and not is_weekend else 0

        features.extend([hour, day_of_week, is_weekend, is_night, is_business_hours])

        # Event type features
        event_type = event.get('event_type', '').lower()
        is_failed = 1 if 'failed' in event_type else 0
        is_invalid = 1 if 'invalid' in event_type else 0
        is_successful = 1 if 'accepted' in event_type else 0

        features.extend([is_failed, is_invalid, is_successful])

        # IP features (basic)
        source_ip = event.get('source_ip', '0.0.0.0')
        try:
            ip_parts = [int(p) for p in source_ip.split('.')]
            features.extend(ip_parts)
        except:
            features.extend([0, 0, 0, 0])

        # Geographic features
        geoip = event.get('geoip', {})
        latitude = geoip.get('latitude', 0) or 0
        longitude = geoip.get('longitude', 0) or 0

        features.extend([latitude, longitude])

        # Threat intelligence features
        threat_rep = event.get('threat_reputation', {})
        is_malicious = 1 if threat_rep.get('is_malicious', False) else 0
        threat_score = threat_rep.get('risk_score', 0) / 100.0  # Normalize

        features.extend([is_malicious, threat_score])

        # Advanced features (if available)
        advanced = event.get('advanced_features', {})

        # Session features
        session_features = advanced.get('session_features', {})
        session_duration = session_features.get('session_duration_seconds', 0) / 3600.0  # Hours

        features.append(session_duration)

        # Travel features
        travel_features = advanced.get('travel_features', {})
        is_impossible_travel = 1 if travel_features.get('is_impossible', False) else 0
        travel_risk = travel_features.get('risk_score', 0) / 100.0

        features.extend([is_impossible_travel, travel_risk])

        # Behavioral features
        ip_behavior = advanced.get('ip_behavior', {})
        attempts_per_hour = min(ip_behavior.get('attempts_per_hour', 0), 100) / 100.0
        is_rapid_fire = 1 if ip_behavior.get('is_rapid_fire', False) else 0

        features.extend([attempts_per_hour, is_rapid_fire])

        user_behavior = advanced.get('user_behavior', {})
        user_success_rate = user_behavior.get('success_rate', 0)
        is_legitimate = 1 if user_behavior.get('is_legitimate', False) else 0

        features.extend([user_success_rate, is_legitimate])

        return np.array(features).reshape(1, -1)

    def predict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform ML prediction on event

        Args:
            event: SSH event dict

        Returns:
            Prediction results with risk score and confidence
        """
        if not self.models:
            # No models loaded, return heuristic score
            return {
                'ml_available': False,
                'prediction': 0,
                'risk_score': 0,
                'confidence': 0.0,
                'model_used': 'none'
            }

        try:
            # Extract features
            features = self.extract_features_for_ml(event)

            # Use the best available model (prioritize newest)
            model_name = list(self.models.keys())[-1]  # Use last (newest) model
            model = self.models[model_name]

            # Scale features if scaler available
            if model_name in self.scalers and self.scalers[model_name] is not None:
                features = self.scalers[model_name].transform(features)

            # Get prediction
            if hasattr(model, 'predict_proba'):
                # Classification model with probabilities
                prediction = model.predict(features)[0]
                proba = model.predict_proba(features)[0]

                # Risk score based on probability of anomaly class
                if len(proba) > 1:
                    risk_score = int(proba[1] * 100)  # Probability of class 1 (anomaly)
                    confidence = max(proba)
                else:
                    risk_score = int(prediction * 100)
                    confidence = 0.5

            else:
                # Regression or simple classifier
                prediction = model.predict(features)[0]
                risk_score = int(min(100, max(0, prediction * 100)))
                confidence = 0.7  # Fixed confidence for non-proba models

            return {
                'ml_available': True,
                'prediction': int(prediction),
                'risk_score': risk_score,
                'confidence': round(confidence, 3),
                'model_used': model_name,
                'is_anomaly': prediction == 1 if isinstance(prediction, (int, np.integer)) else False
            }

        except Exception as e:
            logger.error(f"ML prediction error: {e}", exc_info=True)
            return {
                'ml_available': False,
                'prediction': 0,
                'risk_score': 0,
                'confidence': 0.0,
                'model_used': 'error',
                'error': str(e)
            }

    def ensemble_predict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use ensemble of all models for prediction

        Args:
            event: SSH event dict

        Returns:
            Ensemble prediction results
        """
        if not self.models:
            return self.predict(event)

        try:
            features = self.extract_features_for_ml(event)
            predictions = []
            probabilities = []

            # Get predictions from all models
            for model_name, model in self.models.items():
                try:
                    # Scale if needed
                    scaled_features = features
                    if model_name in self.scalers and self.scalers[model_name]:
                        scaled_features = self.scalers[model_name].transform(features)

                    pred = model.predict(scaled_features)[0]
                    predictions.append(pred)

                    # Get probability if available
                    if hasattr(model, 'predict_proba'):
                        proba = model.predict_proba(scaled_features)[0]
                        if len(proba) > 1:
                            probabilities.append(proba[1])
                        else:
                            probabilities.append(pred)

                except Exception as e:
                    logger.debug(f"Model {model_name} prediction failed: {e}")
                    continue

            if not predictions:
                return self.predict(event)

            # Ensemble: majority vote for prediction, average for probability
            ensemble_prediction = int(np.round(np.mean(predictions)))

            if probabilities:
                ensemble_probability = np.mean(probabilities)
                risk_score = int(ensemble_probability * 100)
                confidence = 1.0 - np.std(probabilities)  # Lower std = higher confidence
            else:
                risk_score = int(ensemble_prediction * 100)
                confidence = 0.6

            return {
                'ml_available': True,
                'prediction': ensemble_prediction,
                'risk_score': risk_score,
                'confidence': round(confidence, 3),
                'model_used': f'ensemble_{len(predictions)}_models',
                'is_anomaly': ensemble_prediction == 1,
                'individual_predictions': predictions
            }

        except Exception as e:
            logger.error(f"Ensemble prediction error: {e}")
            return self.predict(event)

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        return {
            'models_loaded': len(self.models),
            'model_names': list(self.models.keys()),
            'scalers_available': list(self.scalers.keys()),
            'feature_count': len(self.feature_names) if self.feature_names else 'unknown'
        }


# Convenience function
def create_model_manager(models_dir: Path) -> MLModelManager:
    """Factory function to create ML Model Manager"""
    return MLModelManager(models_dir)


if __name__ == "__main__":
    # Test the model manager
    logging.basicConfig(level=logging.INFO)

    print("=" * 80)
    print("🤖 TESTING ML MODEL MANAGER")
    print("=" * 80)

    # Initialize
    models_dir = Path(__file__).parent / "saved_models"
    manager = create_model_manager(models_dir)

    print(f"\n📊 Model Info:")
    info = manager.get_model_info()
    for key, value in info.items():
        print(f"   {key}: {value}")

    # Test prediction
    print("\n" + "=" * 80)
    print("📍 TEST PREDICTION")
    print("=" * 80)

    test_event = {
        'timestamp': datetime.now(),
        'source_ip': '185.220.101.1',
        'username': 'root',
        'event_type': 'failed_password',
        'geoip': {
            'latitude': 55.7558,
            'longitude': 37.6173,
            'country': 'Russia'
        },
        'threat_reputation': {
            'is_malicious': True,
            'risk_score': 75
        },
        'advanced_features': {
            'session_features': {'session_duration_seconds': 0},
            'travel_features': {'is_impossible': False, 'risk_score': 0},
            'ip_behavior': {'attempts_per_hour': 15, 'is_rapid_fire': True},
            'user_behavior': {'success_rate': 0.0, 'is_legitimate': False}
        }
    }

    print("\n📌 Test Event: Failed login from known malicious IP (Russia)")

    if manager.models:
        result = manager.ensemble_predict(test_event)

        print(f"\n✅ ML PREDICTION:")
        print(f"   Risk Score: {result['risk_score']}/100")
        print(f"   Is Anomaly: {result['is_anomaly']}")
        print(f"   Confidence: {result['confidence']}")
        print(f"   Model Used: {result['model_used']}")
    else:
        print("\n⚠️  No models available for testing")

    print("\n" + "=" * 80)
