import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib
import json
from datetime import datetime
import sys
import os
sys.path.append('/home/rana-workspace/ssh_guardian_2.0/src/')

from ml.feature_extractor import MLFeatureExtractor

class RandomForestTrainer:
    def __init__(self):
        self.model = None
        self.results = {}
        self.feature_importance = {}
        
    def load_data(self):
        """Load and prepare data for training"""
        print("🔄 Loading and extracting features...")
        
        extractor = MLFeatureExtractor()
        df = extractor.process_all_json_files()
        
        if len(df) == 0:
            raise ValueError("No data found! Make sure you have JSON files in data/parsed_json/")
        
        print(f"✅ Loaded {len(df)} samples")
        print(f"📊 Anomaly distribution: {df['is_anomaly'].value_counts().to_dict()}")
        
        return df
    
    def train_model(self, df):
        """Train Random Forest model with hyperparameter tuning"""
        
        # Prepare features and target
        feature_columns = ['hour', 'day_of_week', 'is_weekend', 'is_night', 
                          'is_failed_login', 'is_invalid_user', 'is_successful', 
                          'is_disconnect', 'ip_frequency', 'user_frequency']
        
        X = df[feature_columns]
        y = df['is_anomaly']
        
        print(f"📈 Features: {feature_columns}")
        print(f"🎯 Target distribution: Normal={sum(y==0)}, Anomaly={sum(y==1)}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"🔀 Train size: {len(X_train)}, Test size: {len(X_test)}")
        
        # Hyperparameter tuning
        print("🔧 Starting hyperparameter tuning...")
        param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [5, 10, None],
            'min_samples_split': [2, 5]
        }
        
        rf = RandomForestClassifier(random_state=42)
        grid_search = GridSearchCV(rf, param_grid, cv=3, scoring='f1', n_jobs=2)
        grid_search.fit(X_train, y_train)
        
        # Best model
        self.model = grid_search.best_estimator_
        
        # Predictions
        y_pred = self.model.predict(X_test)
        
        # Calculate metrics
        self.results = {
            'best_params': grid_search.best_params_,
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1_score': f1_score(y_test, y_pred, zero_division=0),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'train_size': len(X_train),
            'test_size': len(X_test),
            'total_features': len(feature_columns),
            'training_time': datetime.now().isoformat()
        }
        
        # Feature importance
        self.feature_importance = dict(zip(feature_columns, self.model.feature_importances_))
        
        print("✅ Training completed!")
        
    def save_model_and_results(self):
        """Save model and results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save model
        model_path = f"src/ml/saved_models/random_forest_model_{timestamp}.pkl"
        joblib.dump(self.model, model_path)
        
        # Save results
        results_data = {
            'model_type': 'RandomForest',
            'timestamp': timestamp,
            'performance_metrics': self.results,
            'feature_importance': self.feature_importance,
            'model_path': model_path
        }
        
        results_path = f"src/ml/results/random_forest_results_{timestamp}.json"
        with open(results_path, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        print(f"💾 Model saved: {model_path}")
        print(f"📊 Results saved: {results_path}")
        
        return model_path, results_path
    
    def print_results(self):
        """Print training results"""
        print("\n" + "="*60)
        print("🎯 RANDOM FOREST TRAINING RESULTS")
        print("="*60)
        print(f"Best Parameters: {self.results['best_params']}")
        print(f"Accuracy:  {self.results['accuracy']:.4f} ({self.results['accuracy']*100:.2f}%)")
        print(f"Precision: {self.results['precision']:.4f} ({self.results['precision']*100:.2f}%)")
        print(f"Recall:    {self.results['recall']:.4f} ({self.results['recall']*100:.2f}%)")
        print(f"F1-Score:  {self.results['f1_score']:.4f} ({self.results['f1_score']*100:.2f}%)")
        
        print(f"\nConfusion Matrix:")
        cm = self.results['confusion_matrix']
        print(f"  True Neg:  {cm[0][0]}")
        print(f"  False Pos: {cm[0][1]}")
        print(f"  False Neg: {cm[1][0]}")
        print(f"  True Pos:  {cm[1][1]}")
        
        print(f"\nTop 5 Important Features:")
        sorted_features = sorted(self.feature_importance.items(), key=lambda x: x[1], reverse=True)
        for feature, importance in sorted_features[:5]:
            print(f"  {feature}: {importance:.4f}")

if __name__ == "__main__":
    trainer = RandomForestTrainer()
    
    try:
        # Load data
        df = trainer.load_data()
        
        # Train model
        trainer.train_model(df)
        
        # Print results
        trainer.print_results()
        
        # Save everything
        model_path, results_path = trainer.save_model_and_results()
        
        print(f"\n🎉 Training completed successfully!")
        
    except Exception as e:
        print(f"❌ Error: {e}")