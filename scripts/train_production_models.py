#!/usr/bin/env python3
"""
Production ML Model Training for SSH Guardian 2.0
Trains high-accuracy models on the 62k+ event dataset
"""

import sys
import os
import pymysql
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import joblib
from pathlib import Path

# Add src to path
sys.path.insert(0, '/home/rana-workspace/ssh_guardian_2.0')

from src.ml.enhanced_feature_extractor import EnhancedFeatureExtractor
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', '123123'),
    'database': os.getenv('DB_NAME', 'ssh_guardian_20'),
    'charset': 'utf8mb4'
}

class ProductionModelTrainer:
    """Train production-ready ML models"""

    def __init__(self):
        self.connection = None
        self.extractor = EnhancedFeatureExtractor()
        self.models = {}
        self.scalers = {}
        self.metrics = {}

        # Output directory
        self.output_dir = Path('/home/rana-workspace/ssh_guardian_2.0/src/ml/models/production')
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def connect_db(self):
        """Connect to database"""
        try:
            self.connection = pymysql.connect(**DB_CONFIG)
            print(f"✅ Connected to database: {DB_CONFIG['database']}")
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False

    def load_training_data(self, limit: int = None):
        """Load training data from database"""
        print("\n📊 Loading training data from database...")

        # Load failed logins
        query_failed = """
        SELECT
            timestamp, source_ip, username, server_hostname, port,
            failure_reason as event_type,
            country, city, latitude, longitude,
            ip_risk_score, ip_reputation, ml_risk_score,
            is_anomaly, ml_threat_type,
            0 as session_duration
        FROM failed_logins
        ORDER BY timestamp
        """
        if limit:
            query_failed += f" LIMIT {limit}"

        # Load successful logins
        query_success = """
        SELECT
            timestamp, source_ip, username, server_hostname, port,
            'successful_login' as event_type,
            country, city, latitude, longitude,
            ip_risk_score, ip_reputation, ml_risk_score,
            is_anomaly, ml_threat_type, session_duration
        FROM successful_logins
        ORDER BY timestamp
        """
        if limit:
            query_success += f" LIMIT {limit}"

        with self.connection.cursor(pymysql.cursors.DictCursor) as cursor:
            # Failed logins
            cursor.execute(query_failed)
            failed_events = cursor.fetchall()
            print(f"   Loaded {len(failed_events):,} failed login events")

            # Successful logins
            cursor.execute(query_success)
            success_events = cursor.fetchall()
            print(f"   Loaded {len(success_events):,} successful login events")

        # Combine
        all_events = failed_events + success_events

        # Sort by timestamp
        all_events.sort(key=lambda x: x['timestamp'])

        print(f"✅ Total events loaded: {len(all_events):,}")
        return all_events

    def extract_features_and_labels(self, events):
        """Extract features and labels from events"""
        print("\n🔧 Extracting features...")

        features_list = []
        labels = []

        for i, event in enumerate(events):
            try:
                # Extract features
                feature_vector = self.extractor.extract_features(event)
                features_list.append(feature_vector)

                # Label: 1 for anomaly, 0 for normal
                label = int(event.get('is_anomaly', 0))
                labels.append(label)

                if (i + 1) % 5000 == 0:
                    print(f"   Processed: {i + 1:,}/{len(events):,}")

            except Exception as e:
                print(f"   Warning: Error processing event {i}: {e}")
                continue

        X = np.array(features_list)
        y = np.array(labels)

        print(f"✅ Features extracted: {X.shape}")
        print(f"   Feature count: {X.shape[1]}")
        print(f"   Normal events: {np.sum(y == 0):,} ({np.sum(y == 0)/len(y)*100:.1f}%)")
        print(f"   Anomaly events: {np.sum(y == 1):,} ({np.sum(y == 1)/len(y)*100:.1f}%)")

        return X, y

    def train_random_forest(self, X_train, X_test, y_train, y_test):
        """Train Random Forest classifier"""
        print("\n🌲 Training Random Forest Classifier...")

        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Train model
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=10,
            min_samples_leaf=5,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            verbose=1
        )

        print("   Training...")
        model.fit(X_train_scaled, y_train)

        # Predictions
        y_pred = model.predict(X_test_scaled)
        y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

        # Metrics
        metrics = self._calculate_metrics(y_test, y_pred, y_pred_proba, "Random Forest")

        # Feature importance
        feature_names = self.extractor.get_feature_names()
        importances = model.feature_importances_
        feature_importance = sorted(zip(feature_names, importances),
                                   key=lambda x: x[1], reverse=True)

        print("\n   📊 Top 10 Important Features:")
        for i, (feat, imp) in enumerate(feature_importance[:10], 1):
            print(f"   {i:2}. {feat:<30} {imp:.4f}")

        # Save model
        model_path = self.output_dir / f"random_forest_v3_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pkl"
        joblib.dump({
            'model': model,
            'scaler': scaler,
            'feature_names': feature_names,
            'metrics': metrics,
            'feature_importance': feature_importance,
            'trained_at': datetime.now().isoformat()
        }, model_path)

        print(f"\n✅ Model saved: {model_path}")

        self.models['random_forest'] = model
        self.scalers['random_forest'] = scaler
        self.metrics['random_forest'] = metrics

        return model, scaler, metrics

    def train_isolation_forest(self, X_train, X_test, y_test):
        """Train Isolation Forest for anomaly detection"""
        print("\n🌳 Training Isolation Forest (Anomaly Detection)...")

        # Isolation Forest works best on normal data
        # We'll train on all data but optimize for anomaly detection
        X_combined = np.vstack([X_train, X_test])

        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_combined)
        X_test_scaled = scaler.transform(X_test)

        # Train model
        model = IsolationForest(
            n_estimators=200,
            max_samples='auto',
            contamination=0.45,  # Expected anomaly rate based on our data
            random_state=42,
            n_jobs=-1,
            verbose=1
        )

        print("   Training...")
        model.fit(X_scaled)

        # Predictions (-1 for anomalies, 1 for normal)
        y_pred_iso = model.predict(X_test_scaled)
        y_pred = np.where(y_pred_iso == -1, 1, 0)  # Convert to 0/1

        # Anomaly scores (lower = more anomalous)
        scores = model.score_samples(X_test_scaled)
        # Normalize to 0-1 (higher = more anomalous)
        y_pred_proba = 1 - ((scores - scores.min()) / (scores.max() - scores.min()))

        # Metrics
        metrics = self._calculate_metrics(y_test, y_pred, y_pred_proba, "Isolation Forest")

        # Save model
        model_path = self.output_dir / f"isolation_forest_v3_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pkl"
        joblib.dump({
            'model': model,
            'scaler': scaler,
            'metrics': metrics,
            'trained_at': datetime.now().isoformat()
        }, model_path)

        print(f"\n✅ Model saved: {model_path}")

        self.models['isolation_forest'] = model
        self.scalers['isolation_forest'] = scaler
        self.metrics['isolation_forest'] = metrics

        return model, scaler, metrics

    def _calculate_metrics(self, y_true, y_pred, y_pred_proba, model_name):
        """Calculate comprehensive metrics"""
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        try:
            auc = roc_auc_score(y_true, y_pred_proba)
        except:
            auc = 0.0

        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'auc_roc': auc,
            'false_positive_rate': fpr,
            'false_negative_rate': fnr,
            'confusion_matrix': cm.tolist(),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp)
        }

        # Print results
        print(f"\n   📊 {model_name} Performance:")
        print(f"   {'='*50}")
        print(f"   Accuracy:      {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"   Precision:     {precision:.4f} ({precision*100:.2f}%)")
        print(f"   Recall:        {recall:.4f} ({recall*100:.2f}%)")
        print(f"   F1-Score:      {f1:.4f} ({f1*100:.2f}%)")
        print(f"   AUC-ROC:       {auc:.4f}")
        print(f"   False Pos Rate: {fpr:.4f} ({fpr*100:.2f}%)")
        print(f"   False Neg Rate: {fnr:.4f} ({fnr*100:.2f}%)")
        print(f"\n   Confusion Matrix:")
        print(f"   ┌─────────────┬─────────────┐")
        print(f"   │ TN: {tn:7} │ FP: {fp:7} │")
        print(f"   ├─────────────┼─────────────┤")
        print(f"   │ FN: {fn:7} │ TP: {tp:7} │")
        print(f"   └─────────────┴─────────────┘")

        return metrics

    def generate_report(self):
        """Generate comprehensive training report"""
        print("\n" + "="*80)
        print("📋 PRODUCTION MODEL TRAINING REPORT")
        print("="*80)

        report_path = self.output_dir / f"training_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        with open(report_path, 'w') as f:
            f.write("SSH Guardian 2.0 - ML Model Training Report\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write("="*80 + "\n\n")

            for model_name, metrics in self.metrics.items():
                f.write(f"\n{model_name.upper()}\n")
                f.write("-"*80 + "\n")
                for key, value in metrics.items():
                    if key != 'confusion_matrix':
                        f.write(f"{key}: {value}\n")

                f.write("\nConfusion Matrix:\n")
                cm = metrics['confusion_matrix']
                f.write(f"[[{cm[0][0]}, {cm[0][1]}],\n")
                f.write(f" [{cm[1][0]}, {cm[1][1]}]]\n")

        print(f"\n✅ Report saved: {report_path}")

        # Print summary
        print("\n📊 MODEL COMPARISON:")
        print(f"{'Model':<20} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
        print("-"*80)
        for model_name, metrics in self.metrics.items():
            print(f"{model_name:<20} "
                  f"{metrics['accuracy']:>10.4f}  "
                  f"{metrics['precision']:>10.4f}  "
                  f"{metrics['recall']:>10.4f}  "
                  f"{metrics['f1_score']:>10.4f}")

    def close(self):
        if self.connection:
            self.connection.close()

def main():
    print("="*80)
    print("🛡️  SSH GUARDIAN 2.0 - PRODUCTION ML TRAINING")
    print("="*80)

    trainer = ProductionModelTrainer()

    # Connect to database
    if not trainer.connect_db():
        sys.exit(1)

    # Load data
    events = trainer.load_training_data()

    # Extract features
    X, y = trainer.extract_features_and_labels(events)

    # Split data (80/20)
    print("\n📂 Splitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   Training set: {X_train.shape[0]:,} samples")
    print(f"   Test set: {X_test.shape[0]:,} samples")

    # Train Random Forest
    trainer.train_random_forest(X_train, X_test, y_train, y_test)

    # Train Isolation Forest
    trainer.train_isolation_forest(X_train, X_test, y_test)

    # Generate report
    trainer.generate_report()

    # Close connection
    trainer.close()

    print("\n✅ Production model training complete!")
    print(f"📁 Models saved to: {trainer.output_dir}")
    print("\n🎓 Models are ready for deployment!")

if __name__ == "__main__":
    main()
