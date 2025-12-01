import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler
import joblib
import json
from datetime import datetime
import sys
import os

# Import our improved feature extractor
sys.path.append('/home/rana-workspace/ssh_guardian_2.0/src')
from ml.improved_feature_extractor import ImprovedFeatureExtractor

def train_improved_model():
    """Train model with improved features that reduce false positives"""
    
    print("🚀 Training IMPROVED Random Forest Model")
    print("   Goal: Reduce false positives while maintaining detection accuracy")
    print("="*80)
    
    # Extract improved features
    extractor = ImprovedFeatureExtractor()
    df = extractor.load_data_and_extract_features()
    
    # Prepare features
    feature_columns = [col for col in df.columns if col != 'is_anomaly']
    X = df[feature_columns]
    y = df['is_anomaly']
    
    print(f"\n📈 Training Configuration:")
    print(f"   Total samples: {len(X):,}")
    print(f"   Features: {len(feature_columns)}")
    print(f"   Normal events: {sum(y==0):,} ({sum(y==0)/len(y)*100:.1f}%)")
    print(f"   Anomaly events: {sum(y==1):,} ({sum(y==1)/len(y)*100:.1f}%)")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    print(f"\n🔀 Data Split:")
    print(f"   Train: {len(X_train):,} samples")
    print(f"   Test: {len(X_test):,} samples")
    
    # Feature scaling
    print("📏 Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Hyperparameter tuning focused on reducing false positives
    print("🎯 Hyperparameter tuning (optimized for low false positives)...")
    param_grid = {
        'n_estimators': [200, 300, 400],
        'max_depth': [12, 15, 18],
        'min_samples_split': [10, 15, 20],  # Higher values reduce overfitting
        'min_samples_leaf': [5, 8, 10],     # Higher values reduce overfitting
        'max_features': ['sqrt'],
        'class_weight': ['balanced']
    }
    
    # Use precision as primary metric to minimize false positives
    rf = RandomForestClassifier(random_state=42, n_jobs=-1)
    grid_search = GridSearchCV(
        rf, param_grid, 
        cv=5, 
        scoring='precision',  # Focus on precision (low false positives)
        n_jobs=-1,
        verbose=1
    )
    
    grid_search.fit(X_train_scaled, y_train)
    
    # Best model
    best_model = grid_search.best_estimator_
    
    print("🔮 Making predictions...")
    y_pred = best_model.predict(X_test_scaled)
    y_pred_proba = best_model.predict_proba(X_test_scaled)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    
    # Feature importance
    feature_importance = dict(zip(feature_columns, best_model.feature_importances_))
    
    # Print results
    print("\n" + "="*80)
    print("🎯 IMPROVED RANDOM FOREST RESULTS")
    print("="*80)
    print(f"Training samples: {len(X_train):,}")
    print(f"Test samples: {len(X_test):,}")
    print(f"Total features: {len(feature_columns)}")
    print(f"Best Parameters: {grid_search.best_params_}")
    print()
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    
    print(f"\nConfusion Matrix:")
    print(f"  True Neg:  {cm[0][0]:,} (Correctly identified normal)")
    print(f"  False Pos: {cm[0][1]:,} (False alarms - want this LOW)")
    print(f"  False Neg: {cm[1][0]:,} (Missed attacks)")
    print(f"  True Pos:  {cm[1][1]:,} (Correctly caught attacks)")
    
    # Performance analysis
    false_positive_rate = cm[0][1] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0
    false_negative_rate = cm[1][0] / (cm[1][0] + cm[1][1]) if (cm[1][0] + cm[1][1]) > 0 else 0
    
    print(f"\n📊 Performance Analysis:")
    print(f"  False Positive Rate: {false_positive_rate:.4f} ({false_positive_rate*100:.2f}%) - Target: <5%")
    print(f"  False Negative Rate: {false_negative_rate:.4f} ({false_negative_rate*100:.2f}%) - Target: <15%")
    
    # Top features
    print(f"\n🔝 Top 10 Important Features:")
    sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
    for i, (feature, importance) in enumerate(sorted_features[:10]):
        print(f"   {i+1:2d}. {feature:.<35} {importance:.4f}")
    
    # Performance evaluation
    print(f"\n📈 Model Quality Assessment:")
    if false_positive_rate <= 0.05:
        print("   ✅ EXCELLENT: False positive rate ≤ 5%")
    elif false_positive_rate <= 0.10:
        print("   ⚠️  GOOD: False positive rate ≤ 10%")
    else:
        print("   ❌ NEEDS WORK: False positive rate > 10%")
    
    if precision >= 0.85:
        print("   ✅ EXCELLENT: High precision (low false alarms)")
    elif precision >= 0.75:
        print("   ⚠️  GOOD: Moderate precision")
    else:
        print("   ❌ NEEDS WORK: Low precision (too many false alarms)")
    
    if recall >= 0.80:
        print("   ✅ EXCELLENT: High recall (catches most attacks)")
    elif recall >= 0.70:
        print("   ⚠️  GOOD: Moderate recall")
    else:
        print("   ❌ NEEDS WORK: Low recall (misses too many attacks)")
    
    # Save model and results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save model with scaler and feature columns
    model_data = {
        'model': best_model,
        'scaler': scaler,
        'feature_columns': feature_columns,
        'feature_extractor_class': 'ImprovedFeatureExtractor'
    }
    model_path = f"src/ml/saved_models/random_forest_improved_{timestamp}.pkl"
    joblib.dump(model_data, model_path)
    
    # Save results
    results_data = {
        'model_type': 'RandomForest_Improved',
        'timestamp': timestamp,
        'performance_metrics': {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm.tolist(),
            'false_positive_rate': false_positive_rate,
            'false_negative_rate': false_negative_rate,
            'train_size': len(X_train),
            'test_size': len(X_test),
            'total_features': len(feature_columns),
            'best_params': grid_search.best_params_,
            'training_time': datetime.now().isoformat()
        },
        'feature_importance': feature_importance,
        'model_path': model_path
    }
    
    results_path = f"src/ml/results/random_forest_improved_results_{timestamp}.json"
    with open(results_path, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\n💾 Improved model saved: {model_path}")
    print(f"📊 Results saved: {results_path}")
    
    # Success criteria
    success_criteria = [
        f1 >= 0.85,
        precision >= 0.85,
        false_positive_rate <= 0.05
    ]
    
    if all(success_criteria):
        print("\n🎉 EXCELLENT! Model meets all success criteria!")
        print("   ✅ F1-Score ≥ 85%")
        print("   ✅ Precision ≥ 85%") 
        print("   ✅ False Positive Rate ≤ 5%")
    else:
        print("\n⚠️  Model performance needs improvement:")
        if f1 < 0.85:
            print(f"   ❌ F1-Score {f1:.1%} < 85% target")
        if precision < 0.85:
            print(f"   ❌ Precision {precision:.1%} < 85% target")
        if false_positive_rate > 0.05:
            print(f"   ❌ False Positive Rate {false_positive_rate:.1%} > 5% target")

if __name__ == "__main__":
    train_improved_model()