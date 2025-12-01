import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib
import json
from datetime import datetime

def load_realistic_dataset():
    """Load realistic dataset"""
    print("🔄 Loading realistic SSH dataset...")
    
    with open("data/training_datasets/realistic_ssh_20k.json", 'r') as f:
        events = json.load(f)
    
    print(f"✅ Loaded {len(events):,} realistic events")
    
    df = pd.DataFrame(events)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    print(f"📊 Target distribution: {df['is_suspicious'].value_counts().to_dict()}")
    return df

def extract_features(df):
    """Extract features from realistic dataset"""
    print("🔧 Extracting features...")
    
    # Get frequency features
    ip_counts = df['source_ip'].value_counts().to_dict()
    user_counts = df['username'].value_counts().to_dict()
    
    features = []
    for idx, event in df.iterrows():
        timestamp = event['timestamp']
        
        feature_row = {
            # Time features
            'hour': timestamp.hour,
            'day_of_week': timestamp.weekday(),
            'is_weekend': 1 if timestamp.weekday() >= 5 else 0,
            'is_night': 1 if timestamp.hour < 6 or timestamp.hour > 22 else 0,
            'is_business_hours': 1 if 9 <= timestamp.hour <= 17 else 0,
            
            # Event type features  
            'is_failed_login': 1 if 'failed' in str(event['event_type']).lower() else 0,
            'is_invalid_user': 1 if 'invalid' in str(event['event_type']).lower() else 0,
            'is_successful': 1 if 'accepted' in str(event['event_type']).lower() else 0,
            
            # Behavioral features
            'ip_frequency': ip_counts.get(event['source_ip'], 1),
            'user_frequency': user_counts.get(event['username'], 1),
            
            # Geographic features
            'is_suspicious_country': 1 if event['location_country'] in ['China', 'Russia', 'Unknown'] else 0,
            
            # Port features
            'is_standard_port': 1 if event['port'] == 22 else 0,
            
            # Risk indicators
            'event_risk_score': (
                3 if 'failed' in str(event['event_type']).lower() else
                4 if 'invalid' in str(event['event_type']).lower() else 1
            ),
            
            # Interaction features  
            'failed_suspicious_country': (
                (1 if 'failed' in str(event['event_type']).lower() else 0) *
                (1 if event['location_country'] in ['China', 'Russia'] else 0)
            ),
            
            # Target
            'is_anomaly': 1 if event['is_suspicious'] else 0
        }
        features.append(feature_row)
        
        if len(features) % 2000 == 0:
            print(f"   Processed {len(features):,} / {len(df):,} events")
    
    return pd.DataFrame(features)

def train_realistic_model(df):
    """Train model on realistic data"""
    
    # Prepare features
    feature_columns = [col for col in df.columns if col != 'is_anomaly']
    X = df[feature_columns]
    y = df['is_anomaly']
    
    print(f"📈 Training with {len(X):,} samples and {len(feature_columns)} features")
    print(f"🎯 Target distribution: Normal={sum(y==0):,}, Anomaly={sum(y==1):,}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    print(f"🔀 Train: {len(X_train):,}, Test: {len(X_test):,}")
    
    # Feature scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Hyperparameter tuning
    print("🎯 Hyperparameter tuning...")
    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [10, 15, 20],
        'min_samples_split': [5, 10],
        'max_features': ['sqrt', 'log2'],
        'class_weight': ['balanced', None]
    }
    
    rf = RandomForestClassifier(random_state=42, n_jobs=-1)
    grid_search = GridSearchCV(
        rf, param_grid, 
        cv=5, 
        scoring='f1', 
        n_jobs=-1,
        verbose=1
    )
    
    grid_search.fit(X_train_scaled, y_train)
    
    # Best model
    best_model = grid_search.best_estimator_
    
    # Predictions
    y_pred = best_model.predict(X_test_scaled)
    
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
    print("🎯 REALISTIC RANDOM FOREST RESULTS")
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
    print(f"  True Neg:  {cm[0][0]:,}")
    print(f"  False Pos: {cm[0][1]:,}")
    print(f"  False Neg: {cm[1][0]:,}")
    print(f"  True Pos:  {cm[1][1]:,}")
    
    # Performance analysis
    false_positive_rate = cm[0][1] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0
    false_negative_rate = cm[1][0] / (cm[1][0] + cm[1][1]) if (cm[1][0] + cm[1][1]) > 0 else 0
    
    print(f"\n📊 Performance Analysis:")
    print(f"  False Positive Rate: {false_positive_rate:.4f} ({false_positive_rate*100:.2f}%)")
    print(f"  False Negative Rate: {false_negative_rate:.4f} ({false_negative_rate*100:.2f}%)")
    
    # Top features
    print(f"\n🔝 Top Important Features:")
    sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
    for i, (feature, importance) in enumerate(sorted_features[:8]):
        print(f"   {i+1:2d}. {feature:.<30} {importance:.4f}")
    
    # Save model and results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save model with scaler
    model_data = {
        'model': best_model,
        'scaler': scaler,
        'feature_columns': feature_columns
    }
    model_path = f"src/ml/saved_models/random_forest_realistic_{timestamp}.pkl"
    joblib.dump(model_data, model_path)
    
    # Save results
    results_data = {
        'model_type': 'RandomForest_Realistic',
        'timestamp': timestamp,
        'performance_metrics': {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm.tolist(),
            'train_size': len(X_train),
            'test_size': len(X_test),
            'total_features': len(feature_columns),
            'best_params': grid_search.best_params_,
            'false_positive_rate': false_positive_rate,
            'false_negative_rate': false_negative_rate,
            'training_time': datetime.now().isoformat()
        },
        'feature_importance': feature_importance,
        'model_path': model_path
    }
    
    results_path = f"src/ml/results/random_forest_realistic_results_{timestamp}.json"
    with open(results_path, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\n💾 Realistic model saved: {model_path}")
    print(f"📊 Results saved: {results_path}")
    
    # Expectation check
    if f1 >= 0.85:
        print(f"🎉 EXCELLENT! F1-Score {f1:.1%} exceeds 85% target!")
    elif f1 >= 0.78:
        print(f"✅ GOOD! F1-Score {f1:.1%} is improved from 78.3%!")
    else:
        print(f"⚠️  F1-Score {f1:.1%} - need more tuning")

if __name__ == "__main__":
    # Load realistic dataset
    df = load_realistic_dataset()
    
    # Extract features  
    feature_df = extract_features(df)
    
    # Train model
    train_realistic_model(feature_df)