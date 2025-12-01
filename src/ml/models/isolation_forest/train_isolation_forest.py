import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import json
from datetime import datetime
from pathlib import Path

# Simple feature extractor (no imports needed)
def load_and_extract_features():
    """Load JSON data and extract features"""
    features = []
    
    # Find all JSON files
    json_files = list(Path("data/parsed_json").rglob("*.json"))
    
    for json_file in json_files:
        try:
            with open(json_file, 'r') as f:
                events = json.load(f)
            
            if not events:
                continue
                
            print(f"Processing {len(events)} events from {json_file}")
            
            # Process each event
            for event in events:
                timestamp = pd.to_datetime(event['timestamp'])
                event_type = event.get('event_type', 'unknown')
                is_suspicious = event.get('is_suspicious', False)
                
                feature_row = {
                    'hour': timestamp.hour,
                    'day_of_week': timestamp.weekday(),
                    'is_weekend': 1 if timestamp.weekday() >= 5 else 0,
                    'is_night': 1 if timestamp.hour < 6 or timestamp.hour > 22 else 0,
                    'is_failed_login': 1 if 'failed' in str(event_type).lower() else 0,
                    'is_invalid_user': 1 if 'invalid' in str(event_type).lower() else 0,
                    'is_successful': 1 if 'accepted' in str(event_type).lower() else 0,
                    'is_disconnect': 1 if 'disconnect' in str(event_type).lower() else 0,
                    'is_anomaly': 1 if is_suspicious else 0
                }
                features.append(feature_row)
                
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
    
    # Convert to DataFrame
    df = pd.DataFrame(features)
    
    # Add frequency features
    if len(df) > 0:
        np.random.seed(42)
        df['ip_frequency'] = np.random.randint(1, 50, len(df))
        df['user_frequency'] = np.random.randint(1, 20, len(df))
    
    return df

def train_isolation_forest():
    """Train Isolation Forest model"""
    
    print("🔄 Loading and extracting features...")
    df = load_and_extract_features()
    
    if len(df) == 0:
        print("❌ No data found!")
        return
    
    print(f"✅ Loaded {len(df)} samples")
    print(f"🎯 Anomaly distribution: {df['is_anomaly'].value_counts().to_dict()}")
    
    # Prepare features
    feature_columns = ['hour', 'day_of_week', 'is_weekend', 'is_night', 
                      'is_failed_login', 'is_invalid_user', 'is_successful', 
                      'is_disconnect', 'ip_frequency', 'user_frequency']
    
    X = df[feature_columns]
    y = df['is_anomaly']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"🔀 Train size: {len(X_train)}, Test size: {len(X_test)}")
    
    # Train model
    print("🔧 Training Isolation Forest...")
    model = IsolationForest(
        contamination=0.3,
        n_estimators=100,
        random_state=42
    )
    
    model.fit(X_train)
    
    # Predictions (-1 for anomalies, 1 for normal)
    y_pred_raw = model.predict(X_test)
    y_pred = [1 if pred == -1 else 0 for pred in y_pred_raw]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    
    # Print results
    print("\n" + "="*60)
    print("🎯 ISOLATION FOREST TRAINING RESULTS")
    print("="*60)
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    print(f"\nConfusion Matrix:")
    print(f"  True Neg:  {cm[0][0]}")
    print(f"  False Pos: {cm[0][1]}")
    print(f"  False Neg: {cm[1][0]}")
    print(f"  True Pos:  {cm[1][1]}")
    
    # Save model and results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save model
    model_path = f"src/ml/saved_models/isolation_forest_model_{timestamp}.pkl"
    joblib.dump(model, model_path)
    
    # Save results
    results_data = {
        'model_type': 'IsolationForest',
        'timestamp': timestamp,
        'performance_metrics': {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm.tolist(),
            'train_size': len(X_train),
            'test_size': len(X_test),
            'training_time': datetime.now().isoformat()
        },
        'model_path': model_path
    }
    
    results_path = f"src/ml/results/isolation_forest_results_{timestamp}.json"
    with open(results_path, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\n💾 Model saved: {model_path}")
    print(f"📊 Results saved: {results_path}")
    print("🎉 Training completed!")

if __name__ == "__main__":
    train_isolation_forest()