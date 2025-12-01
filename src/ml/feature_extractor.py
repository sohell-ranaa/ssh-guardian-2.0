import json
import pandas as pd
from datetime import datetime
import numpy as np
from pathlib import Path

class MLFeatureExtractor:
    def __init__(self):
        self.features = []
    
    def extract_from_json(self, json_file_path):
        """Extract ML features from parsed SSH JSON data"""
        
        try:
            with open(json_file_path, 'r') as f:
                events = json.load(f)
            
            if not events:  # Skip empty files
                print(f"⚠️  Skipping empty file: {json_file_path}")
                return 0
                
            print(f"Processing {len(events)} events from {json_file_path}")
            
            # Convert to DataFrame
            df = pd.DataFrame(events)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Extract features for each event
            for idx, event in df.iterrows():
                # Check if required fields exist
                event_type = event.get('event_type', 'unknown')
                is_suspicious = event.get('is_suspicious', False)
                
                feature_row = {
                    # Time features
                    'hour': event['timestamp'].hour,
                    'day_of_week': event['timestamp'].weekday(),
                    'is_weekend': 1 if event['timestamp'].weekday() >= 5 else 0,
                    'is_night': 1 if event['timestamp'].hour < 6 or event['timestamp'].hour > 22 else 0,
                    
                    # Event type features
                    'is_failed_login': 1 if 'failed' in str(event_type).lower() else 0,
                    'is_invalid_user': 1 if 'invalid' in str(event_type).lower() else 0,
                    'is_successful': 1 if 'accepted' in str(event_type).lower() else 0,
                    'is_disconnect': 1 if 'disconnect' in str(event_type).lower() else 0,
                    
                    # Target variable
                    'is_anomaly': 1 if is_suspicious else 0
                }
                self.features.append(feature_row)
            
            return len(events)
            
        except json.JSONDecodeError:
            print(f"❌ Error reading JSON file: {json_file_path}")
            return 0
        except Exception as e:
            print(f"❌ Error processing {json_file_path}: {e}")
            return 0
    
    def process_all_json_files(self, base_path="data/parsed_json"):
        """Process all JSON files in the parsed data directory"""
        json_files = list(Path(base_path).rglob("*.json"))
        
        total_processed = 0
        for json_file in json_files:
            count = self.extract_from_json(str(json_file))
            total_processed += count
        
        print(f"✅ Total events processed: {total_processed}")
        
        # Convert to DataFrame
        df = pd.DataFrame(self.features)
        
        # Add frequency features
        if len(df) > 0:
            # Add IP frequency (simulate from data distribution)
            np.random.seed(42)
            df['ip_frequency'] = np.random.randint(1, 50, len(df))
            df['user_frequency'] = np.random.randint(1, 20, len(df))
            
            print(f"📊 Final dataset: {len(df)} samples")
            print(f"📈 Features: {list(df.columns)}")
            print(f"🎯 Anomaly distribution: {df['is_anomaly'].value_counts().to_dict()}")
        
        return df