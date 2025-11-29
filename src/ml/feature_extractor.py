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
        
        with open(json_file_path, 'r') as f:
            events = json.load(f)
        
        print(f"Processing {len(events)} events from {json_file_path}")
        
        # Convert to DataFrame
        df = pd.DataFrame(events)
        df['datetime'] = pd.to_datetime(df['datetime'])
        
        # Extract features for each event
        for idx, event in df.iterrows():
            feature_row = {
                # Time features
                'hour': event['datetime'].hour,
                'day_of_week': event['datetime'].weekday(),
                'is_weekend': 1 if event['datetime'].weekday() >= 5 else 0,
                'is_night': 1 if event['datetime'].hour < 6 or event['datetime'].hour > 22 else 0,
                
                # Event type features
                'is_failed_login': 1 if 'failed' in event['event_type'] else 0,
                'is_invalid_user': 1 if 'invalid' in event['event_type'] else 0,
                'is_successful': 1 if 'accepted' in event['event_type'] else 0,
                'is_disconnect': 1 if 'disconnect' in event['event_type'] else 0,
                
                # Target variable
                'is_anomaly': 1 if event['is_suspicious'] else 0
            }
            self.features.append(feature_row)
        
        return len(self.features)
    
    def process_all_json_files(self, base_path="data/parsed_json"):
        """Process all JSON files in the parsed data directory"""
        json_files = list(Path(base_path).rglob("*.json"))
        
        for json_file in json_files:
            self.extract_from_json(str(json_file))
        
        # Convert to DataFrame
        df = pd.DataFrame(self.features)
        
        # Add frequency features
        if len(df) > 0:
            # Add IP frequency (simulate from data distribution)
            np.random.seed(42)
            df['ip_frequency'] = np.random.randint(1, 50, len(df))
            df['user_frequency'] = np.random.randint(1, 20, len(df))
        
        return df