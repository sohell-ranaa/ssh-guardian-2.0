import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
import ipaddress
import json
from pathlib import Path

class ImprovedFeatureExtractor:
    def __init__(self):
        self.ip_history = defaultdict(list)
        self.user_history = defaultdict(list)
        self.country_risk_scores = {
            'China': 8, 'Russia': 8, 'North Korea': 10, 'Iran': 9,
            'United States': 2, 'Canada': 2, 'United Kingdom': 2, 
            'Germany': 2, 'Australia': 2, 'Unknown': 7
        }
        
    def load_data_and_extract_features(self, dataset_path="data/training_datasets/realistic_ssh_20k.json"):
        """Load dataset and extract improved features"""
        
        print("🔄 Loading realistic dataset...")
        with open(dataset_path, 'r') as f:
            events = json.load(f)
        
        print(f"✅ Loaded {len(events):,} events")
        
        # Convert to DataFrame
        df = pd.DataFrame(events)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp').reset_index(drop=True)
        
        print("🔧 Extracting improved features...")
        
        features = []
        
        for idx, event in df.iterrows():
            timestamp = event['timestamp']
            source_ip = event['source_ip']
            username = event['username']
            event_type = str(event.get('event_type', '')).lower()
            location_country = event.get('location_country', 'Unknown')
            
            # Update histories
            self.update_histories(timestamp, source_ip, username, event_type)
            
            # Get behavior patterns
            ip_events = [e for e in self.ip_history[source_ip] if e['timestamp'] <= timestamp]
            user_events = [e for e in self.user_history[username] if e['timestamp'] <= timestamp]
            
            # TIME FEATURES
            hour = timestamp.hour
            day_of_week = timestamp.weekday()
            is_weekend = 1 if day_of_week >= 5 else 0
            is_night = 1 if hour < 6 or hour > 22 else 0
            is_business_hours = 1 if 9 <= hour <= 17 and not is_weekend else 0
            
            # IMPROVED BEHAVIORAL FEATURES
            
            # 1. Recent failure analysis (last 10 minutes)
            recent_events = [e for e in ip_events if e['timestamp'] > timestamp - timedelta(minutes=10)]
            recent_failures = [e for e in recent_events if 'failed' in e['event_type']]
            recent_attempts = len(recent_events)
            recent_failure_rate = len(recent_failures) / max(len(recent_events), 1)
            
            # 2. Historical success rate (last 24 hours)
            day_events = [e for e in ip_events if e['timestamp'] > timestamp - timedelta(hours=24)]
            day_successes = [e for e in day_events if 'accepted' in e['event_type']]
            historical_success_rate = len(day_successes) / max(len(day_events), 1)
            
            # 3. User legitimacy indicators
            user_total_attempts = len(user_events)
            user_success_count = len([e for e in user_events if 'accepted' in e['event_type']])
            user_success_rate = user_success_count / max(user_total_attempts, 1)
            user_has_recent_success = any('accepted' in e['event_type'] for e in user_events[-5:])
            
            # 4. IP reputation indicators
            is_private_ip = self.is_private_ip(source_ip)
            ip_user_diversity = len(set(e['username'] for e in ip_events[-20:]))
            ip_total_attempts = len(ip_events)
            
            # 5. Velocity analysis
            minute_events = [e for e in ip_events if e['timestamp'] > timestamp - timedelta(minutes=1)]
            hour_events = [e for e in ip_events if e['timestamp'] > timestamp - timedelta(hours=1)]
            attempts_per_minute = len(minute_events)
            attempts_per_hour = len(hour_events)
            
            # 6. Geographic analysis
            country_risk = self.country_risk_scores.get(location_country, 5)
            is_high_risk_country = 1 if country_risk >= 7 else 0
            is_local_network = 1 if is_private_ip else 0
            
            # EVENT TYPE FEATURES
            is_failed_login = 1 if 'failed' in event_type else 0
            is_invalid_user = 1 if 'invalid' in event_type else 0
            is_successful = 1 if 'accepted' in event_type else 0
            is_disconnect = 1 if 'disconnect' in event_type else 0
            
            # COMPOSITE RISK INDICATORS
            rapid_fire_attack = 1 if attempts_per_minute > 5 else 0
            persistent_attack = 1 if attempts_per_hour > 20 and recent_failure_rate > 0.8 else 0
            credential_stuffing = 1 if (ip_user_diversity > 5 and recent_failure_rate > 0.9) else 0
            new_ip_suspicious = 1 if (ip_total_attempts < 3 and is_failed_login and not is_private_ip) else 0
            
            # IMPROVED ANOMALY LABELING (realistic thresholds)
            is_anomaly = self.determine_improved_anomaly(
                is_invalid_user, rapid_fire_attack, persistent_attack, 
                credential_stuffing, new_ip_suspicious, is_high_risk_country,
                is_private_ip, user_has_recent_success, recent_failure_rate,
                attempts_per_minute, attempts_per_hour
            )
            
            feature_row = {
                # Time features
                'hour': hour,
                'day_of_week': day_of_week,
                'is_weekend': is_weekend,
                'is_night': is_night,
                'is_business_hours': is_business_hours,
                
                # Improved behavioral features
                'recent_attempts': min(recent_attempts, 20),
                'recent_failure_rate': recent_failure_rate,
                'historical_success_rate': historical_success_rate,
                'user_success_rate': user_success_rate,
                'user_has_recent_success': 1 if user_has_recent_success else 0,
                'ip_user_diversity': min(ip_user_diversity, 10),
                'attempts_per_minute': min(attempts_per_minute, 30),
                'attempts_per_hour': min(attempts_per_hour, 100),
                
                # Geographic features
                'country_risk': country_risk,
                'is_high_risk_country': is_high_risk_country,
                'is_local_network': is_local_network,
                
                # Event type features
                'is_failed_login': is_failed_login,
                'is_invalid_user': is_invalid_user,
                'is_successful': is_successful,
                'is_disconnect': is_disconnect,
                
                # Composite indicators
                'rapid_fire_attack': rapid_fire_attack,
                'persistent_attack': persistent_attack,
                'credential_stuffing': credential_stuffing,
                'new_ip_suspicious': new_ip_suspicious,
                
                # Target
                'is_anomaly': is_anomaly
            }
            
            features.append(feature_row)
            
            # Progress indicator
            if (idx + 1) % 2000 == 0:
                print(f"   Processed {idx + 1:,} / {len(df):,} events")
        
        feature_df = pd.DataFrame(features)
        
        print(f"✅ Extracted {len(feature_df.columns)-1} features from {len(feature_df):,} events")
        print(f"📊 Anomaly distribution: {feature_df['is_anomaly'].value_counts().to_dict()}")
        
        return feature_df
    
    def update_histories(self, timestamp, source_ip, username, event_type):
        """Update IP and user histories"""
        self.ip_history[source_ip].append({
            'timestamp': timestamp,
            'event_type': event_type,
            'username': username
        })
        
        self.user_history[username].append({
            'timestamp': timestamp,
            'event_type': event_type,
            'source_ip': source_ip
        })
    
    def is_private_ip(self, ip_str):
        """Check if IP is private"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return ip.is_private
        except:
            return False
    
    def determine_improved_anomaly(self, is_invalid_user, rapid_fire_attack, 
                                 persistent_attack, credential_stuffing, 
                                 new_ip_suspicious, is_high_risk_country,
                                 is_private_ip, user_has_recent_success, 
                                 recent_failure_rate, attempts_per_minute, 
                                 attempts_per_hour):
        """
        Improved anomaly detection with realistic thresholds
        This reduces false positives significantly
        """
        
        # CLEAR ATTACKS (always anomaly)
        if is_invalid_user:
            return True
        
        if rapid_fire_attack:  # >5 attempts per minute
            return True
        
        if persistent_attack:  # >20 attempts/hour with >80% failures
            return True
        
        if credential_stuffing:  # Many users, high failure rate
            return True
        
        if new_ip_suspicious and is_high_risk_country:
            return True
        
        # LEGITIMATE SCENARIOS (not anomaly)
        if is_private_ip and attempts_per_minute <= 2:
            return False  # Local network, reasonable attempts
        
        if user_has_recent_success and attempts_per_minute <= 1:
            return False  # Known user, single attempt
        
        if recent_failure_rate <= 0.3 and attempts_per_hour <= 5:
            return False  # Low failure rate, few attempts
        
        # MODERATE RISK (use stricter thresholds)
        if attempts_per_hour > 10 and recent_failure_rate > 0.7:
            return True
        
        if is_high_risk_country and attempts_per_hour > 3 and recent_failure_rate > 0.6:
            return True
        
        # Default to not anomaly (conservative approach)
        return False

if __name__ == "__main__":
    # Test the improved feature extractor
    extractor = ImprovedFeatureExtractor()
    feature_df = extractor.load_data_and_extract_features()
    
    print(f"\n📊 Feature Summary:")
    print(f"Total samples: {len(feature_df):,}")
    print(f"Features: {len(feature_df.columns)-1}")
    print(f"Anomaly rate: {feature_df['is_anomaly'].mean()*100:.1f}%")
    
    # Show feature names
    feature_cols = [col for col in feature_df.columns if col != 'is_anomaly']
    print(f"\nFeatures: {feature_cols}")