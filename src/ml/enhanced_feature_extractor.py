"""
Enhanced Feature Extractor for SSH Guardian ML Models
Extracts 35+ features for high-accuracy threat detection
"""

import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)

class EnhancedFeatureExtractor:
    """
    Extracts comprehensive features from SSH events for ML prediction
    """

    def __init__(self):
        # Track historical patterns per IP
        self.ip_history = defaultdict(lambda: {
            'failed_attempts': [],
            'successful_logins': [],
            'unique_usernames': set(),
            'unique_servers': set(),
            'first_seen': None,
            'last_seen': None,
            'locations': []
        })

        # High-risk indicators
        self.malicious_usernames = {
            'root', 'admin', 'test', 'guest', 'oracle', 'postgres',
            'mysql', 'admin123', 'administrator', 'user', 'ftpuser'
        }

        self.high_risk_countries = {
            'CN', 'RU', 'KP', 'IR', 'VN', 'UA', 'PK'
        }

    def extract_features(self, event: Dict, context: Dict = None) -> np.array:
        """
        Extract 35 features from an SSH event

        Returns:
            numpy array of shape (35,)
        """
        features = []
        ip = event.get('source_ip', '')

        # === TEMPORAL FEATURES (5) ===
        timestamp = event.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        features.append(timestamp.hour)  # 0-23
        features.append(timestamp.weekday())  # 0-6
        features.append(1 if 9 <= timestamp.hour <= 17 else 0)  # business hours
        features.append(1 if timestamp.weekday() < 5 else 0)  # weekday
        features.append(timestamp.minute)

        # === EVENT TYPE FEATURES (4) ===
        event_type = event.get('event_type', 'unknown')
        features.append(1 if 'failed' in event_type else 0)
        features.append(1 if 'success' in event_type or 'accepted' in event_type else 0)
        features.append(1 if event.get('failure_reason') == 'invalid_user' else 0)
        features.append(1 if event.get('failure_reason') == 'invalid_password' else 0)

        # === GEOGRAPHIC FEATURES (5) ===
        country = event.get('country', 'Unknown')
        features.append(1 if country in self.high_risk_countries else 0)
        features.append(1 if country == 'Unknown' else 0)
        features.append(event.get('latitude', 0.0) if event.get('latitude') else 0.0)
        features.append(event.get('longitude', 0.0) if event.get('longitude') else 0.0)

        # Distance from previous location (impossible travel)
        prev_loc = self.ip_history[ip].get('last_location')
        if prev_loc and event.get('latitude') and event.get('longitude'):
            distance = self._haversine_distance(
                prev_loc[0], prev_loc[1],
                event['latitude'], event['longitude']
            )
            features.append(distance)
        else:
            features.append(0.0)

        # === USERNAME FEATURES (4) ===
        username = event.get('username', '')
        features.append(1 if username in self.malicious_usernames else 0)
        features.append(len(username))
        features.append(self._calculate_entropy(username))
        features.append(1 if username.isdigit() else 0)

        # === IP BEHAVIOR FEATURES (8) ===
        history = self.ip_history[ip]

        # Failed attempts in last hour
        recent_fails = [t for t in history['failed_attempts']
                       if (timestamp - t).total_seconds() < 3600]
        features.append(len(recent_fails))

        # Failed attempts in last 10 minutes
        very_recent_fails = [t for t in history['failed_attempts']
                            if (timestamp - t).total_seconds() < 600]
        features.append(len(very_recent_fails))

        # Success rate (if any history)
        total_attempts = len(history['failed_attempts']) + len(history['successful_logins'])
        if total_attempts > 0:
            success_rate = len(history['successful_logins']) / total_attempts
        else:
            success_rate = 0.0
        features.append(success_rate)

        # Unique usernames tried
        features.append(len(history['unique_usernames']))

        # Unique servers targeted
        features.append(len(history['unique_servers']))

        # Time since first seen (in hours)
        if history['first_seen']:
            hours_since_first = (timestamp - history['first_seen']).total_seconds() / 3600
            features.append(hours_since_first)
        else:
            features.append(0.0)

        # Average time between attempts
        if len(history['failed_attempts']) > 1:
            times = sorted(history['failed_attempts'])
            intervals = [(times[i] - times[i-1]).total_seconds()
                        for i in range(1, len(times))]
            avg_interval = np.mean(intervals) if intervals else 0
            features.append(avg_interval)
        else:
            features.append(0.0)

        # Attempts per minute (rate)
        if len(very_recent_fails) > 0:
            rate = len(very_recent_fails) / 10.0  # per minute
        else:
            rate = 0.0
        features.append(rate)

        # === REPUTATION FEATURES (3) ===
        ip_reputation = event.get('ip_reputation', 'unknown')
        features.append(1 if ip_reputation == 'malicious' else 0)
        features.append(1 if ip_reputation == 'suspicious' else 0)
        features.append(1 if ip_reputation == 'clean' else 0)

        # === RISK SCORE FEATURES (2) ===
        features.append(event.get('ip_risk_score', 0))
        features.append(event.get('ml_risk_score', 0))

        # === SESSION FEATURES (2) ===
        port = event.get('port', 22)
        features.append(1 if port != 22 else 0)  # non-standard port
        session_duration = event.get('session_duration', 0)
        features.append(session_duration / 3600.0 if session_duration else 0.0)  # hours

        # === PATTERN FEATURES (2) ===
        # Sequential username pattern (user1, user2, user3)
        features.append(1 if username and username[:-1].isalpha() and username[-1].isdigit() else 0)

        # Multiple failed attempts from same IP to different servers (distributed)
        if len(history['unique_servers']) > 3 and len(recent_fails) > 5:
            features.append(1)
        else:
            features.append(0)

        # Update history
        self._update_history(ip, event, timestamp)

        # Ensure we have exactly 35 features
        assert len(features) == 35, f"Expected 35 features, got {len(features)}"

        return np.array(features, dtype=np.float32)

    def extract_batch(self, events: List[Dict]) -> np.array:
        """Extract features for multiple events"""
        return np.array([self.extract_features(event) for event in events])

    def get_feature_names(self) -> List[str]:
        """Return list of feature names"""
        return [
            # Temporal (5)
            'hour', 'weekday', 'is_business_hours', 'is_weekday', 'minute',

            # Event type (4)
            'is_failed', 'is_successful', 'is_invalid_user', 'is_invalid_password',

            # Geographic (5)
            'is_high_risk_country', 'is_unknown_country', 'latitude', 'longitude',
            'distance_from_previous',

            # Username (4)
            'is_malicious_username', 'username_length', 'username_entropy',
            'username_is_numeric',

            # IP behavior (8)
            'failed_attempts_last_hour', 'failed_attempts_last_10min',
            'success_rate', 'unique_usernames_tried', 'unique_servers_targeted',
            'hours_since_first_seen', 'avg_time_between_attempts',
            'attempts_per_minute',

            # Reputation (3)
            'is_malicious_ip', 'is_suspicious_ip', 'is_clean_ip',

            # Risk scores (2)
            'ip_risk_score', 'ml_risk_score',

            # Session (2)
            'is_non_standard_port', 'session_duration_hours',

            # Patterns (2)
            'is_sequential_username', 'is_distributed_attack'
        ]

    def _update_history(self, ip: str, event: Dict, timestamp: datetime):
        """Update historical tracking for an IP"""
        history = self.ip_history[ip]

        # Update timestamps
        if not history['first_seen']:
            history['first_seen'] = timestamp
        history['last_seen'] = timestamp

        # Track attempts
        if 'failed' in event.get('event_type', ''):
            history['failed_attempts'].append(timestamp)
            # Keep only last 24 hours
            cutoff = timestamp - timedelta(hours=24)
            history['failed_attempts'] = [t for t in history['failed_attempts'] if t > cutoff]
        elif 'success' in event.get('event_type', '') or 'accepted' in event.get('event_type', ''):
            history['successful_logins'].append(timestamp)
            history['successful_logins'] = [t for t in history['successful_logins']
                                           if t > timestamp - timedelta(hours=24)]

        # Track unique attributes
        username = event.get('username')
        if username:
            history['unique_usernames'].add(username)

        server = event.get('server_hostname')
        if server:
            history['unique_servers'].add(server)

        # Track location
        if event.get('latitude') and event.get('longitude'):
            history['last_location'] = (event['latitude'], event['longitude'])
            history['locations'].append({
                'lat': event['latitude'],
                'lon': event['longitude'],
                'time': timestamp
            })

    def _haversine_distance(self, lat1: float, lon1: float,
                           lat2: float, lon2: float) -> float:
        """Calculate distance between two points in km"""
        from math import radians, sin, cos, sqrt, asin

        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        return 6371 * c  # Earth radius in km

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0

        from collections import Counter
        from math import log2

        counts = Counter(text)
        length = len(text)

        entropy = -sum((count/length) * log2(count/length)
                      for count in counts.values())

        return entropy

    def reset_history(self):
        """Reset IP history (useful for batch processing)"""
        self.ip_history.clear()

    def get_statistics(self) -> Dict:
        """Get statistics about tracked IPs"""
        return {
            'total_ips_tracked': len(self.ip_history),
            'ips_with_failures': sum(1 for h in self.ip_history.values()
                                    if h['failed_attempts']),
            'ips_with_successes': sum(1 for h in self.ip_history.values()
                                     if h['successful_logins']),
            'most_active_ip': max(self.ip_history.items(),
                                 key=lambda x: len(x[1]['failed_attempts']),
                                 default=(None, None))[0]
        }
