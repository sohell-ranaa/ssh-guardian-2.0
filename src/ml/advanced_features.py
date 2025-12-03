"""
Advanced Feature Extraction for SSH Guardian 2.0
Includes: Session duration, impossible travel, behavioral patterns
Designed for real-time analysis and thesis evaluation
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from math import radians, cos, sin, asin, sqrt
import json

logger = logging.getLogger(__name__)


class SessionTracker:
    """
    Tracks SSH sessions to calculate duration and patterns
    """

    def __init__(self, max_session_age_hours: int = 24):
        self.sessions = defaultdict(dict)  # {ip: {username: session_info}}
        self.max_age = timedelta(hours=max_session_age_hours)

    def start_session(self, ip: str, username: str, timestamp: datetime, event_data: Dict):
        """Record a successful login (session start)"""
        if ip not in self.sessions:
            self.sessions[ip] = {}

        self.sessions[ip][username] = {
            'start_time': timestamp,
            'last_activity': timestamp,
            'event_count': 1,
            'location': event_data.get('geoip', {}),
            'server': event_data.get('server_hostname', 'unknown')
        }

        logger.debug(f"Session started: {username}@{ip} at {timestamp}")

    def update_activity(self, ip: str, username: str, timestamp: datetime):
        """Update last activity time for existing session"""
        if ip in self.sessions and username in self.sessions[ip]:
            self.sessions[ip][username]['last_activity'] = timestamp
            self.sessions[ip][username]['event_count'] += 1

    def end_session(self, ip: str, username: str, timestamp: datetime) -> Optional[Dict]:
        """
        End a session and return duration info
        Returns None if no active session found
        """
        if ip not in self.sessions or username not in self.sessions[ip]:
            return None

        session = self.sessions[ip][username]
        duration_seconds = (timestamp - session['start_time']).total_seconds()

        result = {
            'duration_seconds': int(duration_seconds),
            'duration_minutes': round(duration_seconds / 60, 2),
            'duration_hours': round(duration_seconds / 3600, 2),
            'event_count': session['event_count'],
            'start_time': session['start_time'].isoformat(),
            'end_time': timestamp.isoformat()
        }

        # Remove session
        del self.sessions[ip][username]
        if not self.sessions[ip]:
            del self.sessions[ip]

        return result

    def get_active_session_duration(self, ip: str, username: str, current_time: datetime) -> Optional[int]:
        """Get duration of currently active session in seconds"""
        if ip in self.sessions and username in self.sessions[ip]:
            session = self.sessions[ip][username]
            return int((current_time - session['start_time']).total_seconds())
        return None

    def cleanup_old_sessions(self, current_time: datetime):
        """Remove sessions older than max_age"""
        ips_to_remove = []

        for ip, users in self.sessions.items():
            users_to_remove = []
            for username, session in users.items():
                age = current_time - session['last_activity']
                if age > self.max_age:
                    users_to_remove.append(username)

            for username in users_to_remove:
                del users[username]

            if not users:
                ips_to_remove.append(ip)

        for ip in ips_to_remove:
            del self.sessions[ip]

        if ips_to_remove or any(users_to_remove):
            logger.debug(f"Cleaned up old sessions: {len(ips_to_remove)} IPs")


class ImpossibleTravelDetector:
    """
    Detects impossible travel patterns
    E.g., same user logging in from locations that are too far apart in too short a time
    """

    # Average commercial flight speed in km/h
    MAX_TRAVEL_SPEED_KMH = 900  # ~560 mph

    def __init__(self):
        self.user_locations = defaultdict(list)  # {username: [(timestamp, lat, lon, ip)]}

    def haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate great circle distance between two points in kilometers
        Using Haversine formula
        """
        # Convert to radians
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])

        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))

        # Radius of earth in kilometers
        r = 6371

        return c * r

    def check_impossible_travel(self, username: str, timestamp: datetime,
                               latitude: float, longitude: float, ip: str) -> Dict:
        """
        Check if this login represents impossible travel

        Returns:
            Dict with:
                - is_impossible: bool
                - distance_km: float
                - time_diff_hours: float
                - required_speed_kmh: float
                - previous_location: str
                - risk_score: int (0-100)
        """
        result = {
            'is_impossible': False,
            'distance_km': 0,
            'time_diff_hours': 0,
            'required_speed_kmh': 0,
            'previous_location': None,
            'previous_ip': None,
            'risk_score': 0
        }

        # Get user's previous locations
        if username not in self.user_locations or not self.user_locations[username]:
            # First login for this user
            self.user_locations[username].append((timestamp, latitude, longitude, ip))
            return result

        # Get most recent previous location
        prev_timestamp, prev_lat, prev_lon, prev_ip = self.user_locations[username][-1]

        # Calculate distance
        distance_km = self.haversine_distance(prev_lat, prev_lon, latitude, longitude)

        # Calculate time difference
        time_diff = timestamp - prev_timestamp
        time_diff_hours = time_diff.total_seconds() / 3600

        # Avoid division by zero
        if time_diff_hours < 0.01:  # Less than 36 seconds
            time_diff_hours = 0.01

        # Calculate required speed
        required_speed_kmh = distance_km / time_diff_hours

        # Update result
        result['distance_km'] = round(distance_km, 2)
        result['time_diff_hours'] = round(time_diff_hours, 2)
        result['required_speed_kmh'] = round(required_speed_kmh, 2)
        result['previous_location'] = f"{prev_lat},{prev_lon}"
        result['previous_ip'] = prev_ip

        # Determine if impossible
        if required_speed_kmh > self.MAX_TRAVEL_SPEED_KMH:
            result['is_impossible'] = True

            # Calculate risk score based on how impossible it is
            # More impossible = higher score
            impossibility_factor = required_speed_kmh / self.MAX_TRAVEL_SPEED_KMH
            result['risk_score'] = min(100, int(50 + (impossibility_factor * 30)))

            logger.warning(
                f"Impossible travel detected for {username}: "
                f"{distance_km}km in {time_diff_hours}h "
                f"({required_speed_kmh} km/h required)"
            )
        else:
            # Possible but suspicious if very fast
            if required_speed_kmh > 500:  # Faster than typical travel
                result['risk_score'] = min(50, int(required_speed_kmh / 20))

        # Store this location
        self.user_locations[username].append((timestamp, latitude, longitude, ip))

        # Keep only last 10 locations per user
        if len(self.user_locations[username]) > 10:
            self.user_locations[username] = self.user_locations[username][-10:]

        return result


class BehavioralPatternAnalyzer:
    """
    Analyzes user and IP behavioral patterns over time
    """

    def __init__(self, lookback_window_hours: int = 24):
        self.lookback_window = timedelta(hours=lookback_window_hours)
        self.ip_history = defaultdict(list)  # {ip: [events]}
        self.user_history = defaultdict(list)  # {username: [events]}

    def record_event(self, event: Dict):
        """Record an event for pattern analysis"""
        ip = event.get('source_ip')
        username = event.get('username')
        timestamp = event.get('timestamp')

        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        event_record = {
            'timestamp': timestamp,
            'event_type': event.get('event_type'),
            'username': username,
            'ip': ip,
            'server': event.get('server_hostname'),
            'success': 'accepted' in event.get('event_type', '').lower()
        }

        self.ip_history[ip].append(event_record)
        self.user_history[username].append(event_record)

        # Keep history manageable
        self._cleanup_old_events(ip, username, timestamp)

    def _cleanup_old_events(self, ip: str, username: str, current_time: datetime):
        """Remove events outside lookback window"""
        cutoff_time = current_time - self.lookback_window

        # Clean IP history
        self.ip_history[ip] = [
            e for e in self.ip_history[ip] if e['timestamp'] > cutoff_time
        ]

        # Clean user history
        self.user_history[username] = [
            e for e in self.user_history[username] if e['timestamp'] > cutoff_time
        ]

    def analyze_ip_behavior(self, ip: str, current_time: datetime) -> Dict:
        """Analyze IP's behavioral patterns"""
        events = self.ip_history.get(ip, [])

        if not events:
            return {
                'total_attempts': 0,
                'successful_logins': 0,
                'failed_attempts': 0,
                'success_rate': 0,
                'unique_users': 0,
                'unique_servers': 0,
                'attempts_per_hour': 0,
                'is_rapid_fire': False,
                'is_distributed': False,
                'risk_score': 0
            }

        # Calculate metrics
        total_attempts = len(events)
        successful = sum(1 for e in events if e['success'])
        failed = total_attempts - successful
        success_rate = successful / total_attempts if total_attempts > 0 else 0

        unique_users = len(set(e['username'] for e in events if e['username']))
        unique_servers = len(set(e['server'] for e in events if e['server']))

        # Calculate velocity
        if events:
            time_span = (current_time - events[0]['timestamp']).total_seconds() / 3600
            attempts_per_hour = total_attempts / max(time_span, 0.1)
        else:
            attempts_per_hour = 0

        # Detect patterns
        is_rapid_fire = attempts_per_hour > 10
        is_distributed = unique_servers > 3  # Attacking multiple servers

        # Calculate risk score
        risk_score = 0
        if is_rapid_fire:
            risk_score += 30
        if unique_users > 10:  # Trying many users
            risk_score += 25
        if success_rate < 0.1 and total_attempts > 5:  # High failure rate
            risk_score += 20
        if is_distributed:
            risk_score += 15

        return {
            'total_attempts': total_attempts,
            'successful_logins': successful,
            'failed_attempts': failed,
            'success_rate': round(success_rate, 3),
            'unique_users': unique_users,
            'unique_servers': unique_servers,
            'attempts_per_hour': round(attempts_per_hour, 2),
            'is_rapid_fire': is_rapid_fire,
            'is_distributed': is_distributed,
            'risk_score': min(100, risk_score)
        }

    def analyze_user_behavior(self, username: str, current_time: datetime) -> Dict:
        """Analyze user's behavioral patterns"""
        events = self.user_history.get(username, [])

        if not events:
            return {
                'total_logins': 0,
                'successful_logins': 0,
                'success_rate': 0,
                'unique_ips': 0,
                'unique_servers': 0,
                'is_legitimate': False,
                'risk_score': 100  # Unknown user = suspicious
            }

        total_logins = len(events)
        successful = sum(1 for e in events if e['success'])
        success_rate = successful / total_logins if total_logins > 0 else 0

        unique_ips = len(set(e['ip'] for e in events if e['ip']))
        unique_servers = len(set(e['server'] for e in events if e['server']))

        # Determine if legitimate
        # Legitimate users typically have:
        # - Multiple successful logins
        # - High success rate
        # - Low IP diversity (unless traveling)
        is_legitimate = (
            successful >= 3 and
            success_rate > 0.7 and
            unique_ips < 10
        )

        # Calculate risk score
        risk_score = 50  # Start neutral
        if is_legitimate:
            risk_score -= 30
        if success_rate > 0.8:
            risk_score -= 10
        if unique_ips > 20:  # Too many IPs
            risk_score += 25
        if successful == 0 and total_logins > 3:  # All failures
            risk_score += 30

        return {
            'total_logins': total_logins,
            'successful_logins': successful,
            'success_rate': round(success_rate, 3),
            'unique_ips': unique_ips,
            'unique_servers': unique_servers,
            'is_legitimate': is_legitimate,
            'risk_score': max(0, min(100, risk_score))
        }


class AdvancedFeatureExtractor:
    """
    Combines all advanced feature extraction capabilities
    Designed for real-time use in SSH Guardian
    """

    def __init__(self):
        self.session_tracker = SessionTracker()
        self.travel_detector = ImpossibleTravelDetector()
        self.behavior_analyzer = BehavioralPatternAnalyzer()

    def extract_features(self, event: Dict) -> Dict:
        """
        Extract all advanced features from an SSH event

        Args:
            event: SSH event dict with keys like:
                - timestamp
                - source_ip
                - username
                - event_type
                - geoip (with latitude, longitude)
                - server_hostname

        Returns:
            Dict with advanced features
        """
        timestamp = event.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        ip = event.get('source_ip')
        username = event.get('username')
        event_type = event.get('event_type', '')

        features = {
            'session_features': {},
            'travel_features': {},
            'ip_behavior': {},
            'user_behavior': {},
            'composite_risk_score': 0
        }

        # 1. Session features
        if 'accepted' in event_type.lower():
            self.session_tracker.start_session(ip, username, timestamp, event)
            active_duration = self.session_tracker.get_active_session_duration(ip, username, timestamp)
            features['session_features'] = {
                'has_active_session': True,
                'session_duration_seconds': active_duration or 0
            }
        elif 'disconnect' in event_type.lower() or 'closed' in event_type.lower():
            session_info = self.session_tracker.end_session(ip, username, timestamp)
            features['session_features'] = session_info or {'has_active_session': False}
        else:
            active_duration = self.session_tracker.get_active_session_duration(ip, username, timestamp)
            features['session_features'] = {
                'has_active_session': active_duration is not None,
                'session_duration_seconds': active_duration or 0
            }

        # 2. Impossible travel detection
        geoip = event.get('geoip', {})
        latitude = geoip.get('latitude')
        longitude = geoip.get('longitude')

        if latitude is not None and longitude is not None:
            travel_result = self.travel_detector.check_impossible_travel(
                username, timestamp, latitude, longitude, ip
            )
            features['travel_features'] = travel_result
        else:
            features['travel_features'] = {
                'is_impossible': False,
                'risk_score': 0,
                'distance_km': 0
            }

        # 3. Record event for behavioral analysis
        self.behavior_analyzer.record_event(event)

        # 4. IP behavioral analysis
        features['ip_behavior'] = self.behavior_analyzer.analyze_ip_behavior(ip, timestamp)

        # 5. User behavioral analysis
        features['user_behavior'] = self.behavior_analyzer.analyze_user_behavior(username, timestamp)

        # 6. Calculate composite risk score
        features['composite_risk_score'] = self._calculate_composite_risk(features)

        return features

    def _calculate_composite_risk(self, features: Dict) -> int:
        """Calculate overall risk score from all features"""
        scores = [
            features['travel_features'].get('risk_score', 0),
            features['ip_behavior'].get('risk_score', 0),
            features['user_behavior'].get('risk_score', 0)
        ]

        # Weighted average with bias towards highest risk
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)

        composite = int((max_score * 0.6) + (avg_score * 0.4))

        return min(100, max(0, composite))


# Convenience function for integration
def extract_advanced_features(event: Dict, feature_extractor: AdvancedFeatureExtractor = None) -> Dict:
    """
    Standalone function for extracting advanced features
    Can be called with or without an existing extractor instance
    """
    if feature_extractor is None:
        feature_extractor = AdvancedFeatureExtractor()

    return feature_extractor.extract_features(event)


if __name__ == "__main__":
    # Test the advanced feature extractor
    logging.basicConfig(level=logging.DEBUG)

    extractor = AdvancedFeatureExtractor()

    # Test event 1: Normal login from USA
    event1 = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': '1.2.3.4',
        'username': 'john',
        'event_type': 'accepted_password',
        'server_hostname': 'web-server-1',
        'geoip': {'latitude': 40.7128, 'longitude': -74.0060}  # New York
    }

    features1 = extractor.extract_features(event1)
    print("Test 1 - Normal Login:")
    print(json.dumps(features1, indent=2))

    # Test event 2: Same user from China 5 minutes later (impossible travel!)
    event2 = {
        'timestamp': (datetime.now() + timedelta(minutes=5)).isoformat(),
        'source_ip': '5.6.7.8',
        'username': 'john',
        'event_type': 'accepted_password',
        'server_hostname': 'web-server-1',
        'geoip': {'latitude': 39.9042, 'longitude': 116.4074}  # Beijing
    }

    features2 = extractor.extract_features(event2)
    print("\nTest 2 - Impossible Travel:")
    print(json.dumps(features2, indent=2))
