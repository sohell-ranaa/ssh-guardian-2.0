"""
Advanced Brute Force Attack Detection System
Multiple detection strategies to catch sophisticated attacks
Designed to outperform fail2ban's simple regex matching
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
import re

logger = logging.getLogger(__name__)


class RateBasedDetector:
    """
    Detects brute force attacks based on attempt rates
    Configurable thresholds for different severity levels
    """

    def __init__(self,
                 critical_threshold: int = 10,  # attempts per minute
                 high_threshold: int = 20,      # attempts per 10 minutes
                 medium_threshold: int = 30,    # attempts per hour
                 window_minutes: int = 60):

        self.critical_threshold = critical_threshold
        self.high_threshold = high_threshold
        self.medium_threshold = medium_threshold
        self.window = timedelta(minutes=window_minutes)

        # Store attempts: {ip: [(timestamp, success)]}
        self.attempts = defaultdict(lambda: deque(maxlen=100))

    def record_attempt(self, ip: str, timestamp: datetime, success: bool):
        """Record a login attempt"""
        self.attempts[ip].append((timestamp, success))

    def analyze(self, ip: str, current_time: datetime) -> Dict:
        """
        Analyze attempt patterns for an IP

        Returns:
            Dict with detection results
        """
        if ip not in self.attempts:
            return {
                'is_brute_force': False,
                'severity': 'none',
                'reason': None,
                'risk_score': 0
            }

        # Clean old attempts
        attempts = [(ts, success) for ts, success in self.attempts[ip]
                   if current_time - ts <= self.window]

        if not attempts:
            return {
                'is_brute_force': False,
                'severity': 'none',
                'reason': None,
                'risk_score': 0
            }

        # Count attempts in different time windows
        one_min_ago = current_time - timedelta(minutes=1)
        ten_min_ago = current_time - timedelta(minutes=10)
        one_hour_ago = current_time - timedelta(hours=1)

        attempts_1min = sum(1 for ts, _ in attempts if ts > one_min_ago)
        attempts_10min = sum(1 for ts, _ in attempts if ts > ten_min_ago)
        attempts_1hour = sum(1 for ts, _ in attempts if ts > one_hour_ago)

        failed_1min = sum(1 for ts, success in attempts if ts > one_min_ago and not success)
        failed_1hour = sum(1 for ts, success in attempts if ts > one_hour_ago and not success)

        # Check thresholds
        if attempts_1min >= self.critical_threshold:
            return {
                'is_brute_force': True,
                'severity': 'critical',
                'reason': f'{attempts_1min} attempts in 1 minute',
                'attempts_1min': attempts_1min,
                'attempts_10min': attempts_10min,
                'attempts_1hour': attempts_1hour,
                'failed_rate': failed_1min / max(attempts_1min, 1),
                'risk_score': 95
            }
        elif attempts_10min >= self.high_threshold:
            return {
                'is_brute_force': True,
                'severity': 'high',
                'reason': f'{attempts_10min} attempts in 10 minutes',
                'attempts_1min': attempts_1min,
                'attempts_10min': attempts_10min,
                'attempts_1hour': attempts_1hour,
                'failed_rate': failed_1hour / max(attempts_1hour, 1),
                'risk_score': 80
            }
        elif attempts_1hour >= self.medium_threshold:
            return {
                'is_brute_force': True,
                'severity': 'medium',
                'reason': f'{attempts_1hour} attempts in 1 hour',
                'attempts_1min': attempts_1min,
                'attempts_10min': attempts_10min,
                'attempts_1hour': attempts_1hour,
                'failed_rate': failed_1hour / max(attempts_1hour, 1),
                'risk_score': 60
            }
        else:
            return {
                'is_brute_force': False,
                'severity': 'low',
                'reason': 'Below threshold',
                'attempts_1min': attempts_1min,
                'attempts_10min': attempts_10min,
                'attempts_1hour': attempts_1hour,
                'risk_score': min(50, attempts_1hour * 2)
            }


class PatternBasedDetector:
    """
    Detects patterns indicative of brute force attacks:
    - Sequential usernames (admin, admin1, admin2, ...)
    - Dictionary attacks (common usernames)
    - Password spraying (same password, many users)
    """

    COMMON_USERNAMES = {
        'root', 'admin', 'administrator', 'test', 'guest', 'user',
        'oracle', 'postgres', 'mysql', 'ubuntu', 'centos', 'debian',
        'support', 'service', 'backup', 'jenkins', 'git', 'ftp'
    }

    def __init__(self):
        self.ip_usernames = defaultdict(set)  # {ip: set(usernames)}
        self.ip_username_sequence = defaultdict(list)  # {ip: [usernames in order]}

    def record_attempt(self, ip: str, username: str, timestamp: datetime):
        """Record username attempted by IP"""
        self.ip_usernames[ip].add(username)
        self.ip_username_sequence[ip].append((timestamp, username))

        # Keep last 100 attempts
        if len(self.ip_username_sequence[ip]) > 100:
            self.ip_username_sequence[ip] = self.ip_username_sequence[ip][-100:]

    def analyze(self, ip: str) -> Dict:
        """Analyze patterns for an IP"""
        if ip not in self.ip_usernames:
            return {
                'is_pattern_attack': False,
                'patterns_detected': [],
                'risk_score': 0
            }

        usernames = self.ip_usernames[ip]
        patterns = []
        risk_score = 0

        # Check for high username diversity (credential stuffing)
        if len(usernames) > 10:
            patterns.append(f'credential_stuffing:{len(usernames)}_users')
            risk_score += min(40, len(usernames) * 2)

        # Check for common username dictionary attack
        common_count = sum(1 for u in usernames if u.lower() in self.COMMON_USERNAMES)
        if common_count > 5:
            patterns.append(f'dictionary_attack:{common_count}_common_users')
            risk_score += min(30, common_count * 3)

        # Check for sequential usernames (admin1, admin2, ...)
        if self._detect_sequential_usernames(list(usernames)):
            patterns.append('sequential_usernames')
            risk_score += 35

        # Check for invalid user pattern (testing non-existent accounts)
        # This would need to be integrated with actual user validation

        return {
            'is_pattern_attack': len(patterns) > 0,
            'patterns_detected': patterns,
            'unique_usernames': len(usernames),
            'common_usernames_tried': common_count,
            'risk_score': min(100, risk_score)
        }

    def _detect_sequential_usernames(self, usernames: List[str]) -> bool:
        """Detect sequential patterns like user1, user2, user3"""
        # Extract base names and numbers
        pattern = re.compile(r'^([a-zA-Z]+)(\d+)$')

        base_sequences = defaultdict(list)
        for username in usernames:
            match = pattern.match(username)
            if match:
                base, num = match.groups()
                base_sequences[base.lower()].append(int(num))

        # Check if any base has sequential numbers
        for base, numbers in base_sequences.items():
            if len(numbers) >= 3:
                sorted_nums = sorted(numbers)
                # Check for consecutive sequences
                for i in range(len(sorted_nums) - 2):
                    if sorted_nums[i+1] == sorted_nums[i] + 1 and sorted_nums[i+2] == sorted_nums[i] + 2:
                        return True

        return False


class DistributedAttackDetector:
    """
    Detects coordinated distributed attacks
    - Multiple IPs attacking same target
    - Coordinated timing
    - Similar patterns across IPs
    """

    def __init__(self, time_window_minutes: int = 30):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.server_attacks = defaultdict(list)  # {server: [(ip, timestamp, username)]}

    def record_attack(self, server: str, ip: str, timestamp: datetime, username: str):
        """Record a potential attack attempt"""
        self.server_attacks[server].append((ip, timestamp, username))

        # Keep only recent attempts
        cutoff = timestamp - self.time_window
        self.server_attacks[server] = [
            (i, t, u) for i, t, u in self.server_attacks[server] if t > cutoff
        ]

    def analyze(self, server: str, current_time: datetime) -> Dict:
        """Analyze if server is under distributed attack"""
        if server not in self.server_attacks:
            return {
                'is_distributed_attack': False,
                'unique_ips': 0,
                'risk_score': 0
            }

        attacks = self.server_attacks[server]

        if not attacks:
            return {
                'is_distributed_attack': False,
                'unique_ips': 0,
                'risk_score': 0
            }

        unique_ips = len(set(ip for ip, _, _ in attacks))
        unique_users = len(set(user for _, _, user in attacks))
        total_attempts = len(attacks)

        # Calculate time clustering (are attacks coordinated in time?)
        timestamps = [ts for _, ts, _ in attacks]
        if len(timestamps) > 1:
            time_spread = (max(timestamps) - min(timestamps)).total_seconds() / 60
            attempts_per_minute = total_attempts / max(time_spread, 1)
        else:
            attempts_per_minute = 0

        # Distributed attack indicators
        is_distributed = (
            unique_ips >= 5 and  # Multiple source IPs
            (unique_users > unique_ips or unique_users > 10) and  # Testing many users
            attempts_per_minute > 2  # Coordinated timing
        )

        risk_score = 0
        if is_distributed:
            risk_score = min(100, 50 + (unique_ips * 3) + (unique_users * 2))

        return {
            'is_distributed_attack': is_distributed,
            'unique_ips': unique_ips,
            'unique_users': unique_users,
            'total_attempts': total_attempts,
            'attempts_per_minute': round(attempts_per_minute, 2),
            'risk_score': risk_score
        }


class BruteForceDetectionEngine:
    """
    Unified brute force detection engine
    Combines multiple detection strategies
    """

    def __init__(self):
        self.rate_detector = RateBasedDetector()
        self.pattern_detector = PatternBasedDetector()
        self.distributed_detector = DistributedAttackDetector()

        # Detection history for trend analysis
        self.detection_history = defaultdict(list)  # {ip: [detection_results]}

    def analyze_event(self, event: Dict) -> Dict:
        """
        Analyze an SSH event for brute force indicators

        Args:
            event: Dict with keys:
                - timestamp (datetime or str)
                - source_ip (str)
                - username (str)
                - event_type (str)
                - server_hostname (str)

        Returns:
            Comprehensive brute force detection result
        """
        # Parse timestamp
        timestamp = event.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        ip = event.get('source_ip')
        username = event.get('username', '')
        event_type = event.get('event_type', '')
        server = event.get('server_hostname', 'unknown')

        # Determine if login was successful
        is_success = 'accepted' in event_type.lower()
        is_failed = 'failed' in event_type.lower() or 'invalid' in event_type.lower()

        # Record attempt in all detectors
        self.rate_detector.record_attempt(ip, timestamp, is_success)

        if username:  # Only record if username present
            self.pattern_detector.record_attempt(ip, username, timestamp)

        if is_failed:  # Only record failures for distributed detection
            self.distributed_detector.record_attack(server, ip, timestamp, username)

        # Run all detection strategies
        rate_result = self.rate_detector.analyze(ip, timestamp)
        pattern_result = self.pattern_detector.analyze(ip)
        distributed_result = self.distributed_detector.analyze(server, timestamp)

        # Combine results
        combined = {
            'ip': ip,
            'timestamp': timestamp.isoformat(),
            'detection_strategies': {
                'rate_based': rate_result,
                'pattern_based': pattern_result,
                'distributed': distributed_result
            },
            'is_brute_force_attack': (
                rate_result.get('is_brute_force', False) or
                pattern_result.get('is_pattern_attack', False) or
                distributed_result.get('is_distributed_attack', False)
            ),
            'combined_risk_score': 0,
            'severity': 'none',
            'attack_types': [],
            'recommendations': []
        }

        # Calculate combined risk score
        scores = [
            rate_result.get('risk_score', 0),
            pattern_result.get('risk_score', 0),
            distributed_result.get('risk_score', 0)
        ]
        combined['combined_risk_score'] = int(max(scores) * 0.7 + (sum(scores) / len(scores)) * 0.3)

        # Determine severity
        score = combined['combined_risk_score']
        if score >= 90:
            combined['severity'] = 'critical'
        elif score >= 70:
            combined['severity'] = 'high'
        elif score >= 50:
            combined['severity'] = 'medium'
        elif score >= 30:
            combined['severity'] = 'low'

        # Identify attack types
        if rate_result.get('is_brute_force'):
            combined['attack_types'].append(f"rate_based_{rate_result['severity']}")
        if pattern_result.get('is_pattern_attack'):
            combined['attack_types'].extend(pattern_result['patterns_detected'])
        if distributed_result.get('is_distributed_attack'):
            combined['attack_types'].append('distributed_attack')

        # Generate recommendations
        if combined['severity'] in ['critical', 'high']:
            combined['recommendations'].append('IMMEDIATE: Block this IP')
            combined['recommendations'].append('Alert security team')
        elif combined['severity'] == 'medium':
            combined['recommendations'].append('Consider temporary block')
            combined['recommendations'].append('Increase monitoring')
        else:
            combined['recommendations'].append('Continue monitoring')

        # Store in history
        self.detection_history[ip].append({
            'timestamp': timestamp,
            'severity': combined['severity'],
            'score': combined['combined_risk_score']
        })

        # Keep last 50 detections per IP
        if len(self.detection_history[ip]) > 50:
            self.detection_history[ip] = self.detection_history[ip][-50:]

        return combined

    def get_statistics(self) -> Dict:
        """Get overall detection statistics"""
        total_ips = len(self.detection_history)
        active_attacks = sum(
            1 for ip, history in self.detection_history.items()
            if history and history[-1]['severity'] in ['critical', 'high']
        )

        return {
            'total_ips_tracked': total_ips,
            'active_high_severity_attacks': active_attacks,
            'rate_detector_ips': len(self.rate_detector.attempts),
            'pattern_detector_ips': len(self.pattern_detector.ip_usernames),
            'servers_monitored': len(self.distributed_detector.server_attacks)
        }


if __name__ == "__main__":
    # Test the brute force detection engine
    logging.basicConfig(level=logging.INFO)

    engine = BruteForceDetectionEngine()

    print("=" * 80)
    print("BRUTE FORCE DETECTION ENGINE - TEST")
    print("=" * 80)

    # Simulate a brute force attack
    base_time = datetime.now()
    attacker_ip = "185.220.101.1"

    print("\n📍 Simulating brute force attack...")
    print(f"   Attacker IP: {attacker_ip}")
    print(f"   Pattern: 15 rapid failed attempts with different usernames\n")

    usernames = ['root', 'admin', 'user', 'test', 'admin1', 'admin2', 'admin3',
                 'oracle', 'postgres', 'mysql', 'backup', 'support', 'guest',
                 'administrator', 'jenkins']

    for i, username in enumerate(usernames):
        event = {
            'timestamp': base_time + timedelta(seconds=i*5),
            'source_ip': attacker_ip,
            'username': username,
            'event_type': 'failed_password',
            'server_hostname': 'web-server-1'
        }

        result = engine.analyze_event(event)

        if i == 0 or i == len(usernames) - 1:  # Show first and last
            print(f"Attempt {i+1}/{len(usernames)}:")
            print(f"  Is Brute Force: {result['is_brute_force_attack']}")
            print(f"  Severity: {result['severity']}")
            print(f"  Risk Score: {result['combined_risk_score']}/100")
            print(f"  Attack Types: {result['attack_types']}")
            print(f"  Recommendations: {result['recommendations']}")
            print()

    # Final statistics
    stats = engine.get_statistics()
    print("\n📊 DETECTION STATISTICS:")
    for key, value in stats.items():
        print(f"   {key}: {value}")

    print("\n" + "=" * 80)
