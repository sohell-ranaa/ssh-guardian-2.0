"""
Intelligent Event Classifier
Determines threat severity and appropriate actions
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat severity levels"""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ActionType(Enum):
    """Recommended actions"""
    ALLOW = "allow"
    LOG = "log_and_monitor"
    RATE_LIMIT = "rate_limit"
    TEMPORARY_BLOCK = "temporary_block"
    IMMEDIATE_BLOCK = "immediate_block"

@dataclass
class ThreatClassification:
    """Classification result"""
    threat_level: ThreatLevel
    risk_score: int
    primary_action: ActionType
    block_duration_hours: int = 0
    alert_priority: str = "none"  # none, low, medium, high, critical
    reasons: List[str] = None
    confidence: float = 0.0

    def __post_init__(self):
        if self.reasons is None:
            self.reasons = []

class IntelligentEventClassifier:
    """
    Multi-layered threat classification system
    Combines ML predictions with rule-based logic
    """

    # Risk score thresholds
    THRESHOLDS = {
        ThreatLevel.CRITICAL: 90,
        ThreatLevel.HIGH: 75,
        ThreatLevel.MEDIUM: 60,
        ThreatLevel.LOW: 40,
        ThreatLevel.CLEAN: 0
    }

    # Threat type base scores
    THREAT_TYPE_SCORES = {
        'intrusion': 95,
        'successful_breach': 95,
        'brute_force': 80,
        'distributed_attack': 85,
        'reconnaissance': 60,
        'slow_scan': 55,
        'credential_stuffing': 75,
        'failed_auth': 30,
        'normal': 10
    }

    # Risk modifiers
    RISK_MODIFIERS = {
        # IP reputation
        'malicious_ip': +15,
        'suspicious_ip': +10,
        'tor_exit': +10,
        'unknown_location': +5,

        # Geographic
        'high_risk_country': +10,
        'impossible_travel': +20,

        # Behavioral
        'rapid_attempts': +20,
        'multiple_servers': +15,
        'multiple_usernames': +10,
        'successful_after_failures': +25,
        'off_hours_access': +5,

        # Credentials
        'suspicious_username': +10,
        'root_or_admin': +5,
        'sequential_usernames': +15,

        # Patterns
        'distributed_pattern': +20,
        'coordinated_attack': +25,

        # History
        'repeat_offender': +15,
        'escalating_behavior': +10
    }

    # Whitelisted IP patterns
    WHITELIST_PATTERNS = [
        '192.168.',  # Private networks
        '10.',       # Private networks
        '172.16.',   # Private networks
        # Add your office/VPN IPs here
    ]

    def __init__(self, whitelist_ips: List[str] = None):
        self.whitelist = set(whitelist_ips or [])
        self.statistics = {
            'total_classified': 0,
            'by_threat_level': {},
            'by_action': {},
            'whitelisted_count': 0
        }

    def classify_event(self, event: Dict, ml_prediction: Dict,
                       threat_intel: Dict = None) -> ThreatClassification:
        """
        Classify an event and determine appropriate action

        Args:
            event: The SSH event
            ml_prediction: ML model prediction with confidence
            threat_intel: Optional threat intelligence data

        Returns:
            ThreatClassification with threat level and recommended action
        """

        # Check whitelist first
        source_ip = event.get('source_ip', '')
        if self._is_whitelisted(source_ip):
            self.statistics['whitelisted_count'] += 1
            return ThreatClassification(
                threat_level=ThreatLevel.CLEAN,
                risk_score=0,
                primary_action=ActionType.ALLOW,
                alert_priority="none",
                reasons=["Whitelisted IP"],
                confidence=1.0
            )

        # Calculate base risk score
        base_score = ml_prediction.get('risk_score', 0)
        threat_type = ml_prediction.get('threat_type', 'unknown')
        ml_confidence = ml_prediction.get('confidence', 0.5)

        # Start with threat type base score if higher
        if threat_type in self.THREAT_TYPE_SCORES:
            base_score = max(base_score, self.THREAT_TYPE_SCORES[threat_type])

        # Apply modifiers
        risk_score, reasons = self._apply_risk_modifiers(
            base_score, event, threat_intel
        )

        # Determine threat level
        threat_level = self._get_threat_level(risk_score)

        # Determine action and alert priority
        action, block_duration, alert_priority = self._determine_action(
            threat_level, risk_score, threat_type, event
        )

        # Update statistics
        self.statistics['total_classified'] += 1
        self.statistics['by_threat_level'][threat_level.value] = \
            self.statistics['by_threat_level'].get(threat_level.value, 0) + 1
        self.statistics['by_action'][action.value] = \
            self.statistics['by_action'].get(action.value, 0) + 1

        return ThreatClassification(
            threat_level=threat_level,
            risk_score=risk_score,
            primary_action=action,
            block_duration_hours=block_duration,
            alert_priority=alert_priority,
            reasons=reasons,
            confidence=ml_confidence
        )

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        if ip in self.whitelist:
            return True

        for pattern in self.WHITELIST_PATTERNS:
            if ip.startswith(pattern):
                return True

        return False

    def _apply_risk_modifiers(self, base_score: int, event: Dict,
                              threat_intel: Dict = None) -> Tuple[int, List[str]]:
        """Apply risk modifiers based on event characteristics"""
        score = base_score
        reasons = []

        # IP reputation
        ip_reputation = event.get('ip_reputation', 'unknown')
        if ip_reputation == 'malicious':
            score += self.RISK_MODIFIERS['malicious_ip']
            reasons.append("Known malicious IP")
        elif ip_reputation == 'suspicious':
            score += self.RISK_MODIFIERS['suspicious_ip']
            reasons.append("Suspicious IP reputation")

        # Geographic
        country = event.get('country', '')
        high_risk_countries = {'CN', 'RU', 'KP', 'IR', 'VN', 'PK'}
        if country in high_risk_countries:
            score += self.RISK_MODIFIERS['high_risk_country']
            reasons.append(f"High-risk country: {country}")

        if country == 'Unknown':
            score += self.RISK_MODIFIERS['unknown_location']
            reasons.append("Unknown geographic location")

        # Username analysis
        username = event.get('username', '').lower()
        suspicious_usernames = {
            'root', 'admin', 'administrator', 'test', 'guest'
        }
        if username in suspicious_usernames:
            score += self.RISK_MODIFIERS['root_or_admin']
            reasons.append(f"Suspicious username: {username}")

        # Sequential username pattern (user1, user2, etc.)
        if username and username[:-1].isalpha() and username[-1].isdigit():
            score += self.RISK_MODIFIERS['sequential_usernames']
            reasons.append("Sequential username pattern detected")

        # Event type specific
        event_type = event.get('event_type', '')

        # Successful login after failures
        if 'success' in event_type or 'accepted' in event_type:
            if ip_reputation in ['malicious', 'suspicious']:
                score += self.RISK_MODIFIERS['successful_after_failures']
                reasons.append("Successful login from suspicious IP")

        # Time-based (off-hours)
        if 'timestamp' in event:
            timestamp = event['timestamp']
            hour = timestamp.hour if hasattr(timestamp, 'hour') else 12
            if hour < 6 or hour > 22:  # Outside 6am-10pm
                score += self.RISK_MODIFIERS['off_hours_access']
                reasons.append("Off-hours access attempt")

        # Threat intel data
        if threat_intel:
            if threat_intel.get('is_tor_exit'):
                score += self.RISK_MODIFIERS['tor_exit']
                reasons.append("Tor exit node")

            if threat_intel.get('impossible_travel'):
                score += self.RISK_MODIFIERS['impossible_travel']
                reasons.append("Impossible travel detected")

            if threat_intel.get('multiple_servers_targeted', 0) > 3:
                score += self.RISK_MODIFIERS['multiple_servers']
                reasons.append(f"Multiple servers targeted ({threat_intel['multiple_servers_targeted']})")

            if threat_intel.get('rapid_attempts'):
                score += self.RISK_MODIFIERS['rapid_attempts']
                reasons.append("Rapid succession attempts")

        # Normalize to 0-100
        score = min(100, max(0, score))

        return score, reasons

    def _get_threat_level(self, risk_score: int) -> ThreatLevel:
        """Determine threat level from risk score"""
        if risk_score >= self.THRESHOLDS[ThreatLevel.CRITICAL]:
            return ThreatLevel.CRITICAL
        elif risk_score >= self.THRESHOLDS[ThreatLevel.HIGH]:
            return ThreatLevel.HIGH
        elif risk_score >= self.THRESHOLDS[ThreatLevel.MEDIUM]:
            return ThreatLevel.MEDIUM
        elif risk_score >= self.THRESHOLDS[ThreatLevel.LOW]:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.CLEAN

    def _determine_action(self, threat_level: ThreatLevel, risk_score: int,
                         threat_type: str, event: Dict) -> Tuple[ActionType, int, str]:
        """
        Determine action, block duration, and alert priority

        Returns:
            (action_type, block_duration_hours, alert_priority)
        """

        # CRITICAL: Immediate block
        if threat_level == ThreatLevel.CRITICAL:
            # Longer blocks for breaches
            if threat_type in ['intrusion', 'successful_breach']:
                return ActionType.IMMEDIATE_BLOCK, 30 * 24, "critical"  # 30 days
            else:
                return ActionType.IMMEDIATE_BLOCK, 7 * 24, "critical"  # 7 days

        # HIGH: Temporary block
        elif threat_level == ThreatLevel.HIGH:
            if risk_score >= 85:
                return ActionType.IMMEDIATE_BLOCK, 7 * 24, "high"  # 7 days
            else:
                return ActionType.TEMPORARY_BLOCK, 24, "high"  # 1 day

        # MEDIUM: Rate limiting
        elif threat_level == ThreatLevel.MEDIUM:
            return ActionType.RATE_LIMIT, 0, "medium"

        # LOW: Monitor
        elif threat_level == ThreatLevel.LOW:
            return ActionType.LOG, 0, "low"

        # CLEAN: Allow
        else:
            return ActionType.ALLOW, 0, "none"

    def get_block_recommendation(self, classification: ThreatClassification) -> Dict:
        """Get blocking recommendation details"""
        if classification.primary_action in [ActionType.IMMEDIATE_BLOCK,
                                             ActionType.TEMPORARY_BLOCK]:
            return {
                'should_block': True,
                'duration_hours': classification.block_duration_hours,
                'reason': '; '.join(classification.reasons),
                'threat_level': classification.threat_level.value,
                'risk_score': classification.risk_score
            }
        else:
            return {
                'should_block': False,
                'reason': 'Risk level below blocking threshold'
            }

    def should_send_alert(self, classification: ThreatClassification) -> bool:
        """Determine if Telegram alert should be sent"""
        return classification.alert_priority in ['medium', 'high', 'critical']

    def get_statistics(self) -> Dict:
        """Get classification statistics"""
        return {
            **self.statistics,
            'total_blocked': sum(
                self.statistics['by_action'].get(action, 0)
                for action in ['temporary_block', 'immediate_block']
            ),
            'total_monitored': self.statistics['by_action'].get('log_and_monitor', 0),
            'block_rate': (
                sum(self.statistics['by_action'].get(action, 0)
                    for action in ['temporary_block', 'immediate_block'])
                / max(1, self.statistics['total_classified'])
            )
        }

    def reset_statistics(self):
        """Reset statistics counters"""
        self.statistics = {
            'total_classified': 0,
            'by_threat_level': {},
            'by_action': {},
            'whitelisted_count': 0
        }
