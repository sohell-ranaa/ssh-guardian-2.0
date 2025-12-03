"""
SSH Guardian 2.0 - Unified Engine
Integrates all detection and response capabilities
"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import sys

# Add paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "src"))

# Import all modules
from intelligence.unified_threat_intel import UnifiedThreatIntelligence
from ml.advanced_features import AdvancedFeatureExtractor
from ml.model_manager import MLModelManager
from detection.brute_force_detector import BruteForceDetectionEngine
from response.ip_blocker import IPBlocker

logger = logging.getLogger(__name__)


class GuardianEngine:
    """
    Unified SSH Guardian Engine
    Coordinates all security analysis and response capabilities
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Guardian Engine

        Args:
            config: Configuration dict with keys:
                - threat_feeds_dir: Path to local threat feeds
                - api_cache_dir: Path for API cache
                - api_config: Dict with API keys
                - block_state_file: Path for IP blocker state
                - whitelist_file: Path to IP whitelist
                - enable_auto_block: Bool, enable automatic blocking
                - auto_block_threshold: Int, risk score threshold for auto-block
        """
        self.config = config
        self.enable_auto_block = config.get('enable_auto_block', True)
        self.auto_block_threshold = config.get('auto_block_threshold', 85)

        logger.info("=" * 80)
        logger.info("🛡️  SSH GUARDIAN 2.0 ENGINE - INITIALIZING")
        logger.info("=" * 80)

        # Initialize threat intelligence
        logger.info("📡 Initializing Threat Intelligence...")
        self.threat_intel = UnifiedThreatIntelligence(
            threat_feeds_dir=Path(config['threat_feeds_dir']),
            api_cache_dir=Path(config['api_cache_dir']),
            api_config=config.get('api_config', {})
        )

        # Initialize advanced features
        logger.info("🧠 Initializing Advanced Feature Extraction...")
        self.feature_extractor = AdvancedFeatureExtractor()

        # Initialize ML models
        logger.info("🤖 Initializing ML Models...")
        models_dir = Path(config.get('models_dir', PROJECT_ROOT / "src" / "ml" / "saved_models"))
        self.ml_manager = MLModelManager(models_dir)
        model_info = self.ml_manager.get_model_info()
        if model_info['models_loaded'] > 0:
            logger.info(f"   ✅ Loaded {model_info['models_loaded']} ML model(s)")
        else:
            logger.warning("   ⚠️  No ML models found, using heuristic scoring only")

        # Initialize brute force detector
        logger.info("🔍 Initializing Brute Force Detection...")
        self.brute_force_detector = BruteForceDetectionEngine()

        # Initialize IP blocker
        logger.info("🚫 Initializing IP Blocking System...")
        self.ip_blocker = IPBlocker(
            state_file=Path(config['block_state_file']),
            whitelist_file=Path(config.get('whitelist_file')) if config.get('whitelist_file') else None
        )

        # Statistics
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'ips_blocked': 0,
            'impossible_travel_detected': 0,
            'brute_force_detected': 0
        }

        logger.info("✅ SSH Guardian Engine Initialized Successfully")
        logger.info("=" * 80)

    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on an SSH event

        Args:
            event: SSH event dict with keys:
                - timestamp: datetime or str
                - source_ip: str
                - username: str
                - event_type: str (accepted_password, failed_password, etc.)
                - server_hostname: str
                - geoip: dict (optional, will be added if missing)

        Returns:
            Comprehensive analysis result with all detections and recommendations
        """
        self.stats['events_processed'] += 1

        # Parse timestamp
        timestamp = event.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
            event['timestamp'] = timestamp

        ip = event.get('source_ip')
        username = event.get('username', '')

        # Initialize result
        result = {
            'event': event,
            'timestamp': timestamp.isoformat(),
            'ip': ip,
            'username': username,
            'analysis': {
                'threat_intelligence': None,
                'advanced_features': None,
                'brute_force_detection': None
            },
            'overall_risk_score': 0,
            'threat_level': 'unknown',
            'is_threat': False,
            'recommendations': [],
            'actions_taken': []
        }

        try:
            # 1. Threat Intelligence Check
            logger.debug(f"Analyzing IP: {ip}")
            threat_result = self.threat_intel.check_ip_reputation(ip, use_apis=True)
            result['analysis']['threat_intelligence'] = threat_result

            # 2. Advanced Feature Extraction
            logger.debug(f"Extracting advanced features for {username}@{ip}")
            features = self.feature_extractor.extract_features(event)
            result['analysis']['advanced_features'] = features

            # Check for impossible travel
            if features['travel_features'].get('is_impossible'):
                self.stats['impossible_travel_detected'] += 1
                result['recommendations'].append('ALERT: Impossible travel detected!')

            # 3. Brute Force Detection
            logger.debug(f"Checking for brute force patterns")
            brute_force_result = self.brute_force_detector.analyze_event(event)
            result['analysis']['brute_force_detection'] = brute_force_result

            if brute_force_result['is_brute_force_attack']:
                self.stats['brute_force_detected'] += 1

            # 4. ML Prediction
            logger.debug(f"Running ML prediction")
            ml_result = self.ml_manager.ensemble_predict(event)
            result['analysis']['ml_prediction'] = ml_result

            # Add ML score to overall calculation if available
            if ml_result.get('ml_available'):
                logger.debug(f"ML Risk Score: {ml_result['risk_score']}/100")

            # 4. Calculate Overall Risk Score
            result['overall_risk_score'] = self._calculate_overall_risk(result['analysis'])

            # 5. Determine Threat Level
            score = result['overall_risk_score']
            if score >= 90:
                result['threat_level'] = 'critical'
                result['is_threat'] = True
            elif score >= 70:
                result['threat_level'] = 'high'
                result['is_threat'] = True
            elif score >= 50:
                result['threat_level'] = 'medium'
                result['is_threat'] = True
            elif score >= 30:
                result['threat_level'] = 'low'
            else:
                result['threat_level'] = 'clean'

            # 6. Generate Recommendations
            result['recommendations'].extend(self._generate_recommendations(result))

            # 7. Automated Response
            if self.enable_auto_block and score >= self.auto_block_threshold:
                action = self._auto_block_ip(ip, result)
                if action:
                    result['actions_taken'].append(action)

            # 8. Update statistics
            if result['is_threat']:
                self.stats['threats_detected'] += 1

            logger.info(
                f"Event analyzed: {ip} | Risk: {score}/100 | "
                f"Level: {result['threat_level']} | "
                f"Threat: {result['is_threat']}"
            )

            return result

        except Exception as e:
            logger.error(f"Error analyzing event: {e}", exc_info=True)
            result['error'] = str(e)
            return result

    def _calculate_overall_risk(self, analysis: Dict) -> int:
        """Calculate overall risk score from all analysis components"""
        scores = []

        # Threat intelligence score
        threat_intel = analysis.get('threat_intelligence', {})
        if threat_intel:
            scores.append(threat_intel.get('combined_score', 0))

        # Advanced features composite score
        advanced_features = analysis.get('advanced_features', {})
        if advanced_features:
            scores.append(advanced_features.get('composite_risk_score', 0))

        # Brute force detection score
        brute_force = analysis.get('brute_force_detection', {})
        if brute_force:
            scores.append(brute_force.get('combined_risk_score', 0))

        # ML prediction score (if available)
        ml_prediction = analysis.get('ml_prediction', {})
        if ml_prediction and ml_prediction.get('ml_available'):
            ml_score = ml_prediction.get('risk_score', 0)
            # Weight ML score higher if confidence is high
            confidence = ml_prediction.get('confidence', 0.5)
            weighted_ml_score = int(ml_score * (0.7 + (confidence * 0.3)))
            scores.append(weighted_ml_score)

        if not scores:
            return 0

        # Weighted calculation: highest score gets 50%, average gets 50%
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        overall = int((max_score * 0.5) + (avg_score * 0.5))

        return min(100, max(0, overall))

    def _generate_recommendations(self, result: Dict) -> list:
        """Generate actionable recommendations based on analysis"""
        recommendations = []

        score = result['overall_risk_score']
        analysis = result['analysis']

        # High-priority recommendations
        if score >= 90:
            recommendations.append("🚨 CRITICAL: Immediate action required")
            recommendations.append("Block IP immediately")
            recommendations.append("Investigate all activity from this IP")
            recommendations.append("Alert security team")

        elif score >= 70:
            recommendations.append("⚠️  HIGH RISK: Urgent attention needed")
            recommendations.append("Consider blocking this IP")
            recommendations.append("Review logs for this IP")

        elif score >= 50:
            recommendations.append("⚡ MEDIUM RISK: Monitor closely")
            recommendations.append("Increase monitoring for this IP")

        # Specific recommendations based on detections
        brute_force = analysis.get('brute_force_detection', {})
        if brute_force and brute_force.get('is_brute_force_attack'):
            attack_types = brute_force.get('attack_types', [])
            if 'credential_stuffing' in str(attack_types):
                recommendations.append("Credential stuffing attack detected")
            if 'dictionary_attack' in str(attack_types):
                recommendations.append("Dictionary attack in progress")
            if 'distributed_attack' in str(attack_types):
                recommendations.append("Coordinated distributed attack")

        features = analysis.get('advanced_features', {})
        if features:
            travel = features.get('travel_features', {})
            if travel.get('is_impossible'):
                recommendations.append(
                    f"Impossible travel: {travel.get('distance_km', 0)}km in "
                    f"{travel.get('time_diff_hours', 0)}h"
                )
                recommendations.append("Account may be compromised")

        threat_intel = analysis.get('threat_intelligence', {})
        if threat_intel and threat_intel.get('is_malicious'):
            recommendations.append("IP flagged in threat intelligence feeds")
            for threat in threat_intel.get('detailed_threats', [])[:3]:
                recommendations.append(f"  - {threat}")

        return recommendations

    def _auto_block_ip(self, ip: str, result: Dict) -> Optional[Dict]:
        """Automatically block an IP based on threat level"""
        if not self.enable_auto_block:
            return None

        threat_level = result['threat_level']
        score = result['overall_risk_score']

        # Prepare reason
        reasons = []
        analysis = result['analysis']

        if analysis.get('brute_force_detection', {}).get('is_brute_force_attack'):
            reasons.append("Brute force attack")

        if analysis.get('advanced_features', {}).get('travel_features', {}).get('is_impossible'):
            reasons.append("Impossible travel")

        if analysis.get('threat_intelligence', {}).get('is_malicious'):
            reasons.append("Malicious IP (threat intel)")

        reason = f"Auto-blocked (score: {score}): {', '.join(reasons) if reasons else 'High risk activity'}"

        # Attempt to block
        block_result = self.ip_blocker.block_ip(
            ip=ip,
            reason=reason,
            threat_level=threat_level,
            dry_run=False
        )

        if block_result['success']:
            self.stats['ips_blocked'] += 1
            logger.warning(f"🚫 AUTO-BLOCKED: {ip} | Reason: {reason}")
            return {
                'action': 'auto_block',
                'ip': ip,
                'reason': reason,
                'duration_hours': block_result['block_info']['duration_hours']
            }
        else:
            logger.error(f"Failed to auto-block {ip}: {block_result.get('reason')}")
            return None

    def cleanup(self):
        """Cleanup expired blocks and old data"""
        logger.info("Running cleanup...")
        unblocked = self.ip_blocker.cleanup_expired_blocks()
        if unblocked > 0:
            logger.info(f"Cleaned up {unblocked} expired IP blocks")

    def get_statistics(self) -> Dict:
        """Get comprehensive statistics"""
        return {
            'engine_stats': self.stats,
            'threat_intel_stats': self.threat_intel.get_statistics(),
            'brute_force_stats': self.brute_force_detector.get_statistics(),
            'blocking_stats': self.ip_blocker.get_statistics()
        }


def create_guardian_engine(config_dict: Dict) -> GuardianEngine:
    """
    Factory function to create Guardian Engine with configuration

    Args:
        config_dict: Configuration dictionary

    Returns:
        Initialized GuardianEngine instance
    """
    return GuardianEngine(config_dict)


if __name__ == "__main__":
    # Test the Guardian Engine
    logging.basicConfig(level=logging.INFO)

    print("=" * 80)
    print("🧪 TESTING GUARDIAN ENGINE")
    print("=" * 80)

    # Test configuration
    test_config = {
        'threat_feeds_dir': PROJECT_ROOT / "data" / "threat_feeds",
        'api_cache_dir': PROJECT_ROOT / "data" / "api_cache",
        'api_config': {},  # No API keys for test
        'block_state_file': PROJECT_ROOT / "data" / "blocks_state.json",
        'whitelist_file': None,
        'enable_auto_block': False,  # Disabled for test
        'auto_block_threshold': 85
    }

    engine = create_guardian_engine(test_config)

    print("\n" + "=" * 80)
    print("📍 TEST 1: Normal login from legitimate user")
    print("=" * 80)

    event1 = {
        'timestamp': datetime.now(),
        'source_ip': '8.8.8.8',  # Google DNS
        'username': 'john',
        'event_type': 'accepted_password',
        'server_hostname': 'web-server-1',
        'geoip': {'latitude': 37.4056, 'longitude': -122.0775, 'country': 'United States'}
    }

    result1 = engine.analyze_event(event1)
    print(f"\n✅ RESULT:")
    print(f"   Overall Risk: {result1['overall_risk_score']}/100")
    print(f"   Threat Level: {result1['threat_level']}")
    print(f"   Is Threat: {result1['is_threat']}")
    print(f"   Recommendations: {len(result1['recommendations'])}")

    print("\n" + "=" * 80)
    print("📍 TEST 2: Brute force attack simulation")
    print("=" * 80)

    attacker_ip = "185.220.101.1"
    base_time = datetime.now()

    # Simulate 15 rapid failed attempts
    for i in range(15):
        event = {
            'timestamp': base_time,
            'source_ip': attacker_ip,
            'username': f'admin{i}' if i < 5 else ['root', 'oracle', 'test', 'mysql', 'backup',
                                                     'administrator', 'jenkins', 'git', 'postgres', 'support'][i-5],
            'event_type': 'failed_password',
            'server_hostname': 'web-server-1',
            'geoip': {'latitude': 55.7558, 'longitude': 37.6173, 'country': 'Russia'}
        }

        result = engine.analyze_event(event)

        if i == 14:  # Show final result
            print(f"\n✅ RESULT (after {i+1} attempts):")
            print(f"   Overall Risk: {result['overall_risk_score']}/100")
            print(f"   Threat Level: {result['threat_level']}")
            print(f"   Is Threat: {result['is_threat']}")
            print(f"   Brute Force Detected: {result['analysis']['brute_force_detection']['is_brute_force_attack']}")
            print(f"\n   Top Recommendations:")
            for rec in result['recommendations'][:5]:
                print(f"     • {rec}")

    print("\n" + "=" * 80)
    print("📊 FINAL STATISTICS")
    print("=" * 80)

    stats = engine.get_statistics()
    print(f"\n   Events Processed: {stats['engine_stats']['events_processed']}")
    print(f"   Threats Detected: {stats['engine_stats']['threats_detected']}")
    print(f"   Brute Force Detected: {stats['engine_stats']['brute_force_detected']}")
    print(f"   IPs Blocked: {stats['engine_stats']['ips_blocked']}")

    print("\n" + "=" * 80)
    print("✅ GUARDIAN ENGINE TEST COMPLETED")
    print("=" * 80)
