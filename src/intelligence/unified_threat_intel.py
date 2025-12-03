"""
Unified Threat Intelligence Module
Combines local threat feeds with third-party API intelligence
Provides seamless fallback when APIs are unavailable
"""

import logging
from pathlib import Path
from typing import Dict, Set, Optional, Any
from .api_clients import ThreatIntelligenceAggregator

logger = logging.getLogger(__name__)


class UnifiedThreatIntelligence:
    """
    Unified threat intelligence combining:
    1. Local cached threat feeds (fast, offline)
    2. Third-party APIs (comprehensive, requires keys)
    3. Intelligent caching and fallback
    """

    def __init__(self, threat_feeds_dir: Path, api_cache_dir: Path, api_config: Dict[str, str]):
        """
        Initialize unified threat intelligence

        Args:
            threat_feeds_dir: Directory containing local threat feeds
            api_cache_dir: Directory for API response caching
            api_config: Dict with API keys (virustotal_api_key, abuseipdb_api_key, shodan_api_key)
        """
        self.threat_feeds_dir = threat_feeds_dir
        self.local_feeds = {}

        # Initialize API aggregator if keys are provided
        has_api_keys = any(api_config.values())
        if has_api_keys:
            self.api_aggregator = ThreatIntelligenceAggregator(api_config, api_cache_dir)
            logger.info("✅ Third-party API intelligence enabled")
        else:
            self.api_aggregator = None
            logger.warning("⚠️  No API keys configured, using local feeds only")

        # Load local feeds
        self.load_local_feeds()

    def load_local_feeds(self):
        """Load all local threat feed files"""
        if not self.threat_feeds_dir.exists():
            logger.warning(f"Threat feeds directory not found: {self.threat_feeds_dir}")
            return

        feed_files = {
            'ssh_attackers': 'ssh_attackers.txt',
            'feodo_ips': 'feodo_ips.txt',
            'tor_exits': 'tor_exits.txt'
        }

        for feed_name, filename in feed_files.items():
            feed_path = self.threat_feeds_dir / filename
            if feed_path.exists():
                try:
                    with open(feed_path, 'r') as f:
                        ips = set(line.strip() for line in f if line.strip() and not line.startswith('#'))
                    self.local_feeds[feed_name] = ips
                    logger.info(f"Loaded {len(ips)} IPs from {feed_name}")
                except Exception as e:
                    logger.error(f"Failed to load {feed_name}: {e}")
            else:
                logger.warning(f"Feed file not found: {filename}")

    def check_ip_reputation(self, ip_address: str, use_apis: bool = True) -> Dict[str, Any]:
        """
        Check IP reputation using both local feeds and APIs

        Args:
            ip_address: IP to check
            use_apis: Whether to use third-party APIs (True) or local feeds only (False)

        Returns:
            Dict with comprehensive reputation data
        """
        # Initialize result structure
        result = {
            'ip': ip_address,
            'local_feeds': self._check_local_feeds(ip_address),
            'api_intelligence': None,
            'combined_score': 0,
            'is_malicious': False,
            'threat_level': 'unknown',
            'threat_types': [],
            'detailed_threats': [],
            'recommendations': []
        }

        # Check if private IP
        if self._is_private_ip(ip_address):
            result['combined_score'] = 5
            result['threat_level'] = 'clean'
            result['detailed_threats'] = ['Private IP - Local Network']
            result['is_malicious'] = False
            return result

        # Process local feed results
        local_score = result['local_feeds']['risk_score']
        result['combined_score'] = local_score
        result['is_malicious'] = result['local_feeds']['is_malicious']
        result['threat_types'].extend(result['local_feeds']['threat_types'])
        result['detailed_threats'].extend(result['local_feeds']['detailed_threats'])

        # Query APIs if available and requested
        if use_apis and self.api_aggregator:
            try:
                api_result = self.api_aggregator.analyze_ip(ip_address)
                result['api_intelligence'] = api_result

                # Combine scores (weighted average favoring API data if available)
                api_score = api_result.get('aggregated_score', 0)

                # If API returned useful data, weight it heavily
                if api_result.get('sources'):
                    result['combined_score'] = int((api_score * 0.7) + (local_score * 0.3))
                else:
                    # API didn't return data, use local only
                    result['combined_score'] = local_score

                # Combine malicious flags
                if api_result.get('is_malicious'):
                    result['is_malicious'] = True

                # Add API-based threats
                for source_name, source_data in api_result.get('sources', {}).items():
                    if source_data.get('is_malicious'):
                        result['threat_types'].append(f"api_{source_name}")
                        result['detailed_threats'].append(
                            f"{source_name.upper()}: Risk {source_data.get('risk_score', 0)}/100"
                        )

                # Merge recommendations
                if api_result.get('recommendations'):
                    result['recommendations'].extend(api_result['recommendations'])

            except Exception as e:
                logger.error(f"API intelligence failed for {ip_address}: {e}")
                # Continue with local feeds only

        # Determine final threat level
        score = result['combined_score']
        if score >= 80:
            result['threat_level'] = 'critical'
        elif score >= 60:
            result['threat_level'] = 'high'
        elif score >= 40:
            result['threat_level'] = 'medium'
        elif score >= 20:
            result['threat_level'] = 'low'
        else:
            result['threat_level'] = 'clean'

        # Add default recommendations if none exist
        if not result['recommendations']:
            if result['threat_level'] in ['critical', 'high']:
                result['recommendations'].append('Consider blocking this IP')
            elif result['threat_level'] == 'medium':
                result['recommendations'].append('Monitor activity closely')
            else:
                result['recommendations'].append('Standard monitoring')

        return result

    def _check_local_feeds(self, ip_address: str) -> Dict[str, Any]:
        """Check IP against local threat feeds"""
        result = {
            'is_malicious': False,
            'risk_score': 20,  # Base score for external IPs
            'threat_types': [],
            'detailed_threats': [],
            'feeds_matched': []
        }

        # Check against each feed
        for feed_name, ips in self.local_feeds.items():
            if ip_address in ips:
                result['is_malicious'] = True
                result['threat_types'].append(feed_name)
                result['feeds_matched'].append(feed_name)

                # Add risk score based on feed type
                if feed_name == 'feodo_ips':
                    result['detailed_threats'].append("Feodo Tracker - Known Botnet")
                    result['risk_score'] += 40
                elif feed_name == 'ssh_attackers':
                    result['detailed_threats'].append("SSH Attacker - Brute Force Source")
                    result['risk_score'] += 35
                elif feed_name == 'tor_exits':
                    result['detailed_threats'].append("Tor Exit Node")
                    result['risk_score'] += 25
                else:
                    result['detailed_threats'].append(f"Threat Feed: {feed_name}")
                    result['risk_score'] += 30

        return result

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        return ip.startswith((
            '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '127.', 'localhost'
        ))

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about threat intelligence sources"""
        stats = {
            'local_feeds': {
                name: len(ips) for name, ips in self.local_feeds.items()
            },
            'total_local_ips': sum(len(ips) for ips in self.local_feeds.values()),
            'api_enabled': self.api_aggregator is not None
        }

        if self.api_aggregator:
            stats['api_clients'] = {
                'virustotal': self.api_aggregator.vt_client is not None,
                'abuseipdb': self.api_aggregator.abuse_client is not None,
                'shodan': self.api_aggregator.shodan_client is not None
            }

        return stats


# Backward compatible function for existing code
def check_ip_reputation_legacy(ip: str, threat_feeds_cache: Dict[str, Set[str]]) -> Dict:
    """
    Legacy function signature for backward compatibility
    Maintains exact same behavior as original implementation
    """
    reputation = {
        'is_malicious': False,
        'threat_types': [],
        'risk_score': 0,
        'detailed_threats': []
    }

    # Check for private/local IPs first
    if ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                     '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                     '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')):
        reputation['detailed_threats'] = ["Private IP - Low Risk"]
        reputation['risk_score'] = 5
        return reputation

    # Check against threat feeds
    for feed_name, ips in threat_feeds_cache.items():
        if ip in ips:
            reputation['is_malicious'] = True
            reputation['threat_types'].append(feed_name)

            if feed_name == 'feodo_ips':
                reputation['detailed_threats'].append("Feodo Tracker - Known Botnet")
                reputation['risk_score'] += 40
            elif feed_name == 'ssh_attackers':
                reputation['detailed_threats'].append("SSH Attacker - Brute Force Source")
                reputation['risk_score'] += 35
            else:
                reputation['detailed_threats'].append(f"Threat Feed: {feed_name}")
                reputation['risk_score'] += 30

    # If no threats found, it's clean
    if not reputation['detailed_threats']:
        reputation['detailed_threats'] = []
        reputation['risk_score'] = max(reputation['risk_score'], 20)

    return reputation
