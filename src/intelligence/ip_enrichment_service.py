"""
IP Enrichment Service
Coordinates multiple threat intelligence sources to provide comprehensive IP analysis
"""

import logging
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class IPEnrichmentService:
    """
    Unified service for IP threat intelligence
    Aggregates data from multiple sources: VirusTotal, Shodan, AbuseIPDB
    """

    def __init__(self,
                 virustotal_api_key: Optional[str] = None,
                 shodan_api_key: Optional[str] = None,
                 abuseipdb_api_key: Optional[str] = None,
                 cache_dir = None):
        """
        Initialize IP enrichment service with multiple intelligence sources

        Args:
            virustotal_api_key: VirusTotal API key (optional)
            shodan_api_key: Shodan API key (optional)
            abuseipdb_api_key: AbuseIPDB API key (optional)
            cache_dir: Directory for caching API responses (Path or str)
        """
        # Handle both Path and str for cache_dir
        if cache_dir is None:
            self.cache_dir = Path('/tmp/ssh_guardian/intel_cache')
        elif isinstance(cache_dir, str):
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Store API keys
        self.api_keys = {
            'virustotal': virustotal_api_key,
            'shodan': shodan_api_key,
            'abuseipdb': abuseipdb_api_key
        }

        # Initialize clients (will be done in substeps 2-4)
        self.virustotal_client = None
        self.shodan_client = None
        self.abuseipdb_client = None

        # Track which services are available
        self.available_services = []

        logger.info(f"IPEnrichmentService initialized with cache at {self.cache_dir}")

    def _init_clients(self):
        """
        Initialize API clients (lazy initialization)
        Called when first lookup is performed
        """
        if self.virustotal_client is None and self.api_keys['virustotal']:
            try:
                from .virustotal_client import VirusTotalClient
                self.virustotal_client = VirusTotalClient(
                    api_key=self.api_keys['virustotal'],
                    cache_dir=self.cache_dir / 'virustotal'
                )
                self.available_services.append('virustotal')
                logger.info("✓ VirusTotal client initialized")
            except Exception as e:
                logger.warning(f"Could not initialize VirusTotal client: {e}")

        if self.shodan_client is None and self.api_keys['shodan']:
            try:
                from .shodan_client import ShodanClient
                self.shodan_client = ShodanClient(
                    api_key=self.api_keys['shodan'],
                    cache_dir=self.cache_dir / 'shodan'
                )
                self.available_services.append('shodan')
                logger.info("✓ Shodan client initialized")
            except Exception as e:
                logger.warning(f"Could not initialize Shodan client: {e}")

        if self.abuseipdb_client is None and self.api_keys['abuseipdb']:
            try:
                from .abuseipdb_client import AbuseIPDBClient
                self.abuseipdb_client = AbuseIPDBClient(
                    api_key=self.api_keys['abuseipdb'],
                    cache_dir=self.cache_dir / 'abuseipdb'
                )
                self.available_services.append('abuseipdb')
                logger.info("✓ AbuseIPDB client initialized")
            except Exception as e:
                logger.warning(f"Could not initialize AbuseIPDB client: {e}")

    def lookup_ip(self, ip_address: str, use_cache: bool = True) -> Dict:
        """
        Perform comprehensive IP lookup across all available sources

        Args:
            ip_address: IP address to look up
            use_cache: Whether to use cached results

        Returns:
            Dictionary with aggregated threat intelligence data
        """
        logger.info(f"Looking up IP: {ip_address}")

        # Initialize clients on first use
        self._init_clients()

        results = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'summary': {
                'is_threat': False,
                'threat_score': 0,
                'threat_level': 'unknown',
                'sources_queried': 0,
                'sources_responded': 0
            }
        }

        # Query VirusTotal
        if self.virustotal_client:
            results['sources']['virustotal'] = self._lookup_virustotal(ip_address, use_cache)
            results['summary']['sources_queried'] += 1
            if not results['sources']['virustotal'].get('error'):
                results['summary']['sources_responded'] += 1

        # Query Shodan
        if self.shodan_client:
            results['sources']['shodan'] = self._lookup_shodan(ip_address, use_cache)
            results['summary']['sources_queried'] += 1
            if not results['sources']['shodan'].get('error'):
                results['summary']['sources_responded'] += 1

        # Query AbuseIPDB
        if self.abuseipdb_client:
            results['sources']['abuseipdb'] = self._lookup_abuseipdb(ip_address, use_cache)
            results['summary']['sources_queried'] += 1
            if not results['sources']['abuseipdb'].get('error'):
                results['summary']['sources_responded'] += 1

        # Aggregate and analyze results
        results['summary'] = self._analyze_results(results['sources'])
        results['summary']['sources_queried'] = len(self.available_services)

        logger.info(f"IP lookup complete: {ip_address} - Threat: {results['summary']['is_threat']}")

        return results

    def _lookup_virustotal(self, ip_address: str, use_cache: bool) -> Dict:
        """Query VirusTotal for IP information"""
        try:
            if self.virustotal_client:
                return self.virustotal_client.lookup(ip_address, use_cache=use_cache)
            return {'error': 'VirusTotal client not available'}
        except Exception as e:
            logger.error(f"VirusTotal lookup error: {e}")
            return {'error': str(e)}

    def _lookup_shodan(self, ip_address: str, use_cache: bool) -> Dict:
        """Query Shodan for IP information"""
        try:
            if self.shodan_client:
                return self.shodan_client.lookup(ip_address, use_cache=use_cache)
            return {'error': 'Shodan client not available'}
        except Exception as e:
            logger.error(f"Shodan lookup error: {e}")
            return {'error': str(e)}

    def _lookup_abuseipdb(self, ip_address: str, use_cache: bool) -> Dict:
        """Query AbuseIPDB for IP information"""
        try:
            if self.abuseipdb_client:
                return self.abuseipdb_client.lookup(ip_address, use_cache=use_cache)
            return {'error': 'AbuseIPDB client not available'}
        except Exception as e:
            logger.error(f"AbuseIPDB lookup error: {e}")
            return {'error': str(e)}

    def _analyze_results(self, sources: Dict) -> Dict:
        """
        Analyze results from all sources and create unified summary

        Returns:
            Summary dictionary with threat assessment
        """
        summary = {
            'is_threat': False,
            'threat_score': 0,
            'threat_level': 'clean',
            'threat_indicators': [],
            'sources_responded': 0,
            'confidence': 'low'
        }

        threat_scores = []

        # Analyze VirusTotal results
        vt_data = sources.get('virustotal', {})
        if not vt_data.get('error'):
            summary['sources_responded'] += 1
            malicious_count = vt_data.get('malicious_count', 0)
            total_scanners = vt_data.get('total_scanners', 1)

            if malicious_count > 0:
                vt_score = (malicious_count / total_scanners) * 100
                threat_scores.append(vt_score)
                summary['threat_indicators'].append(
                    f"VirusTotal: {malicious_count}/{total_scanners} flagged as malicious"
                )

        # Analyze Shodan results
        shodan_data = sources.get('shodan', {})
        if not shodan_data.get('error'):
            summary['sources_responded'] += 1
            vulns = shodan_data.get('vulnerabilities', [])
            open_ports = shodan_data.get('open_ports', [])

            if vulns:
                threat_scores.append(70)  # Known vulnerabilities
                summary['threat_indicators'].append(
                    f"Shodan: {len(vulns)} known vulnerabilities"
                )

            if len(open_ports) > 5:
                threat_scores.append(40)  # Many open ports
                summary['threat_indicators'].append(
                    f"Shodan: {len(open_ports)} open ports detected"
                )

        # Analyze AbuseIPDB results
        abuse_data = sources.get('abuseipdb', {})
        if not abuse_data.get('error'):
            summary['sources_responded'] += 1
            abuse_score = abuse_data.get('abuse_confidence_score', 0)

            if abuse_score > 0:
                threat_scores.append(abuse_score)
                summary['threat_indicators'].append(
                    f"AbuseIPDB: {abuse_score}% abuse confidence"
                )

        # Calculate overall threat score
        if threat_scores:
            summary['threat_score'] = max(threat_scores)  # Use highest score
            summary['is_threat'] = summary['threat_score'] >= 30

            # Determine threat level
            if summary['threat_score'] >= 80:
                summary['threat_level'] = 'critical'
            elif summary['threat_score'] >= 60:
                summary['threat_level'] = 'high'
            elif summary['threat_score'] >= 30:
                summary['threat_level'] = 'medium'
            else:
                summary['threat_level'] = 'low'

            # Confidence based on number of sources
            if summary['sources_responded'] >= 3:
                summary['confidence'] = 'high'
            elif summary['sources_responded'] >= 2:
                summary['confidence'] = 'medium'
            else:
                summary['confidence'] = 'low'

        return summary

    def get_service_status(self) -> Dict:
        """
        Get status of all intelligence services

        Returns:
            Dictionary with service availability and stats
        """
        self._init_clients()

        status = {
            'services': {
                'virustotal': {
                    'available': self.virustotal_client is not None,
                    'configured': self.api_keys['virustotal'] is not None
                },
                'shodan': {
                    'available': self.shodan_client is not None,
                    'configured': self.api_keys['shodan'] is not None
                },
                'abuseipdb': {
                    'available': self.abuseipdb_client is not None,
                    'configured': self.api_keys['abuseipdb'] is not None
                }
            },
            'cache_stats': self._get_cache_stats()
        }

        return status

    def _get_cache_stats(self) -> Dict:
        """Get cache statistics for all services"""
        stats = {}

        if self.virustotal_client:
            stats['virustotal'] = self.virustotal_client.get_cache_stats()

        if self.shodan_client:
            stats['shodan'] = self.shodan_client.get_cache_stats()

        if self.abuseipdb_client:
            stats['abuseipdb'] = self.abuseipdb_client.get_cache_stats()

        return stats

    def clear_all_caches(self) -> Dict:
        """Clear caches for all services"""
        results = {}

        if self.virustotal_client:
            results['virustotal'] = self.virustotal_client.clear_cache()

        if self.shodan_client:
            results['shodan'] = self.shodan_client.clear_cache()

        if self.abuseipdb_client:
            results['abuseipdb'] = self.abuseipdb_client.clear_cache()

        return results
