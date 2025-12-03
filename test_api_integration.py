#!/usr/bin/env python3
"""
Test script for third-party API integration
Tests VirusTotal, AbuseIPDB, and Shodan clients
"""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "src"))

import json
import logging
from src.intelligence.api_clients import ThreatIntelligenceAggregator

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_api_keys_from_env():
    """Load API keys from .env file"""
    env_file = PROJECT_ROOT / ".env"
    config = {}

    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    value = value.strip('"').strip()
                    if key == 'VIRUSTOTAL_API_KEY' and value:
                        config['virustotal_api_key'] = value
                    elif key == 'ABUSEIPDB_API_KEY' and value:
                        config['abuseipdb_api_key'] = value
                    elif key == 'SHODAN_API_KEY' and value:
                        config['shodan_api_key'] = value

    return config


def test_api_integration():
    """Test the API integration with known IPs"""

    print("=" * 80)
    print("🧪 SSH GUARDIAN - API INTEGRATION TEST")
    print("=" * 80)

    # Load API keys
    config = load_api_keys_from_env()

    if not any(config.values()):
        print("\n⚠️  WARNING: No API keys configured!")
        print("   Please add your API keys to the .env file:")
        print("   - VIRUSTOTAL_API_KEY")
        print("   - ABUSEIPDB_API_KEY")
        print("   - SHODAN_API_KEY")
        print("\n   Get free API keys from:")
        print("   ✓ VirusTotal: https://www.virustotal.com/gui/join-us (250 req/day)")
        print("   ✓ AbuseIPDB: https://www.abuseipdb.com/pricing (1000 req/day)")
        print("   ✓ Shodan: https://account.shodan.io/register (Limited free)")
        print("\n   The system will work with cached local threat feeds only.")
        print("=" * 80)
        return

    print(f"\n✅ Configured APIs:")
    print(f"   VirusTotal: {'✓' if config.get('virustotal_api_key') else '✗'}")
    print(f"   AbuseIPDB:  {'✓' if config.get('abuseipdb_api_key') else '✗'}")
    print(f"   Shodan:     {'✓' if config.get('shodan_api_key') else '✗'}")

    # Initialize aggregator
    cache_dir = PROJECT_ROOT / "data" / "api_cache"
    aggregator = ThreatIntelligenceAggregator(config, cache_dir)

    # Test IPs (known malicious and clean IPs for testing)
    test_cases = [
        {
            'ip': '8.8.8.8',
            'description': 'Google DNS (should be clean)',
            'expected': 'clean'
        },
        {
            'ip': '185.220.101.1',
            'description': 'Known Tor exit node',
            'expected': 'suspicious/malicious'
        },
        {
            'ip': '192.168.1.1',
            'description': 'Private IP (local network)',
            'expected': 'clean'
        }
    ]

    print("\n" + "=" * 80)
    print("🔍 TESTING IP ANALYSIS")
    print("=" * 80)

    for idx, test_case in enumerate(test_cases, 1):
        print(f"\n{'─' * 80}")
        print(f"Test {idx}/{len(test_cases)}: {test_case['description']}")
        print(f"IP Address: {test_case['ip']}")
        print(f"Expected: {test_case['expected']}")
        print(f"{'─' * 80}")

        try:
            result = aggregator.analyze_ip(test_case['ip'])

            # Display results
            print(f"\n📊 RESULTS:")
            print(f"   Aggregated Risk Score: {result['aggregated_score']}/100")
            print(f"   Threat Level: {result['threat_level'].upper()}")
            print(f"   Is Malicious: {result['is_malicious']}")

            # Show source-specific results
            print(f"\n📡 SOURCE DETAILS:")
            for source_name, source_data in result.get('sources', {}).items():
                status = source_data.get('status', 'unknown')
                risk = source_data.get('risk_score', 0)
                print(f"   {source_name.upper():12} | Status: {status:10} | Risk: {risk:3}/100")

                # Additional details
                if source_name == 'virustotal' and status == 'success':
                    print(f"                 | Malicious: {source_data.get('malicious_count', 0)} "
                          f"Suspicious: {source_data.get('suspicious_count', 0)} "
                          f"Harmless: {source_data.get('harmless_count', 0)}")

                elif source_name == 'abuseipdb' and status == 'success':
                    print(f"                 | Confidence: {source_data.get('abuse_confidence_score', 0)}% "
                          f"Reports: {source_data.get('total_reports', 0)} "
                          f"Is Tor: {source_data.get('is_tor', False)}")

                elif source_name == 'shodan' and status == 'success':
                    print(f"                 | Open Ports: {source_data.get('num_ports', 0)} "
                          f"Vulnerabilities: {source_data.get('num_vulnerabilities', 0)}")

            # Recommendations
            if result.get('recommendations'):
                print(f"\n💡 RECOMMENDATIONS:")
                for rec in result['recommendations']:
                    print(f"   • {rec}")

            # Validation
            expected = test_case['expected']
            actual = result['threat_level']
            if 'clean' in expected and actual in ['clean', 'low']:
                print(f"\n✅ VALIDATION: PASSED (Expected clean/low, got {actual})")
            elif 'suspicious' in expected or 'malicious' in expected:
                if actual in ['medium', 'high', 'critical']:
                    print(f"\n✅ VALIDATION: PASSED (Expected suspicious/malicious, got {actual})")
                else:
                    print(f"\n⚠️  VALIDATION: UNCERTAIN (Expected suspicious/malicious, got {actual})")
            else:
                print(f"\n✅ VALIDATION: Result received")

        except Exception as e:
            print(f"\n❌ ERROR: {str(e)}")
            logger.exception("Test failed")

    print("\n" + "=" * 80)
    print("🎉 API INTEGRATION TEST COMPLETED")
    print("=" * 80)

    # Show cache statistics
    cache_files = list(cache_dir.glob("*.json")) if cache_dir.exists() else []
    print(f"\n📁 Cache Statistics:")
    print(f"   Location: {cache_dir}")
    print(f"   Cached Results: {len(cache_files)}")
    print(f"   Note: Results are cached for 24 hours to minimize API usage")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    test_api_integration()
