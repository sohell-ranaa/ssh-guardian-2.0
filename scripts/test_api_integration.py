#!/usr/bin/env python3
"""
SSH Guardian 2.0 - API Integration Testing Script
Tests VirusTotal, AbuseIPDB, and Shodan API connectivity and functionality
"""

import sys
import os
from pathlib import Path
import json
import argparse
from datetime import datetime

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "src"))

from intelligence.api_clients import (
    ThreatIntelligenceAggregator,
    VirusTotalClient,
    AbuseIPDBClient,
    ShodanClient,
    IntelligenceCache
)


class Colors:
    """Terminal colors for pretty output"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_header(text):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(80)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.END}\n")


def print_success(text):
    """Print success message"""
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")


def print_warning(text):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")


def print_error(text):
    """Print error message"""
    print(f"{Colors.RED}✗ {text}{Colors.END}")


def print_info(text):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ {text}{Colors.END}")


def load_env():
    """Load configuration from .env file"""
    env_file = PROJECT_ROOT / ".env"
    config = {
        'virustotal_api_key': '',
        'abuseipdb_api_key': '',
        'shodan_api_key': ''
    }

    if not env_file.exists():
        print_error(f".env file not found at {env_file}")
        return config

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


def test_virustotal(api_key, test_ip, verbose=False):
    """Test VirusTotal API"""
    print_header("Testing VirusTotal API")

    if not api_key:
        print_error("VirusTotal API key not configured in .env file")
        print_info("Get free API key at: https://www.virustotal.com/gui/join-us")
        return False

    # Validate key format (should be 64 hex characters)
    if len(api_key) != 64:
        print_warning(f"API key length is {len(api_key)}, expected 64 characters")

    cache = IntelligenceCache(PROJECT_ROOT / "data" / "api_cache")
    client = VirusTotalClient(api_key, cache)

    print_info(f"Testing with IP: {test_ip}")
    print_info("Making API request...")

    try:
        result = client.check_ip(test_ip)

        if result['status'] == 'success':
            print_success("VirusTotal API connection successful!")
            print(f"\n{Colors.BOLD}Results:{Colors.END}")
            print(f"  Risk Score: {result['risk_score']}/100")
            print(f"  Malicious Detections: {result['malicious_count']}")
            print(f"  Suspicious Detections: {result['suspicious_count']}")
            print(f"  Total Scans: {result['total_scans']}")
            print(f"  Detection Rate: {result['detection_rate']*100:.1f}%")
            print(f"  Country: {result.get('country', 'Unknown')}")
            print(f"  ASN: {result.get('asn', 'Unknown')}")
            print(f"  AS Owner: {result.get('as_owner', 'Unknown')}")

            if result['is_malicious']:
                print_warning(f"  Status: MALICIOUS")
            else:
                print_success(f"  Status: Clean")

            if verbose:
                print(f"\n{Colors.BOLD}Full Response:{Colors.END}")
                print(json.dumps(result, indent=2))

            return True

        elif result['status'] == 'not_found':
            print_warning("IP not found in VirusTotal database (this is normal for many IPs)")
            print_success("API connection working correctly!")
            return True
        else:
            print_error(f"API request failed: {result.get('status')}")
            return False

    except Exception as e:
        print_error(f"VirusTotal API test failed: {e}")
        return False


def test_abuseipdb(api_key, test_ip, verbose=False):
    """Test AbuseIPDB API"""
    print_header("Testing AbuseIPDB API")

    if not api_key:
        print_error("AbuseIPDB API key not configured in .env file")
        print_info("Get free API key at: https://www.abuseipdb.com/pricing")
        return False

    # Validate key format (should be 80 characters)
    if len(api_key) != 80:
        print_warning(f"API key length is {len(api_key)}, expected 80 characters")

    cache = IntelligenceCache(PROJECT_ROOT / "data" / "api_cache")
    client = AbuseIPDBClient(api_key, cache)

    print_info(f"Testing with IP: {test_ip}")
    print_info("Making API request...")

    try:
        result = client.check_ip(test_ip)

        if result['status'] == 'success':
            print_success("AbuseIPDB API connection successful!")
            print(f"\n{Colors.BOLD}Results:{Colors.END}")
            print(f"  Abuse Confidence Score: {result['abuse_confidence_score']}/100")
            print(f"  Total Reports: {result['total_reports']}")
            print(f"  Distinct Reporters: {result['num_distinct_users']}")
            print(f"  Risk Score: {result['risk_score']}/100")
            print(f"  Country: {result.get('country_code', 'Unknown')}")
            print(f"  ISP: {result.get('isp', 'Unknown')}")
            print(f"  Usage Type: {result.get('usage_type', 'Unknown')}")

            if result.get('is_tor'):
                print_warning("  Tor Exit Node: YES")

            if result['is_whitelisted']:
                print_success("  Whitelisted: YES")

            if result['is_malicious']:
                print_warning(f"  Status: MALICIOUS")
            else:
                print_success(f"  Status: Clean")

            if verbose:
                print(f"\n{Colors.BOLD}Full Response:{Colors.END}")
                print(json.dumps(result, indent=2))

            return True
        else:
            print_error(f"API request failed: {result.get('status')}")
            return False

    except Exception as e:
        print_error(f"AbuseIPDB API test failed: {e}")
        return False


def test_shodan(api_key, test_ip, verbose=False):
    """Test Shodan API"""
    print_header("Testing Shodan API")

    if not api_key:
        print_error("Shodan API key not configured in .env file")
        print_info("Get free API key at: https://account.shodan.io/register")
        return False

    # Validate key format (should be 32 characters)
    if len(api_key) != 32:
        print_warning(f"API key length is {len(api_key)}, expected 32 characters")

    cache = IntelligenceCache(PROJECT_ROOT / "data" / "api_cache")
    client = ShodanClient(api_key, cache)

    print_info(f"Testing with IP: {test_ip}")
    print_info("Making API request...")
    print_warning("Note: Free tier has limited credits (100/month)")

    try:
        result = client.check_ip(test_ip)

        if result['status'] == 'success':
            print_success("Shodan API connection successful!")
            print(f"\n{Colors.BOLD}Results:{Colors.END}")
            print(f"  Open Ports: {len(result['open_ports'])} ports")
            if result['open_ports']:
                print(f"    Ports: {', '.join(map(str, result['open_ports'][:10]))}")
            print(f"  Vulnerabilities: {result['num_vulnerabilities']}")
            print(f"  Risk Score: {result['risk_score']}/100")
            print(f"  Organization: {result.get('organization', 'Unknown')}")
            print(f"  ISP: {result.get('isp', 'Unknown')}")
            print(f"  Country: {result.get('country', 'Unknown')}")
            print(f"  City: {result.get('city', 'Unknown')}")

            if result.get('tags'):
                print(f"  Tags: {', '.join(result['tags'])}")

            if result['is_malicious']:
                print_warning(f"  Status: MALICIOUS")
            else:
                print_success(f"  Status: Clean")

            if verbose:
                print(f"\n{Colors.BOLD}Full Response:{Colors.END}")
                print(json.dumps(result, indent=2))

            return True

        elif result['status'] == 'not_found':
            print_warning("IP not found in Shodan database (may not have been scanned)")
            print_success("API connection working correctly!")
            return True
        else:
            print_error(f"API request failed: {result.get('status')}")
            return False

    except Exception as e:
        print_error(f"Shodan API test failed: {e}")
        return False


def test_aggregator(config, test_ip, verbose=False):
    """Test unified threat intelligence aggregator"""
    print_header("Testing Unified Threat Intelligence Aggregator")

    cache_dir = PROJECT_ROOT / "data" / "api_cache"
    aggregator = ThreatIntelligenceAggregator(config, cache_dir)

    # Check which APIs are enabled
    enabled_apis = []
    if aggregator.vt_client:
        enabled_apis.append("VirusTotal")
    if aggregator.abuse_client:
        enabled_apis.append("AbuseIPDB")
    if aggregator.shodan_client:
        enabled_apis.append("Shodan")

    if not enabled_apis:
        print_error("No API keys configured!")
        print_info("Please add at least one API key to .env file")
        return False

    print_success(f"Enabled APIs: {', '.join(enabled_apis)}")
    print_info(f"Testing with IP: {test_ip}")
    print_info("Querying all enabled APIs...")

    try:
        result = aggregator.analyze_ip(test_ip)

        print_success("Aggregator working correctly!")
        print(f"\n{Colors.BOLD}Aggregated Results:{Colors.END}")
        print(f"  Combined Risk Score: {result['aggregated_score']}/100")
        print(f"  Threat Level: {result['threat_level'].upper()}")
        print(f"  Malicious: {'YES' if result['is_malicious'] else 'NO'}")

        print(f"\n{Colors.BOLD}Individual Source Results:{Colors.END}")
        for source_name, source_data in result['sources'].items():
            status_icon = "✓" if source_data.get('status') == 'success' else "✗"
            print(f"  {status_icon} {source_name.upper()}:")
            print(f"      Risk Score: {source_data.get('risk_score', 0)}/100")
            print(f"      Malicious: {'YES' if source_data.get('is_malicious') else 'NO'}")

        if result.get('recommendations'):
            print(f"\n{Colors.BOLD}Recommendations:{Colors.END}")
            for rec in result['recommendations']:
                print(f"  • {rec}")

        if verbose:
            print(f"\n{Colors.BOLD}Full Aggregated Response:{Colors.END}")
            print(json.dumps(result, indent=2))

        return True

    except Exception as e:
        print_error(f"Aggregator test failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Test SSH Guardian 2.0 API integrations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test all configured APIs
  python3 test_api_integration.py --test-all

  # Test specific API
  python3 test_api_integration.py --api virustotal

  # Test with custom IP
  python3 test_api_integration.py --api abuseipdb --ip 1.2.3.4

  # Test with verbose output
  python3 test_api_integration.py --test-all --verbose

  # Test known malicious IP
  python3 test_api_integration.py --test-all --ip 185.220.101.1
        """
    )

    parser.add_argument(
        '--api',
        choices=['virustotal', 'abuseipdb', 'shodan', 'aggregator'],
        help='Test specific API'
    )
    parser.add_argument(
        '--test-all',
        action='store_true',
        help='Test all configured APIs'
    )
    parser.add_argument(
        '--ip',
        default='8.8.8.8',
        help='IP address to test with (default: 8.8.8.8)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed API responses'
    )

    args = parser.parse_args()

    if not args.api and not args.test_all:
        parser.print_help()
        print_error("\nPlease specify --api or --test-all")
        sys.exit(1)

    # Load configuration
    print_header("SSH Guardian 2.0 - API Integration Tester")
    print_info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info(f"Test IP: {args.ip}")

    config = load_env()

    # Show configuration status
    print(f"\n{Colors.BOLD}Configuration Status:{Colors.END}")
    print(f"  VirusTotal: {'✓ Configured' if config['virustotal_api_key'] else '✗ Not configured'}")
    print(f"  AbuseIPDB:  {'✓ Configured' if config['abuseipdb_api_key'] else '✗ Not configured'}")
    print(f"  Shodan:     {'✓ Configured' if config['shodan_api_key'] else '✗ Not configured'}")

    results = {}

    # Run tests
    if args.test_all:
        if config['virustotal_api_key']:
            results['virustotal'] = test_virustotal(config['virustotal_api_key'], args.ip, args.verbose)
        else:
            print_warning("\nSkipping VirusTotal (no API key)")

        if config['abuseipdb_api_key']:
            results['abuseipdb'] = test_abuseipdb(config['abuseipdb_api_key'], args.ip, args.verbose)
        else:
            print_warning("\nSkipping AbuseIPDB (no API key)")

        if config['shodan_api_key']:
            results['shodan'] = test_shodan(config['shodan_api_key'], args.ip, args.verbose)
        else:
            print_warning("\nSkipping Shodan (no API key)")

        # Test aggregator if any API is configured
        if any(config.values()):
            results['aggregator'] = test_aggregator(config, args.ip, args.verbose)

    else:
        # Test specific API
        if args.api == 'virustotal':
            results['virustotal'] = test_virustotal(config['virustotal_api_key'], args.ip, args.verbose)
        elif args.api == 'abuseipdb':
            results['abuseipdb'] = test_abuseipdb(config['abuseipdb_api_key'], args.ip, args.verbose)
        elif args.api == 'shodan':
            results['shodan'] = test_shodan(config['shodan_api_key'], args.ip, args.verbose)
        elif args.api == 'aggregator':
            results['aggregator'] = test_aggregator(config, args.ip, args.verbose)

    # Print summary
    print_header("Test Summary")

    passed = sum(1 for result in results.values() if result)
    total = len(results)

    for test_name, result in results.items():
        if result:
            print_success(f"{test_name.upper()}: PASSED")
        else:
            print_error(f"{test_name.upper()}: FAILED")

    print(f"\n{Colors.BOLD}Overall: {passed}/{total} tests passed{Colors.END}\n")

    if passed == total:
        print_success("All tests passed! API integration is working correctly.")
        print_info("You can now restart SSH Guardian to use the enhanced threat intelligence.")
        sys.exit(0)
    else:
        print_warning("Some tests failed. Check the error messages above.")
        print_info("See docs/API_SETUP_GUIDE.md for troubleshooting help.")
        sys.exit(1)


if __name__ == "__main__":
    main()
