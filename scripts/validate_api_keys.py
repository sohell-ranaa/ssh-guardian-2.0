#!/usr/bin/env python3
"""
SSH Guardian 2.0 - API Key Validation Utility
Validates API key format and checks if they're active
"""

import sys
import os
from pathlib import Path
import re

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")


def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")


def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.END}")


def print_info(text):
    print(f"{Colors.BLUE}ℹ {text}{Colors.END}")


def validate_virustotal_key(api_key):
    """Validate VirusTotal API key format"""
    if not api_key:
        return False, "API key is empty"

    # Remove any whitespace
    api_key = api_key.strip()

    # VirusTotal keys are 64 character hexadecimal strings
    if len(api_key) != 64:
        return False, f"Invalid length: {len(api_key)} characters (expected 64)"

    if not re.match(r'^[a-f0-9]{64}$', api_key, re.IGNORECASE):
        return False, "Invalid format: should be 64 hexadecimal characters"

    return True, "Valid format"


def validate_abuseipdb_key(api_key):
    """Validate AbuseIPDB API key format"""
    if not api_key:
        return False, "API key is empty"

    # Remove any whitespace
    api_key = api_key.strip()

    # AbuseIPDB keys are 80 character alphanumeric strings
    if len(api_key) != 80:
        return False, f"Invalid length: {len(api_key)} characters (expected 80)"

    if not re.match(r'^[a-zA-Z0-9]{80}$', api_key):
        return False, "Invalid format: should be 80 alphanumeric characters"

    return True, "Valid format"


def validate_shodan_key(api_key):
    """Validate Shodan API key format"""
    if not api_key:
        return False, "API key is empty"

    # Remove any whitespace
    api_key = api_key.strip()

    # Shodan keys are 32 character alphanumeric strings
    if len(api_key) != 32:
        return False, f"Invalid length: {len(api_key)} characters (expected 32)"

    if not re.match(r'^[a-zA-Z0-9]{32}$', api_key):
        return False, "Invalid format: should be 32 alphanumeric characters"

    return True, "Valid format"


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
        return None

    with open(env_file, 'r') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                value = value.strip('"').strip()

                if key == 'VIRUSTOTAL_API_KEY':
                    config['virustotal_api_key'] = value
                elif key == 'ABUSEIPDB_API_KEY':
                    config['abuseipdb_api_key'] = value
                elif key == 'SHODAN_API_KEY':
                    config['shodan_api_key'] = value

    return config


def main():
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}SSH Guardian 2.0 - API Key Validator{Colors.END}".center(88))
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.END}\n")

    # Load configuration
    config = load_env()
    if config is None:
        print_error("Cannot proceed without .env file")
        print_info("Copy .env.example to .env and add your API keys")
        sys.exit(1)

    print_info(f"Reading configuration from: {PROJECT_ROOT / '.env'}\n")

    all_valid = True

    # Validate VirusTotal
    print(f"{Colors.BOLD}VirusTotal API Key:{Colors.END}")
    vt_key = config['virustotal_api_key']
    if vt_key:
        is_valid, message = validate_virustotal_key(vt_key)
        if is_valid:
            print_success(f"Format: {message}")
            print_info(f"Key: {vt_key[:8]}...{vt_key[-8:]}")
        else:
            print_error(f"Format: {message}")
            print_info(f"Key: {vt_key}")
            all_valid = False
    else:
        print_warning("Not configured")
        print_info("Get free key at: https://www.virustotal.com/gui/join-us")

    # Validate AbuseIPDB
    print(f"\n{Colors.BOLD}AbuseIPDB API Key:{Colors.END}")
    abuse_key = config['abuseipdb_api_key']
    if abuse_key:
        is_valid, message = validate_abuseipdb_key(abuse_key)
        if is_valid:
            print_success(f"Format: {message}")
            print_info(f"Key: {abuse_key[:8]}...{abuse_key[-8:]}")
        else:
            print_error(f"Format: {message}")
            print_info(f"Key: {abuse_key}")
            all_valid = False
    else:
        print_warning("Not configured")
        print_info("Get free key at: https://www.abuseipdb.com/pricing")

    # Validate Shodan
    print(f"\n{Colors.BOLD}Shodan API Key:{Colors.END}")
    shodan_key = config['shodan_api_key']
    if shodan_key:
        is_valid, message = validate_shodan_key(shodan_key)
        if is_valid:
            print_success(f"Format: {message}")
            print_info(f"Key: {shodan_key[:8]}...{shodan_key[-8:]}")
        else:
            print_error(f"Format: {message}")
            print_info(f"Key: {shodan_key}")
            all_valid = False
    else:
        print_warning("Not configured")
        print_info("Get free key at: https://account.shodan.io/register")

    # Summary
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}Summary:{Colors.END}\n")

    configured_count = sum(1 for k in config.values() if k)
    print_info(f"APIs Configured: {configured_count}/3")

    if configured_count == 0:
        print_warning("No API keys configured!")
        print_info("SSH Guardian will use local threat feeds only")
        print_info("See docs/API_SETUP_GUIDE.md for setup instructions")
    elif all_valid:
        print_success("All configured API keys have valid format!")
        print_info("Run 'python3 scripts/test_api_integration.py --test-all' to verify connectivity")
    else:
        print_error("Some API keys have invalid format!")
        print_info("Please check your .env file and correct the invalid keys")

    print()

    sys.exit(0 if all_valid else 1)


if __name__ == "__main__":
    main()
