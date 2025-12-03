#!/usr/bin/env python3
"""
Configure API Rate Limits for Free Tier
Sets up proper rate limiting for VirusTotal, AbuseIPDB, and Shodan
"""

import os
import sys
from pathlib import Path

# Add project to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

def configure_rate_limits():
    """Configure rate limits in .env for free tier APIs"""

    env_file = PROJECT_ROOT / ".env"

    # Free tier rate limits
    rate_limits = {
        # VirusTotal: 250 requests/day, 4 requests/minute
        'VIRUSTOTAL_RATE_LIMIT_PER_DAY': '250',
        'VIRUSTOTAL_RATE_LIMIT_PER_MINUTE': '4',
        'VIRUSTOTAL_ENABLED': 'true',

        # AbuseIPDB: 1000 requests/day, 60 requests/minute (but we'll be conservative)
        'ABUSEIPDB_RATE_LIMIT_PER_DAY': '1000',
        'ABUSEIPDB_RATE_LIMIT_PER_MINUTE': '30',
        'ABUSEIPDB_ENABLED': 'true',

        # Shodan: 100 credits/month (very limited, use sparingly)
        'SHODAN_RATE_LIMIT_PER_MONTH': '100',
        'SHODAN_RATE_LIMIT_PER_DAY': '3',
        'SHODAN_ENABLED': 'true',
        'SHODAN_HIGH_RISK_ONLY': 'true',  # Only use for high-risk IPs

        # Global API settings
        'API_CACHE_ENABLED': 'true',
        'API_CACHE_TTL_HOURS': '24',  # Cache results for 24 hours
        'API_RETRY_ENABLED': 'true',
        'API_RETRY_MAX_ATTEMPTS': '3',
        'API_TIMEOUT_SECONDS': '10',
    }

    print("=" * 80)
    print("Configuring API Rate Limits for Free Tier")
    print("=" * 80)
    print()

    # Read existing .env
    env_lines = []
    if env_file.exists():
        with open(env_file, 'r') as f:
            env_lines = f.readlines()

    # Update or add rate limit settings
    updated_keys = set()
    new_lines = []

    for line in env_lines:
        if '=' in line and not line.strip().startswith('#'):
            key = line.split('=')[0].strip()
            if key in rate_limits:
                new_lines.append(f"{key}={rate_limits[key]}\n")
                updated_keys.add(key)
                print(f"✓ Updated: {key}={rate_limits[key]}")
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    # Add new settings that weren't in the file
    if new_lines and not new_lines[-1].endswith('\n'):
        new_lines.append('\n')

    new_lines.append('\n# API Rate Limits (Free Tier)\n')
    for key, value in rate_limits.items():
        if key not in updated_keys:
            new_lines.append(f"{key}={value}\n")
            print(f"✓ Added: {key}={value}")

    # Write back to .env
    with open(env_file, 'w') as f:
        f.writelines(new_lines)

    print()
    print("=" * 80)
    print("Rate Limits Configured Successfully!")
    print("=" * 80)
    print()
    print("Summary:")
    print("  • VirusTotal: 4 req/min, 250 req/day")
    print("  • AbuseIPDB: 30 req/min, 1000 req/day")
    print("  • Shodan: 3 req/day, 100 req/month (high-risk IPs only)")
    print("  • API caching enabled (24 hour TTL)")
    print()

    return True

if __name__ == "__main__":
    configure_rate_limits()
