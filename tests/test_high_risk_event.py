#!/usr/bin/env python3
"""
Test high-risk event that should trigger Telegram alert
"""
import requests
import json
from datetime import datetime, timedelta

GUARDIAN_URL = "http://localhost:5000"

def send_high_risk_brute_force():
    """Send a high-risk brute force attack pattern"""

    # Create 20 rapid failed attempts from a known threat IP (Tor exit)
    # This should trigger:
    # 1. Threat Intelligence detection (Tor exit node)
    # 2. Brute force detection (high rate)
    # 3. Pattern detection (sequential usernames)

    base_time = datetime.now()
    logs = []

    # Use a known Tor exit node
    threat_ip = "185.220.101.50"  # Known Tor exit node from feed

    for i in range(20):
        logs.append({
            "timestamp": (base_time + timedelta(seconds=i)).isoformat(),
            "event_type": "failed_password",
            "source_ip": threat_ip,
            "username": f"admin{i}",  # Sequential pattern
            "server_name": "production-server",
            "port": 22,
            "country": "Unknown",
            "city": "Unknown"
        })

    try:
        response = requests.post(
            f"{GUARDIAN_URL}/logs/upload",
            json={"logs": logs},
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        print(f"\n{'='*80}")
        print(f"HIGH-RISK BRUTE FORCE TEST")
        print(f"{'='*80}")
        print(f"IP: {threat_ip} (Tor Exit Node)")
        print(f"Failed Attempts: {len(logs)}")
        print(f"Pattern: Sequential usernames (admin0, admin1, admin2...)")
        print(f"\nStatus Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")

        # Wait a moment for processing
        import time
        time.sleep(3)

        # Get statistics
        print(f"\n{'='*80}")
        print(f"STATISTICS AFTER ATTACK")
        print(f"{'='*80}")
        stats = requests.get(f"{GUARDIAN_URL}/statistics", timeout=10).json()
        print(json.dumps(stats, indent=2))

        # Check blocks
        print(f"\n{'='*80}")
        print(f"ACTIVE BLOCKS")
        print(f"{'='*80}")
        blocks = requests.get(f"{GUARDIAN_URL}/blocks", timeout=10).json()
        print(json.dumps(blocks, indent=2))

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("\n🔥 Testing High-Risk Attack Scenario\n")
    send_high_risk_brute_force()
    print("\n✅ Test complete - Check your Telegram for alerts!")
