#!/usr/bin/env python3
"""
Test script to send sample SSH events to SSH Guardian
"""
import requests
import json
from datetime import datetime

GUARDIAN_URL = "http://localhost:5000"

def send_test_event(event_type="failed_login"):
    """Send a test SSH event to Guardian"""

    # Sample events for different scenarios
    events = {
        "failed_login": {
            "timestamp": datetime.now().isoformat(),
            "event_type": "failed_password",
            "source_ip": "185.220.101.50",  # Known Tor exit node
            "username": "admin",
            "server_name": "test-server",
            "port": 22,
            "country": "Unknown",
            "city": "Unknown"
        },
        "brute_force": [
            {
                "timestamp": datetime.now().isoformat(),
                "event_type": "failed_password",
                "source_ip": "45.142.120.10",
                "username": f"user{i}",
                "server_name": "test-server",
                "port": 22,
                "country": "Unknown",
                "city": "Unknown"
            }
            for i in range(15)  # 15 failed attempts in rapid succession
        ],
        "known_threat": {
            "timestamp": datetime.now().isoformat(),
            "event_type": "failed_password",
            "source_ip": "222.186.42.34",  # From SSH attackers feed
            "username": "root",
            "server_name": "test-server",
            "port": 22,
            "country": "CN",
            "city": "Unknown"
        }
    }

    if event_type == "brute_force":
        logs = events[event_type]
    else:
        logs = [events[event_type]]

    try:
        response = requests.post(
            f"{GUARDIAN_URL}/logs/upload",
            json={"logs": logs},
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        print(f"\n{'='*80}")
        print(f"Test: {event_type.upper()}")
        print(f"{'='*80}")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")

        return response.json()

    except Exception as e:
        print(f"❌ Error sending test event: {e}")
        return None

if __name__ == "__main__":
    print("\n🧪 SSH Guardian Test Suite\n")

    # Test 1: Single failed login from Tor exit node
    print("\n[Test 1] Sending failed login from Tor exit node...")
    send_test_event("failed_login")

    # Test 2: Brute force attack pattern
    print("\n[Test 2] Sending brute force attack pattern (15 rapid attempts)...")
    send_test_event("brute_force")

    # Test 3: Known threat IP
    print("\n[Test 3] Sending event from known threat IP...")
    send_test_event("known_threat")

    # Get statistics
    print("\n" + "="*80)
    print("FINAL STATISTICS")
    print("="*80)
    try:
        stats = requests.get(f"{GUARDIAN_URL}/statistics", timeout=10).json()
        print(json.dumps(stats, indent=2))
    except Exception as e:
        print(f"❌ Error getting statistics: {e}")
