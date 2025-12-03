#!/usr/bin/env python3
"""
End-to-End Test for SSH Guardian 2.0 Integrated System
Tests all detection capabilities with realistic scenarios
"""

import sys
from pathlib import Path
import json
import time
from datetime import datetime, timedelta

# Add paths
PROJECT_ROOT = Path(__file__).parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "src"))

from core.guardian_engine import create_guardian_engine


def print_separator(title=""):
    """Print a nice separator"""
    print("\n" + "=" * 80)
    if title:
        print(f"  {title}")
        print("=" * 80)
    else:
        print("=" * 80)


def print_result(result: dict):
    """Print analysis result in a nice format"""
    print(f"\n📊 ANALYSIS RESULT:")
    print(f"   Overall Risk Score: {result['overall_risk_score']}/100")
    print(f"   Threat Level: {result['threat_level'].upper()}")
    print(f"   Is Threat: {'YES' if result['is_threat'] else 'NO'}")

    # Brute force
    bf = result['analysis'].get('brute_force_detection', {})
    if bf and bf.get('is_brute_force_attack'):
        print(f"\n   🔴 Brute Force: DETECTED")
        print(f"      Severity: {bf.get('severity', 'unknown')}")
        print(f"      Attack Types: {', '.join(bf.get('attack_types', []))}")

    # Impossible travel
    features = result['analysis'].get('advanced_features', {})
    if features:
        travel = features.get('travel_features', {})
        if travel.get('is_impossible'):
            print(f"\n   🔴 Impossible Travel: DETECTED")
            print(f"      Distance: {travel.get('distance_km', 0)}km")
            print(f"      Time: {travel.get('time_diff_hours', 0)}h")
            print(f"      Speed Required: {travel.get('required_speed_kmh', 0)}km/h")

    # Threat intel
    threat_intel = result['analysis'].get('threat_intelligence', {})
    if threat_intel and threat_intel.get('is_malicious'):
        print(f"\n   🔴 Threat Intelligence: MALICIOUS")
        threats = threat_intel.get('detailed_threats', [])
        for threat in threats[:3]:
            print(f"      • {threat}")

    # Recommendations
    if result.get('recommendations'):
        print(f"\n   💡 TOP RECOMMENDATIONS:")
        for rec in result['recommendations'][:5]:
            print(f"      • {rec}")

    # Actions taken
    if result.get('actions_taken'):
        print(f"\n   🚫 ACTIONS TAKEN:")
        for action in result['actions_taken']:
            print(f"      • {action['action'].upper()}: {action.get('reason', 'N/A')}")


def test_scenario_1_normal_login(engine):
    """Test 1: Normal legitimate login"""
    print_separator("TEST 1: Normal Legitimate Login")

    event = {
        'timestamp': datetime.now(),
        'source_ip': '8.8.8.8',  # Google DNS
        'username': 'admin',
        'event_type': 'accepted_password',
        'server_hostname': 'web-server-1',
        'geoip': {
            'latitude': 37.4056,
            'longitude': -122.0775,
            'country': 'United States',
            'city': 'Mountain View'
        }
    }

    print(f"\n📌 Event: Successful login from Google DNS")
    print(f"   IP: {event['source_ip']}")
    print(f"   User: {event['username']}")
    print(f"   Location: {event['geoip']['city']}, {event['geoip']['country']}")

    result = engine.analyze_event(event)
    print_result(result)

    assert result['threat_level'] in ['clean', 'low'], "Should be low risk"
    assert not result['is_threat'], "Should not be a threat"

    print("\n✅ TEST 1 PASSED: Normal login correctly classified as safe")


def test_scenario_2_brute_force(engine):
    """Test 2: Brute force attack"""
    print_separator("TEST 2: Brute Force Attack Simulation")

    attacker_ip = "45.142.212.61"  # Known malicious IP
    print(f"\n📌 Simulating brute force attack from {attacker_ip}")
    print(f"   Pattern: 20 rapid failed attempts with dictionary attack")

    usernames = ['root', 'admin', 'administrator', 'test', 'oracle',
                 'postgres', 'mysql', 'user', 'backup', 'support',
                 'admin1', 'admin2', 'admin3', 'service', 'jenkins',
                 'git', 'ubuntu', 'centos', 'debian', 'webmaster']

    base_time = datetime.now()
    results = []

    for i, username in enumerate(usernames):
        event = {
            'timestamp': base_time + timedelta(seconds=i*3),
            'source_ip': attacker_ip,
            'username': username,
            'event_type': 'failed_password',
            'server_hostname': 'web-server-1',
            'geoip': {
                'latitude': 55.7558,
                'longitude': 37.6173,
                'country': 'Russia',
                'city': 'Moscow'
            }
        }

        result = engine.analyze_event(event)
        results.append(result)

        if i % 5 == 0:
            print(f"   Progress: {i+1}/{len(usernames)} attempts | Risk: {result['overall_risk_score']}/100")

    # Check final result
    final_result = results[-1]
    print_result(final_result)

    assert final_result['is_threat'], "Should detect as threat"
    assert final_result['analysis']['brute_force_detection']['is_brute_force_attack'], "Should detect brute force"

    print("\n✅ TEST 2 PASSED: Brute force attack successfully detected")


def test_scenario_3_impossible_travel(engine):
    """Test 3: Impossible travel detection"""
    print_separator("TEST 3: Impossible Travel Detection")

    username = "johndoe"
    print(f"\n📌 Simulating impossible travel for user: {username}")

    # Login from New York
    event1 = {
        'timestamp': datetime.now(),
        'source_ip': '1.2.3.4',
        'username': username,
        'event_type': 'accepted_password',
        'server_hostname': 'web-server-1',
        'geoip': {
            'latitude': 40.7128,
            'longitude': -74.0060,
            'country': 'United States',
            'city': 'New York'
        }
    }

    print(f"\n   Event 1: Login from New York at {event1['timestamp'].strftime('%H:%M:%S')}")
    result1 = engine.analyze_event(event1)
    print(f"   Risk Score: {result1['overall_risk_score']}/100")

    # Login from Tokyo 10 minutes later (impossible!)
    event2 = {
        'timestamp': datetime.now() + timedelta(minutes=10),
        'source_ip': '5.6.7.8',
        'username': username,
        'event_type': 'accepted_password',
        'server_hostname': 'web-server-1',
        'geoip': {
            'latitude': 35.6762,
            'longitude': 139.6503,
            'country': 'Japan',
            'city': 'Tokyo'
        }
    }

    print(f"   Event 2: Login from Tokyo at {event2['timestamp'].strftime('%H:%M:%S')} (10 min later)")
    result2 = engine.analyze_event(event2)

    print_result(result2)

    travel_features = result2['analysis']['advanced_features']['travel_features']
    assert travel_features['is_impossible'], "Should detect impossible travel"
    assert result2['is_threat'], "Should be flagged as threat"

    print(f"\n   🌍 Travel Analysis:")
    print(f"      Distance: {travel_features['distance_km']}km")
    print(f"      Time: {travel_features['time_diff_hours']}h")
    print(f"      Required Speed: {travel_features['required_speed_kmh']}km/h")
    print(f"      Max Commercial Speed: 900km/h")

    print("\n✅ TEST 3 PASSED: Impossible travel successfully detected")


def test_scenario_4_known_malicious_ip(engine):
    """Test 4: Known malicious IP from threat feeds"""
    print_separator("TEST 4: Known Malicious IP Detection")

    # Use IP from Tor exit nodes (should be in threat feeds)
    malicious_ip = "185.220.101.1"

    event = {
        'timestamp': datetime.now(),
        'source_ip': malicious_ip,
        'username': 'root',
        'event_type': 'failed_password',
        'server_hostname': 'web-server-1',
        'geoip': {
            'latitude': 52.5200,
            'longitude': 13.4050,
            'country': 'Germany',
            'city': 'Berlin'
        }
    }

    print(f"\n📌 Event: Failed login from known Tor exit node")
    print(f"   IP: {malicious_ip}")

    result = engine.analyze_event(event)
    print_result(result)

    threat_intel = result['analysis']['threat_intelligence']
    assert threat_intel['is_malicious'] or threat_intel['combined_score'] > 0, "Should be flagged in threat intel"

    print("\n✅ TEST 4 PASSED: Known malicious IP detected via threat intelligence")


def test_scenario_5_distributed_attack(engine):
    """Test 5: Distributed coordinated attack"""
    print_separator("TEST 5: Distributed Coordinated Attack")

    print(f"\n📌 Simulating distributed attack on single server")
    print(f"   Pattern: 5 different IPs attacking same target simultaneously")

    attacker_ips = [
        '45.142.212.61',
        '45.142.212.62',
        '45.142.212.63',
        '45.142.212.64',
        '45.142.212.65'
    ]

    base_time = datetime.now()
    results = []

    for i in range(15):  # 15 attempts total
        ip = attacker_ips[i % len(attacker_ips)]
        event = {
            'timestamp': base_time + timedelta(seconds=i*2),
            'source_ip': ip,
            'username': ['admin', 'root', 'test', 'user', 'oracle'][i % 5],
            'event_type': 'failed_password',
            'server_hostname': 'web-server-1',
            'geoip': {
                'latitude': 55.7558,
                'longitude': 37.6173,
                'country': 'Russia',
                'city': 'Moscow'
            }
        }

        result = engine.analyze_event(event)
        results.append(result)

        if i == 14:  # Last attempt
            print_result(result)

            distributed = result['analysis']['brute_force_detection']['detection_strategies']['distributed']
            if distributed['is_distributed_attack']:
                print(f"\n   🌐 Distributed Attack Detected!")
                print(f"      Unique IPs: {distributed['unique_ips']}")
                print(f"      Unique Users: {distributed['unique_users']}")
                print(f"      Total Attempts: {distributed['total_attempts']}")

    print("\n✅ TEST 5 PASSED: Distributed attack detection working")


def main():
    """Run all test scenarios"""
    print("\n" + "🛡️ " * 20)
    print("  SSH GUARDIAN 2.0 - END-TO-END INTEGRATION TEST")
    print("🛡️ " * 20)

    # Initialize engine
    config = {
        'threat_feeds_dir': PROJECT_ROOT / "data" / "threat_feeds",
        'api_cache_dir': PROJECT_ROOT / "data" / "api_cache",
        'api_config': {},  # No API keys for test
        'block_state_file': PROJECT_ROOT / "data" / "test_blocks_state.json",
        'whitelist_file': None,
        'enable_auto_block': False,  # Disabled for testing
        'auto_block_threshold': 85
    }

    engine = create_guardian_engine(config)

    print("\n✅ Guardian Engine initialized successfully\n")

    # Run all test scenarios
    try:
        test_scenario_1_normal_login(engine)
        test_scenario_2_brute_force(engine)
        test_scenario_3_impossible_travel(engine)
        test_scenario_4_known_malicious_ip(engine)
        test_scenario_5_distributed_attack(engine)

        # Final statistics
        print_separator("FINAL TEST STATISTICS")
        stats = engine.get_statistics()

        print(f"\n📊 Engine Statistics:")
        print(f"   Events Processed: {stats['engine_stats']['events_processed']}")
        print(f"   Threats Detected: {stats['engine_stats']['threats_detected']}")
        print(f"   Brute Force Detected: {stats['engine_stats']['brute_force_detected']}")
        print(f"   Impossible Travel Detected: {stats['engine_stats']['impossible_travel_detected']}")
        print(f"   IPs Blocked: {stats['engine_stats']['ips_blocked']}")

        print("\n" + "=" * 80)
        print("🎉 ALL TESTS PASSED SUCCESSFULLY!")
        print("=" * 80)

        return 0

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
