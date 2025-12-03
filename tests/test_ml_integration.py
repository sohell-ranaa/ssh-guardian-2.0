#!/usr/bin/env python3
"""
Quick test to verify ML integration is working correctly
"""

import sys
from pathlib import Path
from datetime import datetime

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent
sys.path.append(str(PROJECT_ROOT))

from src.core.enhanced_guardian_engine import create_enhanced_guardian_engine

def test_ml_integration():
    """Test the ML integration with sample events"""

    print("="*80)
    print("🧪 TESTING ML INTEGRATION")
    print("="*80)

    # Create enhanced config
    config = {
        'threat_feeds_dir': PROJECT_ROOT / "data" / "threat_feeds",
        'api_cache_dir': PROJECT_ROOT / "data" / "api_cache",
        'api_config': {},
        'block_state_file': PROJECT_ROOT / "data" / "blocks_state_test.json",
        'whitelist_file': PROJECT_ROOT / "data" / "ip_whitelist.txt",
        'enable_auto_block': False,  # Disable for testing
        'auto_block_threshold': 85,
        'whitelist_ips': [],
        'telegram': {
            'bot_token': '',
            'chat_id': '',
            'smart_grouping': True
        }
    }

    # Create engine
    print("\n1️⃣  Creating Enhanced Guardian Engine...")
    engine = create_enhanced_guardian_engine(config)

    # Test events
    test_events = [
        {
            'timestamp': datetime.now(),
            'source_ip': '203.0.113.45',  # Known malicious IP pattern
            'username': 'root',
            'server_hostname': 'test-server',
            'port': 22,
            'event_type': 'failed_password',
            'country': 'China',
            'city': 'Beijing',
            'latitude': 39.9042,
            'longitude': 116.4074
        },
        {
            'timestamp': datetime.now(),
            'source_ip': '192.168.1.100',  # Whitelisted private IP
            'username': 'admin',
            'server_hostname': 'test-server',
            'port': 22,
            'event_type': 'accepted_password',
            'country': 'Local Network',
            'city': 'Private IP',
            'latitude': None,
            'longitude': None
        },
        {
            'timestamp': datetime.now(),
            'source_ip': '185.220.101.50',  # Suspicious IP
            'username': 'admin',
            'server_hostname': 'test-server',
            'port': 22,
            'event_type': 'failed_password',
            'country': 'Russia',
            'city': 'Moscow',
            'latitude': 55.7558,
            'longitude': 37.6173
        }
    ]

    print("\n2️⃣  Testing with sample events...\n")

    for i, event in enumerate(test_events, 1):
        print(f"\n{'='*80}")
        print(f"Test Event #{i}: {event['source_ip']} - {event['event_type']}")
        print(f"{'='*80}")

        # Analyze event
        result = engine.analyze_event(event)

        # Display results
        classification = result.get('classification', {})
        ml_prediction = result.get('ml_prediction', {})

        print(f"\n📊 ML Prediction:")
        print(f"   ML Available: {ml_prediction.get('ml_available', False)}")
        if ml_prediction.get('ml_available'):
            print(f"   Risk Score: {ml_prediction.get('risk_score', 0)}/100")
            print(f"   Confidence: {ml_prediction.get('confidence', 0):.2%}")
            print(f"   Is Anomaly: {ml_prediction.get('is_anomaly', False)}")
            print(f"   Threat Type: {ml_prediction.get('threat_type', 'unknown')}")

        print(f"\n🎯 Classification:")
        print(f"   Threat Level: {classification.get('threat_level', 'unknown').upper()}")
        print(f"   Risk Score: {classification.get('risk_score', 0)}/100")
        print(f"   Action: {classification.get('action', 'unknown')}")
        print(f"   Alert Priority: {classification.get('alert_priority', 'unknown')}")
        if classification.get('block_duration_hours'):
            print(f"   Block Duration: {classification.get('block_duration_hours')}h")

        print(f"\n💡 Reasons:")
        for reason in classification.get('reasons', [])[:5]:
            print(f"   • {reason}")

        print(f"\n✅ Overall Risk: {result.get('overall_risk_score', 0)}/100")

    # Get statistics
    print("\n" + "="*80)
    print("📈 STATISTICS")
    print("="*80)

    stats = engine.get_statistics()
    print(f"\nEvents Processed: {stats.get('events_processed', 0)}")
    print(f"ML Predictions: {stats.get('ml_predictions', 0)}")
    print(f"Threats Detected: {stats.get('threats_detected', 0)}")
    print(f"IPs Blocked: {stats.get('ips_blocked', 0)}")
    print(f"Alerts Sent: {stats.get('alerts_sent', 0)}")

    ml_stats = stats.get('ml_stats', {})
    if ml_stats:
        print(f"\nML Stats:")
        print(f"   ML Enabled: {ml_stats.get('ml_enabled', False)}")
        print(f"   Random Forest Loaded: {ml_stats.get('random_forest_loaded', False)}")
        print(f"   Isolation Forest Loaded: {ml_stats.get('isolation_forest_loaded', False)}")

    print("\n" + "="*80)
    print("✅ ML INTEGRATION TEST COMPLETE")
    print("="*80)

    if ml_stats.get('ml_enabled'):
        print("\n🎉 SUCCESS: ML models are loaded and working!")
    else:
        print("\n⚠️  WARNING: ML models not loaded - check models directory")

if __name__ == '__main__':
    test_ml_integration()
