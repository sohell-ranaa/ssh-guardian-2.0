#!/usr/bin/env python3
"""
Quick test to verify Telegram notifications work during simulation
"""

import sys
from pathlib import Path

# Add project to path
PROJECT_ROOT = Path(__file__).parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from src.simulation.simulator import AttackSimulator

def main():
    print("=" * 60)
    print("SSH Guardian 2.0 - Simulation Telegram Test")
    print("=" * 60)
    print()

    # Initialize simulator
    print("Initializing simulator...")
    simulator = AttackSimulator(guardian_api_url="http://localhost:5000")

    if simulator.alert_manager:
        print("✅ Telegram alerting is ENABLED")
        print()
    else:
        print("❌ Telegram alerting is DISABLED")
        print("   Check your .env file for TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")
        return

    # Run a simple brute force simulation that should trigger a block
    print("Running brute force simulation (should trigger Telegram alert)...")
    print()

    try:
        result = simulator.execute(
            template_name='brute_force_basic',
            user_email='test@example.com'
        )

        print()
        print("=" * 60)
        print("SIMULATION RESULTS")
        print("=" * 60)
        print(f"Simulation ID: {result['simulation_id']}")
        print(f"Status: {result['status']}")
        print()
        print("Summary:")
        for key, value in result['summary'].items():
            print(f"  {key}: {value}")
        print()

        if result['summary'].get('ips_blocked', 0) > 0:
            print("✅ IPs were blocked - Telegram alerts should have been sent!")
        else:
            print("⚠️ No IPs were blocked - check ML risk thresholds")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
