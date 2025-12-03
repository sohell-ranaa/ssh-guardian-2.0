#!/usr/bin/env python3
"""
Quick test script for simulation functionality
"""
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "src"))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from src.simulation.simulator import AttackSimulator

def test_simulation():
    print("="*80)
    print("🧪 Testing Attack Simulation")
    print("="*80)

    simulator = AttackSimulator(guardian_api_url="http://localhost:5000")

    try:
        result = simulator.execute(
            template_name="brute_force",
            custom_params=None,
            user_id=1,
            user_email="test@example.com"
        )

        print("\n✅ Simulation completed!")
        print(f"Simulation ID: {result['simulation_id']}")
        print(f"Status: {result['status']}")
        print(f"\nSummary:")
        for key, value in result['summary'].items():
            print(f"  {key}: {value}")

        print(f"\n📝 Total log entries: {len(result['logs'])}")

        return True

    except Exception as e:
        print(f"\n❌ Simulation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_simulation()
    sys.exit(0 if success else 1)
