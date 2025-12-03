#!/usr/bin/env python3
"""
Generate ML Effectiveness Report
Command-line tool to prove ML implementation and effectiveness
"""

import sys
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "src"))

from ml.analytics.ml_effectiveness_tracker import MLEffectivenessTracker


def main():
    parser = argparse.ArgumentParser(
        description='Generate ML Effectiveness Report for SSH Guardian 2.0'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Number of days to analyze (default: 7)'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output file path (default: print to stdout)'
    )
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )

    args = parser.parse_args()

    print(f"🔍 Analyzing ML effectiveness for the last {args.days} days...")
    print()

    tracker = MLEffectivenessTracker()

    if args.format == 'json':
        import json
        metrics = tracker.get_ml_performance_metrics(args.days)
        comparison = tracker.compare_ml_vs_baseline(args.days)
        model_info = tracker.get_ml_model_info()

        output = {
            'model_info': model_info,
            'performance_metrics': metrics,
            'ml_vs_baseline_comparison': comparison
        }

        json_output = json.dumps(output, indent=2)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(json_output)
            print(f"✅ JSON report saved to: {args.output}")
        else:
            print(json_output)
    else:
        # Text format
        report = tracker.generate_effectiveness_report(args.days)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"✅ Report saved to: {args.output}")
            print()
            print("Preview:")
            print(report[:500] + "...")
        else:
            print(report)

    tracker.close()


if __name__ == '__main__':
    main()
