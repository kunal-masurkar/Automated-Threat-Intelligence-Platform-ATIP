import argparse
import json
import logging
from atip_core import ThreatIntelligencePlatform

def main():
    """Main entry point for the ATIP application."""
    parser = argparse.ArgumentParser(description='Automated Threat Intelligence Platform')
    parser.add_argument('--config', type=str, default='config.json', help='Path to configuration file')
    parser.add_argument('--mode', type=str, choices=['run', 'collect', 'analyze', 'report'], default='run', 
                        help='Operation mode')
    parser.add_argument('--report-period', type=str, choices=['24h', '7d', '30d'], default='24h',
                        help='Report time period')
    parser.add_argument('--output', type=str, help='Output file for report')
    args = parser.parse_args()
    
    # Initialize the platform
    platform = ThreatIntelligencePlatform(args.config)
    
    if args.mode == 'run':
        # Run the main platform loop
        platform.run()
    elif args.mode == 'collect':
        # Just collect data
        threats = platform.collect_data()
        print(f"Collected {len(threats)} threats")
    elif args.mode == 'analyze':
        # Analyze existing data
        findings = platform.analyze_data()
        print(f"Analysis found {len(findings)} insights")
        for finding in findings:
            print(f"- {finding['description']} (Severity: {finding['severity']})")
    elif args.mode == 'report':
        # Generate a report
        report = platform.generate_report(args.report_period)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report saved to {args.output}")
        else:
            print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
