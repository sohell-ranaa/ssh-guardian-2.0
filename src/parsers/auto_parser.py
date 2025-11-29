"""
Auto Parser for Streaming Logs
Monitors receiving_stream folder and auto-parses new logs
"""
import os
import time
from ssh_log_parser import SSHLogParser
import json

class AutoParser:
    def __init__(self, watch_dir="data/receiving_stream", output_dir="data/parsed_json"):
        self.watch_dir = watch_dir
        self.output_dir = output_dir
        self.parser = SSHLogParser()
        self.processed_positions = {}  # Track file positions
        
        # Create directories
        os.makedirs(watch_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
    
    def get_server_name_from_file(self, filename):
        """Extract server name from authlog_SERVERNAME.log"""
        if filename.startswith('authlog_') and filename.endswith('.log'):
            return filename[8:-4]  # Remove 'authlog_' and '.log'
        return None
    
    def parse_and_save(self, filepath, server_name):
        """Parse new logs from file and save to organized JSON"""
        # Get last processed position
        last_pos = self.processed_positions.get(filepath, 0)
        
        # Read new lines
        try:
            with open(filepath, 'r') as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                current_pos = f.tell()
            
            if not new_lines:
                return 0
            
            # Parse each line
            events = []
            for line in new_lines:
                parsed = self.parser.parse_line(line.strip())
                if parsed:
                    events.append(parsed)
            
            if not events:
                self.processed_positions[filepath] = current_pos
                return 0
            
            # Group by date
            events_by_date = {}
            for event in events:
                if event.get('datetime'):
                    date_str = str(event['datetime']).split()[0]
                    if date_str not in events_by_date:
                        events_by_date[date_str] = []
                    events_by_date[date_str].append(event)
            
            # Save to organized JSON
            saved_count = 0
            for date, date_events in events_by_date.items():
                output_dir = f"{self.output_dir}/{server_name}/{date}"
                os.makedirs(output_dir, exist_ok=True)
                
                output_file = f"{output_dir}/{server_name}.json"
                
                # Load existing data if file exists
                existing_events = []
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        existing_events = json.load(f)
                
                # Append new events
                existing_events.extend(date_events)
                
                # Save combined data
                with open(output_file, 'w') as f:
                    json.dump(existing_events, f, default=str, indent=2)
                
                saved_count += len(date_events)
                print(f"  📁 {date}: +{len(date_events)} events → {output_file}")
            
            # Update position
            self.processed_positions[filepath] = current_pos
            return saved_count
            
        except Exception as e:
            print(f"❌ Error parsing {filepath}: {e}")
            return 0
    
    def scan_and_parse(self):
        """Scan watch directory and parse all streaming files"""
        files = [f for f in os.listdir(self.watch_dir) if f.startswith('authlog_')]
        
        if not files:
            return 0
        
        total_parsed = 0
        for filename in files:
            filepath = os.path.join(self.watch_dir, filename)
            server_name = self.get_server_name_from_file(filename)
            
            if server_name:
                parsed_count = self.parse_and_save(filepath, server_name)
                if parsed_count > 0:
                    print(f"✅ {server_name}: Parsed {parsed_count} new events")
                    total_parsed += parsed_count
        
        return total_parsed
    
    def run(self, interval=10):
        """Main monitoring loop"""
        print("=" * 70)
        print("🔄 AUTO PARSER STARTED")
        print("=" * 70)
        print(f"📁 Watching: {self.watch_dir}")
        print(f"💾 Output: {self.output_dir}")
        print(f"⏱️  Interval: {interval}s")
        print("=" * 70)
        print("\n🔍 Monitoring for new logs... (Ctrl+C to stop)\n")
        
        try:
            while True:
                total = self.scan_and_parse()
                if total > 0:
                    print(f"📊 Total parsed this cycle: {total}\n")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Auto-parser stopped by user")

if __name__ == "__main__":
    parser = AutoParser()
    parser.run(interval=10)