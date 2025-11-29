"""
SSH Log Agent
Monitors local SSH logs and sends them to central receiver
Runs on remote servers
"""
import time
import socket
import requests
import json
from datetime import datetime

class LogAgent:
    def __init__(self, receiver_url, server_name=None, log_file='/var/log/auth.log'):
        self.receiver_url = receiver_url
        self.server_name = server_name or socket.gethostname()
        self.log_file = log_file
        self.last_position = 0
        
    def read_new_logs(self):
        """Read new log lines since last check"""
        try:
            with open(self.log_file, 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
                # Filter only sshd logs
                ssh_lines = [line.strip() for line in new_lines if 'sshd' in line.lower()]
                return ssh_lines
        except Exception as e:
            print(f"❌ Error reading logs: {e}")
            return []
    
    def send_logs(self, logs):
        """Send logs to receiver"""
        if not logs:
            return True
            
        payload = {
            "server_name": self.server_name,
            "logs": logs
        }
        
        try:
            response = requests.post(
                f"{self.receiver_url}/logs/upload",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"✅ Sent {len(logs)} logs to receiver")
                return True
            else:
                print(f"⚠️  Failed to send logs: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error sending logs: {e}")
            return False
    
    def run(self, interval=5):
        """Main monitoring loop"""
        print("=" * 70)
        print("🔍 SSH LOG AGENT STARTED")
        print("=" * 70)
        print(f"📁 Monitoring: {self.log_file}")
        print(f"🖥️  Server: {self.server_name}")
        print(f"🌐 Receiver: {self.receiver_url}")
        print(f"⏱️  Interval: {interval}s")
        print("=" * 70)
        
        # Initialize position (start from end)
        try:
            with open(self.log_file, 'r') as f:
                f.seek(0, 2)  # Go to end
                self.last_position = f.tell()
            print(f"✅ Initialized at position: {self.last_position}")
        except Exception as e:
            print(f"❌ Error initializing: {e}")
            return
        
        print("\n🔄 Monitoring started... (Ctrl+C to stop)\n")
        
        try:
            while True:
                new_logs = self.read_new_logs()
                
                if new_logs:
                    print(f"📊 Found {len(new_logs)} new SSH events")
                    self.send_logs(new_logs)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Agent stopped by user")

if __name__ == "__main__":
    # Configuration
    RECEIVER_URL = "http://31.220.94.187:5000"  # Change to your server IP
    
    # Get server name
    server_name = input("Enter server name (press Enter for hostname): ").strip()
    if not server_name:
        server_name = socket.gethostname()
    
    # Create and run agent
    agent = LogAgent(
        receiver_url=RECEIVER_URL,
        server_name=server_name,
        log_file='/var/log/auth.log'
    )
    
    agent.run(interval=5)