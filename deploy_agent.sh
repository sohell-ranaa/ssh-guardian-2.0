#!/bin/bash
#
# SSH Guardian 2.0 - Agent Deployment Script
# Deploys log agent on remote servers
#

set -e

echo "================================================================================"
echo "🤖 SSH GUARDIAN LOG AGENT - DEPLOYMENT"
echo "================================================================================"

# Get Guardian server URL
read -p "Enter SSH Guardian server URL (e.g., http://192.168.1.100:5000): " GUARDIAN_URL

if [ -z "$GUARDIAN_URL" ]; then
    echo "❌ Guardian URL is required"
    exit 1
fi

# Get server name
HOSTNAME=$(hostname)
read -p "Enter server name (default: $HOSTNAME): " SERVER_NAME
SERVER_NAME=${SERVER_NAME:-$HOSTNAME}

echo ""
echo "📋 Configuration:"
echo "   Guardian URL: $GUARDIAN_URL"
echo "   Server Name: $SERVER_NAME"
echo ""

# Create agent directory
AGENT_DIR="/opt/ssh-guardian-agent"
echo "📁 Creating agent directory: $AGENT_DIR"

if [ "$EUID" -ne 0 ]; then
    echo "⚠️  This script requires sudo/root privileges"
    echo "   Run: sudo ./deploy_agent.sh"
    exit 1
fi

mkdir -p $AGENT_DIR

# Create agent script
echo "📝 Creating agent script..."

cat > $AGENT_DIR/agent.py << 'AGENT_SCRIPT'
#!/usr/bin/env python3
"""
SSH Guardian Log Agent
Monitors SSH logs and sends to central Guardian server
"""

import time
import socket
import requests
import json
import sys
from datetime import datetime
from pathlib import Path

class SSHGuardianAgent:
    def __init__(self, guardian_url, server_name, log_file='/var/log/auth.log'):
        self.guardian_url = guardian_url.rstrip('/')
        self.server_name = server_name
        self.log_file = log_file
        self.last_position = 0
        self.state_file = Path('/var/lib/ssh-guardian-agent/state.json')

        # Load last position
        self.load_state()

    def load_state(self):
        """Load last read position from state file"""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    self.last_position = state.get('last_position', 0)
                    print(f"[INFO] Loaded state: position {self.last_position}")
        except Exception as e:
            print(f"[WARN] Could not load state: {e}")
            self.last_position = 0

    def save_state(self):
        """Save current position to state file"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump({
                    'last_position': self.last_position,
                    'last_update': datetime.now().isoformat()
                }, f)
        except Exception as e:
            print(f"[ERROR] Could not save state: {e}")

    def read_new_logs(self):
        """Read new SSH log lines since last check"""
        try:
            with open(self.log_file, 'r') as f:
                # Seek to last position
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()

                # Filter only SSH lines
                ssh_lines = [
                    line.strip() for line in new_lines
                    if 'sshd' in line.lower() or 'ssh' in line.lower()
                ]

                return ssh_lines

        except FileNotFoundError:
            print(f"[ERROR] Log file not found: {self.log_file}")
            return []
        except Exception as e:
            print(f"[ERROR] Error reading logs: {e}")
            return []

    def send_logs(self, logs):
        """Send logs to Guardian server"""
        if not logs:
            return True

        payload = {
            "server_name": self.server_name,
            "logs": logs,
            "timestamp": datetime.now().isoformat()
        }

        try:
            response = requests.post(
                f"{self.guardian_url}/logs/upload",
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                print(f"[OK] Sent {len(logs)} logs to Guardian")
                return True
            else:
                print(f"[ERROR] Guardian returned status {response.status_code}")
                return False

        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Cannot connect to Guardian at {self.guardian_url}")
            return False
        except Exception as e:
            print(f"[ERROR] Error sending logs: {e}")
            return False

    def run(self, interval=5):
        """Main monitoring loop"""
        print("=" * 70)
        print("🛡️  SSH GUARDIAN LOG AGENT")
        print("=" * 70)
        print(f"Server Name: {self.server_name}")
        print(f"Guardian URL: {self.guardian_url}")
        print(f"Log File: {self.log_file}")
        print(f"Check Interval: {interval}s")
        print("=" * 70)

        # Initialize position if starting fresh
        if self.last_position == 0:
            try:
                with open(self.log_file, 'r') as f:
                    f.seek(0, 2)  # Go to end
                    self.last_position = f.tell()
                print(f"[INFO] Starting from end of file (position: {self.last_position})")
            except Exception as e:
                print(f"[ERROR] Could not initialize: {e}")
                return

        print("\n[INFO] Monitoring started... (Ctrl+C to stop)\n")

        consecutive_failures = 0

        try:
            while True:
                new_logs = self.read_new_logs()

                if new_logs:
                    print(f"[INFO] Found {len(new_logs)} new SSH events")

                    if self.send_logs(new_logs):
                        self.save_state()
                        consecutive_failures = 0
                    else:
                        consecutive_failures += 1
                        if consecutive_failures >= 5:
                            print("[WARN] 5 consecutive failures, check Guardian server")

                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n\n[INFO] Agent stopped by user")
            self.save_state()
        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
            self.save_state()

if __name__ == "__main__":
    # Read configuration from environment or command line
    import os

    guardian_url = os.getenv('GUARDIAN_URL', 'REPLACE_GUARDIAN_URL')
    server_name = os.getenv('SERVER_NAME', 'REPLACE_SERVER_NAME')
    log_file = os.getenv('LOG_FILE', '/var/log/auth.log')
    interval = int(os.getenv('CHECK_INTERVAL', '5'))

    # Create and run agent
    agent = SSHGuardianAgent(
        guardian_url=guardian_url,
        server_name=server_name,
        log_file=log_file
    )

    agent.run(interval=interval)
AGENT_SCRIPT

# Replace placeholders
sed -i "s|REPLACE_GUARDIAN_URL|$GUARDIAN_URL|g" $AGENT_DIR/agent.py
sed -i "s|REPLACE_SERVER_NAME|$SERVER_NAME|g" $AGENT_DIR/agent.py

chmod +x $AGENT_DIR/agent.py

echo "   ✅ Agent script created"

# Install Python requests if not present
echo ""
echo "📦 Installing Python dependencies..."
if command -v pip3 &> /dev/null; then
    pip3 install requests --quiet || echo "⚠️  Could not install requests, please install manually"
else
    echo "⚠️  pip3 not found, please install: pip3 install requests"
fi

# Create systemd service
echo ""
echo "🔧 Creating systemd service..."

cat > /etc/systemd/system/ssh-guardian-agent.service << EOF
[Unit]
Description=SSH Guardian Log Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $AGENT_DIR/agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security
User=root
WorkingDirectory=$AGENT_DIR

[Install]
WantedBy=multi-user.target
EOF

echo "   ✅ Systemd service created"

# Reload systemd
systemctl daemon-reload
echo "   ✅ Systemd reloaded"

# Enable and start service
echo ""
echo "🚀 Starting agent..."
systemctl enable ssh-guardian-agent
systemctl start ssh-guardian-agent

sleep 2

# Check status
if systemctl is-active --quiet ssh-guardian-agent; then
    echo "   ✅ Agent is running!"
else
    echo "   ❌ Agent failed to start"
    echo "   Check status: systemctl status ssh-guardian-agent"
    exit 1
fi

echo ""
echo "================================================================================"
echo "✅ AGENT DEPLOYMENT COMPLETE!"
echo "================================================================================"
echo ""
echo "📋 Management Commands:"
echo "   Status:  systemctl status ssh-guardian-agent"
echo "   Stop:    systemctl stop ssh-guardian-agent"
echo "   Start:   systemctl start ssh-guardian-agent"
echo "   Restart: systemctl restart ssh-guardian-agent"
echo "   Logs:    journalctl -u ssh-guardian-agent -f"
echo ""
echo "================================================================================"
