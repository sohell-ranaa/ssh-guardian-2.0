#!/bin/bash
# SSH Guardian Agent - Installation Manager
# Interactive menu for install/uninstall/status

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/ssh-guardian-agent"
SERVICE_NAME="ssh-guardian-agent"

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}❌ Please run as root (use sudo)${NC}"
        exit 1
    fi
}

# Check if agent is installed
is_installed() {
    [ -d "$INSTALL_DIR" ] && [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]
}

# Check if service is running
is_running() {
    systemctl is-active --quiet $SERVICE_NAME
}

# Show header
show_header() {
    clear
    echo "======================================================================"
    echo -e "${BLUE}🔐 SSH Guardian Agent - Installation Manager${NC}"
    echo "======================================================================"
    echo ""
}

# Show status
show_status() {
    echo -e "${YELLOW}Current Status:${NC}"
    if is_installed; then
        echo -e "  Installation: ${GREEN}✅ Installed${NC}"
        echo -e "  Location: $INSTALL_DIR"
        
        if is_running; then
            echo -e "  Service: ${GREEN}✅ Running${NC}"
        else
            echo -e "  Service: ${RED}❌ Stopped${NC}"
        fi
    else
        echo -e "  Installation: ${RED}❌ Not Installed${NC}"
    fi
    echo ""
}

# Install agent
install_agent() {
    show_header
    echo -e "${GREEN}📥 INSTALL AGENT${NC}"
    echo "======================================================================"
    echo ""
    
    if is_installed; then
        echo -e "${YELLOW}⚠️  Agent is already installed!${NC}"
        read -p "Reinstall? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return
        fi
        uninstall_agent_silent
    fi
    
    # Get configuration
    read -p "Enter receiver URL (e.g., http://YOUR_IP:5000): " RECEIVER_URL
    read -p "Enter server name [$(hostname)]: " SERVER_NAME
    SERVER_NAME=${SERVER_NAME:-$(hostname)}
    
    echo ""
    echo "Configuration:"
    echo "  Receiver: $RECEIVER_URL"
    echo "  Server: $SERVER_NAME"
    echo ""
    read -p "Continue with installation? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return
    fi
    
    echo ""
    echo "======================================================================"
    echo "Starting installation with verbose output..."
    echo "======================================================================"
    echo ""
    
    # Create log file
    LOG_FILE="/tmp/ssh-guardian-install.log"
    
    echo "📦 Step 1/6: Updating package list..."
    if apt-get update -qq 2>&1 | tee -a $LOG_FILE; then
        echo -e "${GREEN}✅ Package list updated${NC}"
    else
        echo -e "${RED}❌ Failed to update package list${NC}"
        echo "Check log: $LOG_FILE"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo ""
    echo "📦 Step 2/6: Installing Python dependencies..."
    if apt-get install -y python3 python3-pip python3-venv 2>&1 | tee -a $LOG_FILE; then
        echo -e "${GREEN}✅ Dependencies installed${NC}"
    else
        echo -e "${RED}❌ Failed to install dependencies${NC}"
        echo "Check log: $LOG_FILE"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo ""
    echo "📁 Step 3/6: Creating directory: $INSTALL_DIR"
    mkdir -p $INSTALL_DIR
    cd $INSTALL_DIR
    echo -e "${GREEN}✅ Directory created${NC}"
    
    echo ""
    echo "🐍 Step 4/6: Setting up Python virtual environment..."
    if python3 -m venv venv 2>&1 | tee -a $LOG_FILE; then
        echo -e "${GREEN}✅ Virtual environment created${NC}"
    else
        echo -e "${RED}❌ Failed to create virtual environment${NC}"
        echo "Check log: $LOG_FILE"
        read -p "Press Enter to continue..."
        return
    fi
    
    source venv/bin/activate
    
    echo ""
    echo "📦 Step 5/6: Installing Python packages..."
    if pip install requests 2>&1 | tee -a $LOG_FILE; then
        echo -e "${GREEN}✅ Python packages installed${NC}"
    else
        echo -e "${RED}❌ Failed to install Python packages${NC}"
        echo "Check log: $LOG_FILE"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo ""
    echo "⬇️  Step 6/6: Creating agent script..."
    cat > log_agent.py << 'AGENT_SCRIPT'
"""
SSH Log Agent - Enterprise Grade
Monitors local SSH logs and sends them to central receiver
"""
import time
import socket
import requests
import sys
import os
from datetime import datetime

class LogAgent:
    def __init__(self, receiver_url, server_name, log_file='/var/log/auth.log'):
        self.receiver_url = receiver_url
        self.server_name = server_name
        self.log_file = log_file
        self.last_position = 0
        self.last_inode = None
        
    def check_log_rotation(self):
        """Detect if log file was rotated"""
        try:
            current_inode = os.stat(self.log_file).st_ino
            if self.last_inode and current_inode != self.last_inode:
                print(f"🔄 Log rotation detected, resetting position")
                self.last_position = 0
            self.last_inode = current_inode
        except Exception as e:
            print(f"⚠️  Error checking log rotation: {e}")
    
    def read_new_logs(self):
        """Read new log lines since last check"""
        try:
            self.check_log_rotation()
            
            with open(self.log_file, 'r') as f:
                file_size = os.path.getsize(self.log_file)
                if file_size < self.last_position:
                    print(f"🔄 File truncated, resetting position")
                    self.last_position = 0
                
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
                ssh_lines = [line.strip() for line in new_lines if 'sshd' in line.lower()]
                return ssh_lines
        except Exception as e:
            print(f"❌ Error reading logs: {e}")
            return []
    
    def send_logs(self, logs):
        """Send logs to receiver with retry"""
        if not logs:
            return True
            
        payload = {
            "server_name": self.server_name,
            "logs": logs
        }
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    f"{self.receiver_url}/logs/upload",
                    json=payload,
                    timeout=10
                )
                
                if response.status_code == 200:
                    return True
                else:
                    print(f"⚠️  Failed (attempt {attempt+1}/{max_retries}): {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Error (attempt {attempt+1}/{max_retries}): {e}")
            
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
        
        return False
    
    def health_check(self):
        """Verify receiver is reachable"""
        try:
            response = requests.get(f"{self.receiver_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def run(self, interval=5):
        """Main monitoring loop"""
        print(f"🔍 SSH Guardian Agent Started")
        print(f"   Server: {self.server_name}")
        print(f"   Receiver: {self.receiver_url}")
        
        if not self.health_check():
            print(f"⚠️  Warning: Cannot reach receiver at startup")
        
        try:
            with open(self.log_file, 'r') as f:
                f.seek(0, 2)
                self.last_position = f.tell()
                self.last_inode = os.stat(self.log_file).st_ino
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
        
        print(f"✅ Monitoring started (interval: {interval}s)\n")
        
        cycle = 0
        try:
            while True:
                new_logs = self.read_new_logs()
                if new_logs:
                    success = self.send_logs(new_logs)
                    if success:
                        print(f"✅ Sent {len(new_logs)} logs")
                
                cycle += 1
                if cycle % 12 == 0:
                    if not self.health_check():
                        print(f"⚠️  Receiver unreachable")
                
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n🛑 Agent stopped")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 log_agent.py <receiver_url> <server_name>")
        sys.exit(1)
    
    agent = LogAgent(
        receiver_url=sys.argv[1],
        server_name=sys.argv[2]
    )
    agent.run(interval=5)
AGENT_SCRIPT

    echo -e "${GREEN}✅ Agent script created${NC}"
    
    echo ""
    echo "⚙️  Creating systemd service..."
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=SSH Guardian Log Agent
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/log_agent.py $RECEIVER_URL $SERVER_NAME

# Resource Limits
MemoryMax=100M
MemoryHigh=80M
CPUQuota=20%

# Restart Policy
Restart=always
RestartSec=10
StartLimitBurst=5

# Security
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    echo -e "${GREEN}✅ Service file created${NC}"
    
    echo ""
    echo "🚀 Enabling and starting service..."
    systemctl daemon-reload 2>&1 | tee -a $LOG_FILE
    
    if systemctl enable $SERVICE_NAME 2>&1 | tee -a $LOG_FILE; then
        echo -e "${GREEN}✅ Service enabled${NC}"
    else
        echo -e "${RED}❌ Failed to enable service${NC}"
    fi
    
    if systemctl start $SERVICE_NAME 2>&1 | tee -a $LOG_FILE; then
        echo -e "${GREEN}✅ Service started${NC}"
    else
        echo -e "${RED}❌ Failed to start service${NC}"
        echo ""
        echo "Service logs:"
        journalctl -u $SERVICE_NAME -n 20 --no-pager
    fi
    
    sleep 2
    echo ""
    echo "======================================================================"
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "${GREEN}✅ Installation Complete & Service Running!${NC}"
    else
        echo -e "${YELLOW}⚠️  Installation Complete but Service Failed to Start${NC}"
        echo ""
        echo "Troubleshooting:"
        echo "  1. Check service status: sudo systemctl status $SERVICE_NAME"
        echo "  2. View logs: sudo journalctl -u $SERVICE_NAME -n 50"
        echo "  3. Installation log: $LOG_FILE"
    fi
    echo "======================================================================"
    echo ""
    read -p "Press Enter to continue..."
}

# Uninstall agent (silent for reinstall)
uninstall_agent_silent() {
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload
    rm -rf $INSTALL_DIR
}

# Uninstall agent (interactive)
uninstall_agent() {
    show_header
    echo -e "${RED}🗑️  UNINSTALL AGENT${NC}"
    echo "======================================================================"
    echo ""
    
    if ! is_installed; then
        echo -e "${YELLOW}Agent is not installed!${NC}"
        echo ""
        read -p "Press Enter to continue..."
        return
    fi
    
    echo -e "${YELLOW}⚠️  This will completely remove the SSH Guardian Agent${NC}"
    echo ""
    read -p "Are you sure? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return
    fi
    
    echo ""
    echo "🛑 Stopping service..."
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    
    echo "❌ Disabling service..."
    systemctl disable $SERVICE_NAME 2>/dev/null || true
    
    echo "🗑️  Removing files..."
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload
    rm -rf $INSTALL_DIR
    
    echo ""
    echo -e "${GREEN}✅ Uninstallation complete!${NC}"
    echo ""
    read -p "Press Enter to continue..."
}

# View logs
view_logs() {
    show_header
    echo -e "${BLUE}📋 VIEW LOGS${NC}"
    echo "======================================================================"
    echo ""
    
    if ! is_installed; then
        echo -e "${YELLOW}Agent is not installed!${NC}"
        echo ""
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Showing last 50 lines (Press Ctrl+C to exit live mode):"
    echo ""
    journalctl -u $SERVICE_NAME -n 50 -f
}

# Start/Stop/Restart service
manage_service() {
    local action=$1
    
    show_header
    echo -e "${BLUE}⚙️  MANAGE SERVICE${NC}"
    echo "======================================================================"
    echo ""
    
    if ! is_installed; then
        echo -e "${YELLOW}Agent is not installed!${NC}"
        echo ""
        read -p "Press Enter to continue..."
        return
    fi
    
    case $action in
        start)
            echo "Starting service..."
            systemctl start $SERVICE_NAME
            ;;
        stop)
            echo "Stopping service..."
            systemctl stop $SERVICE_NAME
            ;;
        restart)
            echo "Restarting service..."
            systemctl restart $SERVICE_NAME
            ;;
    esac
    
    sleep 1
    echo ""
    systemctl status $SERVICE_NAME --no-pager
    echo ""
    read -p "Press Enter to continue..."
}

# Main menu
show_menu() {
    show_header
    show_status
    
    echo "======================================================================"
    echo "Please select an option:"
    echo "======================================================================"
    echo ""
    echo "  1) Install Agent"
    echo "  2) Uninstall Agent"
    echo "  3) Start Service"
    echo "  4) Stop Service"
    echo "  5) Restart Service"
    echo "  6) View Logs"
    echo "  7) Exit"
    echo ""
    read -p "Enter choice [1-7]: " choice
    
    case $choice in
        1) install_agent ;;
        2) uninstall_agent ;;
        3) manage_service start ;;
        4) manage_service stop ;;
        5) manage_service restart ;;
        6) view_logs ;;
        7) exit 0 ;;
        *) 
            echo -e "${RED}Invalid option${NC}"
            sleep 1
            ;;
    esac
}

# Main loop
check_root

while true; do
    show_menu
done