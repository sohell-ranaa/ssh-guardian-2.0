#!/bin/bash
#
# SSH Guardian 2.0 - Automated Installation Script
# This script installs all dependencies and sets up SSH Guardian
#

set -e  # Exit on error

echo "================================================================================"
echo "🛡️  SSH GUARDIAN 2.0 - AUTOMATED INSTALLATION"
echo "================================================================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  This script should be run with sudo for full functionality"
    echo "   Some features (IP blocking) require root privileges"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Detect OS
echo ""
echo "📋 Detecting system..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
    echo "   OS: $OS $VERSION"
else
    echo "❌ Cannot detect OS. Please install manually."
    exit 1
fi

# Check Python version
echo ""
echo "🐍 Checking Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo "   Python version: $PYTHON_VERSION"

    # Check if version is 3.8+
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
        echo "❌ Python 3.8+ required. Found: $PYTHON_VERSION"
        exit 1
    fi
else
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Install system dependencies
echo ""
echo "📦 Installing system dependencies..."

case $OS in
    ubuntu|debian)
        apt-get update
        apt-get install -y python3-pip python3-venv iptables curl
        ;;
    centos|rhel|fedora)
        yum install -y python3-pip iptables curl
        ;;
    *)
        echo "⚠️  Unknown OS. Please install manually: python3-pip, iptables, curl"
        ;;
esac

# Create virtual environment (recommended but optional)
echo ""
echo "🔧 Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "   ✅ Virtual environment created"
else
    echo "   ✅ Virtual environment already exists"
fi

# Activate venv
source venv/bin/activate

# Upgrade pip
echo ""
echo "⬆️  Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install Python dependencies
echo ""
echo "📚 Installing Python packages..."
echo "   This may take a few minutes..."
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "   ✅ All Python packages installed successfully"
else
    echo "   ❌ Failed to install some packages"
    echo "   Please check requirements.txt and install manually"
    exit 1
fi

# Create necessary directories
echo ""
echo "📁 Creating data directories..."
mkdir -p data/threat_feeds
mkdir -p data/api_cache
mkdir -p data/geoip
mkdir -p data/receiving_stream
mkdir -p data/parsed_json
mkdir -p data/detections
echo "   ✅ Directories created"

# Check for GeoIP database
echo ""
echo "🌍 Checking GeoIP database..."
if [ ! -f "data/GeoLite2-City.mmdb" ]; then
    echo "   ⚠️  GeoLite2-City.mmdb not found"
    echo "   Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    echo "   Place in: data/GeoLite2-City.mmdb"
else
    echo "   ✅ GeoIP database found"
fi

# Update threat feeds
echo ""
echo "🔄 Updating threat feeds..."
python3 << 'EOF'
import requests
from pathlib import Path

feeds = {
    'ssh_attackers.txt': 'https://lists.blocklist.de/lists/ssh.txt',
    'tor_exits.txt': 'https://check.torproject.org/torbulkexitlist',
}

feeds_dir = Path('data/threat_feeds')
feeds_dir.mkdir(exist_ok=True)

for filename, url in feeds.items():
    try:
        print(f'   Downloading {filename}...')
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            with open(feeds_dir / filename, 'w') as f:
                f.write(response.text)
            print(f'   ✅ {filename} updated')
        else:
            print(f'   ⚠️  Failed to download {filename}')
    except Exception as e:
        print(f'   ❌ Error downloading {filename}: {e}')

print('   ✅ Threat feeds updated')
EOF

# Create whitelist file if not exists
echo ""
echo "📝 Creating whitelist file..."
if [ ! -f "data/ip_whitelist.txt" ]; then
    cat > data/ip_whitelist.txt << 'EOF'
# SSH Guardian IP Whitelist
# Add trusted IPs here (one per line)
# Lines starting with # are comments

# Example (uncomment and modify):
# 8.8.8.8
# 1.1.1.1
EOF
    echo "   ✅ Whitelist file created at data/ip_whitelist.txt"
else
    echo "   ✅ Whitelist file already exists"
fi

# Check .env file
echo ""
echo "⚙️  Checking configuration..."
if [ ! -f ".env" ]; then
    echo "   ⚠️  .env file not found"
    echo "   Creating .env template..."
    cat > .env << 'EOF'
# SSH Guardian 2.0 Configuration

# Telegram Bot (Required for alerts)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Database Settings (Optional)
DB_HOST=localhost
DB_USER=sshguardian
DB_PASSWORD=guardian123
DB_NAME=ssh_guardian_dev

# Third-Party Threat Intelligence API Keys (Optional)
# Get free API keys from:
# VirusTotal: https://www.virustotal.com/gui/join-us (250 requests/day)
# AbuseIPDB: https://www.abuseipdb.com/pricing (1000 requests/day)
# Shodan: https://account.shodan.io/register (Limited free tier)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=

# Security Settings
ALERT_RISK_THRESHOLD=70
AUTO_BLOCK_THRESHOLD=85
EOF
    echo "   ✅ .env template created"
    echo "   ⚠️  IMPORTANT: Edit .env and add your Telegram bot credentials"
else
    echo "   ✅ .env file already exists"
fi

# Create systemd service
echo ""
echo "🔧 Creating systemd service..."
INSTALL_DIR=$(pwd)
SERVICE_FILE="/etc/systemd/system/ssh-guardian.service"

if [ "$EUID" -eq 0 ]; then
    cat > $SERVICE_FILE << EOF
[Unit]
Description=SSH Guardian 2.0 - Advanced SSH Security System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/ssh_guardian_v2_integrated.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security
NoNewPrivileges=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    echo "   ✅ Systemd service created at $SERVICE_FILE"

    # Reload systemd
    systemctl daemon-reload
    echo "   ✅ Systemd reloaded"
else
    echo "   ⚠️  Skipping systemd service creation (requires root)"
    echo "   Run with sudo to create systemd service"
fi

# Run tests
echo ""
echo "🧪 Running tests..."
python3 test_integrated_system.py

if [ $? -eq 0 ]; then
    echo ""
    echo "================================================================================"
    echo "✅ INSTALLATION COMPLETE!"
    echo "================================================================================"
    echo ""
    echo "🎉 SSH Guardian 2.0 is ready to use!"
    echo ""
    echo "📋 NEXT STEPS:"
    echo ""
    echo "1. Configure Telegram bot:"
    echo "   Edit .env and add your TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID"
    echo ""
    echo "2. (Optional) Add API keys for enhanced threat intelligence:"
    echo "   Edit .env and add VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY"
    echo ""
    echo "3. (Optional) Add trusted IPs to whitelist:"
    echo "   Edit data/ip_whitelist.txt"
    echo ""
    echo "4. Start SSH Guardian:"
    echo "   sudo systemctl start ssh-guardian    # As service"
    echo "   OR"
    echo "   sudo python3 ssh_guardian_v2_integrated.py    # Manually"
    echo ""
    echo "5. Deploy log agents on your servers:"
    echo "   Edit src/agents/log_agent.py and set RECEIVER_URL"
    echo "   Run: python3 src/agents/log_agent.py"
    echo ""
    echo "6. Monitor:"
    echo "   sudo systemctl status ssh-guardian   # Service status"
    echo "   curl http://localhost:5000/statistics  # Get statistics"
    echo "   curl http://localhost:5000/blocks      # View blocked IPs"
    echo ""
    echo "================================================================================"
else
    echo ""
    echo "⚠️  Installation completed but tests failed"
    echo "   Please check the output above for errors"
fi
