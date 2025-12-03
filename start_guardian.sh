#!/bin/bash
#
# SSH Guardian 2.0 - Start Script
# Simple script to start SSH Guardian with all checks
#

echo "🛡️  SSH GUARDIAN 2.0 - STARTING..."
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  WARNING: Not running as root"
    echo "   IP blocking features require root/sudo"
    echo "   Consider running: sudo ./start_guardian.sh"
    echo ""
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found"
    echo "   Run: ./install.sh first"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check .env file
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found"
    echo "   Creating default .env..."
    cp .env.example .env 2>/dev/null || echo "   Please create .env file manually"
fi

# Check GeoIP database
if [ ! -f "data/GeoLite2-City.mmdb" ]; then
    echo "⚠️  GeoLite2-City.mmdb not found"
    echo "   Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    echo "   System will work but without geolocation"
    echo ""
fi

# Start SSH Guardian
echo "✅ Starting SSH Guardian..."
echo ""
python3 ssh_guardian_v2_integrated.py
