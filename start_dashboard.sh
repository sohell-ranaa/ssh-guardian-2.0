#!/bin/bash
# SSH Guardian 2.0 - Dashboard Startup Script

echo "🚀 Starting SSH Guardian Dashboard..."

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "✅ Virtual environment activated"
else
    echo "⚠️  Warning: Virtual environment not found"
fi

# Install/update dependencies
echo "📦 Checking dependencies..."
pip install -q flask flask-cors mysql-connector-python requests python-dotenv

# Check if Guardian is running
echo "🔍 Checking Guardian API..."
if curl -s http://localhost:5000/health > /dev/null 2>&1; then
    echo "✅ Guardian API is running"
else
    echo "⚠️  Warning: Guardian API not detected at localhost:5000"
    echo "   Make sure ssh_guardian_v2_integrated.py is running"
fi

# Check database connection
echo "🗄️  Checking database connection..."
python3 -c "
import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

try:
    conn = mysql.connector.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', 'Osama@2580'),
        database=os.getenv('DB_NAME', 'ssh_guardian_20')
    )
    print('✅ Database connection successful')
    conn.close()
except Exception as e:
    print(f'❌ Database connection failed: {e}')
    exit(1)
"

if [ $? -ne 0 ]; then
    echo "❌ Cannot start dashboard without database access"
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════"
echo "  SSH Guardian 2.0 - Security Dashboard"
echo "════════════════════════════════════════════════════"
echo ""
echo "  📊 Dashboard URL: http://localhost:8080"
echo "  🔌 API Endpoint:  http://localhost:8080/api/"
echo ""
echo "  Press Ctrl+C to stop the dashboard"
echo ""
echo "════════════════════════════════════════════════════"
echo ""

# Start the dashboard server
cd src/dashboard
python3 dashboard_server.py
