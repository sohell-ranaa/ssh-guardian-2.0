# SSH Guardian 2.0 - Dashboard Guide

## Overview

The SSH Guardian Dashboard is a modern, mobile-responsive web interface for real-time monitoring and management of SSH security events. Built with Flask, Bootstrap 5, Chart.js, and Leaflet maps.

## Features

### 📊 Real-Time Monitoring
- **Live Event Statistics**: Track events, threats, and blocked IPs in real-time
- **Auto-refresh**: Dashboard updates every 30 seconds automatically
- **Event Timeline**: 24-hour visualization of SSH activity
- **Geographic Mapping**: Interactive world map showing attack origins

### 🎯 Threat Intelligence
- **High-Risk Event Tracking**: Monitor events with ML risk scores ≥50
- **Attack Type Distribution**: Visualize different attack patterns
- **Top Malicious IPs**: Identify most active threat actors
- **Targeted Usernames**: See which accounts are under attack

### 📈 Analytics & Visualization
- **Line Charts**: Event trends over time (total, failed, anomalies)
- **Doughnut Charts**: Attack type distribution
- **Interactive Maps**: Geographic threat visualization with risk-based coloring
- **Data Tables**: Sortable, detailed threat information

### 🔐 Administrative Controls
- **Manual IP Blocking**: Block IPs with custom duration
- **IP Unblocking**: Remove blocks when needed
- **System Health**: Monitor database and API status
- **Real-time Stats**: Current system performance metrics

## Installation

### Prerequisites
- SSH Guardian 2.0 running on `localhost:5000`
- MySQL database with SSH events
- Python 3.7+

### Quick Start

```bash
# Navigate to project root
cd /home/rana-workspace/ssh_guardian_2.0

# Install dependencies (if not already installed)
pip install flask flask-cors mysql-connector-python requests python-dotenv

# Start the dashboard
./start_dashboard.sh
```

### Manual Start

```bash
# Activate virtual environment
source venv/bin/activate

# Start dashboard server
cd src/dashboard
python3 dashboard_server.py
```

## Access the Dashboard

Once started, access the dashboard at:

- **URL**: http://localhost:8080
- **API**: http://localhost:8080/api/

## Dashboard Components

### 1. Overview Statistics (Top Cards)

Four key metrics displayed prominently:

| Metric | Description |
|--------|-------------|
| **Events (24h)** | Total SSH events in last 24 hours |
| **High Risk Threats** | Events with ML risk score ≥ 70 |
| **Blocked IPs** | Currently blocked IP addresses |
| **Unique IPs (24h)** | Distinct source IPs seen |

### 2. Event Timeline Chart

Line chart showing:
- **Total Events**: Combined failed + successful attempts
- **Failed Attempts**: Authentication failures
- **Anomalies**: ML-detected anomalies

**Time Range**: Last 24 hours, hourly aggregation

### 3. Attack Types Distribution

Doughnut chart showing breakdown of:
- Brute force attacks
- Distributed attacks
- Failed authentication
- Reconnaissance
- Intrusion attempts
- Normal activity

### 4. Geographic Attack Map

Interactive world map with:
- **Circle Markers**: Size = attack count
- **Color Coding**: Risk level (red = critical, yellow = medium, green = low)
- **Popups**: Click for city details, attack count, average risk

### 5. Top Malicious IPs Table

Shows most active threat IPs with:
- IP address and country
- Total attempts (with failed count)
- Average and max risk scores
- Unique usernames tried
- Last seen timestamp

### 6. Recent High-Risk Events Table

Real-time feed of threats with:
- Timestamp (relative: "5m ago")
- Source IP and country
- Target username
- Risk score badge (color-coded)

### 7. Most Targeted Usernames Table

Analysis of attacked accounts:
- Username
- Total attempts
- Unique IPs attempting
- Failed vs successful logins
- Average risk score

## API Endpoints

### Statistics Endpoints

#### GET `/api/stats/overview`
Returns comprehensive overview statistics.

**Response:**
```json
{
  "total_events": 29087,
  "events_24h": 29087,
  "events_1h": 28988,
  "unique_ips_24h": 142,
  "anomalies_24h": 27284,
  "failed_24h": 27644,
  "successful_24h": 1443,
  "high_risk_24h": 456,
  "attack_types": {
    "brute_force": 18734,
    "distributed_attack": 6305,
    "reconnaissance": 1905
  },
  "guardian_stats": { ... }
}
```

#### GET `/api/stats/timeline?hours=24`
Returns hourly event statistics.

**Parameters:**
- `hours` (optional): Time range in hours (default: 24)

**Response:**
```json
[
  {
    "hour": "2025-12-03 00:00:00",
    "total": 1250,
    "failed": 1180,
    "successful": 70,
    "anomalies": 1050,
    "avg_risk": 82.5
  },
  ...
]
```

### Threat Endpoints

#### GET `/api/threats/recent?limit=50`
Returns recent high-risk events (ml_risk_score ≥ 50).

**Parameters:**
- `limit` (optional): Max results (default: 50)

#### GET `/api/threats/geographic?hours=24`
Returns geographic distribution of threats.

**Parameters:**
- `hours` (optional): Time range (default: 24)

**Response:**
```json
{
  "countries": [
    {
      "country": "CN",
      "count": 5432,
      "avg_risk": 85.2,
      "anomalies": 4890
    }
  ],
  "cities": [
    {
      "city": "Beijing",
      "country": "CN",
      "latitude": 39.9042,
      "longitude": 116.4074,
      "count": 1234,
      "avg_risk": 88.5
    }
  ]
}
```

#### GET `/api/threats/top-ips?hours=24&limit=20`
Returns top malicious IP addresses.

**Parameters:**
- `hours` (optional): Time range (default: 24)
- `limit` (optional): Max results (default: 20)

#### GET `/api/threats/usernames?hours=24&limit=20`
Returns most targeted usernames.

### Administrative Endpoints

#### POST `/api/admin/block-ip`
Manually block an IP address.

**Request Body:**
```json
{
  "ip": "1.2.3.4",
  "duration": 24
}
```

**Parameters:**
- `ip`: IP address to block
- `duration`: Hours to block (default: 24)

#### POST `/api/admin/unblock-ip`
Manually unblock an IP address.

**Request Body:**
```json
{
  "ip": "1.2.3.4"
}
```

#### GET `/api/blocks/active`
Get currently blocked IPs from Guardian API.

### System Endpoints

#### GET `/api/system/health`
Returns system health metrics.

**Response:**
```json
{
  "database_size_mb": 125.45,
  "latest_event": "2025-12-03T00:45:23",
  "seconds_since_last_event": 12.5,
  "events_last_hour": 1250,
  "events_per_minute": 20.8,
  "guardian_status": "online",
  "guardian_api": { ... }
}
```

## Configuration

### Environment Variables

The dashboard uses the existing database connection from `dbs/connection.py`:

```python
DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "your_password",
    "database": "ssh_guardian_20"
}
```

### Guardian API URL

Set the Guardian API endpoint (default: http://localhost:5000):

```bash
# In .env file
GUARDIAN_API_URL=http://localhost:5000
```

## Database Schema

The dashboard works with these tables:

### `failed_logins`
- `timestamp`, `source_ip`, `username`, `country`, `city`
- `ml_risk_score`, `ml_threat_type`, `is_anomaly`
- `latitude`, `longitude`

### `successful_logins`
- Same structure as `failed_logins`
- Additional: `session_duration`

## Customization

### Change Refresh Interval

Edit `src/dashboard/static/js/dashboard.js`:

```javascript
// Auto-refresh every 30 seconds (change to desired interval)
refreshInterval = setInterval(loadAllData, 30000);
```

### Adjust Risk Thresholds

In dashboard_server.py, modify the risk threshold for "high-risk" events:

```python
# Current: ml_risk_score >= 70
# Change to different threshold as needed
cursor.execute("""
    SELECT COUNT(*) as count FROM (
        SELECT id FROM failed_logins WHERE ml_risk_score >= 70 ...
```

### Modify Map Colors

Edit `src/dashboard/static/js/dashboard.js`:

```javascript
function getRiskColor(score) {
    if (score >= 90) return '#dc2626';  // Critical - red
    if (score >= 70) return '#f59e0b';  // High - orange
    if (score >= 50) return '#eab308';  // Medium - yellow
    if (score >= 30) return '#3b82f6';  // Low - blue
    return '#10b981';                    // Clean - green
}
```

## Mobile Responsive

The dashboard is fully mobile-responsive with:
- **Adaptive Layout**: Cards stack on mobile devices
- **Touch-Friendly**: Large buttons and interactive elements
- **Optimized Charts**: Chart.js responsive mode
- **Scrollable Tables**: Horizontal scroll for tables on small screens

## Performance

### Optimization Tips

1. **Limit Time Ranges**: Use shorter time ranges (e.g., 6-12 hours) for faster queries
2. **Reduce Refresh Rate**: Increase interval for less active monitoring
3. **Database Indexing**: Ensure indexes on `timestamp`, `source_ip`, `ml_risk_score`
4. **Cache Results**: Consider adding Redis for API response caching

### Recommended Indexes

```sql
-- Speed up dashboard queries
CREATE INDEX idx_failed_timestamp ON failed_logins(timestamp);
CREATE INDEX idx_failed_risk ON failed_logins(ml_risk_score);
CREATE INDEX idx_failed_ip ON failed_logins(source_ip);
CREATE INDEX idx_success_timestamp ON successful_logins(timestamp);
CREATE INDEX idx_success_risk ON successful_logins(ml_risk_score);
CREATE INDEX idx_success_ip ON successful_logins(source_ip);
```

## Troubleshooting

### Dashboard Won't Start

**Error**: `Address already in use`
```bash
# Find process using port 8080
lsof -i :8080

# Kill the process
kill -9 <PID>

# Restart dashboard
./start_dashboard.sh
```

### No Data Showing

**Check**:
1. Guardian API is running: `curl http://localhost:5000/health`
2. Database connection: Test with `python3 dbs/connection.py`
3. Data exists: Check `SELECT COUNT(*) FROM failed_logins;`

### API Errors

**Check logs**:
```bash
# Dashboard logs
tail -f /tmp/dashboard.log

# Guardian logs
journalctl -u ssh_guardian -f
```

## Production Deployment

For production use, replace Flask development server with:

### Using Gunicorn

```bash
# Install gunicorn
pip install gunicorn

# Start with 4 workers
cd src/dashboard
gunicorn -w 4 -b 0.0.0.0:8080 dashboard_server:app
```

### Using systemd Service

Create `/etc/systemd/system/ssh-guardian-dashboard.service`:

```ini
[Unit]
Description=SSH Guardian Dashboard
After=network.target mysql.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/rana-workspace/ssh_guardian_2.0/src/dashboard
ExecStart=/home/rana-workspace/ssh_guardian_2.0/venv/bin/gunicorn \
    -w 4 -b 0.0.0.0:8080 dashboard_server:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ssh-guardian-dashboard
sudo systemctl start ssh-guardian-dashboard
```

## Security Considerations

1. **Authentication**: Add authentication layer for production
2. **HTTPS**: Use reverse proxy (nginx) with SSL
3. **Firewall**: Restrict dashboard port to trusted IPs
4. **Database**: Use read-only database user for dashboard

### Example Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl;
    server_name guardian.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Support

For issues or questions:
1. Check logs: `/tmp/dashboard.log`
2. Verify Guardian API: `curl http://localhost:5000/statistics`
3. Test database: `python3 dbs/connection.py`

## Summary

The SSH Guardian Dashboard provides:
- ✅ Real-time threat monitoring
- ✅ Geographic attack visualization
- ✅ ML risk scoring integration
- ✅ Mobile-responsive design
- ✅ RESTful API
- ✅ Auto-refresh capabilities
- ✅ Administrative controls

**Dashboard is production-ready and fully functional!**
