# Enhanced Dashboard - Quick Start

## Start the Dashboard (2 minutes)

```bash
# 1. Navigate to project directory
cd /home/rana-workspace/ssh_guardian_2.0

# 2. Start the dashboard server
python3 src/dashboard/dashboard_server.py
```

**Access**: http://localhost:8080 or http://YOUR_SERVER_IP:8080

## Key Features at a Glance

### 🏠 Overview Tab
- Real-time statistics and metrics
- Recent high-risk threats table
- Quick-action buttons for blocking IPs

### 🔴 Live Stream Tab
- See SSH events in real-time
- Auto-refresh every 5 seconds
- One-click IP investigation

### 🛡️ IP Management Tab
**Block IPs:**
1. Enter IP address
2. Set duration (1h, 24h, week, permanent)
3. Click "Block IP"

**Whitelist IPs:**
1. Click "Add IP" button
2. Enter IP address
3. Confirm

**Lookup IPs:**
1. Enter IP in search box
2. Click "Lookup"
3. View complete threat history

### 🔍 Search & Filter Tab
Advanced event search with filters:
- IP address, username, country
- Risk score threshold
- Event type (failed/successful)
- Custom time ranges
- Export-ready results

### ⚙️ Settings Tab
- Configure alert thresholds
- Enable/disable auto-blocking
- Test Telegram notifications
- View system health metrics

## Common Actions

### Block an Attacker
```
1. Go to Overview tab
2. Find high-risk IP in threats table
3. Click ban icon (🚫)
4. Select duration
5. Click "Block IP"
```

### Whitelist Your Office IP
```
1. Go to IP Management tab
2. Click "Add IP" under Whitelisted IPs
3. Enter your office IP
4. Confirm
```

### Search for Specific Activity
```
1. Go to Search & Filter tab
2. Enter username (e.g., "root")
3. Set min risk score (e.g., 70)
4. Click "Search"
5. Review results
```

### Monitor Live Activity
```
1. Go to Live Stream tab
2. Click "Start Auto-Refresh"
3. Watch events appear in real-time
4. Click search icon to investigate suspicious IPs
```

## Screenshots

### Overview Dashboard
```
┌─────────────────────────────────────────────────────────┐
│  Events (24h)    High Risk    Blocked IPs   Unique IPs  │
│     2,847           142           28          1,245      │
└─────────────────────────────────────────────────────────┘

Recent High-Risk Threats
┌──────────────────────────────────────────────────────────┐
│ Time      IP             Country    Risk    Actions      │
│ 2m ago    185.220.101.1  Russia     95     🔍 🚫        │
│ 5m ago    91.240.118.2   China      87     🔍 🚫        │
│ 8m ago    162.142.125.3  Brazil     82     🔍 🚫        │
└──────────────────────────────────────────────────────────┘
```

### IP Management
```
┌─────────────────────┐  ┌────────────────────────┐
│  Blocked IPs (28)   │  │  Whitelisted IPs (5)   │
│  ──────────────────│  │  ───────────────────── │
│  185.220.101.1 🔓  │  │  192.168.1.100  ❌     │
│  91.240.118.2  🔓  │  │  10.0.0.50      ❌     │
│  [Clear All]        │  │  [+ Add IP]             │
└─────────────────────┘  └────────────────────────┘

IP Lookup
┌──────────────────────────────────────┐
│  [1.2.3.4        ]  [🔍 Lookup]     │
│  [🚫 Block IP]  [✓ Whitelist IP]    │
└──────────────────────────────────────┘
```

## Pro Tips

1. **Enable Auto-Refresh in Live Stream** for real-time monitoring
2. **Whitelist your IPs first** to avoid accidental lockouts
3. **Use Search filters** to find patterns in attacks
4. **Check System Health regularly** in Settings tab
5. **Test alerts** to ensure Telegram integration works

## Troubleshooting

### Dashboard won't load
```bash
# Check if server is running
ps aux | grep dashboard_server.py

# Check port availability
lsof -i :8080

# Restart dashboard
pkill -f dashboard_server.py
python3 src/dashboard/dashboard_server.py
```

### Can't block IPs
```bash
# Ensure Guardian main service is running
systemctl status ssh-guardian.service

# Check Guardian API
curl http://localhost:5000/health
```

### Data not showing
```bash
# Verify database connection
mysql -u root -p ssh_guardian_20 -e "SELECT COUNT(*) FROM failed_logins;"

# Check API endpoints
curl http://localhost:8080/api/stats/overview
```

## Next Steps

1. ✅ Dashboard running
2. 📖 Read full guide: `docs/ENHANCED_DASHBOARD_GUIDE.md`
3. 🔐 Set up access control (SSH tunnel or basic auth)
4. 🎯 Configure alert thresholds in Settings tab
5. 📊 Explore analytics and reports

## Security Reminder

**⚠️ The dashboard has NO authentication by default!**

**Secure it before exposing to network:**

```bash
# Option 1: SSH Tunnel (recommended)
ssh -L 8080:localhost:8080 user@your-server

# Option 2: Firewall (allow specific IP only)
ufw allow from YOUR_IP_HERE to any port 8080

# Option 3: Use nginx with basic auth
# See docs/ENHANCED_DASHBOARD_GUIDE.md for setup
```

---

**Ready to monitor!** Open http://localhost:8080 🚀
