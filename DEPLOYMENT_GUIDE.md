# SSH Guardian 2.0 - Quick Deployment Guide

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- Python 3.8+
- Linux system with iptables
- MySQL/MariaDB (optional)
- Sudo/root access (for IP blocking)

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- flask
- requests
- geoip2
- python-dotenv
- pymysql (if using database)

### Step 2: Configure Environment

Edit `.env` file:

```bash
# Telegram (Required for alerts)
TELEGRAM_BOT_TOKEN="your_bot_token"
TELEGRAM_CHAT_ID="your_chat_id"

# API Keys (Optional - system works without them)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=

# Security Settings
ALERT_RISK_THRESHOLD=70
AUTO_BLOCK_THRESHOLD=85
```

**Get Free API Keys** (Optional):
- VirusTotal: https://www.virustotal.com/gui/join-us (250 req/day)
- AbuseIPDB: https://www.abuseipdb.com/pricing (1000 req/day)
- Shodan: https://account.shodan.io/register (limited free)

### Step 3: Start SSH Guardian

```bash
sudo python3 ssh_guardian_v2_integrated.py
```

The system will:
- ✅ Load threat intelligence feeds (6,081 IPs)
- ✅ Initialize Guardian Engine
- ✅ Create iptables chain
- ✅ Start API server on port 5000

### Step 4: Deploy Log Agents (On Protected Servers)

Edit `src/agents/log_agent.py` and set:
```python
RECEIVER_URL = "http://your-guardian-ip:5000"
```

Then run:
```bash
python3 src/agents/log_agent.py
```

---

## 🧪 Testing

### Run Comprehensive Tests
```bash
python3 test_integrated_system.py
```

Expected output:
```
✅ TEST 1 PASSED: Normal login correctly classified
✅ TEST 2 PASSED: Brute force attack detected
✅ TEST 3 PASSED: Impossible travel detected
✅ TEST 4 PASSED: Known malicious IP detected
✅ TEST 5 PASSED: Distributed attack detected

🎉 ALL TESTS PASSED SUCCESSFULLY!
```

### Test Individual Components

**Test API Integration**:
```bash
python3 test_api_integration.py
```

**Test Guardian Engine**:
```bash
python3 src/core/guardian_engine.py
```

**Test Brute Force Detector**:
```bash
python3 src/detection/brute_force_detector.py
```

**Test IP Blocker** (dry run):
```bash
python3 src/response/ip_blocker.py
```

---

## 📡 API Endpoints

### Health Check
```bash
curl http://localhost:5000/health
```

### Get Statistics
```bash
curl http://localhost:5000/statistics
```

Returns:
```json
{
  "engine_stats": {
    "events_processed": 1234,
    "threats_detected": 567,
    "brute_force_detected": 89,
    "impossible_travel_detected": 12,
    "ips_blocked": 45
  },
  "threat_intel_stats": {...},
  "brute_force_stats": {...},
  "blocking_stats": {...}
}
```

### Get Blocked IPs
```bash
curl http://localhost:5000/blocks
```

### Manually Block IP
```bash
curl -X POST http://localhost:5000/block/1.2.3.4 \
  -H "Content-Type: application/json" \
  -d '{"reason": "Manual block", "duration_hours": 24}'
```

### Manually Unblock IP
```bash
curl -X POST http://localhost:5000/unblock/1.2.3.4
```

---

## 🔧 Configuration Options

### In `.env` file:

```bash
# Alert Thresholds
ALERT_RISK_THRESHOLD=70      # Send alert if risk >= 70
AUTO_BLOCK_THRESHOLD=85       # Auto-block if risk >= 85

# Database (optional)
DB_HOST=localhost
DB_USER=sshguardian
DB_PASSWORD=guardian123
DB_NAME=ssh_guardian_dev
```

### Whitelist IPs

Create `data/ip_whitelist.txt`:
```
# SSH Guardian Whitelist
8.8.8.8
1.1.1.1
your-trusted-ip
```

---

## 📊 Monitoring

### Real-time Logs
```bash
tail -f /var/log/ssh_guardian.log
```

### Statistics Dashboard
Access via API or create custom dashboard using:
- `/statistics` - Overall stats
- `/blocks` - Current blocks

---

## 🛡️ Security Best Practices

1. **Run with minimal privileges**: Use dedicated user for Guardian (except iptables operations)
2. **Secure API endpoints**: Add authentication if exposing to internet
3. **Regular backups**: Backup `data/blocks_state.json` and whitelist
4. **Monitor alerts**: Review Telegram alerts regularly
5. **Test changes**: Always test in staging before production

---

## 🔥 Troubleshooting

### Issue: "iptables: command not found"
**Solution**: Install iptables
```bash
sudo apt-get install iptables  # Ubuntu/Debian
sudo yum install iptables       # CentOS/RHEL
```

### Issue: "Permission denied" for iptables
**Solution**: Run with sudo
```bash
sudo python3 ssh_guardian_v2_integrated.py
```

### Issue: API keys not working
**Solution**:
1. Verify keys in `.env` file (no quotes around values)
2. Check API rate limits
3. System works without API keys using local feeds

### Issue: High memory usage
**Solution**:
1. Reduce cache sizes in code
2. Cleanup old session data
3. Restart Guardian Engine periodically

### Issue: False positives
**Solution**:
1. Add legitimate IPs to whitelist
2. Adjust `ALERT_RISK_THRESHOLD` higher
3. Review detection patterns

---

## 📈 Performance Tuning

### For High-Traffic Environments (>1000 events/min):

1. **Increase queue size** in `ssh_guardian_v2_integrated.py`:
```python
QUEUE_SIZE = 10000  # Default: 1000
```

2. **Add more worker threads**:
```python
for i in range(4):  # 4 parallel processors
    thread = threading.Thread(target=log_processor_worker, daemon=True)
    thread.start()
```

3. **Use database for persistence** (recommended for production)

4. **Enable caching for GeoIP lookups**

---

## 🎓 For Thesis Evaluation

### Collect Metrics:
```bash
# Detection accuracy
python3 evaluation/collect_metrics.py

# Performance testing
python3 evaluation/benchmark.py

# Compare with fail2ban
python3 evaluation/compare_fail2ban.py
```

### Generate Charts:
```bash
python3 evaluation/generate_charts.py
```

Outputs:
- Detection rate comparison
- False positive/negative rates
- Resource usage graphs
- Response time distributions

---

## 📚 Documentation

- **IMPLEMENTATION_PROGRESS.md** - Development history
- **SESSION_2_SUMMARY.md** - Complete feature list
- **README.md** - Project overview
- **This file** - Deployment guide

---

## 🆘 Support

For issues or questions:
1. Check logs: `tail -f ssh_guardian.log`
2. Review documentation
3. Test individual components
4. Check GitHub issues (if repository exists)

---

## 🎉 You're Ready!

SSH Guardian 2.0 is now protecting your servers with:
- ✅ Multi-source threat intelligence
- ✅ Impossible travel detection
- ✅ Advanced brute force detection
- ✅ Automated IP blocking
- ✅ Smart alerting via Telegram

**Enjoy enhanced SSH security!** 🛡️
