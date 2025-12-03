# API Integration Quick Reference

## Quick Start

### Option 1: Interactive Setup (Recommended)
```bash
./scripts/setup_api_integration.sh
```

### Option 2: Manual Setup
1. Edit `.env` file and add your API keys
2. Validate: `python3 scripts/validate_api_keys.py`
3. Test: `python3 scripts/test_api_integration.py --test-all`

## Get Free API Keys

| Service | URL | Free Tier | Time to Setup |
|---------|-----|-----------|---------------|
| **VirusTotal** | https://www.virustotal.com/gui/join-us | 250/day | 2 minutes |
| **AbuseIPDB** | https://www.abuseipdb.com/pricing | 1,000/day | 3 minutes |
| **Shodan** | https://account.shodan.io/register | 100/month | 3 minutes |

**Total setup time: ~10 minutes for all three**

## Usage Examples

### Validate API Keys
```bash
# Check key format
python3 scripts/validate_api_keys.py
```

### Test Individual APIs
```bash
# Test VirusTotal
python3 scripts/test_api_integration.py --api virustotal

# Test AbuseIPDB
python3 scripts/test_api_integration.py --api abuseipdb

# Test Shodan
python3 scripts/test_api_integration.py --api shodan
```

### Test All APIs
```bash
# Test all configured APIs
python3 scripts/test_api_integration.py --test-all

# Test with known malicious IP
python3 scripts/test_api_integration.py --test-all --ip 185.220.101.1

# Test with verbose output
python3 scripts/test_api_integration.py --test-all --verbose
```

## How It Works

### Without APIs (Local Feeds Only)
```
SSH Event → Local Threat Feeds → Risk Score → Alert/Block
```

### With APIs (Enhanced Intelligence)
```
SSH Event → Local Feeds → API Enrichment → Combined Risk Score → Alert/Block
                             ↓
                    VirusTotal + AbuseIPDB + Shodan
```

### Score Combination
- **API Available**: 70% API score + 30% local feeds
- **API Unavailable**: 100% local feeds (automatic fallback)

## Rate Limit Management

All APIs have built-in rate limiting and caching:

```python
# Results cached for 24 hours
cache_ttl = 24  # hours

# Daily limits automatically enforced
virustotal_limit = 250   # requests/day
abuseipdb_limit = 1000   # requests/day
shodan_limit = 100       # requests/month
```

## Cost Estimate

For a **100-server deployment** with moderate attack traffic:

| Metric | Estimate |
|--------|----------|
| Unique IPs/day | 50-200 |
| API calls/day (with caching) | 20-80 |
| Free tier sufficient? | **YES** |
| Monthly cost | **$0** |

## Monitoring API Usage

### Check Statistics
```bash
curl http://localhost:5000/statistics | jq '.api_stats'
```

### Check Cache
```bash
ls -lh data/api_cache/
```

### Monitor Logs
```bash
tail -f /var/log/ssh_guardian.log | grep "API"
```

## Troubleshooting

### Problem: API key invalid
```bash
# Validate format
python3 scripts/validate_api_keys.py

# Check .env file has no extra spaces
cat .env | grep API_KEY
```

### Problem: Rate limit exceeded
```bash
# Check cache is working
ls data/api_cache/ | wc -l

# Wait for reset (24 hours for daily limits)
```

### Problem: Connection timeout
```bash
# Test internet connectivity
curl -I https://www.virustotal.com

# Check firewall
sudo iptables -L -n | grep HTTPS
```

## Advanced Configuration

### Selective API Querying
Only query APIs for high-risk IPs to save quota:

```python
# In enhanced_guardian_engine.py
use_apis = (local_threat_detected or failed_attempts > 3)
reputation = threat_intel.check_ip_reputation(ip, use_apis=use_apis)
```

### Adjust Cache TTL
```bash
# In .env file
API_CACHE_TTL_HOURS=48  # Extend to 48 hours
```

### Disable Specific APIs
```bash
# In .env file
VIRUSTOTAL_API_KEY=  # Leave empty to disable
ABUSEIPDB_API_KEY="your_key"  # Keep enabled
SHODAN_API_KEY=  # Disable to save limited credits
```

## File Structure

```
ssh_guardian_2.0/
├── .env                              # Configuration (add keys here)
├── .env.example                      # Template
├── docs/
│   ├── API_SETUP_GUIDE.md           # Detailed setup guide
│   └── API_INTEGRATION_README.md    # This file
├── scripts/
│   ├── setup_api_integration.sh     # Interactive setup
│   ├── validate_api_keys.py         # Validate key format
│   └── test_api_integration.py      # Test connectivity
├── src/intelligence/
│   ├── api_clients.py               # API client implementations
│   └── unified_threat_intel.py      # Unified intelligence layer
└── data/
    └── api_cache/                    # Cached API responses (auto-created)
```

## Performance Impact

### With APIs Enabled
- **Initial query**: ~500-1500ms (3 API calls)
- **Cached query**: <1ms (local cache hit)
- **Cache hit rate**: ~95% after warmup

### Network Traffic
- **Per IP lookup**: ~10-50 KB
- **Daily bandwidth**: ~1-5 MB (with caching)

## Security Best Practices

1. **Never commit .env to git** ✓ (already in .gitignore)
2. **Use environment variables in production**
3. **Rotate API keys quarterly**
4. **Monitor API usage for anomalies**
5. **Set up alerts for quota approaching**

## Support

- **Full Documentation**: `docs/API_SETUP_GUIDE.md`
- **API Clients Code**: `src/intelligence/api_clients.py`
- **Unified Intel**: `src/intelligence/unified_threat_intel.py`
- **Issues**: https://github.com/sohell-ranaa/ssh-guardian-2.0/issues

## Next Steps After Setup

1. ✅ APIs configured and tested
2. Restart SSH Guardian: `systemctl restart ssh-guardian`
3. Monitor enhanced detection: `tail -f /var/log/ssh_guardian.log`
4. Review Telegram alerts for API enrichment
5. Check statistics regularly: `curl localhost:5000/statistics`

---

**Need help?** Run `./scripts/setup_api_integration.sh` for interactive guidance.
