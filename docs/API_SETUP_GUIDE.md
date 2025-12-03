# Third-Party API Integration Setup Guide

This guide will help you set up free API keys for VirusTotal, AbuseIPDB, and Shodan to enhance SSH Guardian's threat intelligence capabilities.

## Why Add API Integration?

Adding these APIs significantly improves threat detection:

- **VirusTotal**: Checks IPs against 70+ antivirus engines and URL/file scanners
- **AbuseIPDB**: Database of IPs reported for malicious activity
- **Shodan**: Discovers exposed services and vulnerabilities on attacking IPs

All three offer **FREE tiers** with generous daily limits perfect for SME deployments.

---

## 1. VirusTotal API Setup

### Benefits
- 70+ security vendor detections
- Historical malicious activity data
- ASN and geolocation enrichment
- Categories (malware, phishing, spam)

### Free Tier Limits
- **250 requests/day**
- **4 requests/minute**
- Perfect for monitoring moderate traffic

### Registration Steps

1. **Create Account**
   - Visit: https://www.virustotal.com/gui/join-us
   - Click "Sign Up" in the top-right corner
   - Sign up with email or Google account

2. **Get API Key**
   - After login, click your profile icon (top-right)
   - Select "API Key" from dropdown menu
   - Copy your API key (64-character hex string)
   - Example format: `a1b2c3d4e5f6...` (64 chars)

3. **Add to SSH Guardian**
   ```bash
   # Edit .env file
   nano /home/rana-workspace/ssh_guardian_2.0/.env

   # Add your key:
   VIRUSTOTAL_API_KEY="your_64_character_key_here"
   ```

4. **Verify Setup**
   ```bash
   python3 scripts/test_api_integration.py --api virustotal
   ```

---

## 2. AbuseIPDB API Setup

### Benefits
- Community-driven abuse reporting database
- Confidence score (0-100) for malicious activity
- Detailed abuse categories
- ISP and hosting information
- Tor exit node detection

### Free Tier Limits
- **1,000 requests/day**
- **60 requests/minute**
- Excellent for high-volume monitoring

### Registration Steps

1. **Create Account**
   - Visit: https://www.abuseipdb.com/pricing
   - Click "Sign Up Free" button
   - Register with email

2. **Get API Key**
   - After login, go to: https://www.abuseipdb.com/account/api
   - Click "Create Key" button
   - Give it a name (e.g., "SSH Guardian")
   - Copy the API key (80-character string)
   - Example format: `a1b2c3d4e5f6g7h8...` (80 chars)

3. **Add to SSH Guardian**
   ```bash
   # Edit .env file
   nano /home/rana-workspace/ssh_guardian_2.0/.env

   # Add your key:
   ABUSEIPDB_API_KEY="your_80_character_key_here"
   ```

4. **Verify Setup**
   ```bash
   python3 scripts/test_api_integration.py --api abuseipdb
   ```

---

## 3. Shodan API Setup

### Benefits
- Discover exposed services on attacker IPs
- Vulnerability database
- Banner grabbing results
- Infrastructure profiling
- Compromised/malware tags

### Free Tier Limits
- **100 API credits/month** (limited but valuable)
- **1 query credit per IP lookup**
- Use sparingly for high-risk IPs only

### Registration Steps

1. **Create Account**
   - Visit: https://account.shodan.io/register
   - Sign up with email
   - Verify your email address

2. **Get API Key**
   - After login, go to: https://account.shodan.io/
   - Your API key is displayed at the top of the page
   - Copy the API key (32-character string)
   - Example format: `A1B2C3D4E5F6G7H8...` (32 chars)

3. **Add to SSH Guardian**
   ```bash
   # Edit .env file
   nano /home/rana-workspace/ssh_guardian_2.0/.env

   # Add your key:
   SHODAN_API_KEY="your_32_character_key_here"
   ```

4. **Verify Setup**
   ```bash
   python3 scripts/test_api_integration.py --api shodan
   ```

---

## Complete Configuration

After obtaining all three API keys, your `.env` file should look like:

```bash
# Telegram Bot Settings
TELEGRAM_BOT_TOKEN="8270421918:AAEeAgI5sxsEpN3pHW1_4PI7A8pQG5xSlIU"
TELEGRAM_CHAT_ID="5926359372"

# Database Settings
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=123123
DB_NAME=ssh_guardian_20

# Third-Party Threat Intelligence API Keys
VIRUSTOTAL_API_KEY="your_virustotal_key_here"
ABUSEIPDB_API_KEY="your_abuseipdb_key_here"
SHODAN_API_KEY="your_shodan_key_here"

# Security Settings
ALERT_RISK_THRESHOLD=70
AUTO_BLOCK_THRESHOLD=85
```

---

## Testing the Integration

### Quick Test All APIs

```bash
# Test all configured APIs at once
python3 scripts/test_api_integration.py --test-all

# Test with a known malicious IP
python3 scripts/test_api_integration.py --ip 185.220.101.1 --verbose
```

### Individual API Tests

```bash
# Test VirusTotal only
python3 scripts/test_api_integration.py --api virustotal --ip 8.8.8.8

# Test AbuseIPDB only
python3 scripts/test_api_integration.py --api abuseipdb --ip 8.8.8.8

# Test Shodan only
python3 scripts/test_api_integration.py --api shodan --ip 8.8.8.8
```

---

## Rate Limit Management

SSH Guardian automatically manages rate limits:

- **Caching**: Results cached for 24 hours (configurable)
- **Smart Querying**: Only queries new/uncached IPs
- **Rate Limiting**: Built-in per-minute and per-day limits
- **Graceful Fallback**: Uses local feeds if APIs unavailable

### Monitor API Usage

```bash
# Check API statistics
curl http://localhost:5000/statistics | jq '.api_stats'
```

---

## Optimization Tips

### 1. Prioritize High-Risk IPs
Configure selective API querying:
```python
# Only use APIs for IPs with local feed matches
use_apis = (local_threat_detected or failed_attempts > 3)
```

### 2. Adjust Cache TTL
Extend cache duration to reduce API calls:
```bash
# In .env file
API_CACHE_TTL_HOURS=48  # Default: 24
```

### 3. Shodan Selective Querying
Since Shodan has limited credits, use it only for critical threats:
```python
# Only query Shodan for high-risk IPs
if risk_score > 70:
    shodan_result = shodan_client.check_ip(ip)
```

---

## Troubleshooting

### Error: "API key invalid"
- Verify you copied the complete key (no spaces/newlines)
- Check key hasn't expired
- Ensure quotes around key in .env file

### Error: "Rate limit exceeded"
- Wait 24 hours for daily limit reset
- Check cache is working: `ls data/api_cache/`
- Reduce query frequency

### Error: "Connection timeout"
- Check internet connectivity
- Verify firewall allows HTTPS outbound
- Try increasing timeout in `api_clients.py`

### No API Results
- Verify API keys in .env are loaded:
  ```bash
  python3 -c "from dotenv import load_dotenv; import os; load_dotenv(); print(os.getenv('VIRUSTOTAL_API_KEY'))"
  ```

---

## Cost Analysis

All services offer **paid tiers** for higher volume:

| Service | Free Tier | Paid Tier | Cost |
|---------|-----------|-----------|------|
| VirusTotal | 250/day | 1,000/day | ~$500/month |
| AbuseIPDB | 1,000/day | 10,000/day | $20-40/month |
| Shodan | 100/month | Unlimited | $49-899/month |

**For most SMEs, the free tiers are sufficient!**

Estimated daily queries for 100-server deployment: **~50-200 unique IPs/day**

---

## Next Steps

1. ✅ Sign up for all three APIs (15 minutes total)
2. ✅ Add keys to `.env` file
3. ✅ Run test script to verify
4. ✅ Restart SSH Guardian: `systemctl restart ssh-guardian`
5. ✅ Monitor enhanced threat detection in logs

---

## Security Best Practices

- **Never commit .env to git** (already in .gitignore)
- **Rotate API keys quarterly**
- **Monitor API usage regularly**
- **Use environment variables in production**
- **Set up alerts for API quota approaching**

---

## Support & Resources

- **VirusTotal Docs**: https://docs.virustotal.com/reference/overview
- **AbuseIPDB Docs**: https://docs.abuseipdb.com/
- **Shodan Docs**: https://developer.shodan.io/api
- **SSH Guardian Issues**: https://github.com/sohell-ranaa/ssh-guardian-2.0/issues

---

**Ready to enhance your threat detection? Start with VirusTotal (easiest setup)!**
