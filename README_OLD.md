# SSH Guardian 2.0 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MySQL 8.0+](https://img.shields.io/badge/mysql-8.0+-orange.svg)](https://www.mysql.com/)

**Advanced Real-Time SSH Anomaly Detection & Security Monitoring System**

SSH Guardian 2.0 is a lightweight, intelligent security monitoring solution designed specifically for Small and Medium Enterprises (SMEs). It provides real-time SSH log analysis with machine learning-powered anomaly detection, comprehensive threat intelligence, and smart alerting capabilities.

## 🚀 Features

### Core Security Features
- **Real-Time Log Processing**: Event-driven architecture processes SSH logs instantly
- **ML-Powered Anomaly Detection**: Behavioral analysis with risk scoring (0-100)
- **Threat Intelligence Integration**: Daily-updated feeds from multiple sources
- **GeoIP Enrichment**: Location tracking with timezone support
- **Smart Alerting**: Comprehensive Telegram notifications with analytics

### Advanced Capabilities
- **Zero Duplicates**: Hash-based deduplication prevents redundant entries
- **Behavioral Profiling**: User pattern analysis and deviation detection
- **Comprehensive Analytics**: Hourly patterns, country stats, threat distribution
- **Multi-Channel Alerts**: Telegram with rich formatting and recommendations
- **Background Processing**: Automatic enrichment of existing records

### Enterprise-Ready
- **Scalable Architecture**: Handles 10,000+ events per minute
- **Lightweight Design**: Runs on minimal hardware (2 CPU, 4GB RAM)
- **Open Source**: No licensing costs, full customization
- **Easy Deployment**: Single unified system, no complex orchestration

## 📊 Screenshots

### Telegram Alert Example
```
🚨 HIGH RISK SSH Security Alert

📊 Event Details:
• Server: production-server
• Event: Failed Password  
• Source IP: 203.0.113.42
• Username: root

🌍 Location:
• City: Shanghai, China
• Timezone: Asia/Shanghai

🤖 ML Analysis:
• Risk Score: 75/100
• Threat Type: Suspicious Activity
• Confidence: 85.2%
• Anomaly: 🔴 YES

🛡️ Threat Intelligence:
• SSH Attacker - Brute Force Source
• Known Botnet Infrastructure

💡 Recommendations:
• Immediate investigation required
• Consider IP blocking
• Review server access policies
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   SSH Agents    │───▶│   Log Receiver   │───▶│   Real-time     │
│   (Port 5000)   │    │   (Queue-based)  │    │   Processing    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Telegram      │◀───│   Smart Alerts   │◀───│   ML Analysis   │
│   Notifications │    │   (Analytics)    │    │   (Risk Score)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Analytics     │◀───│    Database      │◀───│   GeoIP +       │
│   Dashboard     │    │   (MySQL 8.0)   │    │   Threat Intel  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

```bash
# System Requirements
- Python 3.8+
- MySQL 8.0+
- 2+ CPU cores, 4GB+ RAM
- Internet connection (for threat feeds)
```

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/sohell-ranaa/ssh-guardian-2.0.git
   cd ssh-guardian-2.0
   ```

2. **Set up Python environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure database**
   ```bash
   # Create database
   mysql -u root -p -e "CREATE DATABASE ssh_guardian_20;"
   
   # Create tables
   mysql -u root -p ssh_guardian_20 < dbs/migrations/004_ssh_security_tables.sql
   ```

4. **Set up configuration**
   ```bash
   # Copy and edit environment file
   cp .env.example .env
   nano .env
   ```

5. **Configure environment variables**
   ```bash
   # .env file
   TELEGRAM_BOT_TOKEN="your_bot_token_here"
   TELEGRAM_CHAT_ID="your_chat_id_here"
   ```

6. **Download GeoIP database**
   ```bash
   # Download GeoLite2-City.mmdb to data/ folder
   # Register at MaxMind for free download
   ```

### Running the System

```bash
# Start SSH Guardian 2.0
python ssh_guardian_realtime.py
```

**System will start on port 5000 with comprehensive logging.**

## 🔧 Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather | `1234567890:ABCdef...` |
| `TELEGRAM_CHAT_ID` | Your Telegram chat ID | `123456789` |
| `ALERT_RISK_THRESHOLD` | Risk score for alerts | `40` |
| `AUTO_BLOCK_THRESHOLD` | Score for auto-blocking | `85` |

### Database Configuration

Edit `dbs/connection.py` for database settings:

```python
DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "root", 
    "password": "your_password",
    "database": "ssh_guardian_20"
}
```

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/logs/upload` | Receive SSH logs from agents |
| `GET` | `/health` | System health and status |
| `GET` | `/logs/status` | Processing queue status |
| `GET` | `/analytics/comprehensive` | Full security analytics |
| `GET` | `/threat/check/<ip>` | Check IP reputation |
| `GET` | `/stats/enrichment` | Enrichment processing stats |
| `POST` | `/test/alert` | Test alert system |
| `GET` | `/test/telegram` | Test Telegram integration |

### Example Usage

```bash
# Send SSH logs
curl -X POST http://localhost:5000/logs/upload \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "web-server-01",
    "logs": [
      "Failed password for root from 203.0.113.42 port 22 ssh2",
      "Invalid user admin from 198.51.100.10 port 22"
    ]
  }'

# Get comprehensive analytics
curl http://localhost:5000/analytics/comprehensive

# Check IP reputation
curl http://localhost:5000/threat/check/203.0.113.42
```

## 🤖 Machine Learning

### Risk Scoring Algorithm

SSH Guardian uses multi-factor risk analysis:

- **Time-based factors**: Off-hours access (+10 points)
- **Geographic factors**: Unusual locations (+15 points) 
- **Behavioral factors**: Failed attempts (+20 points)
- **Threat intelligence**: Known malicious IPs (+30-40 points)
- **User patterns**: Invalid usernames (+20 points)

### Risk Categories

| Score Range | Category | Action |
|-------------|----------|---------|
| 0-39 | Low Risk | Log only |
| 40-59 | Medium Risk | Alert + Monitor |
| 60-79 | High Risk | Alert + Investigate |
| 80-100 | Critical Risk | Alert + Block |

## 📊 Analytics & Insights

### Dashboard Features

- **Hourly Activity Patterns**: 24-hour attack distribution
- **Geographic Analysis**: Country-based threat statistics
- **Threat Intelligence**: Real-time malicious IP tracking
- **Risk Distribution**: Critical/High/Medium/Low breakdown
- **Top Attackers**: Most active malicious sources

### Sample Analytics Response

```json
{
  "threat_stats": {
    "total_events": 1247,
    "critical_risk": 23,
    "high_risk": 156,
    "medium_risk": 445,
    "low_risk": 623,
    "malicious_ips": 67
  },
  "country_stats": {
    "China": {"events": 234, "avg_risk": 62.3, "malicious": 45},
    "Russia": {"events": 189, "avg_risk": 58.7, "malicious": 32}
  },
  "recent_high_risk_events": [...]
}
```

## 🔌 Integrations

### SSH Log Agents

Deploy agents on servers to send logs:

```bash
# Install agent on target server
curl -sSL https://raw.githubusercontent.com/yourusername/ssh-guardian-2.0/main/install_agent.sh | bash

# Or manual setup
python src/agents/log_agent.py --server guardian.example.com:5000
```

### Telegram Bot Setup

1. Create bot with @BotFather
2. Get chat ID: `/start` → copy chat ID
3. Add to `.env` file
4. Test: `curl http://localhost:5000/test/telegram`

## 🛠️ Development

### Project Structure

```
ssh-guardian-2.0/
├── ssh_guardian_realtime.py    # Main unified system
├── dbs/
│   ├── connection.py           # Database connection pool
│   └── migrations/             # Database schema files
├── data/
│   ├── threat_feeds/          # Cached threat intelligence
│   ├── parsed_json/           # Processed log files
│   └── GeoLite2-City.mmdb     # GeoIP database
├── src/
│   ├── agents/                # SSH log collection agents
│   └── ml/                    # Machine learning models
└── database/
    └── schema/                # Database schema
```

### Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push branch: `git push origin feature/amazing-feature`
5. Open Pull Request

### Running Tests

```bash
# Unit tests
python -m pytest tests/

# Integration tests
python -m pytest tests/integration/

# Test with sample data
python tests/test_with_sample_logs.py
```

## 📈 Performance

### Benchmarks

| Metric | Value |
|--------|--------|
| **Log Processing** | 10,000+ events/minute |
| **Detection Latency** | <30 seconds |
| **Memory Usage** | <512MB typical |
| **CPU Usage** | <30% on 2-core system |
| **Database Growth** | ~1MB per 1000 events |

### Scaling

- **Horizontal**: Deploy multiple instances with load balancer
- **Vertical**: Increase CPU/RAM for higher throughput  
- **Database**: Use MySQL clustering for high availability
- **Caching**: Redis for analytics and threat intelligence

## 🔒 Security Considerations

### Best Practices

- **Secure Communication**: Use HTTPS for API endpoints
- **Database Security**: Strong passwords, network restrictions
- **Log Retention**: Implement automated cleanup policies
- **Access Control**: Restrict administrative endpoints
- **Backup Strategy**: Regular database backups

### Threat Model

SSH Guardian protects against:

✅ **Brute Force Attacks**: Pattern detection and alerting  
✅ **Credential Stuffing**: Username/password pattern analysis  
✅ **Geographic Anomalies**: Location-based risk assessment  
✅ **Known Malicious IPs**: Threat intelligence correlation  
✅ **Behavioral Anomalies**: ML-powered deviation detection  

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api.md)
- [Troubleshooting Guide](docs/troubleshooting.md)
- [Performance Tuning](docs/performance.md)

## 🤝 Support

### Community

- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Questions and community support
- **Wiki**: Additional documentation and examples

### Commercial Support

For enterprise support, custom development, or consulting:
- Email: support@yourcompany.com
- Website: https://yourcompany.com/ssh-guardian

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **MaxMind**: GeoIP2 database for location intelligence
- **Abuse.ch**: Feodo Tracker for botnet intelligence  
- **Blocklist.de**: SSH attacker intelligence
- **Telegram**: Bot API for real-time notifications
- **MySQL**: Robust database platform
- **Python Community**: Amazing libraries and tools

## 📊 Statistics

![GitHub stars](https://img.shields.io/github/stars/yourusername/ssh-guardian-2.0?style=social)
![GitHub forks](https://img.shields.io/github/forks/yourusername/ssh-guardian-2.0?style=social)
![GitHub issues](https://img.shields.io/github/issues/yourusername/ssh-guardian-2.0)
![GitHub license](https://img.shields.io/github/license/yourusername/ssh-guardian-2.0)

---

**Made with ❤️ for SME cybersecurity**

*Protecting small businesses from cyber threats, one SSH log at a time.*
