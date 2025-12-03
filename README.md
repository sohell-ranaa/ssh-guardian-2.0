# SSH Guardian 2.0

Advanced Real-Time SSH Anomaly Detection & Security Monitoring System

SSH Guardian 2.0 is a lightweight, intelligent security monitoring solution designed for Small and Medium Enterprises (SMEs). It provides real-time SSH log analysis with machine learning-powered anomaly detection, comprehensive threat intelligence, and smart alerting capabilities.

## Features

### Core Security Features
- **Real-Time Log Processing**: Event-driven architecture processes SSH logs instantly
- **ML-Powered Anomaly Detection**: Behavioral analysis with risk scoring (0-100)
- **Threat Intelligence Integration**: Local feeds + VirusTotal, AbuseIPDB, Shodan APIs (optional)
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

## Quick Start

### Prerequisites

- Python 3.8+
- MySQL 8.0+
- 2+ CPU cores, 4GB+ RAM
- Internet connection (for threat feeds)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/sohell-ranaa/ssh-guardian-2.0.git
   cd ssh-guardian-2.0
   ```

2. **Set up Python environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Configure database**
   ```bash
   mysql -u root -p -e "CREATE DATABASE ssh_guardian_20;"
   mysql -u root -p ssh_guardian_20 < dbs/migrations/004_ssh_security_tables.sql
   ```

4. **Set up configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your Telegram bot token and chat ID
   ```

5. **Download GeoIP database**
   - Register at MaxMind for free download
   - Place GeoLite2-City.mmdb in data/geoip/ folder

6. **[Optional] Set up API Integration** (Recommended - 10 minutes)
   ```bash
   # Get enhanced threat intelligence from VirusTotal, AbuseIPDB, Shodan
   ./scripts/setup_api_integration.sh
   # See API_QUICKSTART.md for details
   ```

### Running the System

```bash
# Start SSH Guardian 2.0
python ssh_guardian_v2_integrated.py
```

## Project Structure

```
ssh-guardian-2.0/
├── config/                      # Configuration files
├── data/                        # Data storage
│   ├── geoip/                  # GeoIP databases
│   ├── threat_feeds/           # Threat intelligence feeds
│   ├── receiving_stream/       # Incoming log files
│   ├── parsed_json/            # Processed logs
│   └── detections/             # Detection results
├── dbs/                         # Database connections and migrations
│   ├── connection.py
│   └── migrations/
├── src/                         # Source code
│   ├── agents/                 # Log collection agents
│   ├── alerts/                 # Alert system
│   ├── core/                   # Core engine
│   ├── dashboard/              # Web dashboard
│   ├── data_generation/        # Synthetic data tools
│   ├── detection/              # Detection modules
│   ├── intelligence/           # Threat intelligence
│   ├── ml/                     # Machine learning models
│   ├── processors/             # Data processors
│   ├── response/               # Response actions
│   └── services/               # Support services
├── scripts/                     # Utility scripts
│   ├── install.sh
│   ├── deploy_agent.sh
│   ├── start_guardian.sh
│   ├── start_dashboard.sh
│   └── train_production_models.py
├── tests/                       # Test files
├── docs/                        # Documentation
├── ssh_guardian_realtime.py     # Legacy real-time processor
├── ssh_guardian_v2_integrated.py # Main integrated system
└── requirements.txt             # Python dependencies
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/logs/upload` | Receive SSH logs from agents |
| `GET` | `/health` | System health and status |
| `GET` | `/analytics/comprehensive` | Full security analytics |
| `GET` | `/threat/check/<ip>` | Check IP reputation |

## Machine Learning

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

## Documentation

See the `docs/` folder for detailed documentation:
- Installation and setup guides
- Configuration reference
- API documentation
- Deployment guides

## License

This project is licensed under the MIT License.

## Acknowledgments

- **MaxMind**: GeoIP2 database for location intelligence
- **Abuse.ch**: Feodo Tracker for botnet intelligence
- **Blocklist.de**: SSH attacker intelligence
- **Telegram**: Bot API for real-time notifications
