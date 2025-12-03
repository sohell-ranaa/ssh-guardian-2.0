# SSH Guardian 2.0 - ML & Dashboard Implementation Guide

**Date:** December 2, 2025
**Status:** Phase 1 Complete - Training Data Ready
**Next Steps:** ML Training → Smart Alerts → Dashboard

---

## ✅ Completed Work

### 1. Large-Scale Training Dataset Generation

**Status:** ✅ COMPLETE

**Results:**
- **Total Events Generated:** 62,109
- **Successful Logins:** 30,854 (49.7%)
- **Failed Logins:** 31,255 (50.3%)
- **Anomalies:** 27,885 (44.9%)
  - Breaches: 340
  - Attack Attempts: 27,545
- **Time Span:** 90 days (Sept 3 - Dec 2, 2025)

**Attack Patterns Included:**
- 250 reconnaissance campaigns (slow scans)
- 333 low-severity brute force attacks
- 142 medium-severity brute force attacks
- 33 high-severity brute force attacks
- 26 distributed attack campaigns
- 40 successful breach scenarios

**Data Quality:**
- ✅ Realistic IP distributions (legit + malicious)
- ✅ Geographic diversity (17+ countries)
- ✅ Temporal patterns (business hours, attack waves)
- ✅ Complete GeoIP data
- ✅ ML-ready features pre-extracted

**Files:**
- `generate_large_training_dataset.py` - Generator script
- Database: `ssh_guardian_20.successful_logins` + `ssh_guardian_20.failed_logins`

### 2. Smart Telegram Alerting System

**Status:** ✅ COMPLETE (Code Ready)

**Key Features:**
- **Intelligent Aggregation:** Prevents message bombardment
- **Severity-Based Routing:**
  - Critical (90-100): Immediate alert
  - High (85-89): Alert within 60s
  - Medium (70-84): Batched every 15 min
  - Low (50-69): Hourly digest
  - Info (0-49): Daily summary

- **Deduplication:** Suppresses duplicate alerts (10-min window)
- **Campaign Tracking:** Identifies ongoing attack patterns
- **Smart Grouping:** Aggregates related events
- **Analytics:** Compression ratio tracking

**Alert Types:**
1. **Immediate Alerts** - Critical/High threats
2. **Batch Alerts** - Medium threats (15-min intervals)
3. **Hourly Digests** - Low threats
4. **Daily Summaries** - Full analytics

**Files:**
- `src/intelligence/smart_alerting.py` - Complete implementation

---

## 🔄 Next Steps: Implementation Roadmap

### Phase 2: Enhanced ML Training (Priority: HIGH)

**Objective:** Train accurate ML models with 62k+ training data

**Steps:**

1. **Create Enhanced Feature Extractor**
   ```python
   # File: src/ml/enhanced_feature_extractor.py
   Features to extract (30+ features):
   - Temporal: hour, day_of_week, is_business_hours
   - Geographic: country_risk, impossible_travel_score
   - Behavioral: failed_attempts_last_hour, unique_usernames_tried
   - Statistical: attempts_per_minute, variance in timing
   - Contextual: username_entropy, is_known_attacker
   ```

2. **Train Multiple Models**
   ```bash
   # Random Forest (primary)
   python3 src/ml/train_random_forest_v3.py --data 62k --features 30

   # XGBoost (secondary)
   python3 src/ml/train_xgboost.py --data 62k

   # Isolation Forest (anomaly detection)
   python3 src/ml/train_isolation_forest_v2.py
   ```

3. **Model Evaluation**
   - Target Accuracy: >95%
   - False Positive Rate: <2%
   - False Negative Rate: <1%
   - Cross-validation: 5-fold

4. **Model Deployment**
   - Save models to `src/ml/models/production/`
   - Update `src/ml/model_manager.py` to load new models
   - Add model versioning

**Expected Results:**
- Brute Force Detection: 98%+ accuracy
- Breach Detection: 95%+ accuracy
- Reconnaissance: 90%+ accuracy
- Normal Traffic: 97%+ correct classification

---

### Phase 3: Intelligent Event Flagging Logic (Priority: HIGH)

**Objective:** Define clear rules for what gets flagged and blocked

**Event Flagging Rules:**

```python
# File: src/core/event_classifier.py

class EventClassifier:
    """
    Multi-layered threat classification system
    """

    FLAGGING_RULES = {
        'CRITICAL_BLOCK': {
            'conditions': [
                'risk_score >= 90',
                'OR threat_type == "intrusion"',
                'OR successful_login AND ip_reputation == "malicious"',
                'OR distributed_attack AND target_count > 5'
            ],
            'action': 'immediate_block',
            'block_duration': '30d',
            'notify': 'immediate_telegram'
        },

        'HIGH_WATCH': {
            'conditions': [
                'risk_score >= 80',
                'OR brute_force_attempts > 20',
                'OR reconnaissance_pattern_detected'
            ],
            'action': 'temporary_block',
            'block_duration': '7d',
            'notify': 'immediate_telegram'
        },

        'MEDIUM_MONITOR': {
            'conditions': [
                'risk_score >= 70',
                'OR brute_force_attempts > 10',
                'OR suspicious_timing_pattern'
            ],
            'action': 'rate_limit',
            'notify': 'batched_telegram'
        },

        'LOW_LOG': {
            'conditions': [
                'risk_score >= 50',
                'OR unknown_country',
                'OR unusual_username'
            ],
            'action': 'log_and_monitor',
            'notify': 'hourly_digest'
        }
    }

    THREAT_SCORING = {
        # Base scores by threat type
        'intrusion': 95,
        'brute_force': 80,
        'distributed_attack': 85,
        'reconnaissance': 60,
        'failed_auth': 30,

        # Modifiers
        'known_malicious_ip': +15,
        'tor_exit_node': +10,
        'high_risk_country': +10,
        'multiple_servers_targeted': +15,
        'rapid_attempts': +20,
        'successful_after_failures': +25,
        'impossible_travel': +20,
        'suspicious_username': +10,
        'off_hours_access': +5
    }

    def calculate_final_risk_score(self, event, ml_score, threat_intel):
        """
        Combine ML prediction with rule-based logic
        """
        base_score = ml_score

        # Apply modifiers
        for condition, modifier in self.THREAT_SCORING.items():
            if self.check_condition(event, threat_intel, condition):
                base_score += modifier

        # Normalize to 0-100
        return min(100, max(0, base_score))
```

**Blocking Strategy:**
1. **Immediate Block (90+):** Critical threats, 30-day ban
2. **Temporary Block (80-89):** High threats, 7-day ban
3. **Rate Limit (70-79):** Medium threats, slow down connections
4. **Monitor Only (50-69):** Log for analysis
5. **Allow (0-49):** Normal traffic

**Whitelist Protection:**
- Office IPs always whitelisted
- Legitimate cloud providers (AWS, GCP, Azure)
- VPN endpoints
- Known service accounts

---

### Phase 4: Mobile-Responsive Dashboard (Priority: MEDIUM)

**Objective:** Beautiful, functional web dashboard

**Technology Stack:**
- Backend: Flask (Python)
- Frontend: HTML5 + Bootstrap 5 + Chart.js
- Real-time: WebSocket for live updates
- Database: MySQL (existing)

**Dashboard Components:**

#### 1. **Main Dashboard** (`/`)
```
┌─────────────────────────────────────────────────┐
│  SSH Guardian 2.0 - Security Dashboard          │
├─────────────────────────────────────────────────┤
│  📊 Statistics (Today)                          │
│  ┌──────┬──────┬──────┬──────┐                 │
│  │ 1,234│  45  │  12  │ 99.2%│                 │
│  │Events│Threat│Block │Uptime│                 │
│  └──────┴──────┴──────┴──────┘                 │
│                                                  │
│  📈 Real-Time Activity (Chart.js)               │
│  ┌────────────────────────────────────┐         │
│  │  [Line graph: Events over time]    │         │
│  └────────────────────────────────────┘         │
│                                                  │
│  🚨 Recent Alerts                               │
│  ┌────────────────────────────────────┐         │
│  │ ⚠️  185.220.101.50 - Brute Force    │         │
│  │ 🚨 222.186.42.34 - Intrusion        │         │
│  └────────────────────────────────────┘         │
└─────────────────────────────────────────────────┘
```

#### 2. **Threats View** (`/threats`)
- Table of all detected threats
- Filters: Severity, Type, Date Range, Country
- Sort by: Risk Score, Timestamp, IP
- Action buttons: Block, Whitelist, Investigate

#### 3. **Blocked IPs** (`/blocked`)
- List of currently blocked IPs
- Block reason, duration, expiry
- Unblock functionality
- Export to CSV

#### 4. **Analytics** (`/analytics`)
- Attack trends over time
- Top attacking countries (world map)
- Attack type distribution (pie chart)
- Server vulnerability heatmap
- ML model performance metrics

#### 5. **Live Monitor** (`/live`)
- Real-time event stream
- WebSocket updates
- Filter by severity
- Search by IP/user

#### 6. **Settings** (`/settings`)
- Configure thresholds
- Manage whitelist
- Telegram settings
- ML model selection
- Email alerts

**Mobile Responsive Design:**
- Bootstrap 5 grid system
- Touch-friendly controls
- Collapsible sidebars
- Swipe gestures
- Works on phones, tablets, desktops

**File Structure:**
```
src/dashboard/
├── app.py (Flask app)
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── threats.html
│   ├── blocked.html
│   ├── analytics.html
│   ├── live.html
│   └── settings.html
├── static/
│   ├── css/
│   │   └── custom.css
│   ├── js/
│   │   ├── dashboard.js
│   │   ├── charts.js
│   │   └── websocket.js
│   └── img/
└── api/
    └── endpoints.py
```

---

## 🎯 Implementation Priority

### Week 1: ML Training & Event Classifier
1. Create enhanced feature extractor (Day 1-2)
2. Train Random Forest with 62k data (Day 2-3)
3. Train XGBoost and Isolation Forest (Day 3-4)
4. Implement Event Classifier logic (Day 4-5)
5. Integration testing (Day 5-7)

**Deliverable:** Production-ready ML models with >95% accuracy

### Week 2: Smart Alerts Integration
1. Integrate Smart Alerting with Guardian Engine (Day 1-2)
2. Configure alert rules and thresholds (Day 2-3)
3. Test Telegram alerts (immediate, batch, digest) (Day 3-4)
4. Fine-tune deduplication logic (Day 4-5)
5. Load testing (1000+ events/min) (Day 5-7)

**Deliverable:** Intelligent alerting system preventing spam

### Week 3: Dashboard Development
1. Set up Flask app structure (Day 1)
2. Build main dashboard + statistics (Day 1-2)
3. Create threats and blocked IPs views (Day 3-4)
4. Implement analytics with Chart.js (Day 4-5)
5. Add WebSocket for live updates (Day 5-6)
6. Mobile responsive testing (Day 6-7)

**Deliverable:** Fully functional, mobile-responsive dashboard

### Week 4: Integration & Thesis Prep
1. End-to-end system testing (Day 1-2)
2. Performance optimization (Day 2-3)
3. Deploy on production server (Day 3-4)
4. Collect metrics for thesis (Day 4-7)
5. Compare with fail2ban baseline (Day 4-7)

**Deliverable:** Production deployment + thesis data

---

## 📊 Success Metrics for Thesis

### ML Model Performance
- [ ] Accuracy: >95%
- [ ] Precision: >93%
- [ ] Recall: >96%
- [ ] F1-Score: >94%
- [ ] False Positive Rate: <2%

### System Performance
- [ ] Event Processing: <100ms per event
- [ ] Alert Latency: <5s for critical alerts
- [ ] Dashboard Load Time: <2s
- [ ] Uptime: >99.9%
- [ ] Memory Usage: <500MB

### Comparison vs Fail2ban
- [ ] Detection Rate: SSH Guardian > Fail2ban by 15%+
- [ ] False Positives: SSH Guardian < Fail2ban by 50%+
- [ ] Response Time: SSH Guardian < Fail2ban by 80%+
- [ ] Attack Pattern Recognition: SSH Guardian 95% vs Fail2ban 60%

---

## 🚀 Quick Start Commands

### Generate More Training Data
```bash
# Generate additional 50k events
python3 generate_large_training_dataset.py

# Total will be: 62k + 50k = 112k events
```

### Train ML Models (Next Step)
```bash
# Install additional dependencies
pip install xgboost lightgbm optuna

# Train models
python3 src/ml/train_production_models.py \
  --data-size 62000 \
  --models rf,xgb,isolation \
  --optimize-hyperparameters \
  --save-to src/ml/models/production/
```

### Start Dashboard (After Implementation)
```bash
# Run Flask dashboard
cd src/dashboard
python3 app.py --port 8080 --host 0.0.0.0

# Access at: http://your-server:8080
```

### Integrate Smart Alerts
```python
# In ssh_guardian_v2_integrated.py

from src.intelligence.smart_alerting import SmartAlertManager

# Initialize
alert_manager = SmartAlertManager(
    telegram_bot_token=config.TELEGRAM_BOT_TOKEN,
    telegram_chat_id=config.TELEGRAM_CHAT_ID,
    enable_smart_grouping=True
)

# Use in processing loop
if guardian_result['overall_risk_score'] >= 70:
    alert_manager.add_alert(event, guardian_result)
```

---

## 📁 Files Created

1. ✅ `generate_large_training_dataset.py` - Large-scale data generator
2. ✅ `src/intelligence/smart_alerting.py` - Smart Telegram alerts
3. ⏳ `src/ml/enhanced_feature_extractor.py` - Advanced feature engineering
4. ⏳ `src/ml/train_production_models.py` - Production ML training
5. ⏳ `src/core/event_classifier.py` - Intelligent threat classification
6. ⏳ `src/dashboard/app.py` - Flask dashboard backend
7. ⏳ `src/dashboard/templates/*.html` - Dashboard UI

## 📝 Next Immediate Action

**Create the ML training script to train on the 62k dataset:**

```bash
cd /home/rana-workspace/ssh_guardian_2.0
python3 src/ml/train_production_models.py
```

This will generate production-ready ML models with high accuracy based on the large training dataset.

---

**Status:**
- ✅ Data Generation: COMPLETE (62,109 events)
- ✅ Smart Alerting: CODE COMPLETE
- ⏳ ML Training: READY TO START
- ⏳ Event Classifier: DESIGN COMPLETE
- ⏳ Dashboard: DESIGN COMPLETE

**Next Session:** Start ML training with the 62k dataset for maximum accuracy.
