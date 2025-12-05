# Live Stream Implementation Plan

## Overview
Create a comprehensive live stream event monitoring system with detailed analytics modals, following the design pattern established in the simulation page.

---

## Feature Requirements

### 1. Main Table View - Recent Events
**Display:** Real-time table of SSH login attempts and security events

**Columns:**
- Timestamp (with relative time: "2 mins ago")
- Event Type (Failed Login, Successful Login, Block, etc.)
- Source IP (with country flag icon)
- Username
- Location (City, Country)
- Risk Score (color-coded badge)
- ML Prediction (badge: Threat/Clean/Unknown)
- Action Taken (badge: Blocked/Monitored/Allowed)
- Actions (icon buttons)

**Design:**
- Clean table with hover effects
- Color-coded rows based on risk level
- Pagination (25/50/100 per page)
- Auto-refresh every 5 seconds (toggle on/off)
- Filter by event type, risk level, IP type
- Search by IP or username
- Export to CSV/JSON

---

### 2. Action Buttons (Per Row)

#### Button 1: Database & ML Analytics 🔍
**Icon:** `fa-chart-line`
**Color:** Primary blue
**Action:** Opens detailed analytics modal

**Modal Content:**
```
┌─────────────────────────────────────────────────┐
│ IP Analytics & ML Insights - 192.168.1.100     │
├─────────────────────────────────────────────────┤
│                                                 │
│ [ML Prediction Card]                           │
│ ┌───────────────────────────────────┐          │
│ │ Prediction: THREAT DETECTED        │          │
│ │ Confidence: 98.5%                  │          │
│ │ Risk Score: 95/100                 │          │
│ │ Model: Random Forest               │          │
│ └───────────────────────────────────┘          │
│                                                 │
│ [Action Taken Card]                            │
│ ┌───────────────────────────────────┐          │
│ │ Status: IP BLOCKED                 │          │
│ │ Blocked At: 2025-12-04 08:00:15   │          │
│ │ Duration: 24 hours                 │          │
│ │ Reason: High-risk brute force      │          │
│ │ Block Source: ML Analysis          │          │
│ └───────────────────────────────────┘          │
│                                                 │
│ [Statistics Grid]                              │
│ ┌──────┬──────┬──────┬──────┐                 │
│ │Total │Success│Failed│Blocked│                │
│ │  15  │   0   │  15  │  Yes  │                │
│ └──────┴──────┴──────┴──────┘                 │
│                                                 │
│ [Recent Activity Timeline]                     │
│ ┌───────────────────────────────────┐          │
│ │ 🔴 08:00:15 - Failed login (root) │          │
│ │ 🔴 08:00:10 - Failed login (admin)│          │
│ │ 🔴 08:00:05 - Failed login (test) │          │
│ │ ... (expandable list)              │          │
│ └───────────────────────────────────┘          │
│                                                 │
│ [User Agents Tried]                            │
│ [Passwords Attempted] (if available)           │
│ [Geographic Pattern]                           │
│                                                 │
└─────────────────────────────────────────────────┘
```

#### Button 2: 3rd Party Intelligence 🌐
**Icon:** `fa-globe`
**Color:** Warning orange
**State:**
- Enabled for public IPs (1.1.1.1, 8.8.8.8, etc.)
- Disabled for private IPs (192.168.x.x, 10.x.x.x, 172.16.x.x)

**Action:** Expands modal with threat intelligence section

**Expanded Modal Content:**
```
┌─────────────────────────────────────────────────┐
│ ... (Above content remains) ...                 │
├─────────────────────────────────────────────────┤
│ [3rd Party Threat Intelligence]                │
│                                                 │
│ Loading... [Spinner]                           │
│                                                 │
│ Then shows:                                    │
│                                                 │
│ [AbuseIPDB Card] (with gradient)              │
│ ┌───────────────────────────────────┐          │
│ │ Abuse Confidence: 85%              │          │
│ │ Total Reports: 142                 │          │
│ │ ISP: Digital Ocean                 │          │
│ │ Usage: Data Center/Hosting         │          │
│ │ Hostname: example.digitalocean.com │          │
│ └───────────────────────────────────┘          │
│                                                 │
│ [VirusTotal Card]                              │
│ [Shodan Card]                                  │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## Technical Architecture

### Database Schema Queries

```sql
-- Get recent events with all details
SELECT
    l.id,
    l.timestamp,
    l.source_ip,
    l.username,
    l.country,
    l.city,
    l.ml_risk_score,
    l.server_hostname,
    'failed' as event_type,
    b.id as block_id,
    b.block_reason,
    b.blocked_at
FROM failed_logins l
LEFT JOIN ip_blocks b ON l.source_ip = b.ip_address AND b.is_active = TRUE
WHERE l.is_simulation = FALSE
UNION ALL
SELECT
    l.id,
    l.timestamp,
    l.source_ip,
    l.username,
    l.country,
    l.city,
    l.ml_risk_score,
    l.server_hostname,
    'successful' as event_type,
    NULL,
    NULL,
    NULL
FROM successful_logins l
WHERE l.is_simulation = FALSE
ORDER BY timestamp DESC
LIMIT 100;

-- Get detailed analytics for specific IP
SELECT
    source_ip,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed,
    AVG(ml_risk_score) as avg_risk,
    MAX(timestamp) as last_seen,
    MIN(timestamp) as first_seen,
    COUNT(DISTINCT username) as unique_usernames
FROM (
    SELECT source_ip, timestamp, username, ml_risk_score, 'successful' as event_type
    FROM successful_logins WHERE is_simulation = FALSE
    UNION ALL
    SELECT source_ip, timestamp, username, ml_risk_score, 'failed' as event_type
    FROM failed_logins WHERE is_simulation = FALSE
) combined
WHERE source_ip = ?
GROUP BY source_ip;

-- Get recent activity timeline for IP
SELECT
    timestamp,
    event_type,
    username,
    ml_risk_score,
    country,
    city
FROM (
    SELECT timestamp, 'successful' as event_type, username, ml_risk_score, country, city
    FROM successful_logins WHERE source_ip = ? AND is_simulation = FALSE
    UNION ALL
    SELECT timestamp, 'failed' as event_type, username, ml_risk_score, country, city
    FROM failed_logins WHERE source_ip = ? AND is_simulation = FALSE
) combined
ORDER BY timestamp DESC
LIMIT 50;

-- Check if IP is blocked
SELECT
    ip_address,
    block_reason,
    blocked_at,
    unblock_at,
    block_source,
    TIMESTAMPDIFF(HOUR, blocked_at, unblock_at) as duration_hours
FROM ip_blocks
WHERE ip_address = ? AND is_active = TRUE;
```

---

## API Endpoints Needed

### 1. GET `/api/events/recent`
**Purpose:** Get recent events for table
**Query Params:**
- `limit` (default: 25)
- `offset` (default: 0)
- `event_type` (filter: all/failed/successful/blocked)
- `risk_level` (filter: all/low/medium/high/critical)
- `ip_type` (filter: all/public/private)
- `search` (IP or username search)

**Response:**
```json
{
  "success": true,
  "events": [
    {
      "id": 12345,
      "timestamp": "2025-12-04T08:15:30",
      "event_type": "failed",
      "source_ip": "103.13.215.175",
      "username": "root",
      "country": "Luxembourg",
      "city": "Luxembourg",
      "ml_risk_score": 95,
      "risk_level": "critical",
      "is_blocked": true,
      "block_reason": "High-risk brute force",
      "server_hostname": "web-01",
      "is_public_ip": true
    }
  ],
  "total": 1523,
  "page": 1,
  "pages": 61
}
```

### 2. GET `/api/events/analytics/<ip>`
**Purpose:** Get detailed analytics for specific IP
**Response:**
```json
{
  "success": true,
  "ip_address": "103.13.215.175",
  "analytics": {
    "statistics": {
      "total_attempts": 15,
      "successful": 0,
      "failed": 15,
      "avg_risk_score": 95.5,
      "first_seen": "2025-12-04T08:00:00",
      "last_seen": "2025-12-04T08:15:30",
      "unique_usernames": 5
    },
    "ml_prediction": {
      "prediction": "threat",
      "confidence": 0.985,
      "risk_score": 95,
      "threat_type": "brute_force",
      "model": "RandomForest"
    },
    "block_info": {
      "is_blocked": true,
      "blocked_at": "2025-12-04T08:00:15",
      "unblock_at": "2025-12-05T08:00:15",
      "duration_hours": 24,
      "block_reason": "High-risk brute force",
      "block_source": "ml_analysis"
    },
    "recent_activity": [
      {
        "timestamp": "2025-12-04T08:15:30",
        "event_type": "failed",
        "username": "root",
        "ml_risk_score": 95
      }
    ],
    "location": {
      "country": "Luxembourg",
      "city": "Luxembourg",
      "latitude": 49.6116,
      "longitude": 6.13
    }
  }
}
```

### 3. GET `/api/events/intelligence/<ip>`
**Purpose:** Get 3rd party threat intelligence
**Response:** (Same as existing `/api/ip/intel/lookup/<ip>`)

---

## Frontend Components

### 1. Live Stream Page Structure

```html
<div class="live-stream-container">
  <!-- Header with filters and controls -->
  <div class="stream-header">
    <h2>Live Event Stream</h2>
    <div class="stream-controls">
      <button id="refresh-toggle">
        <i class="fas fa-sync"></i> Auto-refresh: ON
      </button>
      <select id="event-filter">
        <option value="all">All Events</option>
        <option value="failed">Failed Logins</option>
        <option value="successful">Successful Logins</option>
        <option value="blocked">Blocked IPs</option>
      </select>
      <select id="risk-filter">
        <option value="all">All Risk Levels</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <input type="search" id="search-box" placeholder="Search IP or username...">
      <button id="export-csv">
        <i class="fas fa-download"></i> Export
      </button>
    </div>
  </div>

  <!-- Stats Cards Row -->
  <div class="stream-stats-row">
    <div class="stat-card-compact">
      <i class="fas fa-list"></i>
      <div>
        <div class="stat-label">Total Events (24h)</div>
        <div class="stat-value" id="stat-total-24h">0</div>
      </div>
    </div>
    <div class="stat-card-compact">
      <i class="fas fa-times-circle text-danger"></i>
      <div>
        <div class="stat-label">Failed Logins</div>
        <div class="stat-value" id="stat-failed">0</div>
      </div>
    </div>
    <div class="stat-card-compact">
      <i class="fas fa-shield-alt text-warning"></i>
      <div>
        <div class="stat-label">Blocked IPs</div>
        <div class="stat-value" id="stat-blocked">0</div>
      </div>
    </div>
    <div class="stat-card-compact">
      <i class="fas fa-exclamation-triangle text-danger"></i>
      <div>
        <div class="stat-label">High Risk</div>
        <div class="stat-value" id="stat-high-risk">0</div>
      </div>
    </div>
  </div>

  <!-- Events Table -->
  <div class="events-table-container">
    <table class="table table-hover events-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Type</th>
          <th>Source IP</th>
          <th>Username</th>
          <th>Location</th>
          <th>Risk Score</th>
          <th>ML Prediction</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="events-tbody">
        <!-- Populated dynamically -->
      </tbody>
    </table>
  </div>

  <!-- Pagination -->
  <div class="pagination-controls">
    <button id="prev-page">Previous</button>
    <span id="page-info">Page 1 of 10</span>
    <button id="next-page">Next</button>
    <select id="per-page">
      <option value="25">25 per page</option>
      <option value="50">50 per page</option>
      <option value="100">100 per page</option>
    </select>
  </div>
</div>

<!-- Analytics Modal -->
<div class="modal fade" id="analyticsModal" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title">
          <i class="fas fa-chart-line"></i>
          IP Analytics & ML Insights - <span id="modal-ip">0.0.0.0</span>
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <!-- ML Prediction Section -->
        <div id="ml-prediction-section"></div>

        <!-- Action Taken Section -->
        <div id="action-taken-section"></div>

        <!-- Statistics Grid -->
        <div id="statistics-grid"></div>

        <!-- Recent Activity Timeline -->
        <div id="activity-timeline"></div>

        <!-- 3rd Party Intelligence Button -->
        <div class="text-center my-3">
          <button id="load-intel-btn" class="btn btn-warning">
            <i class="fas fa-globe"></i> Load 3rd Party Intelligence
          </button>
        </div>

        <!-- 3rd Party Intelligence Section (collapsed by default) -->
        <div id="intel-section" style="display: none;">
          <hr>
          <h6><i class="fas fa-database"></i> 3rd Party Threat Intelligence</h6>
          <div id="intel-content"></div>
        </div>
      </div>
    </div>
  </div>
</div>
```

### 2. JavaScript Functions

```javascript
// Main functions needed
async function loadRecentEvents(page = 1, filters = {}) { }
function displayEventsTable(events) { }
function openAnalyticsModal(ip) { }
async function loadIPAnalytics(ip) { }
function displayMLPrediction(data) { }
function displayActionTaken(data) { }
function displayStatistics(data) { }
function displayActivityTimeline(activities) { }
async function load3rdPartyIntel(ip) { }
function displayThreatIntelligence(intel) { }
function isPublicIP(ip) { }
function startAutoRefresh() { }
function stopAutoRefresh() { }
function exportToCSV() { }
```

---

## Design Pattern Consistency

### Colors (Same as Simulation)
- **Critical:** #E74856 (Red)
- **High:** #F59100 (Orange)
- **Medium:** #0078D4 (Blue)
- **Low:** #10893E (Green)
- **Clean:** #E8F5EA (Light Green)

### Typography
- **Headers:** 13-14px, bold (700)
- **Values:** 16-20px, semi-bold (600-700)
- **Labels:** 10-11px, uppercase, letter-spacing
- **Body:** 12-13px

### Card Styles
- Gradient backgrounds for threat levels
- Hover effects with lift + shadow
- 8px border radius
- 0.2s transitions
- Compact padding (14-16px)

### Modal Design
- Large modal (`modal-lg`)
- Sections separated by subtle borders
- Expandable intelligence section
- Smooth expand/collapse animations
- Loading spinners for async operations

---

## Implementation Steps

### Phase 1: Backend API (Day 1)
1. ✅ Create `/api/events/recent` endpoint
2. ✅ Create `/api/events/analytics/<ip>` endpoint
3. ✅ Ensure `/api/ip/intel/lookup/<ip>` works
4. ✅ Add SQL queries for event aggregation
5. ✅ Test all endpoints with real data

### Phase 2: Frontend Structure (Day 1-2)
1. ✅ Create live stream page HTML
2. ✅ Add table structure with headers
3. ✅ Create analytics modal template
4. ✅ Add CSS styles matching simulation design
5. ✅ Implement responsive layout

### Phase 3: Core Functionality (Day 2)
1. ✅ Load and display events table
2. ✅ Implement pagination
3. ✅ Add filters (event type, risk level, search)
4. ✅ Open analytics modal on button click
5. ✅ Load and display IP analytics

### Phase 4: ML & Intelligence (Day 2-3)
1. ✅ Display ML prediction card
2. ✅ Display action taken card
3. ✅ Display statistics grid
4. ✅ Display activity timeline
5. ✅ Implement 3rd party intelligence loading
6. ✅ Detect public vs private IPs
7. ✅ Enable/disable intelligence button

### Phase 5: Polish & Features (Day 3)
1. ✅ Auto-refresh every 5 seconds
2. ✅ Export to CSV functionality
3. ✅ Loading states and spinners
4. ✅ Error handling
5. ✅ Relative time display ("2 mins ago")
6. ✅ Country flag icons
7. ✅ Responsive design testing

---

## Files to Create/Modify

### New Files
1. `src/dashboard/static/js/live-stream.js` - Main JavaScript
2. `src/dashboard/static/css/live-stream.css` - Custom styles

### Modified Files
1. `src/dashboard/dashboard_server.py` - Add new API endpoints
2. `src/dashboard/templates/enhanced_dashboard.html` - Add live stream tab content

---

## Success Criteria

✅ Table displays recent events with all columns
✅ Auto-refresh works (toggle on/off)
✅ Filters work (event type, risk level, search)
✅ Analytics modal opens with IP details
✅ ML prediction displays correctly
✅ Action taken shows block status
✅ Statistics grid shows counts
✅ Activity timeline shows recent events
✅ 3rd party intelligence button enabled only for public IPs
✅ Intelligence data loads and displays when clicked
✅ Design matches simulation page pattern
✅ Responsive on all screen sizes
✅ Export to CSV works

---

## Estimated Timeline
- **Backend:** 4-6 hours
- **Frontend:** 6-8 hours
- **Testing:** 2-3 hours
- **Total:** 12-17 hours (2-3 days)

---

## Notes
- Follow exact same CSS classes as simulation page
- Reuse `displayThreatIntelligence()` function from simulation.js
- Use Bootstrap 5 modal components
- Implement debouncing for search input
- Add loading spinners for all async operations
- Cache intelligence data per IP
- Add keyboard shortcuts (R = refresh, E = export)
