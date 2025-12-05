/**
 * SSH Guardian 2.0 - Live Stream Module
 * Real-time event monitoring with detailed analytics
 * Version: 1.0
 */

console.log('=== Live Stream Module v1.0 loaded ===');

// Namespace for live stream to avoid conflicts
const LiveStream = {
    currentPage: 1,
    currentLimit: 25,
    totalPages: 1,
    refreshInterval: null,
    refreshEnabled: true,
    filters: {
        event_type: 'all',
        risk_level: 'all',
        ip_type: 'all',
        search: ''
    }
};

// Initialize live stream when tab is loaded
function initializeLiveStream() {
    console.log('=== Initializing Live Stream ===');

    // Check if already initialized
    if (window.liveStreamInitialized) {
        console.log('Live Stream already initialized, skipping...');
        return;
    }

    window.liveStreamInitialized = true;

    // Load initial data
    loadRecentEvents();

    // Load stats
    loadStreamStats();

    // Setup event listeners
    setupEventListeners();

    // Start auto-refresh
    startAutoRefresh();

    console.log('Live Stream initialized successfully');
}

// Setup all event listeners
function setupEventListeners() {
    // Auto-refresh toggle
    const refreshToggle = document.getElementById('refresh-toggle-btn');
    if (refreshToggle) {
        refreshToggle.addEventListener('click', toggleAutoRefresh);
    }

    // Filter selects
    const eventFilter = document.getElementById('event-filter');
    if (eventFilter) {
        eventFilter.addEventListener('change', (e) => {
            LiveStream.filters.event_type = e.target.value;
            LiveStream.currentPage = 1;
            loadRecentEvents();
        });
    }

    const riskFilter = document.getElementById('risk-filter');
    if (riskFilter) {
        riskFilter.addEventListener('change', (e) => {
            LiveStream.filters.risk_level = e.target.value;
            LiveStream.currentPage = 1;
            loadRecentEvents();
        });
    }

    const ipTypeFilter = document.getElementById('ip-type-filter');
    if (ipTypeFilter) {
        ipTypeFilter.addEventListener('change', (e) => {
            LiveStream.filters.ip_type = e.target.value;
            LiveStream.currentPage = 1;
            loadRecentEvents();
        });
    }

    // Search box with debounce
    const searchBox = document.getElementById('search-box');
    if (searchBox) {
        let searchTimeout;
        searchBox.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                LiveStream.filters.search = e.target.value;
                LiveStream.currentPage = 1;
                loadRecentEvents();
            }, 500); // 500ms debounce
        });
    }

    // Per page selector
    const perPageSelect = document.getElementById('per-page');
    if (perPageSelect) {
        perPageSelect.addEventListener('change', (e) => {
            LiveStream.currentLimit = parseInt(e.target.value);
            LiveStream.currentPage = 1;
            loadRecentEvents();
        });
    }

    // Pagination buttons
    const prevBtn = document.getElementById('prev-page');
    if (prevBtn) {
        prevBtn.addEventListener('click', () => {
            if (LiveStream.currentPage > 1) {
                LiveStream.currentPage--;
                loadRecentEvents();
            }
        });
    }

    const nextBtn = document.getElementById('next-page');
    if (nextBtn) {
        nextBtn.addEventListener('click', () => {
            if (LiveStream.currentPage < LiveStream.totalPages) {
                LiveStream.currentPage++;
                loadRecentEvents();
            }
        });
    }

    // Export button
    const exportBtn = document.getElementById('export-csv-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportToCSV);
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'r' && e.ctrlKey) {
            e.preventDefault();
            loadRecentEvents();
        } else if (e.key === 'e' && e.ctrlKey) {
            e.preventDefault();
            exportToCSV();
        }
    });
}

// Load recent events from API
async function loadRecentEvents() {
    console.log('Loading recent events...', LiveStream.filters);

    const tbody = document.getElementById('events-tbody');
    if (!tbody) {
        console.error('Events table body not found');
        return;
    }

    // Show loading state
    tbody.innerHTML = '<tr><td colspan="12" class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Loading events...</div></td></tr>';

    try {
        const offset = (LiveStream.currentPage - 1) * LiveStream.currentLimit;
        const params = new URLSearchParams({
            limit: LiveStream.currentLimit,
            offset: offset,
            event_type: LiveStream.filters.event_type,
            risk_level: LiveStream.filters.risk_level,
            ip_type: LiveStream.filters.ip_type,
            search: LiveStream.filters.search
        });

        const url = `${window.API_BASE || ""}/api/events/live?${params}`;
        console.log('Fetching:', url);

        const response = await fetch(url, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        console.log('Events loaded:', data);

        if (data.success) {
            displayEventsTable(data.events);
            updatePaginationControls(data.page, data.pages, data.total);
            LiveStream.totalPages = data.pages;
        } else {
            throw new Error(data.error || 'Failed to load events');
        }

    } catch (error) {
        console.error('Error loading events:', error);
        tbody.innerHTML = '<tr><td colspan="12" class="text-center py-4 text-danger"><i class="fas fa-exclamation-circle"></i> Failed to load events</td></tr>';
        showNotification('Failed to load events: ' + error.message, 'danger');
    }
}

// Display events in table
function displayEventsTable(events) {
    const tbody = document.getElementById('events-tbody');
    if (!tbody) return;

    if (events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="12" class="text-center py-4 text-muted"><i class="fas fa-inbox"></i> No events found</td></tr>';
        return;
    }

    let html = '';
    events.forEach(event => {
        const time = getRelativeTime(event.timestamp);
        const eventTypeIcon = event.event_type === 'failed' ? 'fa-times-circle text-danger' : 'fa-check-circle text-success';
        const eventTypeBadge = event.event_type === 'failed' ?
            '<span class="badge bg-danger">Failed</span>' :
            '<span class="badge bg-success">Success</span>';

        const riskBadgeClass = getRiskBadgeClass(event.risk_level);
        const mlPrediction = event.ml_risk_score >= 70 ? 'Threat' : event.ml_risk_score >= 50 ? 'Suspicious' : 'Clean';
        const mlBadgeClass = event.ml_risk_score >= 70 ? 'danger' : event.ml_risk_score >= 50 ? 'warning' : 'success';

        const statusBadge = event.is_blocked ?
            '<span class="badge bg-danger"><i class="fas fa-ban"></i> Blocked</span>' :
            '<span class="badge bg-secondary">Monitored</span>';

        const rowClass = event.risk_level === 'critical' ? 'table-danger' :
                        event.risk_level === 'high' ? 'table-warning' : '';

        const detail = event.event_type === 'failed' ?
            `<small class="text-danger">${event.failure_reason || 'N/A'}</small>` :
            `<small class="text-success">${event.session_duration ? event.session_duration + 's' : 'Active'}</small>`;

        html += `
            <tr class="${rowClass}">
                <td><small>${time}</small></td>
                <td>${eventTypeBadge}</td>
                <td>
                    <code>${event.source_ip}</code>
                    ${event.is_public_ip ? '<i class="fas fa-globe text-primary ms-1" title="Public IP"></i>' : '<i class="fas fa-home text-secondary ms-1" title="Private IP"></i>'}
                </td>
                <td><code>${event.username}</code></td>
                <td><small>${event.city || 'Unknown'}, ${event.country || 'Unknown'}</small></td>
                <td>
                    <span class="badge ${riskBadgeClass}">${event.ml_risk_score}/100</span>
                </td>
                <td>
                    <span class="badge bg-${mlBadgeClass}">${mlPrediction}</span>
                </td>
                <td>${statusBadge}</td>
                <td><small>${event.server_hostname || 'N/A'}</small></td>
                <td><small>${event.port || '-'}</small></td>
                <td>${detail}</td>
                <td>
                    <button class="btn btn-sm btn-primary me-1" onclick="openAnalyticsModal('${event.source_ip}')" title="View Analytics">
                        <i class="fas fa-chart-line"></i>
                    </button>
                    <button class="btn btn-sm btn-warning" onclick="load3rdPartyIntel('${event.source_ip}')" ${!event.is_public_ip ? 'disabled' : ''} title="3rd Party Intelligence">
                        <i class="fas fa-globe"></i>
                    </button>
                </td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
}

// Update pagination controls
function updatePaginationControls(page, pages, total) {
    const pageInfo = document.getElementById('page-info');
    const prevBtn = document.getElementById('prev-page');
    const nextBtn = document.getElementById('next-page');

    if (pageInfo) {
        pageInfo.textContent = `Page ${page} of ${pages} (${total} total)`;
    }

    if (prevBtn) {
        prevBtn.disabled = page <= 1;
    }

    if (nextBtn) {
        nextBtn.disabled = page >= pages;
    }
}

// Get relative time string
function getRelativeTime(timestamp) {
    if (!timestamp) return 'Unknown';

    const now = new Date();
    const then = new Date(timestamp);
    const diffMs = now - then;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
}

// Get risk badge class
function getRiskBadgeClass(riskLevel) {
    switch (riskLevel) {
        case 'critical': return 'bg-danger';
        case 'high': return 'bg-warning text-dark';
        case 'medium': return 'bg-info';
        case 'low': return 'bg-success';
        default: return 'bg-secondary';
    }
}

// Load stream statistics
async function loadStreamStats() {
    try {
        // For now, calculate from recent events
        // In future, could be a dedicated endpoint
        const response = await fetch(`${window.API_BASE || ""}/api/events/recent?limit=1000`, {
            credentials: 'include'
        });

        if (!response.ok) return;

        const data = await response.json();
        if (!data.success) return;

        const events = data.events;

        // Calculate stats
        const total24h = events.length;
        const failed = events.filter(e => e.event_type === 'failed').length;
        const blocked = events.filter(e => e.is_blocked).length;
        const highRisk = events.filter(e => e.risk_level === 'critical' || e.risk_level === 'high').length;

        // Update stat cards
        const statTotal = document.getElementById('stat-total-24h');
        const statFailed = document.getElementById('stat-failed');
        const statBlocked = document.getElementById('stat-blocked');
        const statHighRisk = document.getElementById('stat-high-risk');

        if (statTotal) statTotal.textContent = total24h;
        if (statFailed) statFailed.textContent = failed;
        if (statBlocked) statBlocked.textContent = blocked;
        if (statHighRisk) statHighRisk.textContent = highRisk;

    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Auto-refresh functionality
function startAutoRefresh() {
    if (LiveStream.refreshInterval) {
        clearInterval(LiveStream.refreshInterval);
    }

    LiveStream.refreshInterval = setInterval(() => {
        if (LiveStream.refreshEnabled) {
            loadRecentEvents();
            loadStreamStats();
        }
    }, 5000); // 5 seconds
}

function stopAutoRefresh() {
    if (LiveStream.refreshInterval) {
        clearInterval(LiveStream.refreshInterval);
        LiveStream.refreshInterval = null;
    }
}

function toggleAutoRefresh() {
    LiveStream.refreshEnabled = !LiveStream.refreshEnabled;

    const toggleBtn = document.getElementById('refresh-toggle-btn');
    const toggleIcon = document.getElementById('refresh-toggle-icon');
    const toggleText = document.getElementById('refresh-toggle-text');

    if (toggleBtn && toggleIcon && toggleText) {
        if (LiveStream.refreshEnabled) {
            toggleBtn.classList.remove('btn-outline-secondary');
            toggleBtn.classList.add('btn-success');
            toggleIcon.classList.remove('fa-pause');
            toggleIcon.classList.add('fa-sync');
            toggleText.textContent = 'ON';
        } else {
            toggleBtn.classList.remove('btn-success');
            toggleBtn.classList.add('btn-outline-secondary');
            toggleIcon.classList.remove('fa-sync');
            toggleIcon.classList.add('fa-pause');
            toggleText.textContent = 'OFF';
        }
    }

    showNotification(`Auto-refresh ${LiveStream.refreshEnabled ? 'enabled' : 'disabled'}`, 'info');
}

// Export to CSV
function exportToCSV() {
    console.log('Exporting to CSV...');

    // Get current events from table
    const tbody = document.getElementById('events-tbody');
    if (!tbody) return;

    const rows = tbody.querySelectorAll('tr');
    if (rows.length === 0) {
        showNotification('No data to export', 'warning');
        return;
    }

    // Build CSV content
    let csv = 'Timestamp,Event Type,Source IP,Username,Location,Risk Score,ML Prediction,Status\n';

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 8) {
            const values = Array.from(cells).slice(0, 8).map(cell => {
                let text = cell.textContent.trim();
                // Remove extra whitespace and newlines
                text = text.replace(/\s+/g, ' ');
                // Escape quotes
                text = text.replace(/"/g, '""');
                return `"${text}"`;
            });
            csv += values.join(',') + '\n';
        }
    });

    // Download file
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ssh_guardian_events_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    showNotification('Events exported to CSV', 'success');
}

// Open analytics modal
async function openAnalyticsModal(ipAddress) {
    console.log('Opening analytics modal for:', ipAddress);

    const modal = new bootstrap.Modal(document.getElementById('analyticsModal'));
    const modalIP = document.getElementById('modal-ip');
    const modalBody = document.getElementById('modal-body-content');

    if (modalIP) modalIP.textContent = ipAddress;

    // Show loading state
    if (modalBody) {
        modalBody.innerHTML = '<div class="text-center py-5"><div class="loading-spinner"></div><div class="mt-2">Loading analytics...</div></div>';
    }

    // Open modal
    modal.show();

    // Load analytics
    try {
        const response = await fetch(`${window.API_BASE || ""}/api/events/analytics/${ipAddress}`, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        console.log('Analytics loaded:', data);

        if (data.success) {
            displayIPAnalytics(data);
        } else {
            throw new Error(data.error || 'Failed to load analytics');
        }

    } catch (error) {
        console.error('Error loading analytics:', error);
        if (modalBody) {
            modalBody.innerHTML = `<div class="text-center py-5 text-danger"><i class="fas fa-exclamation-circle"></i> Failed to load analytics: ${error.message}</div>`;
        }
        showNotification('Failed to load analytics', 'danger');
    }
}

// Display IP analytics in modal
function displayIPAnalytics(data) {
    const modalBody = document.getElementById('modal-body-content');
    if (!modalBody) return;

    const analytics = data.analytics;
    const stats = analytics.statistics;
    const ml = analytics.ml_prediction;
    const blockInfo = analytics.block_info;
    const activities = analytics.recent_activity;
    const location = analytics.location;

    let html = '';

    // ML Prediction Card
    const mlBadgeClass = ml.prediction === 'threat' ? 'malicious' : ml.prediction === 'suspicious' ? 'suspicious' : 'clean';
    const mlIcon = ml.prediction === 'threat' ? 'fa-shield-virus' : ml.prediction === 'suspicious' ? 'fa-exclamation-triangle' : 'fa-shield-check';

    html += `
        <div class="intel-section-enhanced mb-3">
            <div class="intel-section-header">
                <i class="fas fa-robot text-primary me-2"></i>
                <span>ML Prediction & Analysis</span>
            </div>
            <div class="intel-details-grid">
                <div class="intel-detail-card ${mlBadgeClass}-bg">
                    <div class="intel-detail-icon"><i class="fas ${mlIcon}"></i></div>
                    <div class="intel-detail-content">
                        <div class="intel-detail-label">Prediction</div>
                        <div class="intel-detail-value text-uppercase">${ml.prediction}</div>
                        <div class="intel-detail-sub">Confidence: ${(ml.confidence * 100).toFixed(1)}%</div>
                    </div>
                </div>
                <div class="intel-detail-card">
                    <div class="intel-detail-icon"><i class="fas fa-exclamation-triangle"></i></div>
                    <div class="intel-detail-content">
                        <div class="intel-detail-label">Risk Score</div>
                        <div class="intel-detail-value">${ml.risk_score}/100</div>
                        <div class="intel-detail-sub">Model: ${ml.model}</div>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Action Taken Card
    html += `
        <div class="intel-section-enhanced mb-3">
            <div class="intel-section-header">
                <i class="fas fa-shield-alt text-warning me-2"></i>
                <span>Action Taken</span>
            </div>
    `;

    if (blockInfo && blockInfo.is_blocked) {
        html += `
            <div class="alert alert-danger">
                <h6><i class="fas fa-ban"></i> IP BLOCKED</h6>
                <div class="row">
                    <div class="col-md-6">
                        <small><strong>Blocked At:</strong> ${new Date(blockInfo.blocked_at).toLocaleString()}</small>
                    </div>
                    <div class="col-md-6">
                        <small><strong>Duration:</strong> ${blockInfo.duration_hours} hours</small>
                    </div>
                    <div class="col-12 mt-2">
                        <small><strong>Reason:</strong> ${blockInfo.block_reason}</small>
                    </div>
                    <div class="col-12 mt-1">
                        <small><strong>Source:</strong> ${blockInfo.block_source}</small>
                    </div>
                </div>
            </div>
        `;
    } else {
        html += `
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i> IP is currently being monitored but not blocked
            </div>
        `;
    }

    html += `</div>`;

    // Statistics Grid
    html += `
        <div class="intel-section-enhanced mb-3">
            <div class="intel-section-header">
                <i class="fas fa-chart-bar text-info me-2"></i>
                <span>Statistics Overview</span>
            </div>
            <div class="row g-2">
                <div class="col-3">
                    <div class="stat-card-mini text-center">
                        <div class="stat-mini-value">${stats.total_attempts}</div>
                        <div class="stat-mini-label">Total</div>
                    </div>
                </div>
                <div class="col-3">
                    <div class="stat-card-mini text-center">
                        <div class="stat-mini-value text-success">${stats.successful}</div>
                        <div class="stat-mini-label">Success</div>
                    </div>
                </div>
                <div class="col-3">
                    <div class="stat-card-mini text-center">
                        <div class="stat-mini-value text-danger">${stats.failed}</div>
                        <div class="stat-mini-label">Failed</div>
                    </div>
                </div>
                <div class="col-3">
                    <div class="stat-card-mini text-center">
                        <div class="stat-mini-value">${stats.unique_usernames}</div>
                        <div class="stat-mini-label">Users</div>
                    </div>
                </div>
            </div>
            <div class="mt-2">
                <small><strong>First Seen:</strong> ${new Date(stats.first_seen).toLocaleString()}</small><br>
                <small><strong>Last Seen:</strong> ${new Date(stats.last_seen).toLocaleString()}</small><br>
                <small><strong>Location:</strong> ${location.city}, ${location.country}</small>
            </div>
        </div>
    `;

    // Recent Activity Timeline
    html += `
        <div class="intel-section-enhanced mb-3">
            <div class="intel-section-header">
                <i class="fas fa-history text-secondary me-2"></i>
                <span>Recent Activity Timeline</span>
            </div>
            <div class="activity-timeline" style="max-height: 300px; overflow-y: auto;">
    `;

    if (activities && activities.length > 0) {
        activities.forEach(activity => {
            const icon = activity.event_type === 'failed' ? 'fa-times-circle text-danger' : 'fa-check-circle text-success';
            const time = new Date(activity.timestamp).toLocaleString();
            html += `
                <div class="activity-item">
                    <i class="fas ${icon}"></i>
                    <span class="activity-time">${time}</span>
                    <span class="activity-detail">${activity.event_type} login as <code>${activity.username}</code></span>
                    <span class="badge bg-secondary ms-2">${activity.ml_risk_score}/100</span>
                </div>
            `;
        });
    } else {
        html += '<p class="text-muted text-center">No activity recorded</p>';
    }

    html += `
            </div>
        </div>
    `;

    // 3rd Party Intelligence Button
    const isPublic = !data.ip_address.startsWith('192.168.') &&
                     !data.ip_address.startsWith('10.') &&
                     !data.ip_address.startsWith('172.16.') &&
                     !data.ip_address.startsWith('127.');

    html += `
        <div class="text-center my-3">
            <button id="load-intel-modal-btn" class="btn btn-warning" ${!isPublic ? 'disabled' : ''} onclick="loadIntelligenceInModal('${data.ip_address}')">
                <i class="fas fa-globe"></i> Load 3rd Party Intelligence
            </button>
        </div>
        <div id="intel-section-modal" style="display: none;"></div>
    `;

    modalBody.innerHTML = html;
}

// Load 3rd party intelligence in modal
async function loadIntelligenceInModal(ipAddress) {
    console.log('Loading intelligence for:', ipAddress);

    const btn = document.getElementById('load-intel-modal-btn');
    const intelSection = document.getElementById('intel-section-modal');

    if (!btn || !intelSection) return;

    // Disable button and show loading
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Loading...';

    intelSection.style.display = 'block';
    intelSection.innerHTML = '<div class="text-center py-3"><div class="loading-spinner"></div></div>';

    try {
        const response = await fetch(`${window.API_BASE || ""}/api/ip/intel/lookup/${ipAddress}`, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        console.log('Intelligence loaded:', data);

        if (data.status === 'success') {
            // Use the same display function from simulation.js
            intelSection.innerHTML = '<hr><h6><i class="fas fa-database"></i> 3rd Party Threat Intelligence</h6>';
            const intelHTML = buildThreatIntelligenceHTML(data.data, ipAddress);
            intelSection.innerHTML += intelHTML;

            btn.innerHTML = '<i class="fas fa-check"></i> Loaded';
        } else {
            throw new Error(data.error || 'Failed to load intelligence');
        }

    } catch (error) {
        console.error('Error loading intelligence:', error);
        intelSection.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> Failed to load: ${error.message}</div>`;
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-globe"></i> Retry';
    }
}

// Build threat intelligence HTML (same as simulation.js)
function buildThreatIntelligenceHTML(intel, ip) {
    // This will be the same HTML generation as in simulation.js displayThreatIntelligence
    // For now, returning a placeholder - will be filled with actual implementation
    let html = '<div class="intel-content">';

    // Summary section
    if (intel.summary) {
        const summary = intel.summary;
        html += `
            <div class="intel-section-enhanced">
                <div class="intel-header-main">
                    <i class="fas fa-chart-pie text-primary me-2"></i>
                    <span class="intel-header-title">Summary</span>
                </div>
                <div class="intel-grid">
                    <div class="intel-grid-item">
                        <div class="intel-grid-label">Threat Score</div>
                        <div class="intel-score-display">${summary.threat_score || 0}<span class="intel-score-max">/100</span></div>
                    </div>
                    <div class="intel-grid-item">
                        <div class="intel-grid-label">Status</div>
                        <div class="intel-value-large">${summary.is_threat ? 'THREAT' : 'Clean'}</div>
                    </div>
                </div>
            </div>
        `;
    }

    // Add AbuseIPDB, VirusTotal, Shodan sections (same as simulation.js)
    // This would be the full intelligence display code

    html += '</div>';
    return html;
}

// Load 3rd party intelligence directly (for table button)
async function load3rdPartyIntel(ipAddress) {
    console.log('Loading 3rd party intelligence for:', ipAddress);

    // For now, just open the analytics modal and show message
    openAnalyticsModal(ipAddress);
    showNotification(`Click "Load 3rd Party Intelligence" in the modal to view data for ${ipAddress}`, 'info');
}

// Export functions for global access
window.initializeLiveStream = initializeLiveStream;
window.loadRecentEvents = loadRecentEvents;
window.openAnalyticsModal = openAnalyticsModal;
window.load3rdPartyIntel = load3rdPartyIntel;
window.loadIntelligenceInModal = loadIntelligenceInModal;
window.toggleAutoRefresh = toggleAutoRefresh;
window.exportToCSV = exportToCSV;

console.log('=== Live Stream Module loaded successfully ===');
