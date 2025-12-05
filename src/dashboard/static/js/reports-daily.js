/**
 * SSH Guardian 2.0 - Daily Reports JavaScript
 * Handles the Daily Reports tab functionality
 */

// State
let reportDate = new Date().toISOString().split('T')[0];
let hourlyChart = null;
let threatTypesChart = null;
let geoChart = null;

/**
 * Initialize Daily Reports tab
 */
function initializeDailyReports() {
    console.log('Initializing Daily Reports...');

    // Set date picker to today
    const datePicker = document.getElementById('report-date-picker');
    if (datePicker) {
        datePicker.value = reportDate;
        datePicker.max = new Date().toISOString().split('T')[0];
    }

    // Load available dates
    loadAvailableDates();

    // Load report data
    loadDailyReport();
}

/**
 * Load available dates with data
 */
async function loadAvailableDates() {
    try {
        const response = await fetch('/api/reports/daily/available-dates?limit=30');
        const data = await response.json();

        if (data.success && data.dates.length > 0) {
            const dateList = document.getElementById('available-dates-list');
            if (dateList) {
                dateList.innerHTML = data.dates.slice(0, 7).map(d => `
                    <button class="btn btn-sm btn-outline-secondary me-1 mb-1"
                            onclick="selectReportDate('${d.date}')">
                        ${formatDateShort(d.date)}
                        <span class="badge bg-primary ms-1">${formatNumber(d.event_count)}</span>
                    </button>
                `).join('');
            }
        }
    } catch (error) {
        console.error('Error loading available dates:', error);
    }
}

/**
 * Select a report date
 */
function selectReportDate(date) {
    reportDate = date;
    const datePicker = document.getElementById('report-date-picker');
    if (datePicker) {
        datePicker.value = date;
    }
    loadDailyReport();
}

/**
 * Handle date picker change
 */
function onReportDateChange(date) {
    reportDate = date;
    loadDailyReport();
}

/**
 * Load all daily report data
 */
async function loadDailyReport() {
    console.log('Loading daily report for:', reportDate);

    // Show loading state
    showReportLoading();

    try {
        // Load all data in parallel
        await Promise.all([
            loadDailySummary(),
            loadHourlyBreakdown(),
            loadTopThreats(),
            loadGeographicBreakdown(),
            loadTargetedUsernames(),
            loadThreatTypes(),
            loadDailyComparison()
        ]);
    } catch (error) {
        console.error('Error loading daily report:', error);
        showNotification('Failed to load daily report', 'error');
    }
}

/**
 * Show loading state
 */
function showReportLoading() {
    const summaryCards = document.getElementById('report-summary-cards');
    if (summaryCards) {
        summaryCards.innerHTML = `
            <div class="col-12 text-center py-4">
                <div class="loading-spinner"></div>
                <div class="mt-2 text-muted">Loading report data...</div>
            </div>
        `;
    }
}

/**
 * Load daily summary
 */
async function loadDailySummary() {
    try {
        const response = await fetch(`/api/reports/daily/summary?date=${reportDate}`);
        const data = await response.json();

        if (data.success) {
            renderSummaryCards(data.summary);
        }
    } catch (error) {
        console.error('Error loading daily summary:', error);
    }
}

/**
 * Render summary cards
 */
function renderSummaryCards(summary) {
    const container = document.getElementById('report-summary-cards');
    if (!container) return;

    const successRate = summary.total_events > 0
        ? ((summary.successful_logins / summary.total_events) * 100).toFixed(1)
        : 0;

    container.innerHTML = `
        <div class="col-xl-3 col-lg-6 col-md-6">
            <div class="stat-card">
                <div class="stat-icon icon-primary">
                    <i class="fas fa-chart-line"></i>
                </div>
                <div class="stat-label">Total Events</div>
                <div class="stat-value">${formatNumber(summary.total_events)}</div>
                <div class="stat-detail">
                    <span class="text-danger">${formatNumber(summary.failed_logins)} failed</span> /
                    <span class="text-success">${formatNumber(summary.successful_logins)} success</span>
                </div>
            </div>
        </div>
        <div class="col-xl-3 col-lg-6 col-md-6">
            <div class="stat-card">
                <div class="stat-icon icon-danger">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="stat-label">Risk Breakdown</div>
                <div class="stat-value text-danger">${formatNumber(summary.risk_breakdown.critical + summary.risk_breakdown.high)}</div>
                <div class="stat-detail">
                    <span class="badge badge-critical me-1">${summary.risk_breakdown.critical} Critical</span>
                    <span class="badge badge-high">${summary.risk_breakdown.high} High</span>
                </div>
            </div>
        </div>
        <div class="col-xl-3 col-lg-6 col-md-6">
            <div class="stat-card">
                <div class="stat-icon icon-warning">
                    <i class="fas fa-globe"></i>
                </div>
                <div class="stat-label">Unique IPs</div>
                <div class="stat-value text-warning">${formatNumber(summary.unique_ips)}</div>
                <div class="stat-detail">${formatNumber(summary.blocked_ips)} blocked</div>
            </div>
        </div>
        <div class="col-xl-3 col-lg-6 col-md-6">
            <div class="stat-card">
                <div class="stat-icon icon-info">
                    <i class="fas fa-robot"></i>
                </div>
                <div class="stat-label">ML Anomalies</div>
                <div class="stat-value text-info">${formatNumber(summary.anomalies)}</div>
                <div class="stat-detail">Avg Risk: ${summary.avg_risk_score}</div>
            </div>
        </div>
    `;
}

/**
 * Load hourly breakdown
 */
async function loadHourlyBreakdown() {
    try {
        const response = await fetch(`/api/reports/daily/hourly-breakdown?date=${reportDate}`);
        const data = await response.json();

        if (data.success) {
            renderHourlyChart(data.hourly_data);
        }
    } catch (error) {
        console.error('Error loading hourly breakdown:', error);
    }
}

/**
 * Render hourly chart
 */
function renderHourlyChart(hourlyData) {
    const ctx = document.getElementById('hourly-chart');
    if (!ctx) return;

    // Destroy existing chart
    if (hourlyChart) {
        hourlyChart.destroy();
    }

    hourlyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: hourlyData.map(d => d.hour_label),
            datasets: [
                {
                    label: 'Failed Logins',
                    data: hourlyData.map(d => d.failed),
                    backgroundColor: 'rgba(231, 72, 86, 0.8)',
                    borderColor: '#E74856',
                    borderWidth: 1
                },
                {
                    label: 'Successful Logins',
                    data: hourlyData.map(d => d.successful),
                    backgroundColor: 'rgba(16, 137, 62, 0.8)',
                    borderColor: '#10893E',
                    borderWidth: 1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top'
                },
                tooltip: {
                    callbacks: {
                        afterBody: function(context) {
                            const index = context[0].dataIndex;
                            const hourData = hourlyData[index];
                            return `Anomalies: ${hourData.anomalies}\nAvg Risk: ${hourData.avg_risk}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    stacked: false,
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

/**
 * Load top threats
 */
async function loadTopThreats() {
    try {
        const response = await fetch(`/api/reports/daily/top-threats?date=${reportDate}&limit=10`);
        const data = await response.json();

        if (data.success) {
            renderTopThreats(data.top_threats);
        }
    } catch (error) {
        console.error('Error loading top threats:', error);
    }
}

/**
 * Render top threats table
 */
function renderTopThreats(threats) {
    const tbody = document.getElementById('top-threats-tbody');
    if (!tbody) return;

    if (threats.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4 text-muted">
                    <i class="fas fa-check-circle fa-2x mb-2"></i>
                    <div>No threats recorded for this date</div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = threats.map((threat, index) => `
        <tr>
            <td>
                <span class="badge bg-secondary">#${index + 1}</span>
            </td>
            <td>
                <code class="text-primary" style="cursor: pointer;" onclick="showIPAnalytics('${threat.ip}')">
                    ${threat.ip}
                </code>
            </td>
            <td>
                <i class="fas fa-globe-americas text-muted me-1"></i>
                ${threat.country || 'Unknown'}
                ${threat.city ? `<small class="text-muted">(${threat.city})</small>` : ''}
            </td>
            <td><strong>${formatNumber(threat.attempt_count)}</strong></td>
            <td>${threat.unique_usernames}</td>
            <td>
                <span class="badge ${getRiskBadgeClass(threat.max_risk)}">${threat.max_risk}</span>
            </td>
            <td>
                <small class="text-muted">${threat.threat_type || 'Unknown'}</small>
            </td>
        </tr>
    `).join('');
}

/**
 * Load geographic breakdown
 */
async function loadGeographicBreakdown() {
    try {
        const response = await fetch(`/api/reports/daily/geographic?date=${reportDate}&limit=10`);
        const data = await response.json();

        if (data.success) {
            renderGeographicChart(data.countries);
            renderGeographicTable(data.countries);
        }
    } catch (error) {
        console.error('Error loading geographic breakdown:', error);
    }
}

/**
 * Render geographic chart
 */
function renderGeographicChart(countries) {
    const ctx = document.getElementById('geo-chart');
    if (!ctx) return;

    // Destroy existing chart
    if (geoChart) {
        geoChart.destroy();
    }

    const colors = [
        '#0078D4', '#E74856', '#F59100', '#10893E', '#5C2D91',
        '#00BCF2', '#FF8C00', '#107C10', '#B4009E', '#002050'
    ];

    geoChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: countries.map(c => c.country || 'Unknown'),
            datasets: [{
                data: countries.map(c => c.attempt_count),
                backgroundColor: colors.slice(0, countries.length),
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        boxWidth: 12,
                        padding: 10
                    }
                }
            }
        }
    });
}

/**
 * Render geographic table
 */
function renderGeographicTable(countries) {
    const tbody = document.getElementById('geo-table-tbody');
    if (!tbody) return;

    if (countries.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center py-4 text-muted">No geographic data</td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = countries.map(country => `
        <tr>
            <td><strong>${country.country || 'Unknown'}</strong></td>
            <td>${formatNumber(country.attempt_count)}</td>
            <td>${formatNumber(country.unique_ips)}</td>
            <td>${formatNumber(country.anomalies)}</td>
            <td>
                <span class="badge ${getRiskBadgeClass(country.avg_risk)}">${country.avg_risk}</span>
            </td>
        </tr>
    `).join('');
}

/**
 * Load targeted usernames
 */
async function loadTargetedUsernames() {
    try {
        const response = await fetch(`/api/reports/daily/usernames?date=${reportDate}&limit=10`);
        const data = await response.json();

        if (data.success) {
            renderTargetedUsernames(data.usernames);
        }
    } catch (error) {
        console.error('Error loading targeted usernames:', error);
    }
}

/**
 * Render targeted usernames
 */
function renderTargetedUsernames(usernames) {
    const tbody = document.getElementById('usernames-tbody');
    if (!tbody) return;

    if (usernames.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center py-4 text-muted">No username data</td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = usernames.map(u => `
        <tr>
            <td><code>${u.username}</code></td>
            <td>${formatNumber(u.attempt_count)}</td>
            <td>${formatNumber(u.unique_ips)}</td>
            <td>
                <span class="badge ${getRiskBadgeClass(u.avg_risk)}">${u.avg_risk}</span>
            </td>
        </tr>
    `).join('');
}

/**
 * Load threat types breakdown
 */
async function loadThreatTypes() {
    try {
        const response = await fetch(`/api/reports/daily/threat-types?date=${reportDate}`);
        const data = await response.json();

        if (data.success) {
            renderThreatTypesChart(data.threat_types);
        }
    } catch (error) {
        console.error('Error loading threat types:', error);
    }
}

/**
 * Render threat types chart
 */
function renderThreatTypesChart(threatTypes) {
    const ctx = document.getElementById('threat-types-chart');
    if (!ctx) return;

    // Destroy existing chart
    if (threatTypesChart) {
        threatTypesChart.destroy();
    }

    const colors = [
        '#E74856', '#F59100', '#0078D4', '#10893E', '#5C2D91', '#00BCF2'
    ];

    threatTypesChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: threatTypes.map(t => t.threat_type),
            datasets: [{
                label: 'Count',
                data: threatTypes.map(t => t.count),
                backgroundColor: colors.slice(0, threatTypes.length),
                borderWidth: 0
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

/**
 * Load daily comparison
 */
async function loadDailyComparison() {
    try {
        const response = await fetch(`/api/reports/daily/comparison?date=${reportDate}`);
        const data = await response.json();

        if (data.success) {
            renderComparison(data.comparison);
        }
    } catch (error) {
        console.error('Error loading comparison:', error);
    }
}

/**
 * Render comparison cards
 */
function renderComparison(comparison) {
    const container = document.getElementById('comparison-container');
    if (!container) return;

    const renderChange = (value) => {
        const icon = value >= 0 ? 'arrow-up' : 'arrow-down';
        const color = value >= 0 ? 'danger' : 'success';
        return `<span class="text-${color}"><i class="fas fa-${icon}"></i> ${Math.abs(value)}%</span>`;
    };

    container.innerHTML = `
        <div class="col-md-4">
            <div class="card border-0 shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-muted mb-2">Total Events</h6>
                    <h3 class="mb-1">${formatNumber(comparison.current.total_events)}</h3>
                    <div class="small">
                        vs ${formatNumber(comparison.previous.total_events)} yesterday
                        ${renderChange(comparison.changes.total_events)}
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card border-0 shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-muted mb-2">High Risk</h6>
                    <h3 class="mb-1 text-danger">${formatNumber(comparison.current.high_risk)}</h3>
                    <div class="small">
                        vs ${formatNumber(comparison.previous.high_risk)} yesterday
                        ${renderChange(comparison.changes.high_risk)}
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card border-0 shadow-sm">
                <div class="card-body text-center">
                    <h6 class="text-muted mb-2">Unique IPs</h6>
                    <h3 class="mb-1 text-warning">${formatNumber(comparison.current.unique_ips)}</h3>
                    <div class="small">
                        vs ${formatNumber(comparison.previous.unique_ips)} yesterday
                        ${renderChange(comparison.changes.unique_ips)}
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Export report to CSV
 */
async function exportDailyReport() {
    showNotification('Generating CSV export...', 'info');

    try {
        // Fetch all data
        const [summary, threats, geo, usernames] = await Promise.all([
            fetch(`/api/reports/daily/summary?date=${reportDate}`).then(r => r.json()),
            fetch(`/api/reports/daily/top-threats?date=${reportDate}&limit=50`).then(r => r.json()),
            fetch(`/api/reports/daily/geographic?date=${reportDate}&limit=50`).then(r => r.json()),
            fetch(`/api/reports/daily/usernames?date=${reportDate}&limit=50`).then(r => r.json())
        ]);

        // Build CSV content
        let csv = `SSH Guardian Daily Report - ${reportDate}\n\n`;

        // Summary section
        csv += `SUMMARY\n`;
        csv += `Total Events,${summary.summary.total_events}\n`;
        csv += `Failed Logins,${summary.summary.failed_logins}\n`;
        csv += `Successful Logins,${summary.summary.successful_logins}\n`;
        csv += `Unique IPs,${summary.summary.unique_ips}\n`;
        csv += `Blocked IPs,${summary.summary.blocked_ips}\n`;
        csv += `Anomalies,${summary.summary.anomalies}\n`;
        csv += `Avg Risk Score,${summary.summary.avg_risk_score}\n\n`;

        // Top threats section
        csv += `TOP THREATS\n`;
        csv += `IP,Country,City,Attempts,Unique Usernames,Max Risk,Threat Type\n`;
        threats.top_threats.forEach(t => {
            csv += `${t.ip},${t.country || ''},${t.city || ''},${t.attempt_count},${t.unique_usernames},${t.max_risk},${t.threat_type || ''}\n`;
        });
        csv += `\n`;

        // Geographic section
        csv += `GEOGRAPHIC BREAKDOWN\n`;
        csv += `Country,Attempts,Unique IPs,Anomalies,Avg Risk\n`;
        geo.countries.forEach(c => {
            csv += `${c.country},${c.attempt_count},${c.unique_ips},${c.anomalies},${c.avg_risk}\n`;
        });
        csv += `\n`;

        // Usernames section
        csv += `TARGETED USERNAMES\n`;
        csv += `Username,Attempts,Unique IPs,Avg Risk\n`;
        usernames.usernames.forEach(u => {
            csv += `${u.username},${u.attempt_count},${u.unique_ips},${u.avg_risk}\n`;
        });

        // Download
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ssh-guardian-daily-report-${reportDate}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);

        showNotification('Report exported successfully', 'success');
    } catch (error) {
        console.error('Error exporting report:', error);
        showNotification('Failed to export report', 'error');
    }
}

/**
 * Print report
 */
function printDailyReport() {
    window.print();
}

// Utility functions
function getRiskBadgeClass(risk) {
    if (risk >= 80) return 'badge-critical';
    if (risk >= 60) return 'badge-high';
    if (risk >= 40) return 'badge-warning';
    return 'badge-success';
}

function formatNumber(num) {
    if (num === null || num === undefined) return '0';
    return num.toLocaleString();
}

function formatDateShort(dateStr) {
    const date = new Date(dateStr + 'T00:00:00');
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

// Make functions globally available
window.initializeDailyReports = initializeDailyReports;
window.selectReportDate = selectReportDate;
window.onReportDateChange = onReportDateChange;
window.loadDailyReport = loadDailyReport;
window.exportDailyReport = exportDailyReport;
window.printDailyReport = printDailyReport;
