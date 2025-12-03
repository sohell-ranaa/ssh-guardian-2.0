// SSH Guardian 2.0 Dashboard - Main JavaScript

let timelineChart = null;
let attackTypesChart = null;
let map = null;
let markers = [];
let refreshInterval = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('SSH Guardian Dashboard initializing...');
    initializeCharts();
    initializeMap();
    loadAllData();

    // Auto-refresh every 30 seconds
    refreshInterval = setInterval(loadAllData, 30000);

    // Manual refresh button
    document.getElementById('refreshBtn').addEventListener('click', function() {
        this.classList.add('spinning');
        loadAllData();
        setTimeout(() => {
            this.classList.remove('spinning');
        }, 1000);
    });
});

// Initialize Charts
function initializeCharts() {
    // Timeline Chart
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Total Events',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Failed Attempts',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Anomalies',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });

    // Attack Types Chart
    const attackTypesCtx = document.getElementById('attackTypesChart').getContext('2d');
    attackTypesChart = new Chart(attackTypesCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#ef4444',
                    '#f59e0b',
                    '#3b82f6',
                    '#8b5cf6',
                    '#ec4899',
                    '#10b981'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom'
                }
            }
        }
    });
}

// Initialize Map
function initializeMap() {
    map = L.map('map').setView([20, 0], 2);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 18
    }).addTo(map);
}

// Load all data
async function loadAllData() {
    try {
        await Promise.all([
            loadOverviewStats(),
            loadTimeline(),
            loadGeographicData(),
            loadTopIPs(),
            loadRecentThreats(),
            loadTargetedUsernames()
        ]);

        updateLastUpdateTime();
    } catch (error) {
        console.error('Error loading data:', error);
    }
}

// Load overview statistics
async function loadOverviewStats() {
    try {
        const response = await fetch('/api/stats/overview');
        const data = await response.json();

        document.getElementById('events24h').textContent = formatNumber(data.events_24h || 0);
        document.getElementById('highRisk24h').textContent = formatNumber(data.high_risk_24h || 0);
        document.getElementById('uniqueIPs24h').textContent = formatNumber(data.unique_ips_24h || 0);

        // Blocked IPs from Guardian stats
        if (data.guardian_stats && data.guardian_stats.blocking_stats) {
            document.getElementById('blockedIPs').textContent =
                formatNumber(data.guardian_stats.blocking_stats.active_blocks || 0);
        }

        // Update attack types chart
        if (data.attack_types && Object.keys(data.attack_types).length > 0) {
            updateAttackTypesChart(data.attack_types);
        }

        // Update change indicators
        updateChangeIndicators(data);

    } catch (error) {
        console.error('Error loading overview stats:', error);
    }
}

// Load timeline data
async function loadTimeline() {
    try {
        const response = await fetch('/api/stats/timeline?hours=24');
        const data = await response.json();

        if (data.length === 0) return;

        const labels = data.map(d => {
            const date = new Date(d.hour);
            return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        });

        const totalData = data.map(d => d.total || 0);
        const failedData = data.map(d => d.failed || 0);
        const anomaliesData = data.map(d => d.anomalies || 0);

        timelineChart.data.labels = labels;
        timelineChart.data.datasets[0].data = totalData;
        timelineChart.data.datasets[1].data = failedData;
        timelineChart.data.datasets[2].data = anomaliesData;
        timelineChart.update();

    } catch (error) {
        console.error('Error loading timeline:', error);
    }
}

// Update attack types chart
function updateAttackTypesChart(attackTypes) {
    const labels = Object.keys(attackTypes);
    const data = Object.values(attackTypes);

    attackTypesChart.data.labels = labels.map(l => l || 'Unknown');
    attackTypesChart.data.datasets[0].data = data;
    attackTypesChart.update();
}

// Load geographic data
async function loadGeographicData() {
    try {
        const response = await fetch('/api/threats/geographic?hours=24');
        const data = await response.json();

        // Clear existing markers
        markers.forEach(marker => map.removeLayer(marker));
        markers = [];

        // Add city markers
        if (data.cities && data.cities.length > 0) {
            data.cities.forEach(city => {
                if (city.latitude && city.longitude) {
                    const marker = L.circleMarker([city.latitude, city.longitude], {
                        radius: Math.min(city.count / 2 + 5, 20),
                        fillColor: getRiskColor(city.avg_risk),
                        color: '#fff',
                        weight: 2,
                        opacity: 1,
                        fillOpacity: 0.7
                    }).addTo(map);

                    marker.bindPopup(`
                        <strong>${city.city}, ${city.country}</strong><br>
                        Attacks: ${city.count}<br>
                        Avg Risk: ${city.avg_risk.toFixed(1)}
                    `);

                    markers.push(marker);
                }
            });
        }

    } catch (error) {
        console.error('Error loading geographic data:', error);
    }
}

// Load top malicious IPs
async function loadTopIPs() {
    try {
        const response = await fetch('/api/threats/top-ips?hours=24&limit=10');
        const data = await response.json();

        const tbody = document.getElementById('topIPsTable');

        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center">No data available</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(ip => `
            <tr>
                <td><strong>${ip.ip}</strong></td>
                <td>
                    <span class="badge bg-secondary">${ip.country || 'Unknown'}</span>
                </td>
                <td>
                    <strong>${ip.attempts}</strong> attempts
                    <small class="text-muted">(${ip.failed_attempts} failed)</small>
                </td>
                <td>${getRiskBadge(ip.avg_risk)}</td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Error loading top IPs:', error);
    }
}

// Load recent threats
async function loadRecentThreats() {
    try {
        const response = await fetch('/api/threats/recent?limit=10');
        const data = await response.json();

        const tbody = document.getElementById('recentThreatsTable');

        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center">No recent threats</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(threat => `
            <tr>
                <td>
                    <small>${formatTime(threat.timestamp)}</small>
                </td>
                <td>
                    <strong>${threat.ip}</strong>
                    <br>
                    <small class="text-muted">${threat.country || 'Unknown'}</small>
                </td>
                <td>
                    <code>${threat.username || 'N/A'}</code>
                </td>
                <td>${getRiskBadge(threat.ml_risk_score)}</td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Error loading recent threats:', error);
    }
}

// Load targeted usernames
async function loadTargetedUsernames() {
    try {
        const response = await fetch('/api/threats/usernames?hours=24&limit=10');
        const data = await response.json();

        const tbody = document.getElementById('usernamesTable');

        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center">No data available</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(user => `
            <tr>
                <td><strong><code>${user.username}</code></strong></td>
                <td>${user.attempts}</td>
                <td>${user.unique_ips}</td>
                <td><span class="badge bg-danger">${user.failed}</span></td>
                <td><span class="badge bg-success">${user.successful}</span></td>
                <td>${getRiskBadge(user.avg_risk)}</td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Error loading usernames:', error);
    }
}

// Helper functions
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleString();
}

function getRiskBadge(score) {
    if (score === null || score === undefined) {
        return '<span class="risk-badge risk-clean">N/A</span>';
    }

    if (score >= 90) {
        return `<span class="risk-badge risk-critical">${score.toFixed(0)} - CRITICAL</span>`;
    } else if (score >= 70) {
        return `<span class="risk-badge risk-high">${score.toFixed(0)} - HIGH</span>`;
    } else if (score >= 50) {
        return `<span class="risk-badge risk-medium">${score.toFixed(0)} - MEDIUM</span>`;
    } else if (score >= 30) {
        return `<span class="risk-badge risk-low">${score.toFixed(0)} - LOW</span>`;
    } else {
        return `<span class="risk-badge risk-clean">${score.toFixed(0)} - CLEAN</span>`;
    }
}

function getRiskColor(score) {
    if (score >= 90) return '#dc2626';
    if (score >= 70) return '#f59e0b';
    if (score >= 50) return '#eab308';
    if (score >= 30) return '#3b82f6';
    return '#10b981';
}

function updateChangeIndicators(data) {
    const events1h = data.events_1h || 0;
    const events24h = data.events_24h || 0;

    // Calculate hourly average for 24h
    const avgPerHour = events24h / 24;

    if (events1h > avgPerHour * 1.5) {
        document.getElementById('eventsChange').innerHTML =
            '<i class="fas fa-arrow-up"></i> Above average';
        document.getElementById('eventsChange').className = 'stat-change negative';
    } else if (events1h < avgPerHour * 0.5) {
        document.getElementById('eventsChange').innerHTML =
            '<i class="fas fa-arrow-down"></i> Below average';
        document.getElementById('eventsChange').className = 'stat-change positive';
    } else {
        document.getElementById('eventsChange').innerHTML =
            '<i class="fas fa-minus"></i> Normal activity';
        document.getElementById('eventsChange').className = 'stat-change';
    }

    // Update threats indicator
    const highRisk = data.high_risk_24h || 0;
    if (highRisk > 0) {
        document.getElementById('threatsChange').innerHTML =
            `<i class="fas fa-exclamation-triangle"></i> ${highRisk} threats detected`;
        document.getElementById('threatsChange').className = 'stat-change negative';
    } else {
        document.getElementById('threatsChange').innerHTML =
            '<i class="fas fa-check"></i> No high-risk threats';
        document.getElementById('threatsChange').className = 'stat-change positive';
    }

    // Update Guardian stats
    if (data.guardian_stats) {
        const guardianEngine = data.guardian_stats.engine_stats || {};

        document.getElementById('blocksChange').innerHTML =
            `<i class="fas fa-info-circle"></i> ${guardianEngine.threats_detected || 0} total threats`;

        document.getElementById('ipsChange').innerHTML =
            `<i class="fas fa-network-wired"></i> From ${data.unique_ips_24h || 0} sources`;
    }
}

function updateLastUpdateTime() {
    const now = new Date();
    document.getElementById('lastUpdate').textContent =
        `Last updated: ${now.toLocaleTimeString()}`;
}

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
});
