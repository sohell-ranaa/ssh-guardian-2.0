/**
 * SSH Guardian 2.0 - Enhanced Dashboard JavaScript
 * Handles all dashboard interactivity, API calls, and real-time updates
 */

// Global state
let autoRefreshInterval = null;
let currentTab = 'overview';
let lastEventId = null;
let currentUser = null;
let availableRoles = [];

// API Base URL
const API_BASE = '';

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('SSH Guardian Dashboard initializing...');

    // Check authentication and load user data
    checkAuthentication();

    // Setup navigation
    setupNavigation();

    // Load initial data
    loadDashboardData();

    // Setup auto-refresh for stats (every 30 seconds)
    setInterval(loadOverviewStats, 30000);

    console.log('Dashboard initialized successfully');
});

// Navigation
function setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const tab = this.getAttribute('data-tab');
            switchTab(tab);
        });
    });
}

function switchTab(tabName) {
    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    // Hide all tab content
    document.querySelectorAll('.tab-content-panel').forEach(panel => {
        panel.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');

    currentTab = tabName;

    // Load tab-specific data
    switch(tabName) {
        case 'overview':
            loadOverviewStats();
            loadRecentThreats(50);
            break;
        case 'threats':
            loadRecentThreats(100);
            break;
        case 'live-stream':
            loadLiveEvents();
            break;
        case 'ip-management':
            loadBlockedIPs();
            loadWhitelist();
            break;
        case 'settings':
            loadSystemHealth();
            break;
        case 'users':
            loadUsers();
            loadRoles();
            break;
    }
}

// Authentication
async function checkAuthentication() {
    try {
        const response = await fetch(`${API_BASE}/auth/me`, {
            credentials: 'include'
        });

        if (!response.ok) {
            console.error('Auth check failed with status:', response.status);
            if (response.status === 401) {
                window.location.href = '/login';
            }
            return;
        }

        const data = await response.json();
        currentUser = data.user;

        console.log('User authenticated:', currentUser);

        // Update sidebar with user info
        const sidebarInfo = document.getElementById('user-info-sidebar');
        if (sidebarInfo) {
            sidebarInfo.innerHTML = `
                <div class="mb-1"><strong>${currentUser.full_name}</strong></div>
                <div class="small">${currentUser.email}</div>
                <div class="small"><span class="badge bg-primary">${currentUser.role}</span></div>
            `;
        }

        // Show user management tab if super_admin
        if (currentUser.permissions && currentUser.permissions.user_management === true) {
            const navUsers = document.getElementById('nav-users');
            if (navUsers) {
                navUsers.style.display = 'block';
            }
        }

    } catch (error) {
        console.error('Authentication check error:', error);
        // Don't redirect on network errors, only on auth failures
    }
}

async function logout() {
    try {
        await fetch(`${API_BASE}/auth/logout`, {
            method: 'POST',
            credentials: 'include'
        });

        window.location.href = '/login';
    } catch (error) {
        console.error('Logout error:', error);
        window.location.href = '/login';
    }
}

// Load dashboard data
function loadDashboardData() {
    loadOverviewStats();
    loadRecentThreats(50);
}

// Load overview statistics
async function loadOverviewStats() {
    try {
        const response = await fetch(`${API_BASE}/api/stats/overview`);
        const data = await response.json();

        // Update stat cards
        document.getElementById('stat-events-24h').textContent = formatNumber(data.events_24h || 0);
        document.getElementById('stat-events-1h').textContent = `${formatNumber(data.events_1h || 0)} in last hour`;
        document.getElementById('stat-high-risk').textContent = formatNumber(data.high_risk_24h || 0);
        document.getElementById('stat-unique-ips').textContent = formatNumber(data.unique_ips_24h || 0);

        // Load blocked IPs count
        loadBlockedIPsCount();

    } catch (error) {
        console.error('Error loading overview stats:', error);
        showNotification('Failed to load statistics', 'danger');
    }
}

// Load recent threats
async function loadRecentThreats(limit = 50) {
    try {
        const tbody = document.getElementById('threats-tbody');
        tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Loading threats...</div></td></tr>';

        const response = await fetch(`${API_BASE}/api/threats/recent?limit=${limit}`);
        const threats = await response.json();

        if (threats.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-muted">No recent threats found</td></tr>';
            return;
        }

        tbody.innerHTML = threats.map(threat => `
            <tr>
                <td>${formatTime(threat.timestamp)}</td>
                <td><span class="ip-badge">${threat.ip}</span></td>
                <td>${threat.country || 'Unknown'}</td>
                <td>${threat.username || 'N/A'}</td>
                <td><span class="badge ${threat.event_type === 'failed' ? 'bg-danger' : 'bg-success'}">${threat.event_type}</span></td>
                <td><span class="threat-badge ${getRiskClass(threat.ml_risk_score)}">${threat.ml_risk_score}</span></td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" onclick="lookupIPDirect('${threat.ip}')" title="Lookup">
                            <i class="fas fa-search"></i>
                        </button>
                        <button class="btn btn-outline-danger" onclick="showBlockModal('${threat.ip}')" title="Block">
                            <i class="fas fa-ban"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Error loading threats:', error);
        showNotification('Failed to load threats', 'danger');
    }
}

// Load live events
async function loadLiveEvents() {
    try {
        const container = document.getElementById('live-events');

        const response = await fetch(`${API_BASE}/api/events/live?limit=50`);
        const events = await response.json();

        if (events.length === 0) {
            container.innerHTML = '<div class="text-center py-5 text-muted">No recent events</div>';
            return;
        }

        container.innerHTML = events.map(event => `
            <div class="event-item">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <div class="d-flex align-items-center gap-2 mb-2">
                            <span class="ip-badge">${event.source_ip}</span>
                            <i class="fas fa-arrow-right text-muted"></i>
                            <span class="badge ${event.event_type === 'failed' ? 'bg-danger' : 'bg-success'}">${event.event_type}</span>
                            <span class="badge bg-secondary">${event.username}</span>
                            ${event.is_anomaly ? '<span class="badge bg-warning">ANOMALY</span>' : ''}
                        </div>
                        <div class="small text-muted">
                            <i class="fas fa-clock"></i> ${formatTime(event.timestamp)}
                            ${event.country ? `<i class="fas fa-map-marker-alt ms-2"></i> ${event.country}, ${event.city || 'Unknown'}` : ''}
                            <span class="ms-2">Risk: <span class="threat-badge ${getRiskClass(event.ml_risk_score)}">${event.ml_risk_score}</span></span>
                        </div>
                    </div>
                    <div>
                        <button class="btn btn-sm btn-outline-primary" onclick="lookupIPDirect('${event.source_ip}')">
                            <i class="fas fa-search"></i>
                        </button>
                    </div>
                </div>
            </div>
        `).join('');

        // Store last event ID for polling
        if (events.length > 0) {
            lastEventId = events[0].id;
        }

    } catch (error) {
        console.error('Error loading live events:', error);
        showNotification('Failed to load events', 'danger');
    }
}

// Toggle auto-refresh for live stream
function toggleAutoRefresh() {
    if (autoRefreshInterval) {
        // Stop auto-refresh
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        document.getElementById('auto-refresh-icon').className = 'fas fa-play';
        document.getElementById('auto-refresh-text').textContent = 'Start Auto-Refresh';
        showNotification('Auto-refresh stopped', 'info');
    } else {
        // Start auto-refresh
        autoRefreshInterval = setInterval(loadLiveEvents, 5000);
        document.getElementById('auto-refresh-icon').className = 'fas fa-pause';
        document.getElementById('auto-refresh-text').textContent = 'Stop Auto-Refresh';
        showNotification('Auto-refresh started (5s interval)', 'success');
        loadLiveEvents();
    }
}

// Load blocked IPs
async function loadBlockedIPs() {
    try {
        const container = document.getElementById('blocked-ips-list');
        container.innerHTML = '<div class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Loading...</div></div>';

        const response = await fetch(`${API_BASE}/api/blocks/active`);
        const data = await response.json();
        const blocks = data.blocked_ips || data.blocks || [];

        if (blocks.length === 0) {
            container.innerHTML = '<div class="text-center py-4 text-muted">No blocked IPs</div>';
            return;
        }

        container.innerHTML = blocks.map(block => `
            <div class="d-flex justify-content-between align-items-center mb-2 p-2 border rounded">
                <div>
                    <span class="ip-badge">${block.ip || block}</span>
                    ${block.reason ? `<div class="small text-muted">${block.reason}</div>` : ''}
                </div>
                <button class="btn btn-sm btn-outline-success" onclick="unblockIP('${block.ip || block}')">
                    <i class="fas fa-unlock"></i> Unblock
                </button>
            </div>
        `).join('');

    } catch (error) {
        console.error('Error loading blocked IPs:', error);
        document.getElementById('blocked-ips-list').innerHTML = '<div class="text-center py-4 text-danger">Failed to load</div>';
    }
}

async function loadBlockedIPsCount() {
    try {
        const response = await fetch(`${API_BASE}/api/blocks/active`);
        const data = await response.json();
        const blocks = data.blocked_ips || data.blocks || [];
        document.getElementById('stat-blocked').textContent = formatNumber(blocks.length);
    } catch (error) {
        console.error('Error loading blocked IPs count:', error);
    }
}

// Load whitelist
async function loadWhitelist() {
    try {
        const container = document.getElementById('whitelist-ips-list');
        container.innerHTML = '<div class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Loading...</div></div>';

        const response = await fetch(`${API_BASE}/api/admin/whitelist`);
        const data = await response.json();
        const whitelist = data.whitelist || [];

        if (whitelist.length === 0) {
            container.innerHTML = '<div class="text-center py-4 text-muted">No whitelisted IPs</div>';
            return;
        }

        container.innerHTML = whitelist.map(ip => `
            <div class="d-flex justify-content-between align-items-center mb-2 p-2 border rounded">
                <span class="ip-badge">${ip}</span>
                <button class="btn btn-sm btn-outline-danger" onclick="removeWhitelist('${ip}')">
                    <i class="fas fa-times"></i> Remove
                </button>
            </div>
        `).join('');

    } catch (error) {
        console.error('Error loading whitelist:', error);
        document.getElementById('whitelist-ips-list').innerHTML = '<div class="text-center py-4 text-danger">Failed to load</div>';
    }
}

// IP Lookup
async function lookupIP() {
    const ip = document.getElementById('ip-lookup-input').value.trim();
    if (!ip) {
        showNotification('Please enter an IP address', 'warning');
        return;
    }

    try {
        const resultDiv = document.getElementById('ip-lookup-result');
        resultDiv.innerHTML = '<div class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Looking up...</div></div>';

        const response = await fetch(`${API_BASE}/api/threats/lookup/${ip}`);
        const data = await response.json();

        if (data.error) {
            resultDiv.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
            return;
        }

        const stats = data.statistics;
        resultDiv.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <h6 class="card-title">IP: ${ip}</h6>
                    <hr>
                    <div class="row g-2">
                        <div class="col-6">
                            <small class="text-muted">Total Attempts</small>
                            <div class="fw-bold">${stats.total_attempts || 0}</div>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">Unique Usernames</small>
                            <div class="fw-bold">${stats.unique_usernames || 0}</div>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">Avg Risk Score</small>
                            <div class="fw-bold">${Math.round(stats.avg_risk || 0)}</div>
                        </div>
                        <div class="col-6">
                            <small class="text-muted">Max Risk Score</small>
                            <div class="fw-bold text-danger">${stats.max_risk || 0}</div>
                        </div>
                        <div class="col-12 mt-2">
                            <small class="text-muted">First Seen</small>
                            <div class="small">${stats.first_seen ? formatTime(stats.first_seen) : 'N/A'}</div>
                        </div>
                        <div class="col-12">
                            <small class="text-muted">Last Seen</small>
                            <div class="small">${stats.last_seen ? formatTime(stats.last_seen) : 'N/A'}</div>
                        </div>
                    </div>
                    <hr>
                    <div class="small text-muted">${data.events.length} recent events</div>
                </div>
            </div>
        `;

    } catch (error) {
        console.error('Error looking up IP:', error);
        showNotification('Failed to lookup IP', 'danger');
    }
}

function lookupIPDirect(ip) {
    switchTab('ip-management');
    document.getElementById('ip-lookup-input').value = ip;
    lookupIP();
}

// Block IP functions
function showBlockModal(ip = '') {
    document.getElementById('block-ip-address').value = ip;
    const modal = new bootstrap.Modal(document.getElementById('blockIPModal'));
    modal.show();
}

async function confirmBlockIP() {
    const ip = document.getElementById('block-ip-address').value.trim();
    const duration = document.getElementById('block-duration').value;
    const reason = document.getElementById('block-reason').value.trim();

    if (!ip) {
        showNotification('Please enter an IP address', 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/admin/block-ip`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip, duration: parseInt(duration), reason })
        });

        const data = await response.json();

        if (data.success || response.ok) {
            showNotification(`IP ${ip} blocked successfully`, 'success');
            bootstrap.Modal.getInstance(document.getElementById('blockIPModal')).hide();
            loadBlockedIPs();
            loadBlockedIPsCount();
        } else {
            showNotification(data.message || 'Failed to block IP', 'danger');
        }

    } catch (error) {
        console.error('Error blocking IP:', error);
        showNotification('Failed to block IP', 'danger');
    }
}

async function unblockIP(ip) {
    if (!confirm(`Unblock IP ${ip}?`)) return;

    try {
        const response = await fetch(`${API_BASE}/api/admin/unblock-ip`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip })
        });

        const data = await response.json();

        if (data.success || response.ok) {
            showNotification(`IP ${ip} unblocked`, 'success');
            loadBlockedIPs();
            loadBlockedIPsCount();
        } else {
            showNotification(data.message || 'Failed to unblock IP', 'danger');
        }

    } catch (error) {
        console.error('Error unblocking IP:', error);
        showNotification('Failed to unblock IP', 'danger');
    }
}

function blockIPFromLookup() {
    const ip = document.getElementById('ip-lookup-input').value.trim();
    if (ip) {
        showBlockModal(ip);
    } else {
        showNotification('Please enter an IP address first', 'warning');
    }
}

// Whitelist functions
function showAddWhitelistModal() {
    const ip = prompt('Enter IP address to whitelist:');
    if (ip) {
        addToWhitelist(ip);
    }
}

async function addToWhitelist(ip) {
    try {
        const response = await fetch(`${API_BASE}/api/admin/whitelist`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip })
        });

        const data = await response.json();

        if (data.success) {
            showNotification(`IP ${ip} added to whitelist`, 'success');
            loadWhitelist();
        } else {
            showNotification(data.message || 'Failed to add to whitelist', 'danger');
        }

    } catch (error) {
        console.error('Error adding to whitelist:', error);
        showNotification('Failed to add to whitelist', 'danger');
    }
}

async function removeWhitelist(ip) {
    if (!confirm(`Remove ${ip} from whitelist?`)) return;

    try {
        const response = await fetch(`${API_BASE}/api/admin/whitelist`, {
            method: 'DELETE',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip })
        });

        const data = await response.json();

        if (data.success) {
            showNotification(`IP ${ip} removed from whitelist`, 'success');
            loadWhitelist();
        } else {
            showNotification(data.message || 'Failed to remove from whitelist', 'danger');
        }

    } catch (error) {
        console.error('Error removing from whitelist:', error);
        showNotification('Failed to remove from whitelist', 'danger');
    }
}

function whitelistIPFromLookup() {
    const ip = document.getElementById('ip-lookup-input').value.trim();
    if (ip) {
        addToWhitelist(ip);
    } else {
        showNotification('Please enter an IP address first', 'warning');
    }
}

// Search events
async function searchEvents() {
    const params = new URLSearchParams({
        ip: document.getElementById('search-ip').value || '',
        username: document.getElementById('search-username').value || '',
        country: document.getElementById('search-country').value || '',
        min_risk: document.getElementById('search-risk').value || '',
        event_type: document.getElementById('search-event-type').value || '',
        hours: document.getElementById('search-hours').value || 24,
        limit: document.getElementById('search-limit').value || 100
    });

    try {
        const tbody = document.getElementById('search-results-tbody');
        tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Searching...</div></td></tr>';

        const response = await fetch(`${API_BASE}/api/search/events?${params}`);
        const data = await response.json();

        document.getElementById('search-count').textContent = `${data.count} results`;

        if (data.events.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-muted">No events found matching criteria</td></tr>';
            return;
        }

        tbody.innerHTML = data.events.map(event => `
            <tr>
                <td>${formatTime(event.timestamp)}</td>
                <td><span class="ip-badge">${event.source_ip}</span></td>
                <td>${event.username}</td>
                <td>${event.country || 'N/A'}</td>
                <td>${event.city || 'N/A'}</td>
                <td><span class="badge ${event.event_type === 'failed' ? 'bg-danger' : 'bg-success'}">${event.event_type}</span></td>
                <td><span class="threat-badge ${getRiskClass(event.ml_risk_score)}">${event.ml_risk_score}</span></td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="lookupIPDirect('${event.source_ip}')">
                        <i class="fas fa-search"></i>
                    </button>
                </td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Error searching events:', error);
        showNotification('Search failed', 'danger');
    }
}

// System health
async function loadSystemHealth() {
    try {
        const container = document.getElementById('system-health');
        container.innerHTML = '<div class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Loading...</div></div>';

        const response = await fetch(`${API_BASE}/api/system/health`);
        const health = await response.json();

        container.innerHTML = `
            <div class="mb-3">
                <strong>Guardian Status:</strong>
                <span class="badge ${health.guardian_status === 'online' ? 'bg-success' : 'bg-danger'}">${health.guardian_status}</span>
            </div>
            <div class="mb-3">
                <strong>Database Size:</strong> ${health.database_size_mb || 0} MB
            </div>
            <div class="mb-3">
                <strong>Events/Hour:</strong> ${health.events_last_hour || 0}
            </div>
            <div class="mb-3">
                <strong>Events/Minute:</strong> ${health.events_per_minute ? health.events_per_minute.toFixed(2) : 0}
            </div>
            <div class="mb-3">
                <strong>Last Event:</strong> ${health.latest_event ? formatTime(health.latest_event) : 'N/A'}
            </div>
        `;

    } catch (error) {
        console.error('Error loading system health:', error);
        document.getElementById('system-health').innerHTML = '<div class="alert alert-danger">Failed to load health status</div>';
    }
}

// Other functions
async function clearAllBlocks() {
    if (!confirm('Clear ALL blocked IPs? This cannot be undone.')) return;

    try {
        const response = await fetch(`${API_BASE}/api/admin/clear-blocks`, { method: 'POST' });
        const data = await response.json();

        showNotification('All blocks cleared', 'success');
        loadBlockedIPs();
        loadBlockedIPsCount();

    } catch (error) {
        console.error('Error clearing blocks:', error);
        showNotification('Failed to clear blocks', 'danger');
    }
}

async function testAlert() {
    try {
        const response = await fetch(`${API_BASE}/api/admin/test-alert`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ message: 'Test alert from dashboard' })
        });

        showNotification('Test alert sent', 'success');
    } catch (error) {
        console.error('Error sending test alert:', error);
        showNotification('Failed to send test alert', 'danger');
    }
}

function refreshDashboard() {
    loadDashboardData();
    showNotification('Dashboard refreshed', 'info');
}

// User Management Functions
async function loadUsers() {
    try {
        const tbody = document.getElementById('users-tbody');
        tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Loading users...</div></td></tr>';

        const response = await fetch(`${API_BASE}/auth/users`, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Failed to load users');
        }

        const data = await response.json();
        const users = data.users || [];

        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-muted">No users found</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(user => `
            <tr>
                <td>${user.id}</td>
                <td>${user.email}</td>
                <td>${user.full_name}</td>
                <td><span class="badge bg-primary">${user.role}</span></td>
                <td>
                    <span class="badge ${user.is_active ? 'bg-success' : 'bg-danger'}">
                        ${user.is_active ? 'Active' : 'Inactive'}
                    </span>
                </td>
                <td>${user.last_login ? formatTime(user.last_login) : 'Never'}</td>
                <td>${user.created_at ? formatTime(user.created_at) : 'N/A'}</td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" onclick='editUser(${JSON.stringify(user)})' title="Edit">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-outline-danger" onclick="deleteUser(${user.id}, '${user.email}')" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Error loading users:', error);
        showNotification('Failed to load users', 'danger');
    }
}

async function loadRoles() {
    try {
        const response = await fetch(`${API_BASE}/auth/roles`, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('Failed to load roles');
        }

        const data = await response.json();
        availableRoles = data.roles || [];

        // Populate role select in modal
        const roleSelect = document.getElementById('user-role');
        roleSelect.innerHTML = '<option value="">Select a role...</option>' +
            availableRoles.map(role => `
                <option value="${role.id}">${role.name} - ${role.description}</option>
            `).join('');

        // Display roles list
        const rolesList = document.getElementById('roles-list');
        if (rolesList) {
            rolesList.innerHTML = availableRoles.map(role => `
                <div class="mb-3 p-3 border rounded">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <h6 class="mb-1"><i class="fas fa-shield-alt"></i> ${role.name}</h6>
                            <p class="text-muted mb-2 small">${role.description}</p>
                            <div class="d-flex flex-wrap gap-1">
                                ${role.permissions.map(perm => `
                                    <span class="badge bg-secondary">${perm}</span>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');
        }

    } catch (error) {
        console.error('Error loading roles:', error);
        showNotification('Failed to load roles', 'danger');
    }
}

function showCreateUserModal() {
    // Reset form
    document.getElementById('user-form').reset();
    document.getElementById('user-id').value = '';
    document.getElementById('userModalTitle').innerHTML = '<i class="fas fa-user-plus"></i> Create User';
    document.getElementById('save-user-text').textContent = 'Create User';

    // Show password field for new user
    document.getElementById('password-field').style.display = 'block';
    document.getElementById('user-password').required = true;

    // Hide active field for new user
    document.getElementById('active-field').style.display = 'none';

    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('userModal'));
    modal.show();
}

function editUser(user) {
    // Populate form with user data
    document.getElementById('user-id').value = user.id;
    document.getElementById('user-email').value = user.email;
    document.getElementById('user-fullname').value = user.full_name;
    document.getElementById('user-active').checked = user.is_active;

    // Find and set role
    const roleOption = availableRoles.find(r => r.name === user.role);
    if (roleOption) {
        document.getElementById('user-role').value = roleOption.id;
    }

    // Update modal title
    document.getElementById('userModalTitle').innerHTML = '<i class="fas fa-user-edit"></i> Edit User';
    document.getElementById('save-user-text').textContent = 'Update User';

    // Hide password field for edit
    document.getElementById('password-field').style.display = 'none';
    document.getElementById('user-password').required = false;

    // Show active field for edit
    document.getElementById('active-field').style.display = 'block';

    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('userModal'));
    modal.show();
}

async function saveUser() {
    const userId = document.getElementById('user-id').value;
    const email = document.getElementById('user-email').value.trim();
    const password = document.getElementById('user-password').value;
    const fullName = document.getElementById('user-fullname').value.trim();
    const roleId = document.getElementById('user-role').value;
    const isActive = document.getElementById('user-active').checked;

    // Validate
    if (!email || !fullName || !roleId) {
        showNotification('Please fill in all required fields', 'warning');
        return;
    }

    if (!userId && !password) {
        showNotification('Password is required for new users', 'warning');
        return;
    }

    try {
        let response;

        if (userId) {
            // Update existing user
            const updateData = {
                full_name: fullName,
                role_id: parseInt(roleId),
                is_active: isActive
            };

            response = await fetch(`${API_BASE}/auth/users/${userId}`, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                body: JSON.stringify(updateData)
            });
        } else {
            // Create new user
            const createData = {
                email: email,
                password: password,
                full_name: fullName,
                role_id: parseInt(roleId)
            };

            response = await fetch(`${API_BASE}/auth/users`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                body: JSON.stringify(createData)
            });
        }

        const data = await response.json();

        if (!response.ok) {
            showNotification(data.error || 'Failed to save user', 'danger');
            return;
        }

        showNotification(userId ? 'User updated successfully' : 'User created successfully', 'success');
        bootstrap.Modal.getInstance(document.getElementById('userModal')).hide();
        loadUsers();

    } catch (error) {
        console.error('Error saving user:', error);
        showNotification('Failed to save user', 'danger');
    }
}

async function deleteUser(userId, userEmail) {
    if (!confirm(`Delete user "${userEmail}"?\n\nThis will deactivate the account.`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/auth/users/${userId}`, {
            method: 'DELETE',
            credentials: 'include'
        });

        const data = await response.json();

        if (!response.ok) {
            showNotification(data.error || 'Failed to delete user', 'danger');
            return;
        }

        showNotification('User deleted successfully', 'success');
        loadUsers();

    } catch (error) {
        console.error('Error deleting user:', error);
        showNotification('Failed to delete user', 'danger');
    }
}

// Utility functions
function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function formatTime(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;

    // If less than 1 minute
    if (diff < 60000) {
        return 'Just now';
    }
    // If less than 1 hour
    if (diff < 3600000) {
        const mins = Math.floor(diff / 60000);
        return `${mins}m ago`;
    }
    // If less than 24 hours
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return `${hours}h ago`;
    }
    // Otherwise full date
    return date.toLocaleString();
}

function getRiskClass(score) {
    if (score >= 80) return 'threat-critical';
    if (score >= 60) return 'threat-high';
    if (score >= 40) return 'threat-medium';
    return 'threat-low';
}

function showNotification(message, type = 'info') {
    const colors = {
        success: '#10b981',
        danger: '#f56565',
        warning: '#f6ad55',
        info: '#4299e1'
    };

    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.style.borderLeft = `4px solid ${colors[type]}`;
    notification.innerHTML = `
        <div class="d-flex align-items-center gap-2">
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'danger' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}
