/**
 * SSH Guardian 2.0 - Attack Simulation Module
 * Handles simulation UI, execution, and real-time log streaming
 * Version: 2.1 - With IP Analytics Support
 */

console.log('=== Simulation.js v2.1 loaded with IP Analytics support ===');

// Use the global API_BASE and showNotification from enhanced-dashboard.js
// No need to redeclare them

// Global simulation state
let selectedTemplate = null;
let currentSimulationId = null;
let sseConnection = null;
let historyPage = 1;
let historyTotalPages = 1;
let historyAttackTypeFilter = '';
const historyPageSize = 100;

// Initialize simulation when tab is loaded
function initializeSimulation() {
    console.log('=== Initializing attack simulation module ===');
    console.log('API_BASE:', window.API_BASE || '');

    // Check if already initialized
    if (window.simulationInitialized) {
        console.log('Simulation already initialized, skipping...');
        return;
    }

    window.simulationInitialized = true;
    loadTemplates();
    loadAttackTypeFilter();
    loadSimulationHistory();
}

// Load all attack templates
async function loadTemplates() {
    console.log('loadTemplates() called');

    try {
        const container = document.getElementById('template-list');
        if (!container) {
            console.error('template-list element not found!');
            return;
        }

        container.innerHTML = '<div class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Loading...</div></div>';

        const url = `${window.API_BASE || ""}/api/simulation/templates`;
        console.log('Fetching templates from:', url);

        const response = await fetch(`${window.API_BASE || ""}/api/simulation/templates`, {
            credentials: 'include'
        });

        console.log('Templates response status:', response.status);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Templates error response:', errorText);
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        console.log('Templates loaded:', data);
        const templates = data.templates || [];

        if (templates.length === 0) {
            container.innerHTML = '<div class="text-center py-4 text-muted">No templates available</div>';
            return;
        }

        // Group templates by category
        const categories = {
            'high_priority': [],
            'compromise': [],
            'scanning': [],
            'probing': [],
            'anomaly': [],
            'credential_attack': [],
            'evasion': [],
            'temporal_anomaly': [],
            'legitimate': []
        };

        templates.forEach(template => {
            const category = template.category || 'legitimate';
            if (!categories[category]) {
                categories[category] = [];
            }
            categories[category].push(template);
        });

        // Render templates
        let html = '';

        // Priority templates first
        if (categories['high_priority'].length > 0) {
            html += '<div class="mb-3"><div class="small text-uppercase text-muted mb-2"><strong>🔥 High Priority</strong></div>';
            categories['high_priority'].forEach(t => {
                html += renderTemplateItem(t);
            });
            html += '</div>';
        }

        // Other categories
        Object.keys(categories).forEach(category => {
            if (category === 'high_priority' || categories[category].length === 0) return;

            const categoryNames = {
                'compromise': 'Compromise',
                'scanning': 'Scanning',
                'probing': 'Probing',
                'anomaly': 'Anomalies',
                'credential_attack': 'Credential Attacks',
                'evasion': 'Evasion',
                'temporal_anomaly': 'Temporal Anomalies',
                'legitimate': 'Legitimate Traffic'
            };

            html += `<div class="mb-3"><div class="small text-uppercase text-muted mb-2"><strong>${categoryNames[category]}</strong></div>`;
            categories[category].forEach(t => {
                html += renderTemplateItem(t);
            });
            html += '</div>';
        });

        container.innerHTML = html;
        console.log('Templates HTML rendered, total templates:', templates.length);

        // Add click event listeners to all template items
        const items = container.querySelectorAll('.template-item');
        console.log('Template items found:', items.length);

        items.forEach(item => {
            const templateId = item.getAttribute('data-template-id');
            console.log('Adding click listener to template:', templateId);

            item.addEventListener('click', function(e) {
                console.log('Template item clicked via event listener:', templateId);
                e.preventDefault();
                e.stopPropagation();
                selectTemplate(templateId, e);
            });
        });

    } catch (error) {
        console.error('Error loading templates:', error);
        document.getElementById('template-list').innerHTML = '<div class="alert alert-danger m-3">Failed to load templates</div>';
    }
}

function renderTemplateItem(template) {
    const html = `
        <div class="template-item" data-template-id="${template.id}" style="cursor: pointer;">
            <div class="d-flex align-items-start">
                <div class="template-icon severity-${template.severity} me-2">
                    <i class="fas ${template.icon}"></i>
                </div>
                <div class="flex-grow-1">
                    <div class="fw-bold mb-1" style="font-size: 13px;">${template.name}</div>
                    <div class="small text-muted" style="font-size: 11px;">${template.description}</div>
                </div>
            </div>
        </div>
    `;
    return html;
}

// Load attack type filter options from database
async function loadAttackTypeFilter() {
    const filterSelect = document.getElementById('attack-type-filter');
    if (!filterSelect) {
        console.error('attack-type-filter element not found');
        return;
    }

    try {
        const response = await fetch(`${window.API_BASE || ""}/api/simulation/attack-types`, {
            credentials: 'include'
        });

        if (!response.ok) {
            console.error('Failed to load attack types');
            return;
        }

        const data = await response.json();
        const attackTypes = data.attack_types || [];

        // Clear existing options except "All Attack Types"
        filterSelect.innerHTML = '<option value="">All Attack Types</option>';

        // Add options from database
        attackTypes.forEach(type => {
            const option = document.createElement('option');
            option.value = type.template_name;
            option.textContent = type.template_display_name || type.template_name;
            filterSelect.appendChild(option);
        });

        console.log(`Loaded ${attackTypes.length} attack types into filter`);

    } catch (error) {
        console.error('Error loading attack types:', error);
    }
}

// Select a template and load its JSON
async function selectTemplate(templateId, event) {
    console.log('=== selectTemplate called ===');
    console.log('Template ID:', templateId);
    console.log('Event:', event);

    try {
        // Highlight selected template
        const templateItems = document.querySelectorAll('.template-item');
        console.log('Found template items:', templateItems.length);

        templateItems.forEach(item => {
            item.classList.remove('active');
        });

        if (event && event.target) {
            const closestItem = event.target.closest('.template-item');
            console.log('Closest template item:', closestItem);
            if (closestItem) {
                closestItem.classList.add('active');
            }
        }

        selectedTemplate = templateId;
        console.log('Selected template set to:', selectedTemplate);

        // Load template with auto-filled IPs
        const url = `${window.API_BASE || ""}/api/simulation/template/${templateId}`;
        console.log('Fetching template from:', url);

        const response = await fetch(url, {
            credentials: 'include'
        });

        console.log('Template response status:', response.status);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Template error:', errorText);
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        console.log('Template data received:', data);

        const template = data.template;
        const jsonParams = data.json;

        // Update dropdown display
        const displayEl = document.getElementById('selected-template-display');
        if (displayEl) {
            displayEl.textContent = template.name;
        }

        // Update badge
        const badgeEl = document.getElementById('selected-template-badge');
        if (badgeEl) {
            badgeEl.textContent = template.severity.toUpperCase();
            badgeEl.className = 'badge badge-' + template.severity;
            badgeEl.style.display = 'inline-block';
        }

        // Pretty print JSON to editor
        const editor = document.getElementById('sim-json-editor');
        if (editor) {
            editor.value = JSON.stringify(jsonParams, null, 2);
            console.log('JSON populated in editor');
        } else {
            console.error('JSON editor element not found!');
        }

        // Close dropdown
        const dropdown = document.getElementById('template-dropdown');
        if (dropdown) {
            dropdown.classList.remove('open');
        }

        showNotification(`Template "${template.name}" loaded`, 'success');

    } catch (error) {
        console.error('Error selecting template:', error);
        showNotification('Failed to load template: ' + error.message, 'danger');
    }
}

function getSeverityBadgeClass(severity) {
    const mapping = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'success'
    };
    return mapping[severity] || 'secondary';
}

// Format JSON
function formatJSON() {
    try {
        const editor = document.getElementById('sim-json-editor');
        const json = JSON.parse(editor.value);
        editor.value = JSON.stringify(json, null, 2);
        showNotification('JSON formatted', 'success');
    } catch (error) {
        showNotification('Invalid JSON: ' + error.message, 'danger');
    }
}

// Refresh IP pool (get new IPs from pools)
async function refreshIPPool() {
    if (!selectedTemplate) {
        showNotification('Please select a template first', 'warning');
        return;
    }

    try {
        const response = await fetch(`${window.API_BASE || ""}/api/simulation/template/${selectedTemplate}`, {
            credentials: 'include'
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        document.getElementById('sim-json-editor').value = JSON.stringify(data.json, null, 2);

        showNotification('IPs refreshed from pool', 'success');

    } catch (error) {
        console.error('Error refreshing IPs:', error);
        showNotification('Failed to refresh IPs', 'danger');
    }
}

// Execute simulation
async function executeSimulation() {
    if (!selectedTemplate) {
        showNotification('Please select a template first', 'warning');
        return;
    }

    // Get execute button reference once
    const executeBtn = document.getElementById('execute-btn');

    try {
        // Validate JSON
        const jsonText = document.getElementById('sim-json-editor').value;
        const params = JSON.parse(jsonText);

        // Show log panel and clear previous logs
        showLogPanel();
        clearSimulationLogs();

        // Disable execute button
        executeBtn.disabled = true;
        executeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Executing...';

        // Add initial log message
        addLogEntry('INIT', 'INFO', 'Initiating simulation...', new Date().toISOString());

        // Execute simulation
        const response = await fetch(`${window.API_BASE || ""}/api/simulation/execute`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({
                template_name: selectedTemplate,
                parameters: params
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || `HTTP ${response.status}`);
        }

        const data = await response.json();
        currentSimulationId = data.simulation_id;

        addLogEntry('INIT', 'SUCCESS', `Simulation #${currentSimulationId} completed`, new Date().toISOString());

        // Load logs from the completed simulation
        await loadSimulationLogs(currentSimulationId);

        // Show detailed summary
        if (data.summary) {
            const summary = data.summary;
            addLogEntry('SUMMARY', 'INFO', `Total Events: ${summary.total_events}, IPs Blocked: ${summary.ips_blocked}, Completion: ${summary.completion_rate}%`, new Date().toISOString());

            // Display summary card
            displaySimulationSummary(data.summary, currentSimulationId);
        }

        showNotification('Simulation completed!', 'success');

        // Re-enable execute button
        executeBtn.disabled = false;
        executeBtn.innerHTML = '<i class="fas fa-play"></i> Execute Simulation';

    } catch (error) {
        console.error('Error executing simulation:', error);
        addLogEntry('ERROR', 'ERROR', `Execution failed: ${error.message}`, new Date().toISOString());
        showNotification('Simulation failed: ' + error.message, 'danger');

        // Re-enable button
        executeBtn.disabled = false;
        executeBtn.innerHTML = '<i class="fas fa-play"></i> Execute Simulation';
    }
}

// Load simulation logs after completion
async function loadSimulationLogs(simulationId) {
    try {
        const response = await fetch(`${window.API_BASE || ""}/api/simulation/logs/${simulationId}`, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        const logs = data.logs || [];

        // Display all logs in order
        logs.forEach(log => {
            addLogEntry(log.stage, log.level, log.message, log.timestamp, log.metadata);
        });

    } catch (error) {
        console.error('Error loading simulation logs:', error);
        addLogEntry('ERROR', 'ERROR', `Failed to load logs: ${error.message}`, new Date().toISOString());
    }
}

// Start SSE stream for real-time logs (kept for future use)
function startLogStream(simulationId) {
    if (sseConnection) {
        sseConnection.close();
    }

    const url = `${window.API_BASE || ""}/api/simulation/stream/${simulationId}`;

    sseConnection = new EventSource(url, { withCredentials: true });

    sseConnection.onmessage = function(event) {
        const data = JSON.parse(event.data);

        if (data.type === 'connected') {
            addLogEntry('SSE', 'INFO', `Connected to simulation #${data.simulation_id}`, new Date().toISOString());
        } else if (data.type === 'completed') {
            addLogEntry('COMPLETE', 'SUCCESS', `Simulation ${data.status}`, new Date().toISOString());
            sseConnection.close();

            // Re-enable execute button
            const executeBtn = document.getElementById('execute-btn');
            executeBtn.disabled = false;
            executeBtn.innerHTML = '<i class="fas fa-play"></i> Execute Simulation';

            showNotification('Simulation completed!', 'success');
        } else if (data.type === 'error') {
            addLogEntry('ERROR', 'ERROR', data.message, new Date().toISOString());
            sseConnection.close();
        } else {
            // Regular log entry
            addLogEntry(data.stage, data.level, data.message, data.timestamp, data.metadata);
        }
    };

    sseConnection.onerror = function(error) {
        console.error('SSE Error:', error);
        addLogEntry('SSE', 'ERROR', 'Connection error, retrying...', new Date().toISOString());

        // Re-enable execute button on error
        const executeBtn = document.getElementById('execute-btn');
        executeBtn.disabled = false;
        executeBtn.innerHTML = '<i class="fas fa-play"></i> Execute Simulation';
    };
}

// Add log entry to console
function addLogEntry(stage, level, message, timestamp, metadata) {
    const logsDiv = document.getElementById('sim-logs');

    // Remove placeholder if present
    const placeholder = logsDiv.querySelector('.text-center');
    if (placeholder) {
        logsDiv.innerHTML = '';
    }

    const entry = document.createElement('div');
    entry.className = `log-entry log-level-${level}`;

    const levelEmoji = {
        'INFO': 'ℹ️',
        'SUCCESS': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'DEBUG': '🔍'
    };

    const time = new Date(timestamp).toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3
    });

    entry.innerHTML = `
        <span class="log-timestamp">[${time}]</span>
        <span class="log-stage">[${stage}]</span>
        <span class="log-message">${levelEmoji[level] || ''} ${message}</span>
    `;

    // Add metadata if present
    if (metadata && Object.keys(metadata).length > 0) {
        const metaStr = JSON.stringify(metadata, null, 2);
        entry.innerHTML += `<div class="small text-muted ms-4 mt-1">${metaStr}</div>`;
    }

    logsDiv.appendChild(entry);

    // Auto-scroll to bottom
    logsDiv.scrollTop = logsDiv.scrollHeight;
}

// Clear simulation logs
function clearSimulationLogs() {
    const logsDiv = document.getElementById('sim-logs');
    logsDiv.innerHTML = '<div class="text-center text-muted py-5"><i class="fas fa-terminal fa-3x mb-3"></i><p>Logs cleared. Execute a simulation to start...</p></div>';

    if (sseConnection) {
        sseConnection.close();
        sseConnection = null;
    }
}

// Show simulation history
async function showSimulationHistory() {
    document.getElementById('simulation-history-panel').style.display = 'block';
    historyPage = 0;
    await loadSimulationHistory();
}

// Hide simulation history
function hideSimulationHistory() {
    document.getElementById('simulation-history-panel').style.display = 'none';
}

// Load simulation history
// REMOVED: Old table-based history function (duplicate)
// Using the new card-based loadSimulationHistory() at line ~818 instead

function getStatusBadgeClass(status) {
    const mapping = {
        'completed': 'bg-success',
        'running': 'bg-primary',
        'failed': 'bg-danger',
        'cancelled': 'bg-secondary'
    };
    return mapping[status] || 'bg-secondary';
}

// View simulation logs from history
async function viewSimulationLogs(simulationId) {
    try {
        clearSimulationLogs();

        addLogEntry('HISTORY', 'INFO', `Loading logs for simulation #${simulationId}...`, new Date().toISOString());

        const response = await fetch(`${window.API_BASE || ""}/api/simulation/logs/${simulationId}`, {
            credentials: 'include'
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        const logs = data.logs || [];

        clearSimulationLogs();

        if (logs.length === 0) {
            addLogEntry('HISTORY', 'WARNING', 'No logs found for this simulation', new Date().toISOString());
            return;
        }

        // Replay all logs
        logs.forEach(log => {
            addLogEntry(log.stage, log.level, log.message, log.timestamp, log.metadata);
        });

        showNotification(`Loaded ${logs.length} log entries`, 'success');

        // Hide history panel
        hideSimulationHistory();

    } catch (error) {
        console.error('Error viewing simulation logs:', error);
        showNotification('Failed to load simulation logs', 'danger');
    }
}

// Display simulation summary with actions
function displaySimulationSummary(summary, simulationId) {
    // Update summary panel
    const summaryDiv = document.getElementById('sim-summary');
    const statusBadge = document.getElementById('sim-status-badge');

    statusBadge.className = 'badge';
    if (summary.completion_rate === 100) {
        statusBadge.classList.add('bg-success');
        statusBadge.textContent = 'Completed';
    } else if (summary.completion_rate > 0) {
        statusBadge.classList.add('bg-warning');
        statusBadge.textContent = 'Partial';
    } else {
        statusBadge.classList.add('bg-danger');
        statusBadge.textContent = 'Failed';
    }

    summaryDiv.innerHTML = `
        <div class="sim-stat-grid">
            <div class="sim-stat-item">
                <div class="sim-stat-label">Total Events</div>
                <div class="sim-stat-value">${summary.total_events || 0}</div>
            </div>
            <div class="sim-stat-item">
                <div class="sim-stat-label">Successful</div>
                <div class="sim-stat-value text-success">${summary.successful_submissions || 0}</div>
            </div>
            <div class="sim-stat-item">
                <div class="sim-stat-label">IPs Blocked</div>
                <div class="sim-stat-value text-danger">${summary.ips_blocked || 0}</div>
            </div>
            <div class="sim-stat-item">
                <div class="sim-stat-label">Completion</div>
                <div class="sim-stat-value text-info">${summary.completion_rate || 0}%</div>
            </div>
        </div>
        ${summary.high_risk_events > 0 ? `
        <div class="alert alert-warning mb-2">
            <i class="fas fa-exclamation-triangle"></i> <strong>${summary.high_risk_events}</strong> high-risk events
        </div>
        ` : ''}
        <div class="d-flex flex-wrap gap-2">
            <button class="btn btn-sm btn-outline-primary" onclick="loadSimulationLogs(${simulationId})">
                <i class="fas fa-redo"></i> Reload Logs
            </button>
            <button class="btn btn-sm btn-outline-info" onclick="switchTab('ip-management')">
                <i class="fas fa-ban"></i> View Blocks
            </button>
        </div>
    `;

    // Fetch intelligence for blocked IPs
    console.log('=== DEBUG: Summary data ===', summary);
    console.log('=== DEBUG: Blocked IPs ===', summary.blocked_ips);

    console.log('=== CRITICAL DEBUG: Checking simulation results ===');
    console.log('=== total_events:', summary.total_events);
    console.log('=== blocked_ips:', summary.blocked_ips);
    console.log('=== simulationId:', simulationId);

    // Always try to load IP analytics if there were any events
    if (summary.total_events > 0) {
        console.log('✅ === DEBUG: Simulation has events, loading analytics ===');

        // Load IP analytics data (works for both blocked and non-blocked IPs)
        console.log('=== CALLING loadIPAnalytics with ID:', simulationId);
        loadIPAnalytics(simulationId);

        // Fetch threat intelligence only if IPs were blocked
        if (summary.blocked_ips && summary.blocked_ips.length > 0) {
            console.log('=== Also fetching threat intelligence for blocked IPs ===', summary.blocked_ips);
            fetchThreatIntelligence(summary.blocked_ips);
        } else {
            console.log('=== No IPs blocked, skipping threat intelligence lookup ===');
        }
    } else {
        console.log('❌ === DEBUG: No events in simulation ===');
        // Show placeholder if simulation had no activity
        const intelPanel = document.getElementById('sim-intel-panel');
        const intelPlaceholder = document.getElementById('sim-intel-placeholder');
        if (intelPanel) intelPanel.style.display = 'none';
        if (intelPlaceholder) intelPlaceholder.style.display = 'block';
    }
}

// Load IP analytics data for simulation
async function loadIPAnalytics(simulationId) {
    console.log('=== loadIPAnalytics called for simulation ===', simulationId);

    try {
        const response = await fetch(`${window.API_BASE || ""}/api/simulation/analytics/${simulationId}`, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        console.log('=== Analytics data ===', data);

        if (!data.success || !data.has_data) {
            console.log('=== No analytics data available ===');
            return;
        }

        // Display the analytics
        displayIPAnalytics(data);

    } catch (error) {
        console.error('=== Error loading analytics ===', error);
    }
}

// Display IP analytics in the panel
function displayIPAnalytics(data) {
    console.log('=== displayIPAnalytics called ===', data);

    const stats = data.stats;
    const ip = data.ip_address;

    // Update stat cards
    const statTotal = document.getElementById('stat-total');
    const statBreakdown = document.getElementById('stat-breakdown');
    const statLocation = document.getElementById('stat-location');
    const statCoords = document.getElementById('stat-coords');
    const statRisk = document.getElementById('stat-risk');
    const statReputation = document.getElementById('stat-reputation');

    if (statTotal) statTotal.textContent = stats.total_logins;
    if (statBreakdown) {
        statBreakdown.innerHTML = `<span class="text-success">${stats.successful} successful</span>, <span class="text-danger">${stats.failed} failed</span>`;
    }
    if (statLocation) {
        const locationText = stats.location || 'Unknown';
        statLocation.innerHTML = `<i class="fas fa-map-marker-alt me-1" style="font-size: 12px; opacity: 0.7;"></i>${locationText}`;
    }
    if (statCoords) {
        const countryText = stats.country || 'Unknown';
        statCoords.innerHTML = `<i class="fas fa-globe me-1" style="font-size: 11px; opacity: 0.6;"></i>${countryText}`;
    }
    if (statRisk) {
        statRisk.textContent = stats.risk_level;
        statRisk.className = 'stat-value';
        if (stats.risk_level === 'Critical') statRisk.classList.add('text-danger');
        else if (stats.risk_level === 'High') statRisk.classList.add('text-warning');
        else if (stats.risk_level === 'Medium') statRisk.classList.add('text-info');
        else statRisk.classList.add('text-success');
    }
    if (statReputation) {
        const scoreColor = stats.risk_score >= 80 ? 'danger' : stats.risk_score >= 50 ? 'warning' : 'success';
        statReputation.innerHTML = `<span class="text-${scoreColor}"><strong>${stats.risk_score}</strong>/100</span>`;
    }

    // Show behavior alert
    const behaviorAlert = document.getElementById('behavior-alert');
    const behaviorType = document.getElementById('behavior-type');
    const behaviorSuggestions = document.getElementById('behavior-suggestions');

    if (behaviorAlert && stats.risk_score >= 50) {
        behaviorAlert.style.display = 'block';
        behaviorAlert.className = stats.risk_score >= 70 ? 'alert alert-danger' : 'alert alert-warning';
        if (behaviorType) behaviorType.textContent = 'ML Risk Analysis';
        if (behaviorSuggestions) {
            behaviorSuggestions.innerHTML = `
                <ul class="mb-0">
                    <li>High risk activity detected from ${ip}</li>
                    <li>Risk score: ${stats.risk_score}/100</li>
                    <li>IP has been ${stats.block_reason ? 'blocked: ' + stats.block_reason : 'blocked'}</li>
                </ul>
            `;
        }
    }

    // Display successful logins
    const successList = document.getElementById('successful-logins-list');
    if (successList && data.successful_logins) {
        if (data.successful_logins.length > 0) {
            successList.innerHTML = data.successful_logins.map(login => {
                const riskColor = login.ml_risk_score >= 70 ? 'danger' : login.ml_risk_score >= 50 ? 'warning' : 'info';
                return `
                <div class="login-history-item">
                    <div class="login-history-header">
                        <span class="login-history-time"><i class="far fa-clock me-1"></i>${new Date(login.timestamp).toLocaleString()}</span>
                        <span class="badge bg-${riskColor}" style="font-size: 10px;">${login.ml_risk_score}/100</span>
                    </div>
                    <div class="login-history-body">
                        <div class="login-history-user"><i class="fas fa-user me-1"></i><strong>${login.username}</strong></div>
                        <div class="login-history-location"><i class="fas fa-map-marker-alt me-1"></i>${login.city || 'Unknown'}, ${login.country || 'Unknown'}</div>
                    </div>
                </div>
            `}).join('');
        } else {
            successList.innerHTML = '<div class="text-muted text-center small p-3"><i class="fas fa-info-circle me-1"></i>No successful logins</div>';
        }
    }

    // Display failed logins
    const failedList = document.getElementById('failed-logins-list');
    if (failedList && data.failed_logins) {
        if (data.failed_logins.length > 0) {
            failedList.innerHTML = data.failed_logins.map(login => {
                const riskColor = login.ml_risk_score >= 70 ? 'danger' : login.ml_risk_score >= 50 ? 'warning' : 'info';
                return `
                <div class="login-history-item">
                    <div class="login-history-header">
                        <span class="login-history-time"><i class="far fa-clock me-1"></i>${new Date(login.timestamp).toLocaleString()}</span>
                        <span class="badge bg-${riskColor}" style="font-size: 10px;">${login.ml_risk_score}/100</span>
                    </div>
                    <div class="login-history-body">
                        <div class="login-history-user"><i class="fas fa-user me-1"></i><strong>${login.username}</strong></div>
                        <div class="login-history-location"><i class="fas fa-map-marker-alt me-1"></i>${login.city || 'Unknown'}, ${login.country || 'Unknown'}</div>
                    </div>
                </div>
            `}).join('');
        } else {
            failedList.innerHTML = '<div class="text-muted text-center small p-3"><i class="fas fa-info-circle me-1"></i>No failed attempts</div>';
        }
    }

    console.log('=== Analytics display complete ===');
}

// Fetch threat intelligence for IPs
async function fetchThreatIntelligence(ips) {
    console.log('=== fetchThreatIntelligence called with IPs ===', ips);

    const intelPanel = document.getElementById('sim-intel-panel');
    const intelPlaceholder = document.getElementById('sim-intel-placeholder');
    const intelContent = document.getElementById('sim-intel-content');

    console.log('=== Panel elements ===', {
        intelPanel: intelPanel ? 'found' : 'NOT FOUND',
        intelPlaceholder: intelPlaceholder ? 'found' : 'NOT FOUND',
        intelContent: intelContent ? 'found' : 'NOT FOUND'
    });

    if (!intelPanel || !intelPlaceholder || !intelContent) {
        console.error('=== ERROR: Required panel elements not found! ===');
        return;
    }

    intelPlaceholder.style.display = 'none';
    intelPanel.style.display = 'block';

    // Show loading state in the threat intelligence section
    const threatIntelContent = document.getElementById('threat-intel-content');
    if (threatIntelContent) {
        threatIntelContent.innerHTML = '<div class="text-center py-3"><div class="loading-spinner"></div><div class="mt-2 small">Loading intelligence...</div></div>';
    }

    try {
        // Fetch intelligence for first IP (or aggregate if multiple)
        const firstIP = ips[0];
        console.log('=== Fetching intelligence for IP ===', firstIP);

        const url = `${window.API_BASE || ""}/api/ip/intel/lookup/${firstIP}`;
        console.log('=== API URL ===', url);

        const response = await fetch(url, {
            credentials: 'include'
        });

        console.log('=== API Response status ===', response.status);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('=== API Error ===', errorText);
            throw new Error('Failed to fetch intelligence: ' + response.status);
        }

        const result = await response.json();
        console.log('=== API Result ===', result);

        if (result.status === 'success') {
            console.log('=== Calling displayThreatIntelligence ===');
            displayThreatIntelligence(result.data, firstIP);
        } else {
            throw new Error(result.error || 'Unknown error');
        }

    } catch (error) {
        console.error('=== Error fetching intelligence ===', error);
        const threatIntelContent = document.getElementById('threat-intel-content');
        if (threatIntelContent) {
            threatIntelContent.innerHTML = '<div class="text-center py-3 text-muted"><i class="fas fa-exclamation-circle"></i> Failed to load intelligence: ' + error.message + '</div>';
        }
    }
}

// Display threat intelligence
function displayThreatIntelligence(intel, ip) {
    console.log('=== displayThreatIntelligence called ===', {ip, intel});

    const intelContent = document.getElementById('threat-intel-content');
    const badge = document.getElementById('analytics-ip-badge');

    console.log('=== Display elements ===', {
        intelContent: intelContent ? 'found' : 'NOT FOUND',
        badge: badge ? 'found' : 'NOT FOUND'
    });

    // Update badge with IP
    if (badge) badge.textContent = ip;

    // Auto-expand the threat intelligence section
    const threatIntelDetails = document.getElementById('threat-intel-details');
    if (threatIntelDetails) {
        threatIntelDetails.style.display = 'block';
        const chevron = document.getElementById('threat-intel-chevron');
        if (chevron) chevron.classList.replace('fa-chevron-down', 'fa-chevron-up');
    }

    // Build summary section with enhanced styling
    let html = `<div class="intel-section-enhanced">
        <div class="intel-header-main">
            <i class="fas fa-chart-pie text-primary me-2"></i>
            <span class="intel-header-title">IP Analysis Summary</span>
            <span class="intel-header-badge">${ip}</span>
        </div>`;

    // Show summary if available
    if (intel.summary) {
        const summary = intel.summary;
        const threatClass = summary.is_threat ? 'malicious' : 'clean';
        const threatIcon = summary.is_threat ? 'fa-shield-virus' : 'fa-shield-check';
        html += `
        <div class="intel-grid">
            <div class="intel-grid-item">
                <div class="intel-grid-label"><i class="fas ${threatIcon} me-1"></i>Threat Status</div>
                <div class="intel-badge-large ${threatClass}">${summary.is_threat ? 'THREAT DETECTED' : 'Clean'}</div>
            </div>
            <div class="intel-grid-item">
                <div class="intel-grid-label"><i class="fas fa-exclamation-triangle me-1"></i>Threat Score</div>
                <div class="intel-score-display">${summary.threat_score || 0}<span class="intel-score-max">/100</span></div>
            </div>
            <div class="intel-grid-item">
                <div class="intel-grid-label"><i class="fas fa-layer-group me-1"></i>Threat Level</div>
                <div class="intel-value-large text-capitalize">${summary.threat_level || 'unknown'}</div>
            </div>
            <div class="intel-grid-item">
                <div class="intel-grid-label"><i class="fas fa-database me-1"></i>Sources Responded</div>
                <div class="intel-value-large">${summary.sources_responded}/${summary.sources_queried}</div>
            </div>
        </div>`;
    }
    html += `</div>`;

    // Extract sources data
    const sources = intel.sources || {};

    // AbuseIPDB
    if (sources.abuseipdb && !sources.abuseipdb.error) {
        const data = sources.abuseipdb;
        const score = data.abuse_confidence_score || 0;
        const badgeClass = score > 75 ? 'malicious' : score > 25 ? 'suspicious' : 'clean';
        const networkInfo = data.network_info || {};
        const location = data.location || {};

        html += `<div class="intel-section-enhanced">
            <div class="intel-section-header">
                <i class="fas fa-database text-warning me-2"></i>
                <span>AbuseIPDB Intelligence</span>
            </div>
            <div class="intel-details-grid">
                <div class="intel-detail-card ${badgeClass}-bg">
                    <div class="intel-detail-icon"><i class="fas fa-exclamation-circle"></i></div>
                    <div class="intel-detail-content">
                        <div class="intel-detail-label">Abuse Confidence</div>
                        <div class="intel-detail-value">${score}%</div>
                    </div>
                </div>
                <div class="intel-detail-card">
                    <div class="intel-detail-icon"><i class="fas fa-flag"></i></div>
                    <div class="intel-detail-content">
                        <div class="intel-detail-label">Total Reports</div>
                        <div class="intel-detail-value">${data.report_stats?.total_reports || 0}</div>
                        <div class="intel-detail-sub">${data.report_stats?.distinct_reporters || 0} unique reporters</div>
                    </div>
                </div>
            </div>
            <div class="intel-info-list">
                ${networkInfo.isp ? `<div class="intel-info-item">
                    <i class="fas fa-network-wired intel-info-icon"></i>
                    <div class="intel-info-content">
                        <div class="intel-info-label">ISP</div>
                        <div class="intel-info-value">${networkInfo.isp}</div>
                    </div>
                </div>` : ''}
                ${networkInfo.usage_type ? `<div class="intel-info-item">
                    <i class="fas fa-server intel-info-icon"></i>
                    <div class="intel-info-content">
                        <div class="intel-info-label">Usage Type</div>
                        <div class="intel-info-value">${networkInfo.usage_type}</div>
                    </div>
                </div>` : ''}
                ${networkInfo.domain ? `<div class="intel-info-item">
                    <i class="fas fa-globe intel-info-icon"></i>
                    <div class="intel-info-content">
                        <div class="intel-info-label">Domain Name</div>
                        <div class="intel-info-value">${networkInfo.domain}</div>
                    </div>
                </div>` : ''}
                ${networkInfo.hostnames && networkInfo.hostnames.length > 0 ? `<div class="intel-info-item">
                    <i class="fas fa-sitemap intel-info-icon"></i>
                    <div class="intel-info-content">
                        <div class="intel-info-label">Hostname(s)</div>
                        <div class="intel-info-value-small">${networkInfo.hostnames.join(', ')}</div>
                    </div>
                </div>` : ''}
                ${location.country_name ? `<div class="intel-info-item">
                    <i class="fas fa-map-marker-alt intel-info-icon"></i>
                    <div class="intel-info-content">
                        <div class="intel-info-label">Country</div>
                        <div class="intel-info-value">${location.country_code ? '🌍 ' + location.country_code + ' - ' : ''}${location.country_name}</div>
                    </div>
                </div>` : ''}
                ${networkInfo.tor ? `<div class="intel-info-item intel-warning-item">
                    <i class="fas fa-user-secret intel-info-icon"></i>
                    <div class="intel-info-content">
                        <div class="intel-info-label">Tor Exit Node</div>
                        <div class="intel-badge malicious">DETECTED</div>
                    </div>
                </div>` : ''}
            </div>
        </div>`;
    }

    // VirusTotal
    if (sources.virustotal && !sources.virustotal.error) {
        const data = sources.virustotal;
        const malicious = data.malicious_count || 0;
        const suspicious = data.suspicious_count || 0;
        html += `<div class="intel-section">
            <div class="intel-section-title"><i class="fas fa-virus text-danger"></i> VirusTotal</div>
            <div class="intel-item">
                <span class="intel-item-label">Malicious Detections</span>
                <span class="intel-badge ${malicious > 0 ? 'malicious' : 'clean'}">${malicious}</span>
            </div>
            <div class="intel-item">
                <span class="intel-item-label">Suspicious Detections</span>
                <span class="intel-badge ${suspicious > 0 ? 'suspicious' : 'clean'}">${suspicious}</span>
            </div>
            <div class="intel-item">
                <span class="intel-item-label">Total Scanners</span>
                <span class="intel-item-value">${data.total_scanners || 0}</span>
            </div>
        </div>`;
    }

    // Shodan
    if (sources.shodan && !sources.shodan.error) {
        const data = sources.shodan;
        const ports = data.open_ports || [];
        html += `<div class="intel-section">
            <div class="intel-section-title"><i class="fas fa-server text-info"></i> Shodan</div>
            ${ports.length > 0 ? `<div class="intel-item">
                <span class="intel-item-label">Open Ports</span>
                <span class="intel-item-value">${ports.join(', ')}</span>
            </div>` : ''}
            ${data.organization?.name || data.organization ? `<div class="intel-item">
                <span class="intel-item-label">Organization</span>
                <span class="intel-item-value">${typeof data.organization === 'object' ? data.organization.name : data.organization}</span>
            </div>` : ''}
            ${data.os ? `<div class="intel-item">
                <span class="intel-item-label">OS</span>
                <span class="intel-item-value">${data.os}</span>
            </div>` : ''}
            ${data.vulnerabilities && data.vulnerabilities.length > 0 ? `<div class="intel-item">
                <span class="intel-item-label">Vulnerabilities</span>
                <span class="intel-badge malicious">${data.vulnerabilities.length} found</span>
            </div>` : ''}
        </div>`;
    }

    // Show error if no sources responded
    if (intel.summary && intel.summary.sources_responded === 0) {
        html += `<div class="text-center py-3 text-muted">
            <i class="fas fa-exclamation-triangle"></i>
            No threat intelligence sources available. Configure API keys in settings.
        </div>`;
    }

    intelContent.innerHTML = html;
}

// Toggle threat intelligence section expand/collapse
function toggleThreatIntel() {
    const details = document.getElementById('threat-intel-details');
    const chevron = document.getElementById('threat-intel-chevron');

    if (details && chevron) {
        if (details.style.display === 'none') {
            details.style.display = 'block';
            chevron.classList.replace('fa-chevron-down', 'fa-chevron-up');
        } else {
            details.style.display = 'none';
            chevron.classList.replace('fa-chevron-up', 'fa-chevron-down');
        }
    }
}

// Toggle log panel minimize/expand
function toggleLogPanel() {
    const logsContent = document.getElementById('sim-logs-content');
    const minimizeBtn = document.querySelector('#floating-log-panel .fa-window-minimize');

    if (logsContent.style.display === 'none') {
        logsContent.style.display = 'block';
        minimizeBtn.className = 'fas fa-window-minimize';
    } else {
        logsContent.style.display = 'none';
        minimizeBtn.className = 'fas fa-window-maximize';
    }
}

// Close log panel
function closeLogPanel() {
    document.getElementById('floating-log-panel').style.display = 'none';
}

// Show log panel
function showLogPanel() {
    const logPanel = document.getElementById('floating-log-panel');
    const logsContent = document.getElementById('sim-logs-content');
    logPanel.style.display = 'block';
    logsContent.style.display = 'block';
}

// Load simulation history
async function loadSimulationHistory(resetPage = false) {
    if (resetPage) {
        historyPage = 1;
    }

    const historyList = document.getElementById('history-list');
    const paginationDiv = document.getElementById('history-pagination');
    historyList.innerHTML = '<div class="text-center py-3"><div class="loading-spinner"></div><div class="mt-2 small">Loading...</div></div>';

    try {
        // Build query params
        const offset = (historyPage - 1) * historyPageSize;
        let url = `${window.API_BASE || ""}/api/simulation/history?limit=${historyPageSize}&offset=${offset}`;

        if (historyAttackTypeFilter) {
            url += `&attack_type=${encodeURIComponent(historyAttackTypeFilter)}`;
        }

        const response = await fetch(url, {
            credentials: 'include'
        });

        if (!response.ok) throw new Error('Failed to load history');

        const data = await response.json();
        console.log('History data received:', data);
        const simulations = data.history || [];
        const totalCount = data.total || simulations.length;
        historyTotalPages = Math.ceil(totalCount / historyPageSize);

        if (simulations.length === 0) {
            historyList.innerHTML = '<div class="text-center py-5 text-muted"><i class="fas fa-history fa-2x mb-2"></i><p>No simulations yet</p></div>';
            paginationDiv.style.display = 'none';
            return;
        }

        let html = '<div class="list-group list-group-flush">';
        simulations.forEach(sim => {
            const statusClass = sim.status === 'completed' ? 'success' : sim.status === 'failed' ? 'danger' : 'warning';

            // Format date in Malaysian timezone
            let date = 'Unknown';
            if (sim.created_at) {
                try {
                    date = new Date(sim.created_at).toLocaleString('en-MY', {
                        timeZone: 'Asia/Kuala_Lumpur',
                        year: 'numeric',
                        month: 'short',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit'
                    });
                } catch (e) {
                    date = new Date(sim.created_at).toLocaleString();
                }
            }

            const displayName = sim.template_display_name || sim.template_name || 'Simulation #' + sim.id;

            html += `
                <div class="list-group-item list-group-item-action" style="cursor: pointer;" data-sim-id="${sim.id}">
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <h6 class="mb-1" style="font-size: 13px;">
                                <i class="fas fa-flask"></i> ${displayName}
                            </h6>
                            <p class="mb-1 small text-muted">
                                ${date}
                                ${sim.user_email ? ` • ${sim.user_email}` : ''}
                            </p>
                            <div class="d-flex flex-wrap gap-2 mt-1">
                                <span class="badge bg-${statusClass}">${sim.status || 'unknown'}</span>
                                ${sim.total_events ? `<span class="badge bg-info">${sim.events_processed || 0}/${sim.total_events} events</span>` : ''}
                                ${sim.ips_blocked ? `<span class="badge bg-danger">${sim.ips_blocked} blocked</span>` : ''}
                                ${sim.duration_seconds ? `<span class="badge bg-secondary">${sim.duration_seconds}s</span>` : ''}
                            </div>
                        </div>
                        <button class="btn btn-sm btn-outline-primary" data-replay-id="${sim.id}" title="Replay logs">
                            <i class="fas fa-play"></i>
                        </button>
                    </div>
                </div>
            `;
        });
        html += '</div>';

        // Set HTML first
        historyList.innerHTML = html;

        // Update pagination controls
        updatePaginationControls();

        // Then add event listeners to replay buttons
        historyList.querySelectorAll('[data-replay-id]').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const simId = this.getAttribute('data-replay-id');
                console.log('Replaying simulation:', simId);
                replaySimulation(parseInt(simId));
            });
        });

        // Add event listeners to list items
        historyList.querySelectorAll('[data-sim-id]').forEach(item => {
            item.addEventListener('click', function() {
                const simId = this.getAttribute('data-sim-id');
                console.log('Viewing simulation details:', simId);
                viewSimulationDetails(parseInt(simId));
            });
        });

    } catch (error) {
        console.error('Error loading history:', error);
        historyList.innerHTML = '<div class="text-center py-3 text-danger"><i class="fas fa-exclamation-circle"></i> Failed to load history</div>';
        paginationDiv.style.display = 'none';
    }
}

// Update pagination controls
function updatePaginationControls() {
    const paginationDiv = document.getElementById('history-pagination');
    const prevBtn = document.getElementById('prev-page-btn');
    const nextBtn = document.getElementById('next-page-btn');
    const pageInfo = document.getElementById('page-info');

    if (historyTotalPages <= 1) {
        paginationDiv.style.display = 'none';
        return;
    }

    paginationDiv.style.display = 'block';
    pageInfo.textContent = `Page ${historyPage} of ${historyTotalPages}`;

    // Update button states
    prevBtn.disabled = historyPage <= 1;
    nextBtn.disabled = historyPage >= historyTotalPages;
}

// Pagination: Load previous page
function loadPreviousPage() {
    if (historyPage > 1) {
        historyPage--;
        loadSimulationHistory();
    }
}

// Pagination: Load next page
function loadNextPage() {
    if (historyPage < historyTotalPages) {
        historyPage++;
        loadSimulationHistory();
    }
}

// Filter history by attack type
function filterHistoryByAttackType() {
    const filterSelect = document.getElementById('attack-type-filter');
    historyAttackTypeFilter = filterSelect.value;
    loadSimulationHistory(true); // Reset to page 1
}

// View simulation details - Load complete simulation data
async function viewSimulationDetails(simId) {
    console.log('=== Loading complete simulation details for ID:', simId, '===');

    try {
        // Show loading state
        showNotification('Loading simulation data...', 'info');

        // 1. Load simulation summary/detail
        const detailResponse = await fetch(`${window.API_BASE || ""}/api/simulation/history/${simId}`, {
            credentials: 'include'
        });

        if (!detailResponse.ok) throw new Error('Failed to load simulation details');
        const detailData = await detailResponse.json();
        const simulation = detailData.simulation;

        console.log('Simulation detail loaded:', simulation);

        // 2. Load simulation logs
        const logsResponse = await fetch(`${window.API_BASE || ""}/api/simulation/logs/${simId}`, {
            credentials: 'include'
        });

        if (!logsResponse.ok) throw new Error('Failed to load simulation logs');
        const logsData = await logsResponse.json();
        const logs = logsData.logs || [];

        console.log('Simulation logs loaded:', logs.length, 'entries');

        // 3. Load IP analytics
        const analyticsResponse = await fetch(`${window.API_BASE || ""}/api/simulation/analytics/${simId}`, {
            credentials: 'include'
        });

        if (!analyticsResponse.ok) throw new Error('Failed to load IP analytics');
        const analyticsData = await analyticsResponse.json();

        console.log('IP Analytics loaded:', analyticsData);

        // Now display all the data

        // Display logs
        showLogPanel();
        clearSimulationLogs();

        if (logs.length > 0) {
            logs.forEach(log => {
                addLogEntry(log.stage, log.level, log.message, log.timestamp, log.metadata);
            });
        } else {
            addLogEntry('HISTORY', 'WARNING', 'No logs found for this simulation', new Date().toISOString());
        }

        // Display summary
        displaySimulationSummary({
            completion_rate: simulation.status === 'completed' ? 100 : 0,
            total_events: simulation.total_events || 0,
            events_processed: simulation.events_processed || 0,
            threats_detected: simulation.threats_detected || 0,
            ips_blocked: simulation.ips_blocked || 0,
            duration_seconds: simulation.duration_seconds || 0
        }, simId);

        // Display IP Analytics if available
        if (analyticsData.has_data && analyticsData.ip_address) {
            console.log('=== Displaying IP Analytics ===');
            displayIPAnalytics(analyticsData);

            // Load threat intelligence for the IP
            console.log('=== Fetching threat intelligence for:', analyticsData.ip_address, '===');
            await fetchThreatIntelligence([analyticsData.ip_address]);
        } else {
            console.log('No IP analytics data available for this simulation');
            // Hide analytics panel
            const intelPanel = document.getElementById('sim-intel-panel');
            const intelPlaceholder = document.getElementById('sim-intel-placeholder');
            if (intelPanel) intelPanel.style.display = 'none';
            if (intelPlaceholder) intelPlaceholder.style.display = 'block';
        }

        // Close history panel
        hideSimulationHistory();

        showNotification(`Loaded simulation #${simId}`, 'success');

    } catch (error) {
        console.error('Error loading simulation details:', error);
        showNotification('Failed to load simulation: ' + error.message, 'danger');
    }
}

// Replay simulation logs
async function replaySimulation(simId) {
    showLogPanel();
    clearSimulationLogs();
    await loadSimulationLogs(simId);
}

// Export for global access
window.initializeSimulation = initializeSimulation;
window.selectTemplate = selectTemplate;
window.formatJSON = formatJSON;
window.refreshIPPool = refreshIPPool;
window.executeSimulation = executeSimulation;
window.filterHistoryByAttackType = filterHistoryByAttackType;
window.loadPreviousPage = loadPreviousPage;
window.loadNextPage = loadNextPage;
window.clearSimulationLogs = clearSimulationLogs;
window.showSimulationHistory = showSimulationHistory;
window.hideSimulationHistory = hideSimulationHistory;
window.toggleLogPanel = toggleLogPanel;
window.closeLogPanel = closeLogPanel;
window.showLogPanel = showLogPanel;
window.loadSimulationHistory = loadSimulationHistory;
window.viewSimulationDetails = viewSimulationDetails;

// Manual test function for IP Intelligence display
window.testIPIntelligence = function(ip = '185.220.101.45') {
    console.log('=== Manual IP Intelligence Test ===');
    console.log('Testing with IP:', ip);
    fetchThreatIntelligence([ip]);
};
window.replaySimulation = replaySimulation;
window.viewSimulationLogs = viewSimulationLogs;
