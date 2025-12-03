/**
 * SSH Guardian 2.0 - Attack Simulation Module
 * Handles simulation UI, execution, and real-time log streaming
 */

// Global simulation state
let selectedTemplate = null;
let currentSimulationId = null;
let sseConnection = null;
let historyPage = 0;
const historyPageSize = 100;

// Initialize simulation when tab is loaded
function initializeSimulation() {
    console.log('Initializing attack simulation module...');
    loadTemplates();
}

// Load all attack templates
async function loadTemplates() {
    try {
        const container = document.getElementById('template-list');
        container.innerHTML = '<div class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Loading...</div></div>';

        console.log('Fetching templates from:', `${API_BASE}/api/simulation/templates`);

        const response = await fetch(`${API_BASE}/api/simulation/templates`, {
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

    } catch (error) {
        console.error('Error loading templates:', error);
        document.getElementById('template-list').innerHTML = '<div class="alert alert-danger m-3">Failed to load templates</div>';
    }
}

function renderTemplateItem(template) {
    return `
        <div class="template-item" onclick="selectTemplate('${template.id}')">
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
}

// Select a template and load its JSON
async function selectTemplate(templateId) {
    try {
        // Highlight selected template
        document.querySelectorAll('.template-item').forEach(item => {
            item.classList.remove('active');
        });
        event.target.closest('.template-item').classList.add('active');

        selectedTemplate = templateId;

        // Load template with auto-filled IPs
        const response = await fetch(`${API_BASE}/api/simulation/template/${templateId}`, {
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        const template = data.template;
        const jsonParams = data.json;

        // Update UI
        document.getElementById('selected-template-name').innerHTML = `
            <i class="fas ${template.icon}"></i> ${template.name}
            <span class="badge bg-${getSeverityBadgeClass(template.severity)} ms-2">${template.severity.toUpperCase()}</span>
        `;

        // Pretty print JSON
        document.getElementById('sim-json-editor').value = JSON.stringify(jsonParams, null, 2);

        showNotification(`Template "${template.name}" loaded`, 'success');

    } catch (error) {
        console.error('Error selecting template:', error);
        showNotification('Failed to load template', 'danger');
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
        const response = await fetch(`${API_BASE}/api/simulation/template/${selectedTemplate}`, {
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

        // Clear previous logs
        clearSimulationLogs();

        // Disable execute button
        executeBtn.disabled = true;
        executeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Executing...';

        // Add initial log message
        addLogEntry('INIT', 'INFO', 'Initiating simulation...', new Date().toISOString());

        // Execute simulation
        const response = await fetch(`${API_BASE}/api/simulation/execute`, {
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
        const response = await fetch(`${API_BASE}/api/simulation/logs/${simulationId}`, {
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

    const url = `${API_BASE}/api/simulation/stream/${simulationId}`;

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
async function loadSimulationHistory() {
    try {
        const tbody = document.getElementById('history-tbody');
        tbody.innerHTML = '<tr><td colspan="9" class="text-center py-4"><div class="loading-spinner"></div><div class="mt-2">Loading...</div></td></tr>';

        const offset = historyPage * historyPageSize;
        const response = await fetch(`${API_BASE}/api/simulation/history?limit=${historyPageSize}&offset=${offset}`, {
            credentials: 'include'
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        const history = data.history || [];
        const total = data.total || 0;

        if (history.length === 0 && offset === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center py-4 text-muted">No simulation history</td></tr>';
            return;
        }

        tbody.innerHTML = history.map(record => `
            <tr>
                <td>${record.id}</td>
                <td>
                    <div class="small fw-bold">${record.template_display_name || record.template_name}</div>
                    <div class="small text-muted">${record.template_name}</div>
                </td>
                <td>${record.user_email || 'N/A'}</td>
                <td>
                    <span class="badge ${getStatusBadgeClass(record.status)}">${record.status}</span>
                </td>
                <td>${record.events_processed || 0} / ${record.total_events || 0}</td>
                <td>${record.ips_blocked || 0}</td>
                <td>${record.duration_seconds ? record.duration_seconds + 's' : 'N/A'}</td>
                <td class="small">${record.created_at ? new Date(record.created_at).toLocaleString() : 'N/A'}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewSimulationLogs(${record.id})" title="View Logs">
                        <i class="fas fa-file-alt"></i>
                    </button>
                </td>
            </tr>
        `).join('');

        // Update pagination info
        const start = offset + 1;
        const end = Math.min(offset + history.length, total);
        document.getElementById('history-info').textContent = `Showing ${start}-${end} of ${total} simulations`;

        // Update pagination buttons
        document.getElementById('history-prev-btn').disabled = historyPage === 0;
        document.getElementById('history-next-btn').disabled = end >= total;

    } catch (error) {
        console.error('Error loading history:', error);
        document.getElementById('history-tbody').innerHTML = '<tr><td colspan="9" class="text-center py-4 text-danger">Failed to load history</td></tr>';
    }
}

function getStatusBadgeClass(status) {
    const mapping = {
        'completed': 'bg-success',
        'running': 'bg-primary',
        'failed': 'bg-danger',
        'cancelled': 'bg-secondary'
    };
    return mapping[status] || 'bg-secondary';
}

// Load history page (pagination)
function loadHistoryPage(direction) {
    if (direction === 'next') {
        historyPage++;
    } else if (direction === 'prev' && historyPage > 0) {
        historyPage--;
    }
    loadSimulationHistory();
}

// View simulation logs from history
async function viewSimulationLogs(simulationId) {
    try {
        clearSimulationLogs();

        addLogEntry('HISTORY', 'INFO', `Loading logs for simulation #${simulationId}...`, new Date().toISOString());

        const response = await fetch(`${API_BASE}/api/simulation/logs/${simulationId}`, {
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
    const logsDiv = document.getElementById('sim-logs');

    const summaryCard = document.createElement('div');
    summaryCard.className = 'simulation-summary-card mt-3 p-3';
    summaryCard.style.cssText = `
        background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%);
        border: 2px solid rgba(102, 126, 234, 0.3);
        border-radius: 12px;
    `;

    const statusIcon = summary.ips_blocked > 0 ? '🚫' : '✅';
    const statusColor = summary.ips_blocked > 0 ? '#f56565' : '#48bb78';

    summaryCard.innerHTML = `
        <div style="border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 12px; margin-bottom: 12px;">
            <h5 style="margin: 0; color: ${statusColor};">
                ${statusIcon} Simulation Summary
            </h5>
        </div>

        <div class="row">
            <div class="col-md-3 col-6 mb-2">
                <div class="text-muted small">Total Events</div>
                <div class="fs-4 fw-bold">${summary.total_events}</div>
            </div>
            <div class="col-md-3 col-6 mb-2">
                <div class="text-muted small">Successful</div>
                <div class="fs-4 fw-bold text-success">${summary.successful_submissions}</div>
            </div>
            <div class="col-md-3 col-6 mb-2">
                <div class="text-muted small">IPs Blocked</div>
                <div class="fs-4 fw-bold text-danger">${summary.ips_blocked}</div>
            </div>
            <div class="col-md-3 col-6 mb-2">
                <div class="text-muted small">Completion</div>
                <div class="fs-4 fw-bold text-info">${summary.completion_rate}%</div>
            </div>
        </div>

        ${summary.high_risk_events > 0 ? `
        <div class="alert alert-warning mt-3 mb-3" style="margin-bottom: 12px;">
            <i class="fas fa-exclamation-triangle"></i>
            <strong>${summary.high_risk_events}</strong> high-risk events detected
        </div>
        ` : ''}

        <div style="border-top: 1px solid rgba(255,255,255,0.1); padding-top: 12px; margin-top: 12px;">
            <div class="text-muted small mb-2"><strong>📋 Actions:</strong></div>
            <div class="d-flex flex-wrap gap-2">
                <button class="btn btn-sm btn-outline-primary" onclick="viewSimulationLogs(${simulationId})">
                    <i class="fas fa-redo"></i> Replay Logs
                </button>
                <button class="btn btn-sm btn-outline-info" onclick="window.location.href='#threats-tab'; switchTab('threats')">
                    <i class="fas fa-shield-alt"></i> View Threats
                </button>
                <button class="btn btn-sm btn-outline-warning" onclick="window.location.href='#ip-management-tab'; switchTab('ip-management')">
                    <i class="fas fa-ban"></i> Blocked IPs
                </button>
                <button class="btn btn-sm btn-outline-success" onclick="showSimulationHistory()">
                    <i class="fas fa-history"></i> View History
                </button>
            </div>
        </div>
    `;

    logsDiv.appendChild(summaryCard);
    logsDiv.scrollTop = logsDiv.scrollHeight;
}

// Export for global access
window.initializeSimulation = initializeSimulation;
window.selectTemplate = selectTemplate;
window.formatJSON = formatJSON;
window.refreshIPPool = refreshIPPool;
window.executeSimulation = executeSimulation;
window.clearSimulationLogs = clearSimulationLogs;
window.showSimulationHistory = showSimulationHistory;
window.hideSimulationHistory = hideSimulationHistory;
window.loadHistoryPage = loadHistoryPage;
window.viewSimulationLogs = viewSimulationLogs;
