/**
 * IP Intelligence Module
 * Handles IP threat intelligence lookups across multiple sources
 */

class IPIntelligence {
    constructor() {
        this.currentLookup = null;
        this.lookupHistory = [];
    }

    /**
     * Initialize IP intelligence panel
     */
    init() {
        this.setupEventListeners();
        this.checkServiceStatus();
    }

    /**
     * Setup event listeners for IP lookup
     */
    setupEventListeners() {
        // IP lookup form
        const lookupForm = document.getElementById('ip-lookup-form');
        if (lookupForm) {
            lookupForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const ipInput = document.getElementById('ip-lookup-input');
                if (ipInput && ipInput.value) {
                    this.lookupIP(ipInput.value.trim());
                }
            });
        }

        // Click on any IP in tables to look up
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('ip-lookup-link')) {
                e.preventDefault();
                const ip = e.target.dataset.ip || e.target.textContent.trim();
                this.lookupIP(ip);
            }
        });
    }

    /**
     * Check status of threat intelligence services
     */
    async checkServiceStatus() {
        try {
            const response = await fetch('/api/ip/intelligence/status');
            const data = await response.json();

            if (data.status === 'success') {
                this.updateServiceStatusUI(data.data);
            }
        } catch (error) {
            console.error('Error checking service status:', error);
        }
    }

    /**
     * Update service status UI
     */
    updateServiceStatusUI(statusData) {
        const statusContainer = document.getElementById('intel-service-status');
        if (!statusContainer) return;

        const services = statusData.services;
        let html = '<div class="service-status-grid">';

        for (const [name, status] of Object.entries(services)) {
            const statusClass = status.available ? 'status-available' : 'status-unavailable';
            const statusIcon = status.available ? '✓' : '✗';
            const configStatus = status.configured ? 'Configured' : 'Not Configured';

            html += `
                <div class="service-status-item ${statusClass}">
                    <span class="service-icon">${statusIcon}</span>
                    <span class="service-name">${this.formatServiceName(name)}</span>
                    <span class="service-config">${configStatus}</span>
                </div>
            `;
        }

        html += '</div>';
        statusContainer.innerHTML = html;
    }

    /**
     * Format service name for display
     */
    formatServiceName(name) {
        const names = {
            'virustotal': 'VirusTotal',
            'shodan': 'Shodan',
            'abuseipdb': 'AbuseIPDB'
        };
        return names[name] || name;
    }

    /**
     * Lookup IP address across all sources
     */
    async lookupIP(ipAddress) {
        this.currentLookup = ipAddress;

        // Show loading state
        this.showLoadingState(ipAddress);

        try {
            // Fetch comprehensive lookup
            const response = await fetch(`/api/ip/intel/lookup/${ipAddress}`);
            const data = await response.json();

            if (data.status === 'success') {
                this.displayLookupResults(data.data);
                this.addToHistory(ipAddress, data.data);
            } else {
                this.showError(data.error || 'Lookup failed');
            }
        } catch (error) {
            console.error('IP lookup error:', error);
            this.showError('Network error during lookup');
        }
    }

    /**
     * Show loading state
     */
    showLoadingState(ipAddress) {
        const resultsContainer = document.getElementById('ip-intel-results');
        if (!resultsContainer) return;

        resultsContainer.innerHTML = `
            <div class="loading-state">
                <div class="spinner"></div>
                <p>Looking up ${ipAddress} across threat intelligence sources...</p>
            </div>
        `;

        resultsContainer.classList.remove('hidden');
    }

    /**
     * Display comprehensive lookup results
     */
    displayLookupResults(data) {
        const resultsContainer = document.getElementById('ip-intel-results');
        if (!resultsContainer) return;

        const summary = data.summary || {};
        const sources = data.sources || {};

        let html = `
            <div class="ip-intel-container">
                <!-- Summary Header -->
                <div class="intel-header">
                    <h3>IP Intelligence: ${data.ip}</h3>
                    <div class="threat-badge ${this.getThreatClass(summary.threat_level)}">
                        ${summary.threat_level || 'unknown'}
                    </div>
                </div>

                <!-- Overall Summary -->
                <div class="intel-summary">
                    <div class="summary-grid">
                        <div class="summary-item">
                            <span class="label">Threat Status:</span>
                            <span class="value ${summary.is_threat ? 'text-danger' : 'text-success'}">
                                ${summary.is_threat ? 'THREAT DETECTED' : 'Clean'}
                            </span>
                        </div>
                        <div class="summary-item">
                            <span class="label">Threat Score:</span>
                            <span class="value">${summary.threat_score || 0}/100</span>
                        </div>
                        <div class="summary-item">
                            <span class="label">Sources Queried:</span>
                            <span class="value">${summary.sources_responded || 0}/${summary.sources_queried || 0}</span>
                        </div>
                        <div class="summary-item">
                            <span class="label">Confidence:</span>
                            <span class="value">${summary.confidence || 'unknown'}</span>
                        </div>
                    </div>

                    ${summary.threat_indicators && summary.threat_indicators.length > 0 ? `
                        <div class="threat-indicators">
                            <h4>Threat Indicators:</h4>
                            <ul>
                                ${summary.threat_indicators.map(indicator =>
                                    `<li>${indicator}</li>`
                                ).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>

                <!-- Source Details -->
                <div class="source-details">
                    ${this.renderSourceDetails('VirusTotal', sources.virustotal)}
                    ${this.renderSourceDetails('Shodan', sources.shodan)}
                    ${this.renderSourceDetails('AbuseIPDB', sources.abuseipdb)}
                </div>
            </div>
        `;

        resultsContainer.innerHTML = html;
    }

    /**
     * Render individual source details
     */
    renderSourceDetails(sourceName, sourceData) {
        if (!sourceData || sourceData.error) {
            return `
                <div class="source-panel source-error">
                    <h4>${sourceName}</h4>
                    <p class="error-msg">${sourceData?.error || 'Not available'}</p>
                </div>
            `;
        }

        let detailsHTML = '';

        // VirusTotal details
        if (sourceName === 'VirusTotal' && sourceData.service === 'virustotal') {
            detailsHTML = `
                <div class="vt-stats">
                    <div class="stat-item">
                        <span class="stat-label">Malicious:</span>
                        <span class="stat-value text-danger">${sourceData.malicious_count || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Suspicious:</span>
                        <span class="stat-value text-warning">${sourceData.suspicious_count || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Harmless:</span>
                        <span class="stat-value text-success">${sourceData.harmless_count || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Total Scanners:</span>
                        <span class="stat-value">${sourceData.total_scanners || 0}</span>
                    </div>
                </div>
                ${sourceData.network_info ? `
                    <div class="network-info">
                        <p><strong>ASN:</strong> ${sourceData.network_info.as_owner || 'Unknown'}</p>
                        <p><strong>Country:</strong> ${sourceData.network_info.country || 'Unknown'}</p>
                        <p><strong>Network:</strong> ${sourceData.network_info.network || 'Unknown'}</p>
                    </div>
                ` : ''}
            `;
        }

        // Shodan details
        if (sourceName === 'Shodan' && sourceData.service === 'shodan') {
            detailsHTML = `
                <div class="shodan-stats">
                    <div class="stat-item">
                        <span class="stat-label">Open Ports:</span>
                        <span class="stat-value">${sourceData.port_count || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Vulnerabilities:</span>
                        <span class="stat-value text-danger">${sourceData.vulnerability_count || 0}</span>
                    </div>
                </div>
                ${sourceData.open_ports && sourceData.open_ports.length > 0 ? `
                    <div class="ports-list">
                        <strong>Open Ports:</strong>
                        <span class="port-badges">
                            ${sourceData.open_ports.slice(0, 10).map(port =>
                                `<span class="port-badge">${port}</span>`
                            ).join('')}
                            ${sourceData.open_ports.length > 10 ? '<span class="more">+more</span>' : ''}
                        </span>
                    </div>
                ` : ''}
                ${sourceData.location ? `
                    <div class="location-info">
                        <p><strong>Location:</strong> ${sourceData.location.city || ''}, ${sourceData.location.country || 'Unknown'}</p>
                        <p><strong>Organization:</strong> ${sourceData.organization?.name || 'Unknown'}</p>
                    </div>
                ` : ''}
            `;
        }

        // AbuseIPDB details
        if (sourceName === 'AbuseIPDB' && sourceData.service === 'abuseipdb') {
            detailsHTML = `
                <div class="abuse-stats">
                    <div class="stat-item">
                        <span class="stat-label">Abuse Confidence:</span>
                        <span class="stat-value ${sourceData.abuse_confidence_score >= 50 ? 'text-danger' : 'text-warning'}">
                            ${sourceData.abuse_confidence_score || 0}%
                        </span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Total Reports:</span>
                        <span class="stat-value">${sourceData.report_stats?.total_reports || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Distinct Reporters:</span>
                        <span class="stat-value">${sourceData.report_stats?.distinct_reporters || 0}</span>
                    </div>
                </div>
                ${sourceData.network_info ? `
                    <div class="network-info">
                        <p><strong>ISP:</strong> ${sourceData.network_info.isp || 'Unknown'}</p>
                        <p><strong>Usage Type:</strong> ${sourceData.network_info.usage_type || 'Unknown'}</p>
                        <p><strong>Country:</strong> ${sourceData.location?.country_name || 'Unknown'}</p>
                    </div>
                ` : ''}
            `;
        }

        return `
            <div class="source-panel">
                <h4>${sourceName}</h4>
                ${detailsHTML}
            </div>
        `;
    }

    /**
     * Get threat class for styling
     */
    getThreatClass(threatLevel) {
        const classes = {
            'critical': 'threat-critical',
            'high': 'threat-high',
            'medium': 'threat-medium',
            'low': 'threat-low',
            'clean': 'threat-clean',
            'unknown': 'threat-unknown'
        };
        return classes[threatLevel] || 'threat-unknown';
    }

    /**
     * Show error message
     */
    showError(message) {
        const resultsContainer = document.getElementById('ip-intel-results');
        if (!resultsContainer) return;

        resultsContainer.innerHTML = `
            <div class="error-state">
                <p class="error-message">${message}</p>
            </div>
        `;
    }

    /**
     * Add lookup to history
     */
    addToHistory(ipAddress, data) {
        this.lookupHistory.unshift({
            ip: ipAddress,
            timestamp: new Date(),
            threat_level: data.summary?.threat_level || 'unknown',
            is_threat: data.summary?.is_threat || false
        });

        // Keep only last 10
        if (this.lookupHistory.length > 10) {
            this.lookupHistory = this.lookupHistory.slice(0, 10);
        }

        this.updateHistoryUI();
    }

    /**
     * Update history UI
     */
    updateHistoryUI() {
        const historyContainer = document.getElementById('ip-lookup-history');
        if (!historyContainer) return;

        if (this.lookupHistory.length === 0) {
            historyContainer.innerHTML = '<p class="no-history">No recent lookups</p>';
            return;
        }

        let html = '<ul class="history-list">';
        for (const item of this.lookupHistory) {
            const timeAgo = this.formatTimeAgo(item.timestamp);
            const threatClass = item.is_threat ? 'threat' : 'clean';

            html += `
                <li class="history-item ${threatClass}">
                    <a href="#" class="ip-lookup-link" data-ip="${item.ip}">
                        ${item.ip}
                    </a>
                    <span class="threat-indicator ${this.getThreatClass(item.threat_level)}">
                        ${item.threat_level}
                    </span>
                    <span class="timestamp">${timeAgo}</span>
                </li>
            `;
        }
        html += '</ul>';

        historyContainer.innerHTML = html;
    }

    /**
     * Format time ago
     */
    formatTimeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);

        if (seconds < 60) return 'just now';
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        return `${Math.floor(seconds / 86400)}d ago`;
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.ipIntelligence = new IPIntelligence();
    window.ipIntelligence.init();
});
