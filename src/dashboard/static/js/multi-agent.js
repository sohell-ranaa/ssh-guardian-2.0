/**
 * Multi-Agent Dashboard Module
 * Modern UI for managing multiple SSH Guardian agents
 */

class MultiAgentDashboard {
    constructor() {
        this.selectedAgent = localStorage.getItem('selected_agent') || 'all';
        this.agents = [];
        this.refreshInterval = null;
    }

    /**
     * Initialize multi-agent dashboard
     */
    async init() {
        await this.loadAgents();
        this.setupAgentSelector();
        this.setupEventListeners();
        this.startAutoRefresh();
    }

    /**
     * Load all agents from API
     */
    async loadAgents() {
        try {
            const response = await fetch(`${API_BASE}/api/agents`);
            const data = await response.json();

            if (data.status === 'success') {
                this.agents = data.agents;
                return this.agents;
            }
        } catch (error) {
            console.error('Error loading agents:', error);
            return [];
        }
    }

    /**
     * Setup agent selector dropdown - Clean menu style
     */
    setupAgentSelector() {
        const container = document.getElementById('agent-selector-container');
        if (!container) return;

        const html = `
            <div class="agent-selector-clean">
                <div class="agent-selector-header-clean">
                    <div class="agent-title-clean">
                        <i class="fas fa-server"></i>
                        <span>Agent Selection</span>
                    </div>
                    <span class="agent-count-clean">${this.agents.length} agents</span>
                </div>
                <div class="agent-dropdown-clean">
                    <select id="agent-selector" class="form-select">
                        <option value="all">All Agents</option>
                        ${this.agents.map(agent => `
                            <option value="${agent.agent_id}" ${agent.agent_id === this.selectedAgent ? 'selected' : ''}>
                                ${agent.display_name || agent.hostname}
                            </option>
                        `).join('')}
                    </select>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        const selector = document.getElementById('agent-selector');
        if (selector) {
            selector.addEventListener('change', (e) => {
                this.selectedAgent = e.target.value;
                localStorage.setItem('selected_agent', this.selectedAgent);
                this.onAgentChange();
            });
        }
    }

    /**
     * Handle agent change
     */
    async onAgentChange() {
        // Show loading
        this.showLoading();

        // Reload data based on selected agent
        await Promise.all([
            this.loadOverviewStats(),
            this.updateQuickStats()
        ]);

        // Hide loading
        this.hideLoading();

        // Trigger event for other modules
        window.dispatchEvent(new CustomEvent('agentChanged', {
            detail: { agentId: this.selectedAgent }
        }));

        // Reload active tab data
        const activeTab = document.querySelector('.tab-content-panel.active');
        if (activeTab) {
            const tabId = activeTab.id;
            if (tabId === 'threats-tab' && typeof loadThreatsTab === 'function') {
                loadThreatsTab();
            } else if (tabId === 'analytics-tab' && typeof loadAnalyticsTab === 'function') {
                loadAnalyticsTab();
            } else if (tabId === 'live-stream-tab' && typeof loadLiveStreamTab === 'function') {
                loadLiveStreamTab();
            }
        }
    }

    /**
     * Load overview stats for selected agent
     */
    async loadOverviewStats() {
        try {
            const response = await fetch(
                `${API_BASE}/api/stats/overview/multi-agent?agent_id=${this.selectedAgent}`
            );
            const data = await response.json();

            if (data.status === 'success') {
                this.displayOverviewStats(data.stats, data.filter);
            }
        } catch (error) {
            console.error('Error loading overview stats:', error);
        }
    }

    /**
     * Display overview stats with modern UI
     */
    displayOverviewStats(stats, filter) {
        // Show agent context banner if filtered
        const contextBanner = document.getElementById('agent-context-banner');
        if (contextBanner) {
            if (filter !== 'all' && stats.agent_info) {
                contextBanner.innerHTML = `
                    <div class="agent-context-info">
                        <div class="agent-context-icon">
                            <i class="fas fa-server"></i>
                        </div>
                        <div class="agent-context-details">
                            <h4>${stats.agent_info.display_name}</h4>
                            <p>${stats.agent_info.hostname} • ${stats.agent_info.status}</p>
                        </div>
                    </div>
                    <button class="clear-filter-btn" onclick="multiAgent.clearFilter()">
                        <i class="fas fa-times"></i> View All Agents
                    </button>
                `;
                contextBanner.style.display = 'flex';
            } else {
                contextBanner.style.display = 'none';
            }
        }

        // Update stats cards with clean neutral design
        const statsContainer = document.getElementById('overview-stats');
        if (statsContainer) {
            statsContainer.innerHTML = `
                <div class="stats-grid-clean">
                    <div class="stat-card-clean">
                        <div class="stat-icon-clean" style="color: #0078D4;">
                            <i class="fas fa-chart-line"></i>
                        </div>
                        <div class="stat-content-clean">
                            <div class="stat-label-clean">Total Events</div>
                            <div class="stat-value-clean">${stats.total_events?.toLocaleString() || 0}</div>
                            <div class="stat-footer-clean">${stats.events_24h || 0} in last 24h</div>
                        </div>
                    </div>

                    <div class="stat-card-clean">
                        <div class="stat-icon-clean" style="color: #E74856;">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="stat-content-clean">
                            <div class="stat-label-clean">Failed Logins</div>
                            <div class="stat-value-clean">${stats.failed_logins?.toLocaleString() || 0}</div>
                            <div class="stat-footer-clean">${stats.failed_24h || 0} in last 24h</div>
                        </div>
                    </div>

                    <div class="stat-card-clean">
                        <div class="stat-icon-clean" style="color: #FFA500;">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="stat-content-clean">
                            <div class="stat-label-clean">High Risk Threats</div>
                            <div class="stat-value-clean">${stats.high_risk_threats?.toLocaleString() || 0}</div>
                            <div class="stat-footer-clean">ML detected</div>
                        </div>
                    </div>

                    <div class="stat-card-clean">
                        <div class="stat-icon-clean" style="color: #10893E;">
                            <i class="fas fa-network-wired"></i>
                        </div>
                        <div class="stat-content-clean">
                            <div class="stat-label-clean">Unique IPs</div>
                            <div class="stat-value-clean">${stats.unique_ips?.toLocaleString() || 0}</div>
                            <div class="stat-footer-clean">${stats.blocked_ips || 0} blocked</div>
                        </div>
                    </div>

                    ${filter === 'all' && stats.total_agents ? `
                    <div class="stat-card-clean">
                        <div class="stat-icon-clean" style="color: #0078D4;">
                            <i class="fas fa-server"></i>
                        </div>
                        <div class="stat-content-clean">
                            <div class="stat-label-clean">Active Agents</div>
                            <div class="stat-value-clean">${stats.total_agents}</div>
                            <div class="stat-footer-clean">monitoring</div>
                        </div>
                    </div>
                    ` : ''}
                </div>
            `;
        }
    }

    /**
     * Update quick stats in agent selector - Removed for cleaner UI
     */
    async updateQuickStats() {
        // Disabled - stats shown in main cards instead
        return;
    }

    /**
     * Display agent grid view
     */
    async displayAgentGrid() {
        const container = document.getElementById('agents-grid-container');
        if (!container) return;

        await this.loadAgents();

        const html = `
            <div class="agents-grid">
                ${this.agents.map(agent => this.renderAgentCard(agent)).join('')}
            </div>
        `;

        container.innerHTML = html;
    }

    /**
     * Render individual agent card
     */
    renderAgentCard(agent) {
        return `
            <div class="agent-card" onclick="multiAgent.selectAgent('${agent.agent_id}')">
                <div class="agent-card-header">
                    <div class="agent-icon">
                        <i class="fas fa-server"></i>
                    </div>
                    <div class="agent-status-badge ${agent.status}">
                        <div class="agent-status-indicator"></div>
                        ${agent.status}
                    </div>
                </div>
                <div class="agent-card-body">
                    <div class="agent-name">${agent.display_name || agent.hostname}</div>
                    <div class="agent-hostname">${agent.hostname}</div>
                    <div class="agent-metrics">
                        <div class="agent-metric">
                            <div class="agent-metric-label">Failed Logins</div>
                            <div class="agent-metric-value">${agent.failed_logins_count || 0}</div>
                        </div>
                        <div class="agent-metric">
                            <div class="agent-metric-label">Blocked IPs</div>
                            <div class="agent-metric-value">${agent.blocked_ips_count || 0}</div>
                        </div>
                    </div>
                </div>
                <div class="agent-card-footer">
                    <button class="agent-action-btn primary" onclick="event.stopPropagation(); multiAgent.viewAgentDetails('${agent.agent_id}')">
                        <i class="fas fa-eye"></i> View
                    </button>
                    <button class="agent-action-btn secondary" onclick="event.stopPropagation(); multiAgent.filterByAgent('${agent.agent_id}')">
                        <i class="fas fa-filter"></i> Filter
                    </button>
                </div>
            </div>
        `;
    }

    /**
     * Clear agent filter
     */
    clearFilter() {
        const selector = document.getElementById('agent-selector');
        if (selector) {
            selector.value = 'all';
            this.selectedAgent = 'all';
            localStorage.setItem('selected_agent', 'all');
            this.onAgentChange();
        }
    }

    /**
     * Select specific agent
     */
    selectAgent(agentId) {
        const selector = document.getElementById('agent-selector');
        if (selector) {
            selector.value = agentId;
            this.selectedAgent = agentId;
            localStorage.setItem('selected_agent', agentId);
            this.onAgentChange();
        }

        // Switch to overview tab
        switchTab('overview');
    }

    /**
     * Filter by agent
     */
    filterByAgent(agentId) {
        this.selectAgent(agentId);
    }

    /**
     * View agent details
     */
    async viewAgentDetails(agentId) {
        // Implementation for detailed agent view
        console.log('View details for agent:', agentId);
        this.selectAgent(agentId);
    }

    /**
     * Show loading overlay
     */
    showLoading() {
        const overlay = document.createElement('div');
        overlay.id = 'loading-overlay';
        overlay.className = 'loading-overlay';
        overlay.innerHTML = '<div class="loading-spinner-modern"></div>';
        document.body.appendChild(overlay);
    }

    /**
     * Hide loading overlay
     */
    hideLoading() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.remove();
        }
    }

    /**
     * Start auto-refresh
     */
    startAutoRefresh() {
        // Refresh every 30 seconds
        this.refreshInterval = setInterval(() => {
            this.loadOverviewStats();
            this.updateQuickStats();
        }, 30000);
    }

    /**
     * Stop auto-refresh
     */
    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }

    /**
     * Get selected agent ID
     */
    getSelectedAgent() {
        return this.selectedAgent;
    }

    /**
     * Get agent by ID
     */
    getAgent(agentId) {
        return this.agents.find(a => a.agent_id === agentId);
    }
}

// Initialize multi-agent dashboard
let multiAgent;

document.addEventListener('DOMContentLoaded', async () => {
    multiAgent = new MultiAgentDashboard();
    await multiAgent.init();

    // Load initial data
    await multiAgent.loadOverviewStats();

    // Make globally available
    window.multiAgent = multiAgent;
});

// Handle page unload
window.addEventListener('beforeunload', () => {
    if (window.multiAgent) {
        window.multiAgent.stopAutoRefresh();
    }
});
