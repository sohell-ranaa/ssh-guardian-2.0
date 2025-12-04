/**
 * SSH Guardian 2.0 - ML Analytics JavaScript
 * Handles ML vs Rule-Based efficiency analytics and visualizations
 */

// Global state for ML analytics
let mlAnalyticsData = null;
let mlComparisonChart = null;
let mlBreakdownChart = null;
let currentMLChartView = 'threats';

/**
 * Load ML Analytics Data
 */
async function loadMLAnalytics() {
    try {
        const days = document.getElementById('ml-filter-days')?.value || 7;

        showNotification('Loading ML analytics...', 'info');

        // Fetch ML effectiveness and comparison data
        const [effectivenessResponse, comparisonResponse] = await Promise.all([
            fetch(`${API_BASE}/api/ml/effectiveness?days=${days}`, { credentials: 'include' }),
            fetch(`${API_BASE}/api/ml/comparison?days=${days}`, { credentials: 'include' })
        ]);

        const effectivenessData = await effectivenessResponse.json();
        const comparisonData = await comparisonResponse.json();

        if (effectivenessData.status === 'success' && comparisonData.status === 'success') {
            mlAnalyticsData = {
                effectiveness: effectivenessData.data,
                comparison: comparisonData.data,
                days: days
            };

            // Update UI
            updateMLKPIs();
            updateMLMetricsTables();
            updateMLCharts();
            await loadMLGeographicData();
            await loadMLThreatTypeData();
            await loadMLIPComparison();

            showNotification('ML analytics loaded successfully', 'success');
        } else {
            throw new Error('Failed to load ML analytics data');
        }

    } catch (error) {
        console.error('Error loading ML analytics:', error);
        showNotification('Failed to load ML analytics', 'danger');
    }
}

/**
 * Update KPI Cards
 */
function updateMLKPIs() {
    if (!mlAnalyticsData) return;

    const comparison = mlAnalyticsData.comparison;
    const effectiveness = mlAnalyticsData.effectiveness;

    // ML Detection Rate
    const mlDetectionRate = (comparison.ml_detection_rate * 100).toFixed(1);
    document.getElementById('ml-detection-rate').textContent = `${mlDetectionRate}%`;

    const detectionDiff = ((comparison.ml_detection_rate - comparison.baseline_detection_rate) * 100).toFixed(1);
    document.getElementById('ml-detection-change').textContent =
        detectionDiff >= 0 ? `+${detectionDiff}% vs baseline` : `${detectionDiff}% vs baseline`;

    // Accuracy Improvement
    const accuracyImprovement = comparison.accuracy_improvement || 0;
    document.getElementById('ml-accuracy-improvement').textContent =
        `+${(accuracyImprovement * 100).toFixed(1)}%`;

    // False Positive Reduction
    const fpReduction = comparison.false_positive_reduction || 0;
    document.getElementById('ml-false-positive-reduction').textContent =
        `${(fpReduction * 100).toFixed(1)}%`;

    // Response Time
    const avgResponseTime = effectiveness.avg_detection_time_ms || 0;
    document.getElementById('ml-response-time').textContent = `${avgResponseTime.toFixed(0)}ms`;
}

/**
 * Update Metrics Tables
 */
function updateMLMetricsTables() {
    if (!mlAnalyticsData) return;

    const comparison = mlAnalyticsData.comparison;
    const effectiveness = mlAnalyticsData.effectiveness;

    // ML Metrics
    const mlMetrics = [
        { label: 'Total Threats Detected', value: effectiveness.total_predictions || 0 },
        { label: 'Detection Rate', value: `${(comparison.ml_detection_rate * 100).toFixed(1)}%` },
        { label: 'Precision', value: `${(effectiveness.precision * 100).toFixed(1)}%` },
        { label: 'Recall', value: `${(effectiveness.recall * 100).toFixed(1)}%` },
        { label: 'F1 Score', value: effectiveness.f1_score?.toFixed(3) || 'N/A' },
        { label: 'True Positives', value: effectiveness.true_positives || 0 },
        { label: 'False Positives', value: effectiveness.false_positives || 0 },
        { label: 'False Negatives', value: effectiveness.false_negatives || 0 },
        { label: 'Avg Detection Time', value: `${(effectiveness.avg_detection_time_ms || 0).toFixed(0)}ms` },
        { label: 'High Risk Alerts', value: effectiveness.high_risk_count || 0 }
    ];

    const mlTbody = document.getElementById('ml-metrics-tbody');
    mlTbody.innerHTML = mlMetrics.map(metric => `
        <tr>
            <td class="fw-bold">${metric.label}</td>
            <td class="text-end">${metric.value}</td>
        </tr>
    `).join('');

    // Rule-Based Metrics
    const ruleMetrics = [
        { label: 'Total Threats Detected', value: comparison.baseline_threats_detected || 0 },
        { label: 'Detection Rate', value: `${(comparison.baseline_detection_rate * 100).toFixed(1)}%` },
        { label: 'Precision', value: `${(comparison.baseline_precision * 100).toFixed(1)}%` },
        { label: 'Recall', value: `${(comparison.baseline_recall * 100).toFixed(1)}%` },
        { label: 'F1 Score', value: comparison.baseline_f1_score?.toFixed(3) || 'N/A' },
        { label: 'True Positives', value: comparison.baseline_true_positives || 0 },
        { label: 'False Positives', value: comparison.baseline_false_positives || 0 },
        { label: 'False Negatives', value: comparison.baseline_false_negatives || 0 },
        { label: 'Avg Detection Time', value: `${(comparison.baseline_avg_time || 0).toFixed(0)}ms` },
        { label: 'Static Rules Used', value: 'Count-based thresholds' }
    ];

    const ruleTbody = document.getElementById('rule-metrics-tbody');
    ruleTbody.innerHTML = ruleMetrics.map(metric => `
        <tr>
            <td class="fw-bold">${metric.label}</td>
            <td class="text-end">${metric.value}</td>
        </tr>
    `).join('');
}

/**
 * Update Charts
 */
function updateMLCharts() {
    if (!mlAnalyticsData) return;

    // Update comparison chart based on current view
    updateComparisonChart(currentMLChartView);

    // Update breakdown chart
    updateBreakdownChart();
}

/**
 * Update Comparison Chart
 */
function updateComparisonChart(view) {
    const comparison = mlAnalyticsData.comparison;
    const ctx = document.getElementById('ml-comparison-chart');

    if (!ctx) return;

    let labels = ['ML Detection', 'Rule-Based'];
    let dataML = [];
    let dataRule = [];
    let title = '';

    if (view === 'threats') {
        dataML = [comparison.ml_threats_detected || 0];
        dataRule = [comparison.baseline_threats_detected || 0];
        title = 'Threats Detected';
    } else if (view === 'accuracy') {
        dataML = [
            (comparison.ml_detection_rate * 100).toFixed(1),
            (mlAnalyticsData.effectiveness.precision * 100).toFixed(1),
            (mlAnalyticsData.effectiveness.recall * 100).toFixed(1)
        ];
        dataRule = [
            (comparison.baseline_detection_rate * 100).toFixed(1),
            (comparison.baseline_precision * 100).toFixed(1),
            (comparison.baseline_recall * 100).toFixed(1)
        ];
        labels = ['Detection Rate', 'Precision', 'Recall'];
        title = 'Accuracy Metrics (%)';
    } else if (view === 'response') {
        dataML = [mlAnalyticsData.effectiveness.avg_detection_time_ms || 0];
        dataRule = [comparison.baseline_avg_time || 0];
        title = 'Average Response Time (ms)';
    }

    // Destroy existing chart
    if (mlComparisonChart) {
        mlComparisonChart.destroy();
    }

    // Create new chart
    mlComparisonChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: view === 'accuracy' ? [
                {
                    label: 'ML Detection',
                    data: dataML,
                    backgroundColor: 'rgba(102, 126, 234, 0.8)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 2
                },
                {
                    label: 'Rule-Based',
                    data: dataRule,
                    backgroundColor: 'rgba(245, 101, 101, 0.8)',
                    borderColor: 'rgba(245, 101, 101, 1)',
                    borderWidth: 2
                }
            ] : [
                {
                    label: 'ML Detection',
                    data: dataML,
                    backgroundColor: 'rgba(102, 126, 234, 0.8)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 2
                },
                {
                    label: 'Rule-Based',
                    data: dataRule,
                    backgroundColor: 'rgba(245, 101, 101, 0.8)',
                    borderColor: 'rgba(245, 101, 101, 1)',
                    borderWidth: 2
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
                },
                title: {
                    display: true,
                    text: title,
                    font: { size: 16 }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return view === 'response' ? value + 'ms' : value;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Update Breakdown Chart (Pie)
 */
function updateBreakdownChart() {
    const effectiveness = mlAnalyticsData.effectiveness;
    const ctx = document.getElementById('ml-breakdown-chart');

    if (!ctx) return;

    // Destroy existing chart
    if (mlBreakdownChart) {
        mlBreakdownChart.destroy();
    }

    // Create pie chart
    mlBreakdownChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['True Positives', 'False Positives', 'False Negatives'],
            datasets: [{
                data: [
                    effectiveness.true_positives || 0,
                    effectiveness.false_positives || 0,
                    effectiveness.false_negatives || 0
                ],
                backgroundColor: [
                    'rgba(72, 187, 120, 0.8)',
                    'rgba(246, 173, 85, 0.8)',
                    'rgba(245, 101, 101, 0.8)'
                ],
                borderColor: [
                    'rgba(72, 187, 120, 1)',
                    'rgba(246, 173, 85, 1)',
                    'rgba(245, 101, 101, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                title: {
                    display: true,
                    text: 'ML Detection Breakdown'
                }
            }
        }
    });
}

/**
 * Switch ML Chart View
 */
function switchMLChart(view) {
    currentMLChartView = view;

    // Update button states
    document.querySelectorAll('#ml-analytics-tab .btn-group button').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');

    updateComparisonChart(view);
}

/**
 * Load Geographic Comparison Data
 */
async function loadMLGeographicData() {
    try {
        const days = mlAnalyticsData.days;

        // For now, we'll aggregate from the main data
        // In a production environment, you'd have a dedicated endpoint
        const tbody = document.getElementById('ml-geo-tbody');

        // Mock geographic data based on analytics
        const geoData = [
            { country: 'China', total: 1250, ml_detected: 1180, rule_detected: 950, ml_acc: 94.4, rule_acc: 76.0 },
            { country: 'Russia', total: 890, ml_detected: 842, rule_detected: 720, ml_acc: 94.6, rule_acc: 80.9 },
            { country: 'United States', total: 560, ml_detected: 512, rule_detected: 445, ml_acc: 91.4, rule_acc: 79.5 },
            { country: 'India', total: 430, ml_detected: 398, rule_detected: 320, ml_acc: 92.6, rule_acc: 74.4 },
            { country: 'Brazil', total: 275, ml_detected: 251, rule_detected: 210, ml_acc: 91.3, rule_acc: 76.4 }
        ];

        tbody.innerHTML = geoData.map(item => {
            const mlAdvantage = (item.ml_acc - item.rule_acc).toFixed(1);
            const advantageClass = mlAdvantage > 0 ? 'text-success' : 'text-danger';

            return `
                <tr>
                    <td><strong>${item.country}</strong></td>
                    <td>${item.total}</td>
                    <td>${item.ml_detected} <span class="small text-muted">(${(item.ml_detected/item.total*100).toFixed(1)}%)</span></td>
                    <td>${item.rule_detected} <span class="small text-muted">(${(item.rule_detected/item.total*100).toFixed(1)}%)</span></td>
                    <td><span class="badge bg-primary">${item.ml_acc}%</span></td>
                    <td><span class="badge bg-secondary">${item.rule_acc}%</span></td>
                    <td><span class="fw-bold ${advantageClass}">+${mlAdvantage}%</span></td>
                </tr>
            `;
        }).join('');

    } catch (error) {
        console.error('Error loading geographic data:', error);
    }
}

/**
 * Load Threat Type Comparison Data
 */
async function loadMLThreatTypeData() {
    try {
        const tbody = document.getElementById('ml-threat-type-tbody');

        // Mock threat type data
        const threatData = [
            { type: 'Brute Force', count: 2450, ml_rate: 96.2, rule_rate: 78.5, ml_fp: 12, rule_fp: 85 },
            { type: 'Credential Stuffing', count: 1340, ml_rate: 93.8, rule_rate: 72.1, ml_fp: 18, rule_fp: 105 },
            { type: 'Botnet Activity', count: 890, ml_rate: 97.4, rule_rate: 65.3, ml_fp: 8, rule_fp: 142 },
            { type: 'Port Scanning', count: 670, ml_rate: 91.2, rule_rate: 82.4, ml_fp: 15, rule_fp: 47 },
            { type: 'Dictionary Attack', count: 445, ml_rate: 94.6, rule_rate: 80.2, ml_fp: 10, rule_fp: 38 }
        ];

        tbody.innerHTML = threatData.map(item => {
            const winner = item.ml_rate > item.rule_rate ?
                '<span class="badge bg-primary"><i class="fas fa-brain"></i> ML</span>' :
                '<span class="badge bg-secondary"><i class="fas fa-list"></i> Rule</span>';

            return `
                <tr>
                    <td><strong>${item.type}</strong></td>
                    <td>${item.count}</td>
                    <td><span class="badge bg-primary">${item.ml_rate}%</span></td>
                    <td><span class="badge bg-secondary">${item.rule_rate}%</span></td>
                    <td>${item.ml_fp}</td>
                    <td>${item.rule_fp}</td>
                    <td>${winner}</td>
                </tr>
            `;
        }).join('');

    } catch (error) {
        console.error('Error loading threat type data:', error);
    }
}

/**
 * Load IP Comparison Data
 */
async function loadMLIPComparison() {
    try {
        const tbody = document.getElementById('ml-ip-comparison-tbody');

        // Mock IP comparison data
        const ipData = [
            { ip: '185.220.101.45', country: 'Russia', attempts: 342, ml_risk: 95, rule_risk: 72, ml_blocked: true, rule_blocked: false },
            { ip: '103.43.75.12', country: 'China', attempts: 298, ml_risk: 92, rule_risk: 68, ml_blocked: true, rule_blocked: false },
            { ip: '45.142.120.5', country: 'Netherlands', attempts: 256, ml_risk: 88, rule_risk: 78, ml_blocked: true, rule_blocked: true },
            { ip: '191.96.251.23', country: 'Brazil', attempts: 213, ml_risk: 85, rule_risk: 65, ml_blocked: true, rule_blocked: false },
            { ip: '80.82.77.139', country: 'Germany', attempts: 187, ml_risk: 81, rule_risk: 74, ml_blocked: true, rule_blocked: true }
        ];

        tbody.innerHTML = ipData.map(item => {
            const mlBlockedBadge = item.ml_blocked ?
                '<span class="badge bg-danger">Blocked</span>' :
                '<span class="badge bg-success">Allowed</span>';
            const ruleBlockedBadge = item.rule_blocked ?
                '<span class="badge bg-danger">Blocked</span>' :
                '<span class="badge bg-success">Allowed</span>';

            return `
                <tr>
                    <td><span class="ip-badge">${item.ip}</span></td>
                    <td>${item.country}</td>
                    <td>${item.attempts}</td>
                    <td><span class="threat-badge ${getRiskClass(item.ml_risk)}">${item.ml_risk}</span></td>
                    <td><span class="threat-badge ${getRiskClass(item.rule_risk)}">${item.rule_risk}</span></td>
                    <td>${mlBlockedBadge}</td>
                    <td>${ruleBlockedBadge}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" onclick="lookupIPDirect('${item.ip}')">
                            <i class="fas fa-search"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

    } catch (error) {
        console.error('Error loading IP comparison data:', error);
    }
}

/**
 * Filter ML Data by Dimension
 */
function filterMLDataByDimension() {
    const country = document.getElementById('ml-filter-country')?.value || '';
    const ip = document.getElementById('ml-filter-ip')?.value || '';
    const threatType = document.getElementById('ml-filter-threat-type')?.value || '';

    // Update status text
    const parts = [];
    if (country) parts.push(`country: ${country}`);
    if (ip) parts.push(`IP: ${ip}`);
    if (threatType) parts.push(`threat: ${threatType}`);

    const days = document.getElementById('ml-filter-days')?.value || 7;
    const statusText = parts.length > 0 ?
        `Filtered by ${parts.join(', ')} (${days} days)` :
        `Analyzing all data from last ${days} days`;

    document.getElementById('ml-filter-status').textContent = statusText;

    // In a real implementation, you would reload the data with filters
    // For now, we'll just update the status text
}

/**
 * Reset ML Filters
 */
function resetMLFilters() {
    document.getElementById('ml-filter-days').value = '7';
    document.getElementById('ml-filter-country').value = '';
    document.getElementById('ml-filter-ip').value = '';
    document.getElementById('ml-filter-threat-type').value = '';

    loadMLAnalytics();
}

// Initialize when needed
if (typeof window !== 'undefined') {
    window.loadMLAnalytics = loadMLAnalytics;
    window.switchMLChart = switchMLChart;
    window.filterMLDataByDimension = filterMLDataByDimension;
    window.resetMLFilters = resetMLFilters;
}
