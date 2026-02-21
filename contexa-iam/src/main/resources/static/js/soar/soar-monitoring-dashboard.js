/**
 * SOAR Monitoring Dashboard
 * 
 * Real-time session monitoring with health indicators,
 * performance metrics, and resource usage tracking
 */
class SoarMonitoringDashboard {
    constructor(containerId = 'monitoringDashboard') {
        this.containerId = containerId;
        this.container = null;
        this.updateInterval = null;
        this.charts = {};
        this.metrics = {
            sessionHealth: 100,
            apiLatency: [],
            errorRate: 0,
            throughput: 0,
            activeConnections: 0,
            memoryUsage: 0,
            cpuUsage: 0
        };
        
        this.initialize();
    }

    /**
     * Initialize the dashboard
     */
    initialize() {
        this.createStyles();
        this.createDashboardContainer();
        this.render();
        this.startMonitoring();
    }

    /**
     * Create dashboard styles
     */
    createStyles() {
        if (document.getElementById('monitoring-dashboard-styles')) return;

        const styles = `
            .monitoring-dashboard-overlay {
                position: fixed;
                top: 0;
                right: -400px;
                width: 400px;
                height: 100vh;
                background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
                border-left: 1px solid rgba(71, 85, 105, 0.3);
                z-index: 9999;
                transition: right 0.3s ease-in-out;
                overflow-y: auto;
            }

            .monitoring-dashboard-overlay.show {
                right: 0;
            }

            .monitoring-dashboard {
                padding: 1.5rem;
                height: 100%;
                display: flex;
                flex-direction: column;
            }

            .monitoring-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1.5rem;
                padding-bottom: 1rem;
                border-bottom: 1px solid rgba(71, 85, 105, 0.3);
            }

            .monitoring-title {
                font-size: 1.25rem;
                font-weight: 700;
                color: #f1f5f9;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .monitoring-close-btn {
                background: none;
                border: none;
                color: #94a3b8;
                font-size: 1.25rem;
                cursor: pointer;
                transition: color 0.3s ease;
            }

            .monitoring-close-btn:hover {
                color: #f1f5f9;
            }

            .monitoring-section {
                margin-bottom: 1.5rem;
            }

            .monitoring-section-title {
                color: #cbd5e1;
                font-size: 0.875rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 1rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .health-indicator {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 1rem;
                background: rgba(15, 23, 42, 0.8);
                border-radius: 0.75rem;
                border: 1px solid rgba(71, 85, 105, 0.3);
                margin-bottom: 0.75rem;
            }

            .health-label {
                color: #94a3b8;
                font-size: 0.875rem;
            }

            .health-value {
                font-size: 1.25rem;
                font-weight: 700;
            }

            .health-value.good { color: #22c55e; }
            .health-value.warning { color: #facc15; }
            .health-value.error { color: #ef4444; }

            .metric-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 0.75rem;
            }

            .metric-card {
                background: rgba(15, 23, 42, 0.8);
                padding: 1rem;
                border-radius: 0.75rem;
                border: 1px solid rgba(71, 85, 105, 0.3);
            }

            .metric-label {
                color: #94a3b8;
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 0.5rem;
            }

            .metric-value {
                color: #e2e8f0;
                font-size: 1.5rem;
                font-weight: 700;
            }

            .metric-trend {
                display: flex;
                align-items: center;
                gap: 0.25rem;
                margin-top: 0.25rem;
                font-size: 0.75rem;
            }

            .metric-trend.up { color: #22c55e; }
            .metric-trend.down { color: #ef4444; }
            .metric-trend.stable { color: #94a3b8; }

            .server-status-list {
                display: flex;
                flex-direction: column;
                gap: 0.5rem;
            }

            .server-status-item {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 0.75rem;
                background: rgba(15, 23, 42, 0.8);
                border-radius: 0.5rem;
                border: 1px solid rgba(71, 85, 105, 0.3);
            }

            .server-name {
                color: #e2e8f0;
                font-size: 0.875rem;
                font-weight: 600;
            }

            .server-status {
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .status-indicator {
                width: 8px;
                height: 8px;
                border-radius: 50%;
            }

            .status-indicator.online {
                background: #22c55e;
                animation: pulse 2s infinite;
            }

            .status-indicator.offline {
                background: #6b7280;
            }

            .status-indicator.error {
                background: #ef4444;
                animation: pulse 1s infinite;
            }

            .latency-chart {
                height: 150px;
                background: rgba(15, 23, 42, 0.8);
                border-radius: 0.75rem;
                border: 1px solid rgba(71, 85, 105, 0.3);
                padding: 1rem;
                position: relative;
                overflow: hidden;
            }

            .latency-bars {
                display: flex;
                align-items: flex-end;
                height: 100%;
                gap: 2px;
            }

            .latency-bar {
                flex: 1;
                background: linear-gradient(180deg, #6366f1, #8b5cf6);
                border-radius: 2px 2px 0 0;
                transition: height 0.3s ease;
            }

            .alert-list {
                max-height: 200px;
                overflow-y: auto;
            }

            .alert-item {
                padding: 0.75rem;
                background: rgba(15, 23, 42, 0.8);
                border-radius: 0.5rem;
                border-left: 3px solid;
                margin-bottom: 0.5rem;
                font-size: 0.875rem;
            }

            .alert-item.info {
                border-color: #3b82f6;
                background: rgba(59, 130, 246, 0.1);
            }

            .alert-item.warning {
                border-color: #facc15;
                background: rgba(250, 204, 21, 0.1);
            }

            .alert-item.error {
                border-color: #ef4444;
                background: rgba(239, 68, 68, 0.1);
            }

            .alert-time {
                color: #94a3b8;
                font-size: 0.7rem;
                margin-top: 0.25rem;
            }

            .monitoring-toggle-btn {
                position: fixed;
                right: 20px;
                bottom: 20px;
                width: 60px;
                height: 60px;
                border-radius: 50%;
                background: linear-gradient(135deg, #6366f1, #8b5cf6);
                border: none;
                color: white;
                font-size: 1.5rem;
                cursor: pointer;
                box-shadow: 0 10px 25px rgba(99, 102, 241, 0.3);
                transition: all 0.3s ease;
                z-index: 9998;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .monitoring-toggle-btn:hover {
                transform: scale(1.1);
                box-shadow: 0 15px 35px rgba(99, 102, 241, 0.4);
            }

            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }

            .resource-usage-bar {
                height: 8px;
                background: rgba(71, 85, 105, 0.3);
                border-radius: 4px;
                overflow: hidden;
                margin-top: 0.5rem;
            }

            .resource-usage-fill {
                height: 100%;
                border-radius: 4px;
                transition: width 0.3s ease;
            }

            .resource-usage-fill.low {
                background: linear-gradient(90deg, #22c55e, #16a34a);
            }

            .resource-usage-fill.medium {
                background: linear-gradient(90deg, #facc15, #f59e0b);
            }

            .resource-usage-fill.high {
                background: linear-gradient(90deg, #ef4444, #dc2626);
            }
        `;

        const styleSheet = document.createElement('style');
        styleSheet.id = 'monitoring-dashboard-styles';
        styleSheet.textContent = styles;
        document.head.appendChild(styleSheet);
    }

    /**
     * Create dashboard container
     */
    createDashboardContainer() {
        // Create toggle button
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'monitoring-toggle-btn';
        toggleBtn.innerHTML = '<i class="fas fa-chart-line"></i>';
        toggleBtn.onclick = () => this.toggle();
        document.body.appendChild(toggleBtn);

        // Create dashboard overlay
        const overlay = document.createElement('div');
        overlay.id = this.containerId;
        overlay.className = 'monitoring-dashboard-overlay';
        document.body.appendChild(overlay);
        
        this.container = overlay;
    }

    /**
     * Render dashboard
     */
    render() {
        const html = `
            <div class="monitoring-dashboard">
                <div class="monitoring-header">
                    <h3 class="monitoring-title">
                        <i class="fas fa-tachometer-alt"></i>
                        실시간 모니터링
                    </h3>
                    <button class="monitoring-close-btn" onclick="window.soarMonitoring.hide()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>

                <!-- Session Health -->
                <div class="monitoring-section">
                    <div class="monitoring-section-title">
                        <i class="fas fa-heartbeat"></i>
                        세션 상태
                    </div>
                    <div class="health-indicator">
                        <span class="health-label">전체 상태</span>
                        <span class="health-value good" id="session-health">100%</span>
                    </div>
                </div>

                <!-- Performance Metrics -->
                <div class="monitoring-section">
                    <div class="monitoring-section-title">
                        <i class="fas fa-chart-bar"></i>
                        성능 메트릭
                    </div>
                    <div class="metric-grid">
                        <div class="metric-card">
                            <div class="metric-label">API 지연시간</div>
                            <div class="metric-value" id="api-latency">0ms</div>
                            <div class="metric-trend stable" id="latency-trend">
                                <i class="fas fa-minus"></i> 안정
                            </div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-label">오류율</div>
                            <div class="metric-value" id="error-rate">0%</div>
                            <div class="metric-trend stable" id="error-trend">
                                <i class="fas fa-minus"></i> 정상
                            </div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-label">처리량</div>
                            <div class="metric-value" id="throughput">0/s</div>
                            <div class="metric-trend stable" id="throughput-trend">
                                <i class="fas fa-minus"></i> 안정
                            </div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-label">연결 수</div>
                            <div class="metric-value" id="connections">0</div>
                            <div class="metric-trend stable" id="connection-trend">
                                <i class="fas fa-minus"></i> 정상
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Latency Chart -->
                <div class="monitoring-section">
                    <div class="monitoring-section-title">
                        <i class="fas fa-signal"></i>
                        지연시간 추이
                    </div>
                    <div class="latency-chart">
                        <div class="latency-bars" id="latency-bars"></div>
                    </div>
                </div>

                <!-- MCP Server Status -->
                <div class="monitoring-section">
                    <div class="monitoring-section-title">
                        <i class="fas fa-server"></i>
                        MCP 서버 상태
                    </div>
                    <div class="server-status-list">
                        <div class="server-status-item">
                            <span class="server-name">Context7</span>
                            <div class="server-status">
                                <span class="status-text" id="context7-status">온라인</span>
                                <span class="status-indicator online" id="context7-indicator"></span>
                            </div>
                        </div>
                        <div class="server-status-item">
                            <span class="server-name">Sequential</span>
                            <div class="server-status">
                                <span class="status-text" id="sequential-status">온라인</span>
                                <span class="status-indicator online" id="sequential-indicator"></span>
                            </div>
                        </div>
                        <div class="server-status-item">
                            <span class="server-name">Magic</span>
                            <div class="server-status">
                                <span class="status-text" id="magic-status">오프라인</span>
                                <span class="status-indicator offline" id="magic-indicator"></span>
                            </div>
                        </div>
                        <div class="server-status-item">
                            <span class="server-name">Playwright</span>
                            <div class="server-status">
                                <span class="status-text" id="playwright-status">오프라인</span>
                                <span class="status-indicator offline" id="playwright-indicator"></span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Resource Usage -->
                <div class="monitoring-section">
                    <div class="monitoring-section-title">
                        <i class="fas fa-microchip"></i>
                        리소스 사용량
                    </div>
                    <div class="health-indicator">
                        <span class="health-label">메모리</span>
                        <span class="health-value" id="memory-usage">0%</span>
                    </div>
                    <div class="resource-usage-bar">
                        <div class="resource-usage-fill low" id="memory-bar" style="width: 0%"></div>
                    </div>
                    <div class="health-indicator" style="margin-top: 1rem;">
                        <span class="health-label">CPU</span>
                        <span class="health-value" id="cpu-usage">0%</span>
                    </div>
                    <div class="resource-usage-bar">
                        <div class="resource-usage-fill low" id="cpu-bar" style="width: 0%"></div>
                    </div>
                </div>

                <!-- Recent Alerts -->
                <div class="monitoring-section">
                    <div class="monitoring-section-title">
                        <i class="fas fa-bell"></i>
                        최근 알림
                    </div>
                    <div class="alert-list" id="alert-list">
                        <!-- Alerts will be added dynamically -->
                    </div>
                </div>
            </div>
        `;

        this.container.innerHTML = html;
        
        // Initialize latency chart
        this.initializeLatencyChart();
    }

    /**
     * Initialize latency chart
     */
    initializeLatencyChart() {
        const barsContainer = document.getElementById('latency-bars');
        if (!barsContainer) return;

        // Create 20 bars for latency history
        for (let i = 0; i < 20; i++) {
            const bar = document.createElement('div');
            bar.className = 'latency-bar';
            bar.style.height = '0%';
            barsContainer.appendChild(bar);
        }
    }

    /**
     * Start monitoring
     */
    startMonitoring() {
        this.updateInterval = setInterval(() => {
            this.updateMetrics();
        }, 2000); // Update every 2 seconds
    }

    /**
     * Stop monitoring
     */
    stopMonitoring() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
        }
    }

    /**
     * Update metrics
     */
    updateMetrics() {
        // Simulate metric updates (in real app, fetch from server)
        this.updateSessionHealth();
        this.updatePerformanceMetrics();
        this.updateLatencyChart();
        this.updateResourceUsage();
        this.checkForAlerts();
    }

    /**
     * Update session health
     */
    updateSessionHealth() {
        // Calculate health based on various factors
        let health = 100;
        
        if (this.metrics.errorRate > 5) health -= 20;
        if (this.metrics.errorRate > 10) health -= 30;
        if (this.metrics.apiLatency.length > 0) {
            const avgLatency = this.metrics.apiLatency.reduce((a, b) => a + b, 0) / this.metrics.apiLatency.length;
            if (avgLatency > 1000) health -= 10;
            if (avgLatency > 2000) health -= 20;
        }
        
        this.metrics.sessionHealth = Math.max(0, health);
        
        const healthEl = document.getElementById('session-health');
        if (healthEl) {
            healthEl.textContent = `${this.metrics.sessionHealth}%`;
            healthEl.className = health > 70 ? 'health-value good' : 
                               health > 40 ? 'health-value warning' : 
                               'health-value error';
        }
    }

    /**
     * Update performance metrics
     */
    updatePerformanceMetrics() {
        // Simulate API latency
        const newLatency = Math.random() * 500 + 50;
        this.metrics.apiLatency.push(newLatency);
        if (this.metrics.apiLatency.length > 20) {
            this.metrics.apiLatency.shift();
        }
        
        const avgLatency = this.metrics.apiLatency.reduce((a, b) => a + b, 0) / this.metrics.apiLatency.length;
        document.getElementById('api-latency').textContent = `${Math.round(avgLatency)}ms`;
        
        // Update error rate
        this.metrics.errorRate = Math.random() < 0.9 ? 0 : Math.random() * 5;
        document.getElementById('error-rate').textContent = `${this.metrics.errorRate.toFixed(1)}%`;
        
        // Update throughput
        this.metrics.throughput = Math.random() * 100;
        document.getElementById('throughput').textContent = `${Math.round(this.metrics.throughput)}/s`;
        
        // Update connections
        this.metrics.activeConnections = Math.floor(Math.random() * 10) + 1;
        document.getElementById('connections').textContent = this.metrics.activeConnections;
        
        // Update trends
        this.updateTrends();
    }

    /**
     * Update trends
     */
    updateTrends() {
        // Latency trend
        const latencyTrend = document.getElementById('latency-trend');
        if (this.metrics.apiLatency.length > 1) {
            const recent = this.metrics.apiLatency.slice(-5);
            const older = this.metrics.apiLatency.slice(-10, -5);
            const recentAvg = recent.reduce((a, b) => a + b, 0) / recent.length;
            const olderAvg = older.length > 0 ? older.reduce((a, b) => a + b, 0) / older.length : recentAvg;
            
            if (recentAvg > olderAvg * 1.2) {
                latencyTrend.className = 'metric-trend up';
                latencyTrend.innerHTML = '<i class="fas fa-arrow-up"></i> 증가';
            } else if (recentAvg < olderAvg * 0.8) {
                latencyTrend.className = 'metric-trend down';
                latencyTrend.innerHTML = '<i class="fas fa-arrow-down"></i> 감소';
            } else {
                latencyTrend.className = 'metric-trend stable';
                latencyTrend.innerHTML = '<i class="fas fa-minus"></i> 안정';
            }
        }
    }

    /**
     * Update latency chart
     */
    updateLatencyChart() {
        const bars = document.querySelectorAll('.latency-bar');
        const maxLatency = Math.max(...this.metrics.apiLatency, 1);
        
        this.metrics.apiLatency.forEach((latency, index) => {
            if (bars[index]) {
                const height = (latency / maxLatency) * 100;
                bars[index].style.height = `${height}%`;
            }
        });
    }

    /**
     * Update resource usage
     */
    updateResourceUsage() {
        // Simulate resource usage
        this.metrics.memoryUsage = Math.random() * 100;
        this.metrics.cpuUsage = Math.random() * 100;
        
        // Update memory
        document.getElementById('memory-usage').textContent = `${Math.round(this.metrics.memoryUsage)}%`;
        const memoryBar = document.getElementById('memory-bar');
        memoryBar.style.width = `${this.metrics.memoryUsage}%`;
        memoryBar.className = `resource-usage-fill ${
            this.metrics.memoryUsage < 50 ? 'low' : 
            this.metrics.memoryUsage < 80 ? 'medium' : 'high'
        }`;
        
        // Update CPU
        document.getElementById('cpu-usage').textContent = `${Math.round(this.metrics.cpuUsage)}%`;
        const cpuBar = document.getElementById('cpu-bar');
        cpuBar.style.width = `${this.metrics.cpuUsage}%`;
        cpuBar.className = `resource-usage-fill ${
            this.metrics.cpuUsage < 50 ? 'low' : 
            this.metrics.cpuUsage < 80 ? 'medium' : 'high'
        }`;
    }

    /**
     * Check for alerts
     */
    checkForAlerts() {
        const alerts = [];
        
        if (this.metrics.errorRate > 5) {
            alerts.push({
                type: 'warning',
                message: `오류율이 ${this.metrics.errorRate.toFixed(1)}%로 증가했습니다`,
                time: new Date()
            });
        }
        
        if (this.metrics.memoryUsage > 80) {
            alerts.push({
                type: 'error',
                message: `메모리 사용량이 ${Math.round(this.metrics.memoryUsage)}%입니다`,
                time: new Date()
            });
        }
        
        if (alerts.length > 0) {
            this.addAlerts(alerts);
        }
    }

    /**
     * Add alerts
     */
    addAlerts(alerts) {
        const alertList = document.getElementById('alert-list');
        if (!alertList) return;
        
        alerts.forEach(alert => {
            const alertEl = document.createElement('div');
            alertEl.className = `alert-item ${alert.type}`;
            alertEl.innerHTML = `
                <div>${alert.message}</div>
                <div class="alert-time">${alert.time.toLocaleTimeString()}</div>
            `;
            
            alertList.insertBefore(alertEl, alertList.firstChild);
            
            // Keep only last 10 alerts
            while (alertList.children.length > 10) {
                alertList.removeChild(alertList.lastChild);
            }
        });
    }

    /**
     * Update MCP server status
     */
    updateMcpStatus(status) {
        const servers = ['context7', 'sequential', 'magic', 'playwright'];
        
        servers.forEach(server => {
            const isOnline = status[server] || false;
            const statusText = document.getElementById(`${server}-status`);
            const indicator = document.getElementById(`${server}-indicator`);
            
            if (statusText && indicator) {
                statusText.textContent = isOnline ? '온라인' : '오프라인';
                indicator.className = `status-indicator ${isOnline ? 'online' : 'offline'}`;
            }
        });
    }

    /**
     * Toggle dashboard visibility
     */
    toggle() {
        if (this.container.classList.contains('show')) {
            this.hide();
        } else {
            this.show();
        }
    }

    /**
     * Show dashboard
     */
    show() {
        this.container.classList.add('show');
        this.startMonitoring();
    }

    /**
     * Hide dashboard
     */
    hide() {
        this.container.classList.remove('show');
        this.stopMonitoring();
    }

    /**
     * Get current metrics
     */
    getMetrics() {
        return { ...this.metrics };
    }
}

// Create global instance for easy access
window.soarMonitoring = new SoarMonitoringDashboard();

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SoarMonitoringDashboard;
}

// Make available globally for browser environment
if (typeof window !== 'undefined') {
    window.SoarMonitoringDashboard = SoarMonitoringDashboard;
}