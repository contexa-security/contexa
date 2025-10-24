/**
 * 🧠 AI 사용자 행동 패턴 학습 시스템 - Enhanced JavaScript
 * Vector DB + LLM 기반 실시간 행동 분석
 */

document.addEventListener('DOMContentLoaded', function() {
    // 전역 상태 관리
    const state = {
        activeTab: 'realtime',
        stats: null,
        realtimeMonitoring: {
            isActive: false,
            eventSource: null,
            data: []
        },
        charts: {},
        analysisInProgress: false
    };

    // DOM 요소 캐싱
    const elements = {
        tabs: document.querySelectorAll('#behavior-tabs .nav-link'),
        tabPanes: document.querySelectorAll('.tab-pane'),
        refreshBtn: document.getElementById('refresh-stats'),
        // 통계 카드
        totalUsers: document.getElementById('total-users'),
        activeUsers: document.getElementById('active-users'),
        anomaliesDetected: document.getElementById('anomalies-detected'),
        highRiskEvents: document.getElementById('high-risk-events'),
        // 실시간 모니터링
        toggleMonitoringBtn: document.getElementById('toggle-monitoring'),
        realtimeStream: document.getElementById('realtime-stream'),
        // 개별 분석
        analysisForm: document.getElementById('analysis-form'),
        analysisResult: document.getElementById('analysis-result'),
        analysisLoading: document.getElementById('analysis-loading'),
        analysisContent: document.getElementById('analysis-content'),
        streamingLog: document.getElementById('streaming-log'),
        // 설정
        dynamicPermissionForm: document.getElementById('dynamic-permission-form'),
        triggerBatchLearningBtn: document.getElementById('trigger-batch-learning')
    };

    // 초기화
    init();

    function init() {
        bindEventListeners();
        loadDashboardStats();
        initCharts();

        // 30초마다 통계 자동 갱신
        setInterval(loadDashboardStats, 30000);
    }

    // 이벤트 리스너 바인딩
    function bindEventListeners() {
        // 탭 전환
        elements.tabs.forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                switchTab(e.target.closest('.nav-link').dataset.tab);
            });
        });

        // 새로고침 버튼
        elements.refreshBtn.addEventListener('click', loadDashboardStats);

        // 실시간 모니터링 토글
        elements.toggleMonitoringBtn.addEventListener('click', toggleRealtimeMonitoring);

        // 개별 분석 폼
        elements.analysisForm.addEventListener('submit', handleAnalysisSubmit);

        // 동적 권한 규칙 폼
        elements.dynamicPermissionForm.addEventListener('submit', handleDynamicPermissionSubmit);

        // 배치 학습 트리거
        elements.triggerBatchLearningBtn.addEventListener('click', triggerBatchLearning);
    }

    // 탭 전환
    function switchTab(tabName) {
        state.activeTab = tabName;

        // 탭 활성화 상태 업데이트
        elements.tabs.forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabName);
        });

        // 탭 컨텐츠 표시/숨김
        elements.tabPanes.forEach(pane => {
            pane.classList.toggle('active', pane.id === `${tabName}-tab`);
        });

        // 탭별 초기화
        if (tabName === 'statistics') {
            updateStatisticsCharts();
        }
    }

    // 대시보드 통계 로드
    async function loadDashboardStats() {
        try {
            const response = await fetch('/api/ai/behavior-analysis/dashboard/stats?days=7');
            if (!response.ok) throw new Error('통계 로드 실패');

            state.stats = await response.json();
            updateStatsDisplay();
            updateCharts();

        } catch (error) {
            console.error('통계 로드 오류:', error);
            showToast('통계 데이터를 불러올 수 없습니다', 'error');
        }
    }

    // 통계 카드 업데이트
    function updateStatsDisplay() {
        if (!state.stats) return;

        elements.totalUsers.textContent = state.stats.totalUsers || '0';
        elements.activeUsers.textContent = state.stats.activeUsersToday || '0';
        elements.anomaliesDetected.textContent = state.stats.anomaliesDetected || '0';

        // 고위험 이벤트 수 계산
        const highRiskCount = state.stats.recentHighRiskEvents?.length || 0;
        elements.highRiskEvents.textContent = highRiskCount;

        // 고위험 이벤트 테이블 업데이트
        updateHighRiskEventsTable(state.stats.recentHighRiskEvents);
    }

    // 고위험 이벤트 테이블 업데이트
    function updateHighRiskEventsTable(events) {
        const tbody = document.querySelector('#high-risk-events-table tbody');

        if (!events || events.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">고위험 이벤트가 없습니다</td></tr>';
            return;
        }

        tbody.innerHTML = events.map(event => `
            <tr>
                <td>${formatDateTime(event.timestamp)}</td>
                <td><span class="badge badge-secondary">${event.userId}</span></td>
                <td>${event.activity}</td>
                <td><span class="badge badge-danger">${event.riskScore.toFixed(1)}</span></td>
                <td><span class="badge badge-warning">검토 필요</span></td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="analyzeUser('${event.userId}')">
                        <i class="fas fa-search"></i> 분석
                    </button>
                </td>
            </tr>
        `).join('');
    }

    // 차트 초기화
    function initCharts() {
        // 위험 수준 분포 차트
        const riskCtx = document.getElementById('risk-distribution-chart').getContext('2d');
        state.charts.riskDistribution = new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['낮음', '중간', '높음', '심각'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#28a745', '#ffc107', '#fd7e14', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // 시간대별 이상 행동 차트
        const hourlyCtx = document.getElementById('hourly-anomaly-chart').getContext('2d');
        state.charts.hourlyAnomaly = new Chart(hourlyCtx, {
            type: 'bar',
            data: {
                labels: Array.from({length: 24}, (_, i) => `${i}시`),
                datasets: [{
                    label: '이상 행동 수',
                    data: new Array(24).fill(0),
                    backgroundColor: 'rgba(255, 99, 132, 0.5)',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // 차트 업데이트
    function updateCharts() {
        if (!state.stats) return;

        // 위험 수준 분포 업데이트
        if (state.stats.riskDistribution && state.charts.riskDistribution) {
            const dist = state.stats.riskDistribution;
            state.charts.riskDistribution.data.datasets[0].data = [
                dist.LOW || 0,
                dist.MEDIUM || 0,
                dist.HIGH || 0,
                dist.CRITICAL || 0
            ];
            state.charts.riskDistribution.update();
        }

        // 시간대별 이상 행동 업데이트
        if (state.stats.hourlyAnomalyTrend && state.charts.hourlyAnomaly) {
            const hourlyData = new Array(24).fill(0);
            state.stats.hourlyAnomalyTrend.forEach(item => {
                hourlyData[item.hour] = item.count;
            });
            state.charts.hourlyAnomaly.data.datasets[0].data = hourlyData;
            state.charts.hourlyAnomaly.update();
        }
    }

    // 실시간 모니터링 토글
    function toggleRealtimeMonitoring() {
        if (state.realtimeMonitoring.isActive) {
            stopRealtimeMonitoring();
        } else {
            startRealtimeMonitoring();
        }
    }

    // 실시간 모니터링 시작
    function startRealtimeMonitoring() {
        state.realtimeMonitoring.isActive = true;
        elements.toggleMonitoringBtn.innerHTML = '<i class="fas fa-stop"></i> 모니터링 중지';
        elements.toggleMonitoringBtn.classList.replace('btn-primary', 'btn-danger');

        // 초기 메시지 제거
        elements.realtimeStream.innerHTML = '';

        // SSE 연결
        state.realtimeMonitoring.eventSource = new EventSource('/api/ai/behavior-analysis/monitor/realtime');

        state.realtimeMonitoring.eventSource.onmessage = function(event) {
            const data = JSON.parse(event.data);
            addRealtimeEvent(data);
        };

        state.realtimeMonitoring.eventSource.onerror = function() {
            console.error('실시간 모니터링 연결 오류');
            stopRealtimeMonitoring();
            showToast('실시간 모니터링 연결이 끊어졌습니다', 'error');
        };
    }

    // 실시간 모니터링 중지
    function stopRealtimeMonitoring() {
        if (state.realtimeMonitoring.eventSource) {
            state.realtimeMonitoring.eventSource.close();
            state.realtimeMonitoring.eventSource = null;
        }

        state.realtimeMonitoring.isActive = false;
        elements.toggleMonitoringBtn.innerHTML = '<i class="fas fa-play"></i> 모니터링 시작';
        elements.toggleMonitoringBtn.classList.replace('btn-danger', 'btn-primary');
    }

    // 실시간 이벤트 추가
    function addRealtimeEvent(event) {
        const eventEl = document.createElement('div');
        eventEl.className = `realtime-event ${getRiskClass(event.riskLevel)}`;
        eventEl.innerHTML = `
            <div class="event-header">
                <span class="event-time">${formatTime(event.timestamp)}</span>
                <span class="event-user">${event.userId}</span>
                <span class="event-risk badge badge-${getRiskBadgeClass(event.riskLevel)}">${event.riskScore.toFixed(1)}</span>
            </div>
            <div class="event-content">
                <div class="event-activity">${event.activity}</div>
                ${event.anomalies ? `<div class="event-anomalies">${event.anomalies.join(', ')}</div>` : ''}
            </div>
        `;

        // 최신 이벤트를 위에 추가
        elements.realtimeStream.insertBefore(eventEl, elements.realtimeStream.firstChild);

        // 최대 100개만 유지
        while (elements.realtimeStream.children.length > 100) {
            elements.realtimeStream.removeChild(elements.realtimeStream.lastChild);
        }

        // 애니메이션 효과
        eventEl.classList.add('fade-in');
    }

    // 개별 분석 제출 처리
    async function handleAnalysisSubmit(e) {
        e.preventDefault();

        const userId = document.getElementById('analysis-user-id').value;
        if (!userId) return;

        // UI 상태 변경
        elements.analysisResult.style.display = 'block';
        elements.analysisLoading.style.display = 'block';
        elements.analysisContent.style.display = 'none';
        elements.streamingLog.textContent = '';

        try {
            const response = await fetch('/api/ai/behavior-analysis/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ userId: userId, stream: true })
            });

            if (!response.ok) {
                throw new Error(`서버 오류: ${response.status}`);
            }

            // SSE 스트리밍 처리
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });

                const finalResponseMarker = '###FINAL_RESPONSE###';
                if (buffer.includes(finalResponseMarker)) {
                    const parts = buffer.split(finalResponseMarker);
                    const streamingPart = parts[0];
                    const jsonPart = parts[1];

                    // 스트리밍 로그 표시
                    elements.streamingLog.textContent = streamingPart;

                    // 최종 결과 파싱 및 표시
                    const finalData = JSON.parse(jsonPart);
                    displayAnalysisResults(finalData);

                    buffer = '';
                    break;
                } else {
                    // 실시간 로그 업데이트
                    elements.streamingLog.textContent = buffer;
                }
            }

        } catch (error) {
            console.error('분석 실패:', error);
            showToast('분석 중 오류가 발생했습니다', 'error');
            elements.analysisLoading.style.display = 'none';
        }
    }

    // 분석 결과 표시
    function displayAnalysisResults(data) {
        elements.analysisLoading.style.display = 'none';
        elements.analysisContent.style.display = 'block';

        // 위험 점수 게이지
        document.getElementById('risk-score-gauge').innerHTML = createGauge(data.behavioralRiskScore);

        // 위험 수준
        const riskLevelEl = document.getElementById('risk-level');
        riskLevelEl.textContent = getRiskLevelText(data.riskLevel);
        riskLevelEl.className = `h3 mt-2 text-${getRiskLevelColor(data.riskLevel)}`;

        // AI 분석 요약
        document.getElementById('analysis-summary').textContent = data.summary;

        // 이상 징후 목록
        updateAnomaliesList(data.anomalies);

        // 권장 사항 목록
        updateRecommendationsList(data.recommendations);

        // 타임라인 차트
        if (window.timelineChart) {
            window.timelineChart.destroy();
        }
        window.timelineChart = createTimelineChart(data.visualizationData.events);
    }

    // 이상 징후 목록 업데이트
    function updateAnomaliesList(anomalies) {
        const listEl = document.getElementById('anomalies-list');

        if (!anomalies || anomalies.length === 0) {
            listEl.innerHTML = '<li class="list-group-item">탐지된 이상 징후가 없습니다</li>';
            return;
        }

        listEl.innerHTML = anomalies.map(anomaly => `
            <li class="list-group-item">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">${getAnomalyTypeText(anomaly.type)}</h6>
                    <small class="text-danger">${formatDateTime(anomaly.timestamp)}</small>
                </div>
                <p class="mb-1">${anomaly.description}</p>
                <small>위험 기여도: <span class="font-weight-bold">${anomaly.riskContribution.toFixed(1)}점</span></small>
            </li>
        `).join('');
    }

    // 권장 사항 목록 업데이트
    function updateRecommendationsList(recommendations) {
        const listEl = document.getElementById('recommendations-list');

        if (!recommendations || recommendations.length === 0) {
            listEl.innerHTML = '<li class="list-group-item">권장 사항이 없습니다</li>';
            return;
        }

        listEl.innerHTML = recommendations.map(rec => `
            <li class="list-group-item">
                <h6>${getPriorityIcon(rec.priority)} ${rec.action}</h6>
                <small class="text-muted">${rec.reason}</small>
            </li>
        `).join('');
    }

    // 타임라인 차트 생성
    function createTimelineChart(events) {
        const ctx = document.getElementById('behavior-timeline-chart').getContext('2d');

        const data = {
            datasets: [{
                label: '정상 활동',
                data: events.filter(e => !e.isAnomaly).map(e => ({
                    x: new Date(e.timestamp),
                    y: 1,
                    description: e.description
                })),
                backgroundColor: 'rgba(0, 123, 255, 0.6)',
                borderColor: 'rgba(0, 123, 255, 1)',
                pointRadius: 5
            }, {
                label: '이상 활동',
                data: events.filter(e => e.isAnomaly).map(e => ({
                    x: new Date(e.timestamp),
                    y: 1,
                    description: e.description
                })),
                backgroundColor: 'rgba(220, 53, 69, 0.8)',
                borderColor: 'rgba(220, 53, 69, 1)',
                pointRadius: 8
            }]
        };

        return new Chart(ctx, {
            type: 'scatter',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        type: 'time',
                        time: {
                            unit: 'hour',
                            tooltipFormat: 'yyyy-MM-dd HH:mm:ss'
                        },
                        title: { display: true, text: '시간' }
                    },
                    y: {
                        display: false,
                        min: 0,
                        max: 2
                    }
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.raw.description;
                            }
                        }
                    }
                }
            }
        });
    }

    // 동적 권한 규칙 제출
    async function handleDynamicPermissionSubmit(e) {
        e.preventDefault();

        const formData = {
            conditionExpression: document.getElementById('condition-expression').value,
            applicableTo: document.getElementById('applicable-to').value,
            permissionAdjustment: document.getElementById('permission-adjustment').value,
            description: document.getElementById('rule-description').value
        };

        try {
            const response = await fetch('/api/ai/behavior-analysis/dynamic-permissions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });

            if (!response.ok) throw new Error('규칙 저장 실패');

            showToast('동적 권한 규칙이 저장되었습니다', 'success');
            e.target.reset();
            loadActiveRules();

        } catch (error) {
            console.error('규칙 저장 오류:', error);
            showToast('규칙 저장에 실패했습니다', 'error');
        }
    }

    // 배치 학습 트리거
    async function triggerBatchLearning() {
        if (!confirm('배치 학습을 시작하시겠습니까? 시간이 오래 걸릴 수 있습니다.')) {
            return;
        }

        elements.triggerBatchLearningBtn.disabled = true;
        elements.triggerBatchLearningBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 학습 중...';

        try {
            const response = await fetch('/api/ai/behavior-analysis/batch-learning/trigger', {
                method: 'POST'
            });

            if (!response.ok) throw new Error('배치 학습 시작 실패');

            showToast('배치 학습이 시작되었습니다', 'success');

        } catch (error) {
            console.error('배치 학습 오류:', error);
            showToast('배치 학습 시작에 실패했습니다', 'error');
        } finally {
            elements.triggerBatchLearningBtn.disabled = false;
            elements.triggerBatchLearningBtn.innerHTML = '<i class="fas fa-play"></i> 수동 배치 학습 시작';
        }
    }

    // 유틸리티 함수들
    function createGauge(score) {
        const percentage = score / 100;
        const dashArray = 2 * Math.PI * 45;
        const dashOffset = dashArray * (1 - percentage);
        const color = score > 70 ? '#dc3545' : score > 40 ? '#ffc107' : '#28a745';

        return `
            <svg viewBox="0 0 100 55" class="gauge">
                <path class="gauge-bg" d="M10 50 A 40 40 0 0 1 90 50"></path>
                <path class="gauge-bar" d="M10 50 A 40 40 0 0 1 90 50" 
                      style="stroke: ${color}; stroke-dasharray: ${dashArray}; stroke-dashoffset: ${dashOffset};"></path>
                <text x="50" y="40" class="gauge-text">${score.toFixed(1)}</text>
            </svg>
        `;
    }

    function getRiskLevelText(level) {
        const levels = { 'LOW': '낮음', 'MEDIUM': '중간', 'HIGH': '높음', 'CRITICAL': '심각' };
        return levels[level] || '알 수 없음';
    }

    function getRiskLevelColor(level) {
        const colors = { 'LOW': 'success', 'MEDIUM': 'warning', 'HIGH': 'danger', 'CRITICAL': 'dark' };
        return colors[level] || 'secondary';
    }

    function getRiskClass(level) {
        const classes = { 'LOW': 'risk-low', 'MEDIUM': 'risk-medium', 'HIGH': 'risk-high', 'CRITICAL': 'risk-critical' };
        return classes[level] || '';
    }

    function getRiskBadgeClass(level) {
        const classes = { 'LOW': 'success', 'MEDIUM': 'warning', 'HIGH': 'danger', 'CRITICAL': 'dark' };
        return classes[level] || 'secondary';
    }

    function getAnomalyTypeText(type) {
        const types = {
            'UNUSUAL_LOGIN_TIME': '비정상 시간 로그인',
            'UNUSUAL_IP': '비정상 IP 접근',
            'ABNORMAL_RESOURCE_ACCESS': '비정상 리소스 접근'
        };
        return types[type] || type;
    }

    function getPriorityIcon(priority) {
        const icons = {
            'LOW': '<i class="fas fa-info-circle text-info"></i>',
            'MEDIUM': '<i class="fas fa-exclamation-circle text-warning"></i>',
            'HIGH': '<i class="fas fa-exclamation-triangle text-danger"></i>'
        };
        return icons[priority] || '';
    }

    function formatDateTime(timestamp) {
        return new Date(timestamp).toLocaleString('ko-KR');
    }

    function formatTime(timestamp) {
        return new Date(timestamp).toLocaleTimeString('ko-KR');
    }

    function showToast(message, type = 'info') {
        // 기존 toast 함수가 있다면 사용, 없다면 console로 대체
        if (typeof window.showToast === 'function') {
            window.showToast(message, type);
        } else {
            console.log(`[${type.toUpperCase()}] ${message}`);
        }
    }

    // 전역 함수로 노출 (HTML에서 직접 호출용)
    window.analyzeUser = function(userId) {
        document.getElementById('analysis-user-id').value = userId;
        switchTab('analysis');
        elements.analysisForm.dispatchEvent(new Event('submit'));
    };
});