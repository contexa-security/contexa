/**
 * ============================================================================
 * Contexa AI Native Zero Trust Security Platform - Zero Trust Demo
 * ============================================================================
 *
 * security-test.js 기반 확장.
 * Timeline을 모달 안으로 이동하여 실시간 서버 상황을 시각화.
 *
 * 아키텍처:
 * ColdPathEventProcessor -> LlmAnalysisEventListener -> SSE -> Client
 *
 * SSE 이벤트 유형:
 * - CONTEXT_COLLECTED, LAYER1_START, LAYER1_COMPLETE
 * - LAYER2_START, LAYER2_COMPLETE, DECISION_APPLIED
 * - RESPONSE_BLOCKED, ERROR
 */

'use strict';

(function() {

    const API = {
        SSE_ENDPOINT: '/api/sse/llm-analysis',
        ACTION_STATUS: '/api/test-action/status',
        ACTION_RESET: '/api/test-action/reset',
        TEST_SENSITIVE: '/api/security-test/sensitive/',
        BULK_STREAM: '/api/security-test/bulk-stream'
    };

    const SCENARIO_HEADERS = {
        'NORMAL_USER': { 'X-Forwarded-For': '192.168.1.100' },
        'ACCOUNT_TAKEOVER': { 'X-Forwarded-For': '203.0.113.50' },
        'DATA_EXFILTRATION': { 'X-Forwarded-For': '10.0.0.99' }
    };

    const SCENARIO_INFO = {
        'NORMAL_USER': { name: '정상 사용자', ip: '192.168.1.100' },
        'ACCOUNT_TAKEOVER': { name: '계정 탈취', ip: '203.0.113.50' },
        'DATA_EXFILTRATION': { name: '데이터 유출 공격', ip: '10.0.0.99' }
    };

    const ACTION_STYLES = {
        'ALLOW': { class: 'action-ALLOW' },
        'BLOCK': { class: 'action-BLOCK' },
        'CHALLENGE': { class: 'action-CHALLENGE' },
        'ESCALATE': { class: 'action-ESCALATE' },
        'PENDING': { class: 'action-PENDING' }
    };

    const ACTION_LABELS = {
        'ALLOW': '승인', 'BLOCK': '차단', 'CHALLENGE': '2차 승인 필요',
        'ESCALATE': '에스컬레이션', 'PENDING': '대기', 'PENDING_ANALYSIS': '분석 대기'
    };

    // ========================================================================
    // State
    // ========================================================================
    const state = {
        selectedScenario: null,
        currentAction: 'PENDING',
        riskScore: 0.0,
        confidence: 0.0,
        mitre: null,
        reasoning: null,
        isTestRunning: false,
        sseConnected: false,
        eventSource: null,
        analysisPhase: 'idle',
        activeTab: 'test1',
        t2SelectedScenario: null
    };

    let elements = {};

    // ========================================================================
    // DOM Elements
    // ========================================================================
    function initializeElements() {
        elements = {
            sseIndicator: document.getElementById('sse-indicator'),
            sseText: document.getElementById('sse-text'),

            stepContext: document.getElementById('m-step-context'),
            stepLayer1: document.getElementById('m-step-layer1'),
            stepLayer2: document.getElementById('m-step-layer2'),
            stepDecision: document.getElementById('m-step-decision'),
            layer2Arrow: document.querySelector('.m-layer2-arrow'),

            currentActionBadge: document.getElementById('current-action-badge'),
            riskFill: document.getElementById('risk-fill'),
            riskValue: document.getElementById('risk-value'),
            confidenceFill: document.getElementById('confidence-fill'),
            confidenceValue: document.getElementById('confidence-value'),
            mitreDisplay: document.getElementById('mitre-display'),
            mitreValue: document.getElementById('mitre-value'),
            reasoningDisplay: document.getElementById('reasoning-display'),
            reasoningText: document.getElementById('reasoning-text'),

            btnTestAccess: document.getElementById('btn-test-access'),
            btnTestBulkStream: document.getElementById('btn-test-bulk-stream'),
            reloadActionBtn: document.getElementById('reload-action-btn'),

            // Modal
            modalOverlay: document.getElementById('analysis-modal'),
            modalTitle: document.getElementById('modal-title'),
            modalScenarioLabel: document.getElementById('modal-scenario-label'),
            modalLogContainer: document.getElementById('m-log-container'),
            modalCloseX: document.getElementById('modal-close-x'),
            modalCloseBtn: document.getElementById('modal-close-btn'),
            modalResultArea: document.getElementById('m-result-area'),
            modalFinal: document.getElementById('m-final'),
            modalFinalBadge: document.getElementById('m-final-badge'),
            modalFinalIcon: document.getElementById('m-final-icon'),
            modalFinalText: document.getElementById('m-final-text'),
            mRiskFill: document.getElementById('m-risk-fill'),
            mRiskValue: document.getElementById('m-risk-value'),
            mConfFill: document.getElementById('m-conf-fill'),
            mConfValue: document.getElementById('m-conf-value'),

            // Test 2
            t2ProgressBar: document.getElementById('t2-progress-bar'),
            t2ProgressPct: document.getElementById('t2-progress-pct'),
            t2RecordCount: document.getElementById('t2-record-count'),
            t2BytesReceived: document.getElementById('t2-bytes-received'),
            t2Terminal: document.getElementById('t2-terminal')
        };
    }

    // ========================================================================
    // SSE Connection (security-test.js 그대로)
    // ========================================================================
    function connectSSE() {
        if (state.eventSource) {
            state.eventSource.close();
        }

        updateSseStatus('connecting', 'SSE 연결 중...');

        try {
            state.eventSource = new EventSource(API.SSE_ENDPOINT);

            state.eventSource.onopen = function() {
                state.sseConnected = true;
                updateSseStatus('connected', 'SSE 연결됨');
                addTimelineEntry('info', 'SSE 연결 성공 - 실시간 AI 분석 수신 대기');
            };

            state.eventSource.onerror = function() {
                state.sseConnected = false;
                updateSseStatus('disconnected', 'SSE 연결 끊김');
                addTimelineEntry('error', 'SSE 연결 오류 - 재연결 시도 중...');
                setTimeout(connectSSE, 5000);
            };

            // Detailed pipeline events
            state.eventSource.addEventListener('HCAD_ANALYSIS', function(event) {
                handleHcadAnalysis(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('CONTEXT_COLLECTED', function(event) {
                handleContextCollected(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('SESSION_CONTEXT_LOADED', function(event) {
                handleSessionContextLoaded(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('LAYER1_START', function(event) {
                handleLayer1Start(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('RAG_SEARCH_COMPLETE', function(event) {
                handleRagSearchComplete(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('BEHAVIOR_ANALYSIS_COMPLETE', function(event) {
                handleBehaviorAnalysisComplete(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('LLM_EXECUTION_START', function(event) {
                handleLlmExecutionStart(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('LLM_EXECUTION_COMPLETE', function(event) {
                handleLlmExecutionComplete(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('THREAT_INDICATORS', function(event) {
                handleThreatIndicators(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('LAYER1_COMPLETE', function(event) {
                handleLayer1Complete(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('LAYER2_START', function(event) {
                handleLayer2Start(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('LAYER2_COMPLETE', function(event) {
                handleLayer2Complete(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('DECISION_APPLIED', function(event) {
                handleDecisionApplied(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('RESPONSE_BLOCKED', function(event) {
                handleResponseBlocked(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('ERROR', function(event) {
                handleError(JSON.parse(event.data));
            });
            state.eventSource.addEventListener('heartbeat', function() {});

        } catch (error) {
            console.error('SSE connection error:', error);
            updateSseStatus('disconnected', 'SSE 연결 실패');
        }
    }

    function updateSseStatus(status, text) {
        if (elements.sseIndicator) elements.sseIndicator.className = 'sse-indicator ' + status;
        if (elements.sseText) elements.sseText.textContent = text;
    }

    // ========================================================================
    // Detailed Pipeline Event Handlers (SSE data only, no hardcoding)
    // ========================================================================
    function handleHcadAnalysis(data) {
        var meta = {};
        try { meta = JSON.parse(data.metadata || '{}'); } catch(e) { meta = {}; }

        if (meta.sourceIp) addTimelineEntry('info', '[컨텍스트 수집] IP: ' + meta.sourceIp + ' | ' + (meta.geoCountry || '') + ' ' + (meta.geoCity || ''));
        if (meta.userAgent) addTimelineEntry('info', '[컨텍스트 수집] 브라우저: ' + meta.userAgent);
        if (meta.sessionId) addTimelineEntry('info', '[컨텍스트 수집] 세션: ' + meta.sessionId);

        var sessionInfo = [];
        if (meta.isNewSession !== undefined) sessionInfo.push('신규 세션: ' + meta.isNewSession);
        if (meta.isNewDevice !== undefined) sessionInfo.push('신규 디바이스: ' + meta.isNewDevice);
        if (meta.isNewUser !== undefined) sessionInfo.push('신규 사용자: ' + meta.isNewUser);
        if (sessionInfo.length > 0) addTimelineEntry('info', '[컨텍스트 수집] ' + sessionInfo.join(' | '));

        var secInfo = [];
        if (meta.recentRequestCount !== undefined) secInfo.push('최근 요청: ' + meta.recentRequestCount + '건');
        if (meta.failedLoginAttempts !== undefined) secInfo.push('로그인 실패: ' + meta.failedLoginAttempts + '회');
        if (meta.mfaVerified !== undefined) secInfo.push('MFA: ' + (meta.mfaVerified ? '인증됨' : '미인증'));
        if (meta.baselineConfidence !== undefined) secInfo.push('기준선 신뢰도: ' + meta.baselineConfidence);
        if (secInfo.length > 0) addTimelineEntry('info', '[컨텍스트 수집] ' + secInfo.join(' | '));

        if (meta.impossibleTravel) {
            addTimelineEntry('warning', '[컨텍스트 수집] 불가능한 이동 감지 | 거리: ' + (meta.travelDistanceKm || '?') + 'km | 이전 위치: ' + (meta.previousLocation || '?'));
        }
        if (meta.isSensitiveResource !== undefined) addTimelineEntry('info', '[컨텍스트 수집] 민감 리소스: ' + meta.isSensitiveResource);
    }

    function handleSessionContextLoaded(data) {
        var meta = {};
        try { meta = JSON.parse(data.metadata || '{}'); } catch(e) { meta = {}; }

        var info = [];
        if (meta.authMethod) info.push('인증: ' + meta.authMethod);
        if (meta.accessFrequency !== undefined) info.push('접근빈도: ' + meta.accessFrequency);
        if (meta.recentActionsCount !== undefined) info.push('최근 액션: ' + meta.recentActionsCount + '건');
        if (meta.sessionContextMs !== undefined) info.push(meta.sessionContextMs + 'ms');
        addTimelineEntry('info', '[세션 컨텍스트] ' + info.join(' | '));
    }

    function handleRagSearchComplete(data) {
        var matched = data.metadata || '0';
        var ms = data.elapsedMs || 0;
        addTimelineEntry('info', '[유사 패턴 검색] 유사 이벤트 ' + matched + '건 매칭 | ' + ms + 'ms');
    }

    function handleBehaviorAnalysisComplete(data) {
        var meta = {};
        try { meta = JSON.parse(data.metadata || '{}'); } catch(e) { meta = {}; }

        var info = [];
        if (meta.baselineEstablished !== undefined) info.push('기준선: ' + (meta.baselineEstablished ? '수립됨' : '미수립'));
        if (meta.similarEventsCount !== undefined) info.push('유사 패턴: ' + meta.similarEventsCount + '건');
        if (meta.behaviorAnalysisMs !== undefined) info.push(meta.behaviorAnalysisMs + 'ms');
        addTimelineEntry('info', '[행동 분석] ' + info.join(' | '));
    }

    function handleLlmExecutionStart(data) {
        var model = data.metadata || 'LLM';
        var promptMs = data.elapsedMs || 0;
        addTimelineEntry('info', '[AI 엔진] ' + model + ' 실행 시작 | 프롬프트 구성: ' + promptMs + 'ms');
    }

    function handleLlmExecutionComplete(data) {
        var llmMs = data.elapsedMs || 0;
        var parseMs = data.metadata || '0';
        addTimelineEntry('success', '[AI 엔진] 응답 수신 | 분석: ' + llmMs + 'ms | 파싱: ' + parseMs + 'ms');
    }

    function handleThreatIndicators(data) {
        var indicators = data.mitre || 'none';
        var actions = data.reasoning || 'none';
        if (indicators !== 'none' && indicators.trim()) {
            addTimelineEntry('warning', '[위협 지표] ' + indicators);
        }
        if (actions !== 'none' && actions.trim()) {
            addTimelineEntry('info', '[권고 조치] ' + actions);
        }
    }

    // ========================================================================
    // SSE Event Handlers (security-test.js 그대로 + 모달 로그 추가)
    // ========================================================================
    function handleContextCollected(data) {
        state.isTestRunning = true;
        disableTestButtons();
        resetAnalysisUI();

        addTimelineEntry('info', '========== AI 분석 시작 ==========');
        addTimelineEntry('info', `분석 요구 수준: ${data.analysisRequirement || 'N/A'}`);

        state.analysisPhase = 'context';
        updateStepStatus('context', 'active');
    }

    function handleLayer1Start(data) {
        state.analysisPhase = 'layer1';
        updateStepStatus('context', 'completed');
        updateStepStatus('layer1', 'active');
        addTimelineEntry('info', '1차 AI 분석 시작 (모델: Qwen 2.5 7B)');
        showAnalyzingIndicator();
    }

    function handleLayer1Complete(data) {
        hideAnalyzingIndicator();
        updateStepStatus('layer1', 'completed');
        updateMetrics(data.riskScore, data.confidence);

        if (data.mitre && data.mitre !== 'none') {
            showMitre(data.mitre);
            addTimelineEntry('warning', `MITRE ATT&CK: ${data.mitre}`);
        }

        if (data.reasoning) {
            showReasoning(data.reasoning);
            addTimelineEntry('info', `분석 근거: ${data.reasoning}`);
        }

        if (data.action !== 'ESCALATE') {
            updateActionBadge(data.action);
            addTimelineEntry('success', `1차 분석 완료: ${ACTION_LABELS[data.action] || data.action} (위험: ${(data.riskScore || 0).toFixed(2)}, 신뢰도: ${(data.confidence || 0).toFixed(2)}, ${data.elapsedMs || 0}ms)`);
        } else {
            addTimelineEntry('warning', `1차 분석: 에스컬레이션 - 2차 정밀 분석 필요 (위험: ${(data.riskScore || 0).toFixed(2)}, ${data.elapsedMs || 0}ms)`);
        }

        // Modal metrics
        showModalMetrics(data.riskScore, data.confidence);
    }

    function handleLayer2Start(data) {
        state.analysisPhase = 'layer2';

        if (elements.stepLayer2) elements.stepLayer2.style.display = 'flex';
        if (elements.layer2Arrow) elements.layer2Arrow.style.display = 'flex';

        updateStepStatus('layer2', 'active');
        showAnalyzingIndicator();
        addTimelineEntry('warning', `2차 정밀 분석 시작 (Claude Sonnet): ${data.reasoning || data.reason || 'N/A'}`);
    }

    function handleLayer2Complete(data) {
        hideAnalyzingIndicator();
        updateStepStatus('layer2', 'completed');
        updateMetrics(data.riskScore, data.confidence);

        if (data.mitre && data.mitre !== 'none') {
            showMitre(data.mitre);
            addTimelineEntry('warning', `MITRE ATT&CK: ${data.mitre}`);
        }

        if (data.reasoning) {
            showReasoning(data.reasoning);
            addTimelineEntry('info', `분석 근거: ${data.reasoning}`);
        }

        updateActionBadge(data.action);
        addTimelineEntry('success', `2차 분석 완료: ${ACTION_LABELS[data.action] || data.action} (위험: ${(data.riskScore || 0).toFixed(2)}, 신뢰도: ${(data.confidence || 0).toFixed(2)}, ${data.elapsedMs || 0}ms)`);
        showModalMetrics(data.riskScore, data.confidence);
    }

    function handleDecisionApplied(data) {
        state.analysisPhase = 'decision';
        updateStepStatus('decision', 'completed');
        updateActionBadge(data.action);

        const layerInfo = data.layer ? ` (${data.layer})` : '';
        addTimelineEntry('decision', `최종 결정 적용: ${ACTION_LABELS[data.action] || data.action}${layerInfo}`);

        showModalDecision(data.action);

        state.isTestRunning = false;
        enableTestButtons();
    }

    function handleResponseBlocked(data) {
        addTimelineEntry('error', `응답 강제 차단: ${data.reasoning || 'AI 보안 결정에 의해 응답이 중단되었습니다'}`);
        showModalDecision('BLOCK');
    }

    function handleError(data) {
        addTimelineEntry('error', `오류: ${data.reasoning || data.message || '알 수 없는 오류'}`);
        state.isTestRunning = false;
        enableTestButtons();
    }

    // ========================================================================
    // UI Update (security-test.js 그대로)
    // ========================================================================
    function updateStepStatus(step, status) {
        const stepElement = elements[`step${step.charAt(0).toUpperCase() + step.slice(1)}`];
        if (stepElement) {
            const indicator = stepElement.querySelector('.m-step-indicator');
            if (indicator) indicator.className = 'm-step-indicator ' + status;
        }
    }

    function updateActionBadge(action) {
        state.currentAction = action;
        if (elements.currentActionBadge) {
            const actionText = elements.currentActionBadge.querySelector('.action-text');
            if (actionText) actionText.textContent = ACTION_LABELS[action] || action;

            elements.currentActionBadge.classList.remove(
                'action-ALLOW', 'action-BLOCK', 'action-CHALLENGE', 'action-ESCALATE', 'action-PENDING'
            );
            const style = ACTION_STYLES[action] || ACTION_STYLES['PENDING'];
            elements.currentActionBadge.classList.add(style.class);
        }
    }

    function updateMetrics(riskScore, confidence) {
        state.riskScore = riskScore || 0;
        state.confidence = confidence || 0;

        if (elements.riskFill) elements.riskFill.style.width = `${state.riskScore * 100}%`;
        if (elements.riskValue) elements.riskValue.textContent = state.riskScore.toFixed(2);
        if (elements.confidenceFill) elements.confidenceFill.style.width = `${state.confidence * 100}%`;
        if (elements.confidenceValue) elements.confidenceValue.textContent = state.confidence.toFixed(2);
    }

    function showMitre(mitre) {
        state.mitre = mitre;
        if (elements.mitreDisplay && mitre && mitre !== 'none') {
            elements.mitreDisplay.style.display = 'block';
            if (elements.mitreValue) elements.mitreValue.textContent = mitre;
        }
    }

    function showReasoning(reasoning) {
        state.reasoning = reasoning;
        if (elements.reasoningDisplay && reasoning) {
            elements.reasoningDisplay.style.display = 'block';
            if (elements.reasoningText) elements.reasoningText.textContent = reasoning;
        }
    }

    function resetAnalysisUI() {
        state.currentAction = 'PENDING';
        state.riskScore = 0;
        state.confidence = 0;
        state.mitre = null;
        state.reasoning = null;
        state.analysisPhase = 'idle';

        updateActionBadge('PENDING');
        updateMetrics(0, 0);

        if (elements.mitreDisplay) elements.mitreDisplay.style.display = 'none';
        if (elements.reasoningDisplay) elements.reasoningDisplay.style.display = 'none';

        ['context', 'layer1', 'layer2', 'decision'].forEach(step => {
            updateStepStatus(step, 'waiting');
        });

        if (elements.stepLayer2) elements.stepLayer2.style.display = 'none';
        if (elements.layer2Arrow) elements.layer2Arrow.style.display = 'none';
    }

    // ========================================================================
    // Analyzing Indicator
    // ========================================================================
    function showAnalyzingIndicator() {
        if (!elements.modalLogContainer) return;
        var existing = elements.modalLogContainer.querySelector('.analyzing-indicator');
        if (existing) existing.remove();

        var el = document.createElement('div');
        el.className = 'analyzing-indicator';
        el.innerHTML =
            '<span class="analyzing-spinner"></span>' +
            '<span class="analyzing-text">AI 분석 진행 중</span>' +
            '<span class="analyzing-dots"></span>';
        elements.modalLogContainer.appendChild(el);
        elements.modalLogContainer.scrollTop = elements.modalLogContainer.scrollHeight;
    }

    function hideAnalyzingIndicator() {
        if (!elements.modalLogContainer) return;
        var el = elements.modalLogContainer.querySelector('.analyzing-indicator');
        if (!el) return;
        el.classList.add('completed');
        var spinner = el.querySelector('.analyzing-spinner');
        if (spinner) spinner.className = 'analyzing-check';
        var text = el.querySelector('.analyzing-text');
        if (text) text.textContent = 'AI 분석 완료';
        var dots = el.querySelector('.analyzing-dots');
        if (dots) dots.remove();
    }

    // ========================================================================
    // Timeline (security-test.js 그대로 - 모달 안의 m-log-container에 추가)
    // ========================================================================
    function addTimelineEntry(type, message) {
        if (!elements.modalLogContainer) return;

        var now = new Date();
        var timeStr = now.toLocaleTimeString('ko-KR', {
            hour: '2-digit', minute: '2-digit', second: '2-digit'
        });

        var entry = document.createElement('div');
        entry.className = 'timeline-entry ' + type;
        entry.innerHTML =
            '<span class="timeline-time">' + timeStr + '</span>' +
            '<span class="timeline-message">' + escapeHtml(message) + '</span>';

        elements.modalLogContainer.appendChild(entry);
        elements.modalLogContainer.scrollTop = elements.modalLogContainer.scrollHeight;
    }

    function clearModalLog() {
        if (elements.modalLogContainer) {
            elements.modalLogContainer.innerHTML =
                '<div class="timeline-entry info">' +
                '<span class="timeline-time">--:--:--</span>' +
                '<span class="timeline-message">서버 연결 대기 중...</span>' +
                '</div>';
        }
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ========================================================================
    // Modal
    // ========================================================================
    function openModal(scenarioName) {
        clearModalLog();

        // Reset modal result area
        if (elements.modalResultArea) elements.modalResultArea.style.display = 'none';
        if (elements.modalFinal) elements.modalFinal.style.display = 'none';
        if (elements.mRiskFill) elements.mRiskFill.style.width = '0%';
        if (elements.mConfFill) elements.mConfFill.style.width = '0%';
        if (elements.mRiskValue) elements.mRiskValue.textContent = '0.00';
        if (elements.mConfValue) elements.mConfValue.textContent = '0.00';

        if (elements.modalScenarioLabel) elements.modalScenarioLabel.textContent = scenarioName;
        if (elements.modalOverlay) elements.modalOverlay.classList.add('active');
    }

    function closeModal() {
        if (elements.modalOverlay) elements.modalOverlay.classList.remove('active');
    }

    function showModalMetrics(risk, conf) {
        if (elements.modalResultArea) elements.modalResultArea.style.display = '';
        if (elements.mRiskFill) elements.mRiskFill.style.width = ((risk || 0) * 100) + '%';
        if (elements.mRiskValue) elements.mRiskValue.textContent = (risk || 0).toFixed(2);
        if (elements.mConfFill) elements.mConfFill.style.width = ((conf || 0) * 100) + '%';
        if (elements.mConfValue) elements.mConfValue.textContent = (conf || 0).toFixed(2);
    }

    function showModalDecision(action) {
        if (elements.modalFinal) elements.modalFinal.style.display = '';
        if (elements.modalResultArea) elements.modalResultArea.style.display = '';

        var isAllow = action === 'ALLOW';
        if (elements.modalFinalBadge) {
            elements.modalFinalBadge.className = 'm-final-badge ' + (isAllow ? 'allow' : 'block');
        }
        if (elements.modalFinalIcon) elements.modalFinalIcon.textContent = isAllow ? '\u2713' : '\u2717';
        if (elements.modalFinalText) elements.modalFinalText.textContent = ACTION_LABELS[action] || action;
    }

    // ========================================================================
    // Test 1: Access Control
    // ========================================================================
    function selectScenario(scenario, tabOwner) {
        if (tabOwner === 'test1') {
            state.selectedScenario = scenario;
        } else {
            state.t2SelectedScenario = scenario;
        }

        // Deselect siblings in same tab
        document.querySelectorAll('[data-tab-owner="' + tabOwner + '"].scenario-card').forEach(function(card) {
            card.classList.remove('selected');
        });
        var selectedCard = document.querySelector('[data-tab-owner="' + tabOwner + '"][data-scenario="' + scenario + '"]');
        if (selectedCard) selectedCard.classList.add('selected');

        enableTestButtons();
    }

    async function executeTest() {
        if (state.isTestRunning || !state.selectedScenario) return;

        var resourceId = 'resource-' + Date.now();
        var url = API.TEST_SENSITIVE + encodeURIComponent(resourceId);
        var scenarioInfo = SCENARIO_INFO[state.selectedScenario];

        // Open modal
        openModal(scenarioInfo.name);
        addTimelineEntry('info', 'Contexa AI Native Zero Trust Security Platform');
        addTimelineEntry('info', `시나리오: ${scenarioInfo.name} (IP: ${scenarioInfo.ip})`);
        addTimelineEntry('info', `요청 전송: 민감 데이터 접근 (REQUIRED)`);

        try {
            var response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    ...SCENARIO_HEADERS[state.selectedScenario]
                },
                credentials: 'same-origin'
            });

            if (response.ok) {
                var data = await response.json();
                addTimelineEntry('success', `HTTP ${response.status} 요청 성공: ${data.data || 'OK'}`);
            } else {
                if (response.status === 403) {
                    addTimelineEntry('error', `HTTP 403 접근 차단됨`);
                } else {
                    addTimelineEntry('error', `HTTP ${response.status} 요청 실패`);
                }
            }
        } catch (error) {
            addTimelineEntry('error', `네트워크 오류: ${error.message}`);
            state.isTestRunning = false;
            enableTestButtons();
        }
    }

    // ========================================================================
    // Test 2: Response Blocking (Streaming)
    // ========================================================================
    async function executeTest2() {
        if (state.isTestRunning || !state.t2SelectedScenario) return;

        var scenario = state.t2SelectedScenario;
        var scenarioInfo = SCENARIO_INFO[scenario];

        // Open modal
        openModal(scenarioInfo.name);
        if (elements.modalTitle) elements.modalTitle.textContent = 'AI 응답 차단 분석';
        addTimelineEntry('info', 'Contexa AI Native Zero Trust Security Platform');
        addTimelineEntry('info', `시나리오: ${scenarioInfo.name} (IP: ${scenarioInfo.ip})`);
        addTimelineEntry('info', '대량 데이터 스트리밍 다운로드 시작');

        // Reset progress UI
        if (elements.t2ProgressBar) { elements.t2ProgressBar.style.width = '0%'; elements.t2ProgressBar.classList.remove('blocked'); }
        if (elements.t2ProgressPct) elements.t2ProgressPct.textContent = '0%';
        if (elements.t2RecordCount) elements.t2RecordCount.textContent = '0 / 10,000 건';
        if (elements.t2BytesReceived) elements.t2BytesReceived.textContent = '0 KB';
        if (elements.t2Terminal) elements.t2Terminal.innerHTML = '';

        state.isTestRunning = true;
        disableTestButtons();

        var totalBytes = 0;
        var lineCount = 0;
        var buffer = '';
        var TOTAL = 10000;

        try {
            var response = await fetch(API.BULK_STREAM, {
                headers: SCENARIO_HEADERS[scenario],
                credentials: 'same-origin'
            });

            if (!response.ok) {
                addTerminalLine(elements.t2Terminal, 'ERROR: HTTP ' + response.status, 't-blocked');
                addTimelineEntry('error', `HTTP ${response.status} 접근 차단됨`);
                state.isTestRunning = false;
                enableTestButtons();
                return;
            }

            addTimelineEntry('success', `HTTP ${response.status} 연결 성공 - 데이터 스트리밍 시작`);

            var reader = response.body.getReader();
            var decoder = new TextDecoder();

            while (true) {
                var result = await reader.read();
                if (result.done) break;

                totalBytes += result.value.length;
                var text = decoder.decode(result.value, { stream: true });
                buffer += text;

                var lines = buffer.split('\n');
                buffer = lines.pop() || '';

                for (var i = 0; i < lines.length; i++) {
                    if (lines[i].trim()) {
                        lineCount++;
                        if (lineCount % 100 === 0 || lineCount <= 3) {
                            addTerminalLine(elements.t2Terminal, lines[i], 't-line');
                        }
                    }
                }

                var pct = Math.min((lineCount / TOTAL) * 100, 100);
                if (elements.t2ProgressBar) elements.t2ProgressBar.style.width = pct + '%';
                if (elements.t2ProgressPct) elements.t2ProgressPct.textContent = Math.round(pct) + '%';
                if (elements.t2RecordCount) elements.t2RecordCount.textContent = lineCount.toLocaleString() + ' / ' + TOTAL.toLocaleString() + ' 건';
                if (elements.t2BytesReceived) elements.t2BytesReceived.textContent = formatBytes(totalBytes);

                if (lineCount % 1000 === 0) {
                    addTimelineEntry('info', `스트리밍 진행: ${lineCount.toLocaleString()}건 수신 (${formatBytes(totalBytes)})`);
                }
            }

            addTerminalLine(elements.t2Terminal, '=== 다운로드 완료 ===', 't-complete');
            addTimelineEntry('success', `다운로드 완료: ${TOTAL.toLocaleString()}건, ${formatBytes(totalBytes)}`);
            if (elements.t2ProgressBar) elements.t2ProgressBar.style.width = '100%';
            if (elements.t2ProgressPct) elements.t2ProgressPct.textContent = '100%';
            showModalDecision('ALLOW');

        } catch (err) {
            if (elements.t2ProgressBar) elements.t2ProgressBar.classList.add('blocked');
            addTerminalLine(elements.t2Terminal, '', '');
            addTerminalLine(elements.t2Terminal, '\u2588\u2588 서버에 의해 연결 강제 종료 \u2588\u2588', 't-blocked');
            addTerminalLine(elements.t2Terminal, '[AI 보안 결정에 의한 응답 차단]', 't-blocked');

            var blocked = TOTAL - lineCount;
            var preventPct = Math.round((blocked / TOTAL) * 100);
            addTimelineEntry('error', `응답 강제 중단: ${lineCount.toLocaleString()}건에서 차단 (${preventPct}% 유출 방지)`);
            showModalDecision('BLOCK');

        } finally {
            state.isTestRunning = false;
            enableTestButtons();
        }
    }

    function addTerminalLine(terminal, text, cls) {
        if (!terminal) return;
        var div = document.createElement('div');
        div.className = cls;
        div.textContent = text;
        terminal.appendChild(div);
        terminal.scrollTop = terminal.scrollHeight;
        while (terminal.children.length > 300) terminal.removeChild(terminal.firstChild);
    }

    function formatBytes(b) {
        if (b < 1024) return b + ' B';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
        return (b / 1048576).toFixed(1) + ' MB';
    }

    // ========================================================================
    // Action Reload (security-test.js 그대로)
    // ========================================================================
    async function reloadCurrentAction() {
        var btn = elements.reloadActionBtn;
        if (!btn) return;
        btn.classList.add('loading');
        btn.disabled = true;

        try {
            var response = await fetch(API.ACTION_STATUS, {
                method: 'GET',
                headers: { 'Accept': 'application/json' },
                credentials: 'same-origin'
            });
            if (!response.ok) throw new Error('HTTP ' + response.status);
            var data = await response.json();

            var action = data.action === 'PENDING_ANALYSIS' ? 'PENDING' : (data.action || 'PENDING');
            updateActionBadge(action);
            if (data.riskScore !== undefined) updateMetrics(data.riskScore, data.confidence || 0);
            if (data.mitre && data.mitre !== 'none') showMitre(data.mitre);
            if (data.reasoning) showReasoning(data.reasoning);

            addTimelineEntry('info', `Action 조회: ${ACTION_LABELS[data.action] || data.action}`);
        } catch (error) {
            addTimelineEntry('error', `Action 조회 실패: ${error.message}`);
        } finally {
            btn.classList.remove('loading');
            btn.disabled = false;
        }
    }

    // ========================================================================
    // Button Enable/Disable
    // ========================================================================
    function enableTestButtons() {
        if (!state.isTestRunning && state.selectedScenario && elements.btnTestAccess) {
            elements.btnTestAccess.disabled = false;
        }
        if (!state.isTestRunning && state.t2SelectedScenario && elements.btnTestBulkStream) {
            elements.btnTestBulkStream.disabled = false;
        }
    }

    function disableTestButtons() {
        if (elements.btnTestAccess) elements.btnTestAccess.disabled = true;
        if (elements.btnTestBulkStream) elements.btnTestBulkStream.disabled = true;
    }

    // ========================================================================
    // Tabs
    // ========================================================================
    function initTabs() {
        document.querySelectorAll('.tab-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
                document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
                btn.classList.add('active');
                var tab = document.getElementById('tab-' + btn.dataset.tab);
                if (tab) tab.classList.add('active');
                state.activeTab = btn.dataset.tab;
            });
        });
    }

    // ========================================================================
    // Event Listeners
    // ========================================================================
    function bindEventListeners() {
        // Scenario cards
        document.querySelectorAll('.scenario-card').forEach(function(card) {
            card.addEventListener('click', function() {
                var scenario = this.dataset.scenario;
                var tabOwner = this.dataset.tabOwner;
                if (scenario && tabOwner) selectScenario(scenario, tabOwner);
            });
        });

        // Test 1 button
        if (elements.btnTestAccess) {
            elements.btnTestAccess.addEventListener('click', executeTest);
        }

        // Test 2 button
        if (elements.btnTestBulkStream) {
            elements.btnTestBulkStream.addEventListener('click', executeTest2);
        }

        // Action reload
        if (elements.reloadActionBtn) {
            elements.reloadActionBtn.addEventListener('click', reloadCurrentAction);
        }

        // Modal close
        if (elements.modalCloseX) {
            elements.modalCloseX.addEventListener('click', closeModal);
        }
        if (elements.modalCloseBtn) {
            elements.modalCloseBtn.addEventListener('click', closeModal);
        }
        if (elements.modalOverlay) {
            elements.modalOverlay.addEventListener('click', function(e) {
                if (e.target === elements.modalOverlay) closeModal();
            });
        }
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') closeModal();
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.key === '1') selectScenario('NORMAL_USER', state.activeTab);
            if (e.key === '2') {
                if (state.activeTab === 'test1') selectScenario('ACCOUNT_TAKEOVER', 'test1');
                else selectScenario('DATA_EXFILTRATION', 'test2');
            }
        });
    }

    // ========================================================================
    // Initialize
    // ========================================================================
    function initialize() {
        initializeElements();
        bindEventListeners();
        initTabs();
        connectSSE();

        updateActionBadge('PENDING');
        updateMetrics(0, 0);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
