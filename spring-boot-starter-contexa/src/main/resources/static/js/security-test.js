/**
 * ============================================================================
 * Contexa AI Native Zero Trust Security Platform - TIPS Demo
 * ============================================================================
 *
 * 실시간 LLM 분석 시각화 및 SSE 연결
 *
 * 아키텍처:
 * ColdPathEventProcessor -> LlmAnalysisEventListener -> SSE -> Client
 *
 * SSE 이벤트 유형:
 * - CONTEXT_COLLECTED: 컨텍스트 수집 완료
 * - LAYER1_START: Layer1 분석 시작 (Llama 8B)
 * - LAYER1_COMPLETE: Layer1 분석 완료
 * - LAYER2_START: Layer2 에스컬레이션 (Claude)
 * - LAYER2_COMPLETE: Layer2 분석 완료
 * - DECISION_APPLIED: 최종 결정 적용
 * - ERROR: 오류 발생
 *
 * @author contexa
 * @since TIPS Demo v1.0
 */

'use strict';

(function() {
    // ============================================================================
    // 상수 정의
    // ============================================================================

    /**
     * API 엔드포인트
     */
    const API = {
        SSE_ENDPOINT: '/api/sse/llm-analysis',
        ACTION_STATUS: '/api/test-action/status',
        ACTION_RESET: '/api/test-action/reset',
        TEST_NORMAL: '/api/security-test/normal/',
        TEST_SENSITIVE: '/api/security-test/sensitive/',
        TEST_CRITICAL: '/api/security-test/critical/'
    };

    /**
     * Scenario-specific HTTP headers (X-Forwarded-For for IP simulation)
     */
    const SCENARIO_HEADERS = {
        'NORMAL_USER': {
            'X-Forwarded-For': '192.168.1.100'
        },
        'ACCOUNT_TAKEOVER': {
            'X-Forwarded-For': '203.0.113.50'
        },
        'PRIVILEGE_ESCALATION': {
            'X-Forwarded-For': '10.0.0.99'
        }
    };

    /**
     * 시나리오 정보
     */
    const SCENARIO_INFO = {
        'NORMAL_USER': {
            name: '정상 사용자',
            ip: '192.168.1.100',
            userAgent: 'Chrome/120.0 (Windows)',
            expectedAction: 'ALLOW'
        },
        'ACCOUNT_TAKEOVER': {
            name: '계정 탈취 의심',
            ip: '203.0.113.50',
            userAgent: 'Android 10 (Mobile)',
            expectedAction: 'CHALLENGE'
        },
        'PRIVILEGE_ESCALATION': {
            name: '권한 상승 시도',
            ip: '10.0.0.99',
            userAgent: 'python-requests/2.28',
            expectedAction: 'BLOCK'
        }
    };

    /**
     * Action 색상 및 정보
     * CSS 클래스명 형식: action-{ACTION} (예: action-ALLOW, action-BLOCK)
     */
    const ACTION_STYLES = {
        'ALLOW': { class: 'action-ALLOW', color: '#2e7d32' },
        'BLOCK': { class: 'action-BLOCK', color: '#c62828' },
        'CHALLENGE': { class: 'action-CHALLENGE', color: '#1565c0' },
        'ESCALATE': { class: 'action-ESCALATE', color: '#7b1fa2' },
        'PENDING': { class: 'action-PENDING', color: '#666' }
    };

    /**
     * Action 한국어 라벨
     * 화면에 표시되는 텍스트
     */
    const ACTION_LABELS = {
        'ALLOW': '승인',
        'BLOCK': '차단',
        'CHALLENGE': '2차 승인 필요',
        'ESCALATE': '에스컬레이션',
        'PENDING': '대기',
        'PENDING_ANALYSIS': '분석 대기'
    };

    // ============================================================================
    // 상태 관리
    // ============================================================================

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
        analysisPhase: 'idle' // idle, context, layer1, layer2, decision
    };

    // ============================================================================
    // DOM 요소 참조
    // ============================================================================

    let elements = {};

    /**
     * DOM 요소 초기화
     */
    function initializeElements() {
        elements = {
            // SSE 상태
            sseStatus: document.getElementById('sse-status'),
            sseIndicator: document.getElementById('sse-indicator'),
            sseText: document.getElementById('sse-text'),

            // 시나리오 카드
            scenarioNormal: document.getElementById('scenario-normal'),
            scenarioTakeover: document.getElementById('scenario-takeover'),
            scenarioEscalation: document.getElementById('scenario-escalation'),

            // 분석 단계 (컴팩트 레이아웃)
            stepContext: document.getElementById('step-context'),
            stepLayer1: document.getElementById('step-layer1'),
            stepLayer2: document.getElementById('step-layer2'),
            stepDecision: document.getElementById('step-decision'),
            // Layer2 화살표 (에스컬레이션 시 표시)
            layer2Arrow: document.querySelector('.layer2-arrow'),

            // Action 배지
            currentActionBadge: document.getElementById('current-action-badge'),

            // 메트릭
            riskFill: document.getElementById('risk-fill'),
            riskValue: document.getElementById('risk-value'),
            confidenceFill: document.getElementById('confidence-fill'),
            confidenceValue: document.getElementById('confidence-value'),

            // MITRE & Reasoning
            mitreDisplay: document.getElementById('mitre-display'),
            mitreValue: document.getElementById('mitre-value'),
            reasoningDisplay: document.getElementById('reasoning-display'),
            reasoningText: document.getElementById('reasoning-text'),

            // 테스트 버튼 (컴팩트 버튼 바)
            btnTestNormal: document.getElementById('btn-test-normal'),
            btnTestSensitive: document.getElementById('btn-test-sensitive'),
            btnTestCritical: document.getElementById('btn-test-critical'),

            // 타임라인
            timelineContainer: document.getElementById('timeline-container'),

            // 컨트롤 버튼
            btnClearTimeline: document.getElementById('btn-clear-timeline'),
            btnResetAnalysis: document.getElementById('btn-reset-analysis'),

            // AI Native v8.12: Action 리로드 버튼
            reloadActionBtn: document.getElementById('reload-action-btn')
        };
    }

    // ============================================================================
    // SSE 연결 관리
    // ============================================================================

    /**
     * SSE 연결 설정
     */
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
                addTimelineEntry('info', 'SSE 연결 성공 - 실시간 LLM 분석 수신 대기');
            };

            state.eventSource.onerror = function(event) {
                state.sseConnected = false;
                updateSseStatus('disconnected', 'SSE 연결 끊김');
                addTimelineEntry('error', 'SSE 연결 오류 - 재연결 시도 중...');

                // 5초 후 재연결 시도
                setTimeout(connectSSE, 5000);
            };

            // CONTEXT_COLLECTED 이벤트
            state.eventSource.addEventListener('CONTEXT_COLLECTED', function(event) {
                const data = JSON.parse(event.data);
                handleContextCollected(data);
            });

            // LAYER1_START 이벤트
            state.eventSource.addEventListener('LAYER1_START', function(event) {
                const data = JSON.parse(event.data);
                handleLayer1Start(data);
            });

            // LAYER1_COMPLETE 이벤트
            state.eventSource.addEventListener('LAYER1_COMPLETE', function(event) {
                const data = JSON.parse(event.data);
                handleLayer1Complete(data);
            });

            // LAYER2_START 이벤트
            state.eventSource.addEventListener('LAYER2_START', function(event) {
                const data = JSON.parse(event.data);
                handleLayer2Start(data);
            });

            // LAYER2_COMPLETE 이벤트
            state.eventSource.addEventListener('LAYER2_COMPLETE', function(event) {
                const data = JSON.parse(event.data);
                handleLayer2Complete(data);
            });

            // DECISION_APPLIED 이벤트
            state.eventSource.addEventListener('DECISION_APPLIED', function(event) {
                const data = JSON.parse(event.data);
                handleDecisionApplied(data);
            });

            // ERROR 이벤트
            state.eventSource.addEventListener('ERROR', function(event) {
                const data = JSON.parse(event.data);
                handleError(data);
            });

            // heartbeat 이벤트 (연결 유지용)
            state.eventSource.addEventListener('heartbeat', function(event) {
                // 연결 유지 확인
            });

        } catch (error) {
            console.error('SSE 연결 오류:', error);
            updateSseStatus('disconnected', 'SSE 연결 실패');
        }
    }

    /**
     * SSE 상태 표시 업데이트
     */
    function updateSseStatus(status, text) {
        if (elements.sseIndicator) {
            elements.sseIndicator.className = 'sse-indicator ' + status;
        }
        if (elements.sseText) {
            elements.sseText.textContent = text;
        }
    }

    // ============================================================================
    // SSE 이벤트 핸들러
    // ============================================================================

    /**
     * 컨텍스트 수집 완료 처리
     *
     * AI Native v8.12: LLM 분석이 시작됨을 알리는 첫 SSE 이벤트
     * 이 이벤트 수신 시점에 UI 변경 시작 (버튼 비활성화, 분석 UI 초기화)
     */
    function handleContextCollected(data) {
        // AI Native v8.12: LLM 분석 시작 → 이제 UI 변경 시작
        state.isTestRunning = true;
        disableTestButtons();

        // 분석 UI 초기화
        resetAnalysisUI();

        // 타임라인에 분석 시작 메시지
        addTimelineEntry('info', '========== LLM 분석 시작 ==========');
        addTimelineEntry('info', `분석 요구 수준: ${data.analysisRequirement || 'N/A'}`);

        // 분석 단계 업데이트
        state.analysisPhase = 'context';
        updateStepStatus('context', 'active', '수집 완료');
    }

    /**
     * Layer1 분석 시작 처리
     */
    function handleLayer1Start(data) {
        state.analysisPhase = 'layer1';
        updateStepStatus('context', 'completed', '완료');
        updateStepStatus('layer1', 'active', '분석 중...');
        addTimelineEntry('info', 'Layer1 분석 시작 (Llama 8B)');
    }

    /**
     * Layer1 분석 완료 처리
     */
    function handleLayer1Complete(data) {
        updateStepStatus('layer1', 'completed', `완료 (${data.elapsedMs || 0}ms)`);

        // 메트릭 업데이트
        updateMetrics(data.riskScore, data.confidence);

        // MITRE 표시
        if (data.mitre && data.mitre !== 'none') {
            showMitre(data.mitre);
        }

        // Reasoning 표시
        if (data.reasoning) {
            showReasoning(data.reasoning);
        }

        // Action이 ESCALATE가 아니면 최종 결정으로 처리
        if (data.action !== 'ESCALATE') {
            updateActionBadge(data.action);
            addTimelineEntry('success', `Layer1 분석 완료: ${ACTION_LABELS[data.action] || data.action} (Risk: ${(data.riskScore || 0).toFixed(2)})`);
        } else {
            addTimelineEntry('warning', `Layer1: ESCALATE - Layer2로 에스컬레이션`);
        }
    }

    /**
     * Layer2 에스컬레이션 시작 처리 (컴팩트 레이아웃)
     */
    function handleLayer2Start(data) {
        state.analysisPhase = 'layer2';

        // Layer2 단계 및 화살표 표시
        if (elements.stepLayer2) {
            elements.stepLayer2.style.display = 'flex';
        }
        if (elements.layer2Arrow) {
            elements.layer2Arrow.style.display = 'flex';
        }

        updateStepStatus('layer2', 'active', '분석 중...');
        addTimelineEntry('warning', `Layer2 에스컬레이션: ${data.reason || 'N/A'}`);
    }

    /**
     * Layer2 분석 완료 처리
     */
    function handleLayer2Complete(data) {
        updateStepStatus('layer2', 'completed', `완료 (${data.elapsedMs || 0}ms)`);

        // 메트릭 업데이트
        updateMetrics(data.riskScore, data.confidence);

        // MITRE 표시
        if (data.mitre && data.mitre !== 'none') {
            showMitre(data.mitre);
        }

        // Reasoning 표시
        if (data.reasoning) {
            showReasoning(data.reasoning);
        }

        updateActionBadge(data.action);
        addTimelineEntry('success', `Layer2 분석 완료: ${ACTION_LABELS[data.action] || data.action} (Risk: ${(data.riskScore || 0).toFixed(2)})`);
    }

    /**
     * 최종 결정 적용 처리
     */
    function handleDecisionApplied(data) {
        state.analysisPhase = 'decision';
        updateStepStatus('decision', 'completed', '적용됨');
        updateActionBadge(data.action);

        const layerInfo = data.layer ? ` (${data.layer})` : '';
        addTimelineEntry('success', `최종 결정 적용: ${ACTION_LABELS[data.action] || data.action}${layerInfo}`);

        // 테스트 완료
        state.isTestRunning = false;
        enableTestButtons();
    }

    /**
     * 에러 처리
     */
    function handleError(data) {
        addTimelineEntry('error', `오류: ${data.message || 'Unknown error'}`);
        state.isTestRunning = false;
        enableTestButtons();
    }

    // ============================================================================
    // UI 업데이트 함수
    // ============================================================================

    /**
     * 분석 단계 상태 업데이트 (컴팩트 레이아웃)
     */
    function updateStepStatus(step, status, text) {
        const stepElement = elements[`step${step.charAt(0).toUpperCase() + step.slice(1)}`];

        if (stepElement) {
            const indicator = stepElement.querySelector('.step-indicator');
            if (indicator) {
                indicator.className = 'step-indicator ' + status;
            }
        }
    }

    /**
     * Action 배지 업데이트
     */
    function updateActionBadge(action) {
        state.currentAction = action;

        // 디버깅: 전달된 action 값과 변환 결과 확인
        console.log('[updateActionBadge] action:', action, '-> label:', ACTION_LABELS[action] || action);

        if (elements.currentActionBadge) {
            const actionText = elements.currentActionBadge.querySelector('.action-text');
            if (actionText) {
                // 한국어 라벨 사용, 미정의 시 원본 표시
                const label = ACTION_LABELS[action] || action;
                console.log('[updateActionBadge] Setting text to:', label);
                actionText.textContent = label;
            }

            // 모든 action 클래스 제거 (CSS 클래스명 형식: action-{ACTION})
            elements.currentActionBadge.classList.remove(
                'action-ALLOW', 'action-BLOCK', 'action-CHALLENGE', 'action-ESCALATE', 'action-PENDING'
            );

            // 새 action 클래스 추가
            const style = ACTION_STYLES[action] || ACTION_STYLES['PENDING'];
            elements.currentActionBadge.classList.add(style.class);
        }
    }

    /**
     * 메트릭 업데이트
     */
    function updateMetrics(riskScore, confidence) {
        state.riskScore = riskScore || 0;
        state.confidence = confidence || 0;

        // Risk Score
        if (elements.riskFill) {
            elements.riskFill.style.width = `${state.riskScore * 100}%`;
        }
        if (elements.riskValue) {
            elements.riskValue.textContent = state.riskScore.toFixed(2);
        }

        // Confidence
        if (elements.confidenceFill) {
            elements.confidenceFill.style.width = `${state.confidence * 100}%`;
        }
        if (elements.confidenceValue) {
            elements.confidenceValue.textContent = state.confidence.toFixed(2);
        }
    }

    /**
     * MITRE ATT&CK 표시
     */
    function showMitre(mitre) {
        state.mitre = mitre;

        if (elements.mitreDisplay && mitre && mitre !== 'none') {
            elements.mitreDisplay.style.display = 'block';
            if (elements.mitreValue) {
                elements.mitreValue.textContent = mitre;
            }
        }
    }

    /**
     * LLM Reasoning 표시
     */
    function showReasoning(reasoning) {
        state.reasoning = reasoning;

        if (elements.reasoningDisplay && reasoning) {
            elements.reasoningDisplay.style.display = 'block';
            if (elements.reasoningText) {
                elements.reasoningText.textContent = reasoning;
            }
        }
    }

    /**
     * AI Native v8.12: MITRE 정보 숨기기
     */
    function hideMitre() {
        state.mitre = null;
        if (elements.mitreDisplay) {
            elements.mitreDisplay.style.display = 'none';
        }
    }

    /**
     * AI Native v8.12: Reasoning 정보 숨기기
     */
    function hideReasoning() {
        state.reasoning = null;
        if (elements.reasoningDisplay) {
            elements.reasoningDisplay.style.display = 'none';
        }
    }

    /**
     * 타임라인 엔트리 추가
     */
    function addTimelineEntry(type, message) {
        if (!elements.timelineContainer) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('ko-KR', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });

        const entry = document.createElement('div');
        entry.className = `timeline-entry ${type}`;
        entry.innerHTML = `
            <span class="timeline-time">${timeStr}</span>
            <span class="timeline-message">${escapeHtml(message)}</span>
        `;

        elements.timelineContainer.appendChild(entry);

        // 자동 스크롤
        elements.timelineContainer.scrollTop = elements.timelineContainer.scrollHeight;
    }

    /**
     * 타임라인 초기화
     */
    function clearTimeline() {
        if (elements.timelineContainer) {
            elements.timelineContainer.innerHTML = `
                <div class="timeline-entry info">
                    <span class="timeline-time">--:--:--</span>
                    <span class="timeline-message">시나리오를 선택하고 테스트 버튼을 클릭하세요.</span>
                </div>
            `;
        }
    }

    /**
     * 분석 결과 초기화
     */
    function resetAnalysis() {
        state.currentAction = 'PENDING';
        state.riskScore = 0;
        state.confidence = 0;
        state.mitre = null;
        state.reasoning = null;
        state.analysisPhase = 'idle';

        // Action 배지 초기화
        updateActionBadge('PENDING');

        // 메트릭 초기화
        updateMetrics(0, 0);

        // MITRE 숨기기
        if (elements.mitreDisplay) {
            elements.mitreDisplay.style.display = 'none';
        }

        // Reasoning 숨기기
        if (elements.reasoningDisplay) {
            elements.reasoningDisplay.style.display = 'none';
        }

        // 분석 단계 초기화
        ['context', 'layer1', 'layer2', 'decision'].forEach(step => {
            updateStepStatus(step, 'waiting', '대기');
        });

        // Layer2 및 화살표 숨기기
        if (elements.stepLayer2) {
            elements.stepLayer2.style.display = 'none';
        }
        if (elements.layer2Arrow) {
            elements.layer2Arrow.style.display = 'none';
        }

        addTimelineEntry('info', '분석 결과가 초기화되었습니다.');
    }

    // ============================================================================
    // 시나리오 선택
    // ============================================================================

    /**
     * 시나리오 선택 처리
     */
    function selectScenario(scenario) {
        state.selectedScenario = scenario;

        // 모든 시나리오 카드에서 selected 클래스 제거
        document.querySelectorAll('.scenario-card').forEach(card => {
            card.classList.remove('selected');
        });

        // 선택된 카드에 selected 클래스 추가
        const selectedCard = document.querySelector(`[data-scenario="${scenario}"]`);
        if (selectedCard) {
            selectedCard.classList.add('selected');
        }

        // 테스트 버튼 활성화
        enableTestButtons();

        const info = SCENARIO_INFO[scenario];
        addTimelineEntry('info', `시나리오 선택: ${info.name} (IP: ${info.ip})`);
    }

    /**
     * 테스트 버튼 활성화
     */
    function enableTestButtons() {
        const enabled = state.selectedScenario && !state.isTestRunning;

        [elements.btnTestNormal, elements.btnTestSensitive, elements.btnTestCritical].forEach(btn => {
            if (btn) {
                btn.disabled = !enabled;
            }
        });
    }

    /**
     * 테스트 버튼 비활성화
     */
    function disableTestButtons() {
        [elements.btnTestNormal, elements.btnTestSensitive, elements.btnTestCritical].forEach(btn => {
            if (btn) {
                btn.disabled = true;
            }
        });
    }

    // ============================================================================
    // API 테스트 실행
    // ============================================================================

    /**
     * API 테스트 실행
     */
    async function executeTest(type) {
        if (state.isTestRunning) {
            addTimelineEntry('warning', '테스트가 이미 실행 중입니다.');
            return;
        }

        if (!state.selectedScenario) {
            addTimelineEntry('warning', '먼저 시나리오를 선택하세요.');
            return;
        }

        // AI Native v8.12: UI 변경은 SSE 이벤트(CONTEXT_COLLECTED) 수신 시에만 수행
        // 클라이언트 요청 시점에서는 UI 변경 없이 fetch 요청만 전송
        // LLM 분석이 스킵되면 SSE 이벤트가 오지 않으므로 분석 UI 표시 없음

        const resourceId = 'resource-' + Date.now();
        const url = getTestUrl(type, resourceId);
        const scenarioInfo = SCENARIO_INFO[state.selectedScenario];

        // AI Native v8.12: 요청 전송 알림 (최소한의 타임라인 메시지)
        addTimelineEntry('info', `요청 전송: ${getTestTypeName(type)} - ${scenarioInfo.name}`);

        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    ...SCENARIO_HEADERS[state.selectedScenario]
                },
                credentials: 'same-origin'
            });

            if (response.ok) {
                const data = await response.json();
                addTimelineEntry('success', `요청 성공: ${data.data || 'OK'}`);
            } else {
                const errorText = await response.text();
                if (response.status === 403) {
                    addTimelineEntry('error', `접근 차단됨 (HTTP 403)`);
                } else {
                    addTimelineEntry('error', `요청 실패 (HTTP ${response.status})`);
                }
            }
        } catch (error) {
            addTimelineEntry('error', `네트워크 오류: ${error.message}`);
            state.isTestRunning = false;
            enableTestButtons();
        }
    }

    // ============================================================================
    // AI Native v8.12: Action 리로드 기능
    // ============================================================================

    /**
     * 현재 Action 새로고침
     * Redis에서 HCAD 분석 결과 조회하여 UI 업데이트
     */
    async function reloadCurrentAction() {
        const btn = elements.reloadActionBtn;
        if (!btn) return;

        // 로딩 상태 표시
        btn.classList.add('loading');
        btn.disabled = true;

        try {
            const response = await fetch(API.ACTION_STATUS, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json'
                },
                credentials: 'same-origin'
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();

            // UI 업데이트
            handleCurrentActionResponse(data);

            // 타임라인에 기록
            const source = data.analysisStatus === 'ANALYZED' ? 'Redis 캐시' : '분석 없음';
            addTimelineEntry('info', `Action 조회: ${ACTION_LABELS[data.action] || data.action} (${source})`);

        } catch (error) {
            console.error('Action 조회 실패:', error);
            addTimelineEntry('error', `Action 조회 실패: ${error.message}`);
        } finally {
            // 로딩 상태 해제
            btn.classList.remove('loading');
            btn.disabled = false;
        }
    }

    /**
     * 현재 Action 응답 처리
     * @param {Object} data - 서버 응답 데이터
     */
    function handleCurrentActionResponse(data) {
        const action = data.action || 'PENDING_ANALYSIS';

        // Action 배지 업데이트 (PENDING_ANALYSIS는 PENDING으로 표시)
        const displayAction = action === 'PENDING_ANALYSIS' ? 'PENDING' : action;
        updateActionBadge(displayAction);

        // 메트릭 업데이트
        if (data.riskScore !== undefined && data.riskScore !== null) {
            updateMetrics(data.riskScore, data.confidence || 0);
        } else {
            // 분석 결과 없으면 메트릭 초기화
            updateMetrics(0, 0);
        }

        // MITRE 표시/숨기기
        if (data.mitre && data.mitre !== 'none') {
            showMitre(data.mitre);
        } else {
            hideMitre();
        }

        // Reasoning 표시/숨기기
        if (data.reasoning) {
            showReasoning(data.reasoning);
        } else if (data.analysisStatus === 'NOT_ANALYZED') {
            // 분석 결과 없음 메시지
            showReasoning('분석 결과 없음 - 보안 테스트 실행 시 LLM 분석이 수행됩니다.');
        } else {
            hideReasoning();
        }

        // 분석 상태에 따른 단계 표시 업데이트
        if (data.analysisStatus === 'ANALYZED') {
            // 캐시된 분석 결과가 있으면 모든 단계 완료로 표시
            updateStepStatus('context', 'completed', '완료');
            updateStepStatus('layer1', 'completed', '완료');
            updateStepStatus('decision', 'completed', '적용됨');
        } else if (data.analysisStatus === 'NOT_ANALYZED') {
            // 분석 결과 없으면 단계 초기화
            ['context', 'layer1', 'layer2', 'decision'].forEach(step => {
                updateStepStatus(step, 'waiting', '대기');
            });
        }
    }

    /**
     * 분석 UI만 초기화 (분석 결과 API 초기화 없이)
     */
    function resetAnalysisUI() {
        state.currentAction = 'PENDING';
        state.riskScore = 0;
        state.confidence = 0;
        state.mitre = null;
        state.reasoning = null;
        state.analysisPhase = 'idle';

        updateActionBadge('PENDING');
        updateMetrics(0, 0);

        if (elements.mitreDisplay) {
            elements.mitreDisplay.style.display = 'none';
        }
        if (elements.reasoningDisplay) {
            elements.reasoningDisplay.style.display = 'none';
        }

        ['context', 'layer1', 'layer2', 'decision'].forEach(step => {
            updateStepStatus(step, 'waiting', '대기');
        });

        if (elements.stepLayer2) {
            elements.stepLayer2.style.display = 'none';
        }
        if (elements.layer2Arrow) {
            elements.layer2Arrow.style.display = 'none';
        }
    }

    /**
     * 테스트 URL 생성
     */
    function getTestUrl(type, resourceId) {
        switch (type) {
            case 'normal':
                return API.TEST_NORMAL + encodeURIComponent(resourceId);
            case 'sensitive':
                return API.TEST_SENSITIVE + encodeURIComponent(resourceId);
            case 'critical':
                return API.TEST_CRITICAL + encodeURIComponent(resourceId);
            default:
                return null;
        }
    }

    /**
     * 테스트 유형 이름 반환
     */
    function getTestTypeName(type) {
        switch (type) {
            case 'normal': return '일반 데이터 (PREFERRED)';
            case 'sensitive': return '민감 데이터 (REQUIRED)';
            case 'critical': return '중요 데이터 (STRICT)';
            default: return type;
        }
    }

    /**
     * HTML 이스케이프
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ============================================================================
    // 이벤트 리스너
    // ============================================================================

    /**
     * 이벤트 리스너 바인딩
     */
    function bindEventListeners() {
        // 시나리오 카드 클릭
        document.querySelectorAll('.scenario-card').forEach(card => {
            card.addEventListener('click', function() {
                const scenario = this.dataset.scenario;
                if (scenario) {
                    selectScenario(scenario);
                }
            });
        });

        // 테스트 버튼
        if (elements.btnTestNormal) {
            elements.btnTestNormal.addEventListener('click', () => executeTest('normal'));
        }
        if (elements.btnTestSensitive) {
            elements.btnTestSensitive.addEventListener('click', () => executeTest('sensitive'));
        }
        if (elements.btnTestCritical) {
            elements.btnTestCritical.addEventListener('click', () => executeTest('critical'));
        }

        // 타임라인 초기화 버튼
        if (elements.btnClearTimeline) {
            elements.btnClearTimeline.addEventListener('click', clearTimeline);
        }

        // 분석 결과 초기화 버튼
        if (elements.btnResetAnalysis) {
            elements.btnResetAnalysis.addEventListener('click', resetAnalysis);
        }

        // AI Native v8.12: Action 리로드 버튼
        if (elements.reloadActionBtn) {
            elements.reloadActionBtn.addEventListener('click', reloadCurrentAction);
        }

        // 키보드 단축키
        document.addEventListener('keydown', function(event) {
            if (event.key === '1') selectScenario('NORMAL_USER');
            if (event.key === '2') selectScenario('ACCOUNT_TAKEOVER');
            if (event.key === '3') selectScenario('PRIVILEGE_ESCALATION');
        });
    }

    // ============================================================================
    // 초기화
    // ============================================================================

    /**
     * 애플리케이션 초기화
     */
    function initialize() {
        initializeElements();
        bindEventListeners();

        // SSE 연결
        connectSSE();

        // 초기 상태
        updateActionBadge('PENDING');
        updateMetrics(0, 0);

        addTimelineEntry('info', 'Contexa AI Native Zero Trust Security Platform');
        addTimelineEntry('info', '시나리오를 선택하고 테스트 버튼을 클릭하세요.');
    }

    // DOM 로드 완료 시 초기화
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
