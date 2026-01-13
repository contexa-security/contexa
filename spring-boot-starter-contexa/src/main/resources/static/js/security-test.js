/**
 * ============================================================================
 * @Protectable 보안 플로우 테스트 페이지 JavaScript (실제 LLM 분석)
 * ============================================================================
 *
 * 실제 LLM 분석을 통한 Zero Trust 보안 테스트 UI
 *
 * 실제 플로우:
 * 1. 클라이언트가 시나리오 선택 (IP, User-Agent 설정)
 * 2. 1차 요청: @Protectable 메서드 호출 -> 이벤트 발행 -> LLM 분석 트리거
 * 3. 대기: ColdPathEventProcessor의 비동기 분석 완료 대기 (3초)
 * 4. 2차 요청: Redis에 저장된 분석 결과 기반 허용/차단
 *
 * API 엔드포인트:
 * - GET  /api/test-action/status  : 현재 분석 결과 조회
 * - DELETE /api/test-action/reset : 분석 결과 초기화
 * - GET  /api/security-test/*     : @Protectable 메서드 테스트
 *
 * 컨텍스트 전달:
 * - X-Forwarded-For: 클라이언트 IP (시나리오별)
 * - User-Agent: 브라우저/도구 정보 (시나리오별)
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
        ACTION_STATUS: '/api/test-action/status',
        ACTION_RESET: '/api/test-action/reset',
        TEST_PUBLIC: '/api/security-test/public/',
        TEST_NORMAL: '/api/security-test/normal/',
        TEST_SENSITIVE: '/api/security-test/sensitive/',
        TEST_CRITICAL: '/api/security-test/critical/',
        // Admin Override API (AI Native v3.5.0)
        OVERRIDE_PENDING: '/api/admin/override/pending/current',
        OVERRIDE_APPROVE: '/api/admin/override/approve',
        OVERRIDE_REJECT: '/api/admin/override/reject'
    };

    /**
     * 시나리오별 HTTP 헤더 프리셋
     * 실제 플로우에서 HCADFilter와 SecurityEventPublishingFilter가
     * X-Forwarded-For 헤더에서 IP를 추출함
     */
    const SCENARIO_HEADERS = {
        'NORMAL_USER': {
            'X-Forwarded-For': '192.168.1.100',
            'X-Simulated-User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        },
        'ACCOUNT_TAKEOVER': {
            'X-Forwarded-For': '203.0.113.50',
            'X-Simulated-User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
        },
        'BOT_ATTACK': {
            'X-Forwarded-For': '45.33.32.156',
            'X-Simulated-User-Agent': 'curl/7.68.0'
        },
        'PRIVILEGE_ESCALATION': {
            'X-Forwarded-For': '10.0.0.99',
            'X-Simulated-User-Agent': 'python-requests/2.28.0'
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
            expectedAction: 'ALLOW',
            description: '사내 네트워크에서 일반 브라우저로 접속하는 정상 사용자'
        },
        'ACCOUNT_TAKEOVER': {
            name: '계정 탈취 의심',
            ip: '203.0.113.50',
            userAgent: 'Android 10 (Mobile)',
            expectedAction: 'BLOCK / CHALLENGE',
            description: '평소와 다른 위치/디바이스에서의 갑작스러운 접속'
        },
        'BOT_ATTACK': {
            name: '봇 공격',
            ip: '45.33.32.156',
            userAgent: 'curl/7.68.0',
            expectedAction: 'BLOCK',
            description: '자동화 도구를 사용한 악성 봇의 접근 시도'
        },
        'PRIVILEGE_ESCALATION': {
            name: '권한 상승 시도',
            ip: '10.0.0.99',
            userAgent: 'Python-requests/2.28',
            expectedAction: 'ESCALATE / BLOCK',
            description: '일반 사용자가 관리자 리소스에 접근 시도'
        }
    };

    /**
     * Action 정보 매핑
     */
    const ACTION_INFO = {
        'ALLOW': {
            description: '정상 접근이 허용됩니다. LLM 분석 결과 안전한 요청으로 판단되었습니다.',
            badgeClass: 'action-ALLOW'
        },
        'MONITOR': {
            description: '접근은 허용되지만 모니터링됩니다. 추가 분석을 위해 로그가 수집됩니다.',
            badgeClass: 'action-MONITOR'
        },
        'CHALLENGE': {
            description: '추가 인증이 필요합니다. MFA 또는 재인증을 요청할 수 있습니다.',
            badgeClass: 'action-CHALLENGE'
        },
        'INVESTIGATE': {
            description: '수동 조사가 필요합니다. 보안팀의 검토가 진행됩니다.',
            badgeClass: 'action-INVESTIGATE'
        },
        'ESCALATE': {
            description: '상위 권한자에게 에스컬레이션됩니다. 긴급 대응이 필요합니다.',
            badgeClass: 'action-ESCALATE'
        },
        'BLOCK': {
            description: '접근이 차단됩니다. LLM 분석 결과 위험한 요청으로 판단되었습니다.',
            badgeClass: 'action-BLOCK'
        },
        'PENDING_ANALYSIS': {
            description: 'LLM 분석이 진행 중이거나 아직 시작되지 않았습니다.',
            badgeClass: 'action-PENDING_ANALYSIS'
        }
    };

    /**
     * Threat Level 정보 매핑
     */
    const THREAT_LEVEL_INFO = {
        'CRITICAL': { badgeClass: 'threat-CRITICAL' },
        'HIGH': { badgeClass: 'threat-HIGH' },
        'MEDIUM': { badgeClass: 'threat-MEDIUM' },
        'LOW': { badgeClass: 'threat-LOW' },
        'INFO': { badgeClass: 'threat-INFO' },
        'UNKNOWN': { badgeClass: 'threat-UNKNOWN' }
    };

    /**
     * 로그 레벨별 CSS 클래스
     */
    const LOG_LEVELS = {
        INFO: 'log-info',
        SUCCESS: 'log-success',
        WARNING: 'log-warning',
        ERROR: 'log-error',
        BLOCKED: 'log-blocked',
        STEP: 'log-step'
    };

    /**
     * 테스트 유형 정보
     */
    const TEST_INFO = {
        'public': {
            name: '공개 데이터',
            analysisRequirement: 'NOT_REQUIRED',
            description: '분석 불필요 - 인증만 확인'
        },
        'normal': {
            name: '일반 데이터',
            analysisRequirement: 'PREFERRED',
            description: '분석 있으면 사용, 없으면 기본값 (MONITOR)'
        },
        'sensitive': {
            name: '민감 데이터',
            analysisRequirement: 'REQUIRED',
            description: '분석 완료 필수 (동기 대기 3초)'
        },
        'critical': {
            name: '중요 데이터',
            analysisRequirement: 'STRICT',
            description: 'ADMIN 권한 + 분석 완료 + ALLOW만 허용'
        }
    };

    /**
     * LLM 분석 대기 시간 (밀리초)
     */
    const ANALYSIS_WAIT_TIME = 100000000;

    // ============================================================================
    // 상태 관리
    // ============================================================================

    /**
     * 애플리케이션 상태
     */
    const state = {
        selectedScenario: null,
        currentAction: 'PENDING_ANALYSIS',
        riskScore: 0.0,
        confidence: 0.0,
        threatLevel: 'UNKNOWN',
        isAnomaly: false,
        analysisStatus: 'NOT_ANALYZED',
        isLoading: false,
        isTestRunning: false,
        logEntries: [],
        // Admin Override (AI Native v3.5.0)
        pendingRequest: null,
        hasPendingRequest: false
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
            // Action 상태 표시
            currentAction: document.getElementById('current-action'),
            riskScore: document.getElementById('risk-score'),
            confidence: document.getElementById('confidence'),
            threatLevel: document.getElementById('threat-level'),
            isAnomaly: document.getElementById('is-anomaly'),
            analysisStatus: document.getElementById('analysis-status'),

            // 시나리오 카드
            scenarioNormal: document.getElementById('scenario-normal'),
            scenarioTakeover: document.getElementById('scenario-takeover'),
            scenarioBot: document.getElementById('scenario-bot'),
            scenarioEscalation: document.getElementById('scenario-escalation'),
            selectedScenarioInfo: document.getElementById('selected-scenario-info'),

            // 버튼
            btnRefreshStatus: document.getElementById('btn-refresh-status'),
            btnResetAction: document.getElementById('btn-reset-action'),
            btnClearLog: document.getElementById('btn-clear-log'),

            // 테스트 버튼
            btnTestPublic: document.getElementById('btn-test-public'),
            btnTestNormal: document.getElementById('btn-test-normal'),
            btnTestSensitive: document.getElementById('btn-test-sensitive'),
            btnTestCritical: document.getElementById('btn-test-critical'),

            // 테스트 입력
            inputPublic: document.getElementById('input-public'),
            inputNormal: document.getElementById('input-normal'),
            inputSensitive: document.getElementById('input-sensitive'),
            inputCritical: document.getElementById('input-critical'),

            // 테스트 카드
            cardPublic: document.getElementById('card-public'),
            cardNormal: document.getElementById('card-normal'),
            cardSensitive: document.getElementById('card-sensitive'),
            cardCritical: document.getElementById('card-critical'),

            // 로그
            logContainer: document.getElementById('log-container'),
            autoScrollCheckbox: document.getElementById('auto-scroll'),

            // Admin Override (AI Native v3.5.0)
            pendingStatus: document.getElementById('pending-status'),
            pendingDetails: document.getElementById('pending-details'),
            pendingRequestId: document.getElementById('pending-request-id'),
            pendingUserId: document.getElementById('pending-user-id'),
            pendingAction: document.getElementById('pending-action'),
            pendingRiskScore: document.getElementById('pending-risk-score'),
            pendingConfidence: document.getElementById('pending-confidence'),
            pendingReasoning: document.getElementById('pending-reasoning'),
            overrideForm: document.getElementById('override-form'),
            overrideReason: document.getElementById('override-reason'),
            baselineUpdateAllowed: document.getElementById('baseline-update-allowed'),
            btnApprove: document.getElementById('btn-approve'),
            btnReject: document.getElementById('btn-reject'),
            btnRefreshPending: document.getElementById('btn-refresh-pending'),
            overrideResult: document.getElementById('override-result'),
            overrideResultContent: document.getElementById('override-result-content')
        };
    }

    // ============================================================================
    // API 통신
    // ============================================================================

    /**
     * HTTP 요청 수행 (시나리오 헤더 포함)
     *
     * @param {string} url - 요청 URL
     * @param {Object} options - fetch 옵션
     * @param {boolean} includeScenarioHeaders - 시나리오 헤더 포함 여부
     * @returns {Promise<Object>} - 응답 JSON
     */
    async function request(url, options = {}, includeScenarioHeaders = false) {
        const defaultHeaders = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };

        // 시나리오 헤더 추가
        let scenarioHeaders = {};
        if (includeScenarioHeaders && state.selectedScenario) {
            scenarioHeaders = SCENARIO_HEADERS[state.selectedScenario] || {};
        }

        const mergedOptions = {
            ...options,
            headers: {
                ...defaultHeaders,
                ...scenarioHeaders,
                ...options.headers
            },
            credentials: 'same-origin'
        };

        try {
            const response = await fetch(url, mergedOptions);
            const contentType = response.headers.get('content-type');

            if (contentType && contentType.includes('application/json')) {
                const data = await response.json();

                if (!response.ok) {
                    throw new ApiError(
                        data.message || data.error || `HTTP ${response.status}`,
                        response.status,
                        data
                    );
                }

                return data;
            } else {
                const text = await response.text();
                throw new ApiError(
                    extractErrorMessage(text, response.status),
                    response.status,
                    { rawResponse: text }
                );
            }
        } catch (error) {
            if (error instanceof ApiError) {
                throw error;
            }
            throw new ApiError(error.message, 0, { originalError: error });
        }
    }

    /**
     * API 에러 클래스
     */
    class ApiError extends Error {
        constructor(message, status, data) {
            super(message);
            this.name = 'ApiError';
            this.status = status;
            this.data = data;
        }
    }

    /**
     * HTML 응답에서 에러 메시지 추출
     */
    function extractErrorMessage(html, status) {
        if (status === 403) {
            if (html.includes('ZeroTrustAccessDeniedException')) {
                return 'Zero Trust 보안 정책에 의해 접근이 거부되었습니다.';
            }
            if (html.includes('AccessDeniedException')) {
                return '접근이 거부되었습니다. (AccessDeniedException)';
            }
            return '접근이 거부되었습니다. (HTTP 403)';
        }

        if (status === 401) {
            return '인증이 필요합니다. 로그인 후 다시 시도하세요.';
        }

        if (status === 500) {
            const exceptionMatch = html.match(/([A-Za-z]+Exception)/);
            if (exceptionMatch) {
                return `서버 오류: ${exceptionMatch[1]}`;
            }
            return '서버 내부 오류가 발생했습니다. (HTTP 500)';
        }

        return `요청 처리 중 오류가 발생했습니다. (HTTP ${status})`;
    }

    // ============================================================================
    // 시나리오 선택
    // ============================================================================

    /**
     * 시나리오 선택 처리
     *
     * @param {string} scenario - 시나리오 키
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

        // 선택된 시나리오 정보 표시
        const info = SCENARIO_INFO[scenario];
        if (info && elements.selectedScenarioInfo) {
            elements.selectedScenarioInfo.innerHTML = `
                <p><strong>선택된 시나리오:</strong> ${escapeHtml(info.name)}</p>
                <p><strong>IP:</strong> ${escapeHtml(info.ip)} | <strong>User-Agent:</strong> ${escapeHtml(info.userAgent)}</p>
                <p><strong>예상 LLM 판단:</strong> ${escapeHtml(info.expectedAction)}</p>
            `;
            elements.selectedScenarioInfo.classList.add('active');
        }

        log('INFO', `시나리오 선택: ${info.name} (IP: ${info.ip})`);
    }

    // ============================================================================
    // Action 상태 관리
    // ============================================================================

    /**
     * Action 상태 조회 및 UI 갱신
     */
    async function refreshActionStatus() {
        if (state.isLoading) return;

        setLoading(true);
        log('INFO', 'LLM 분석 결과 조회 중...');

        try {
            const data = await request(API.ACTION_STATUS);

            state.currentAction = data.action || 'PENDING_ANALYSIS';
            state.riskScore = data.riskScore || 0.0;
            state.confidence = data.confidence || 0.0;
            state.threatLevel = data.threatLevel || 'UNKNOWN';
            state.isAnomaly = data.isAnomaly || false;
            state.analysisStatus = data.analysisStatus || 'NOT_ANALYZED';

            updateStatusDisplay();

            log('SUCCESS', `분석 결과: Action=${state.currentAction}, Risk=${state.riskScore.toFixed(2)}, Confidence=${state.confidence.toFixed(2)}`);
        } catch (error) {
            log('ERROR', `분석 결과 조회 실패: ${error.message}`);
            console.error('Action status error:', error);
        } finally {
            setLoading(false);
        }
    }

    /**
     * Action 초기화 (PENDING_ANALYSIS로 복귀)
     */
    async function resetAction() {
        if (state.isLoading) return;

        setLoading(true);
        log('INFO', '분석 결과 초기화 중...');

        try {
            await request(API.ACTION_RESET, { method: 'DELETE' });

            state.currentAction = 'PENDING_ANALYSIS';
            state.riskScore = 0.0;
            state.confidence = 0.0;
            state.threatLevel = 'UNKNOWN';
            state.isAnomaly = false;
            state.analysisStatus = 'NOT_ANALYZED';

            updateStatusDisplay();

            log('SUCCESS', '분석 결과가 초기화되었습니다. 새로운 시나리오 테스트를 시작할 수 있습니다.');
        } catch (error) {
            log('ERROR', `초기화 실패: ${error.message}`);
            console.error('Reset action error:', error);
        } finally {
            setLoading(false);
        }
    }

    // ============================================================================
    // 보안 API 테스트 (두 번의 요청 패턴)
    // ============================================================================

    /**
     * 보안 API 테스트 실행 (두 번의 요청)
     *
     * 실제 플로우:
     * 1. 1차 요청: 분석 트리거 (defaultAction 사용 또는 타임아웃)
     * 2. 대기: ColdPathEventProcessor의 비동기 분석 완료 대기
     * 3. 2차 요청: 분석 결과 기반 허용/차단
     *
     * @param {string} type - 테스트 유형 (public, normal, sensitive, critical)
     * @param {string} resourceId - 리소스 ID
     */
    async function executeTest(type, resourceId) {
        if (state.isTestRunning) {
            log('WARNING', '테스트가 이미 실행 중입니다.');
            return;
        }

        if (!state.selectedScenario) {
            log('WARNING', '먼저 시나리오를 선택하세요.');
            return;
        }

        const testInfo = TEST_INFO[type];
        const scenarioInfo = SCENARIO_INFO[state.selectedScenario];
        const card = getTestCard(type);

        // 카드 상태 초기화
        resetCardState(card);

        state.isTestRunning = true;
        setLoading(true);

        const logPrefix = `[${testInfo.name}]`;
        log('STEP', `========== 테스트 시작 ==========`);
        log('INFO', `${logPrefix} 시나리오: ${scenarioInfo.name}`);
        log('INFO', `${logPrefix} 컨텍스트: IP=${scenarioInfo.ip}, UA=${scenarioInfo.userAgent}`);
        log('INFO', `${logPrefix} AnalysisRequirement: ${testInfo.analysisRequirement}`);

        // URL 구성
        const url = getTestUrl(type, resourceId);
        if (!url) {
            log('ERROR', `${logPrefix} 알 수 없는 테스트 유형: ${type}`);
            state.isTestRunning = false;
            setLoading(false);
            return;
        }

        try {
            // ===== 1차 요청: 분석 트리거 =====
            log('STEP', `${logPrefix} [1차 요청] 분석 트리거 중...`);
            log('INFO', `${logPrefix} X-Forwarded-For: ${scenarioInfo.ip}`);

            let firstRequestSuccess = false;
            let firstRequestMessage = '';

            try {
                const startTime1 = performance.now();
                const data1 = await request(url, {}, true);
                const elapsed1 = (performance.now() - startTime1).toFixed(0);

                firstRequestSuccess = true;
                firstRequestMessage = `1차 요청 성공 (${elapsed1}ms)`;
                log('SUCCESS', `${logPrefix} ${firstRequestMessage}`);
            } catch (error1) {
                // 1차 요청 실패는 예상됨 (REQUIRED/STRICT의 경우 타임아웃)
                firstRequestMessage = `1차 요청: ${error1.message}`;
                if (error1.status === 403) {
                    log('WARNING', `${logPrefix} 1차 요청 차단됨 (예상된 동작) - ${error1.message}`);
                } else {
                    log('WARNING', `${logPrefix} 1차 요청 오류 - ${error1.message}`);
                }
            }

            // ===== 대기: 비동기 분석 완료 =====
            log('STEP', `${logPrefix} [대기] LLM 분석 완료 대기 (${ANALYSIS_WAIT_TIME/1000}초)...`);
            log('INFO', `${logPrefix} ColdPathEventProcessor -> Layer1/2/3 분석 -> Redis 저장`);

            /*await sleep(ANALYSIS_WAIT_TIME);

            // 분석 결과 조회
            log('INFO', `${logPrefix} 분석 결과 조회 중...`);
            try {
                const statusData = await request(API.ACTION_STATUS);
                state.currentAction = statusData.action || 'PENDING_ANALYSIS';
                state.riskScore = statusData.riskScore || 0.0;
                state.confidence = statusData.confidence || 0.0;
                state.threatLevel = statusData.threatLevel || 'UNKNOWN';
                state.isAnomaly = statusData.isAnomaly || false;
                state.analysisStatus = statusData.analysisStatus || 'NOT_ANALYZED';
                updateStatusDisplay();

                log('INFO', `${logPrefix} LLM 분석 결과: Action=${state.currentAction}, Risk=${state.riskScore.toFixed(2)}`);
            } catch (statusError) {
                log('WARNING', `${logPrefix} 분석 결과 조회 실패: ${statusError.message}`);
            }

            // ===== 2차 요청: 분석 결과 기반 =====
            log('STEP', `${logPrefix} [2차 요청] 분석 결과 기반 접근 시도...`);

            const startTime2 = performance.now();
            const data2 = await request(url, {}, true);
            const elapsed2 = (performance.now() - startTime2).toFixed(0);

            // 2차 요청 성공
            setCardSuccess(card);
            log('SUCCESS', `${logPrefix} 2차 요청 성공 - 접근 허용됨 (${elapsed2}ms)`);
            log('SUCCESS', `${logPrefix} LLM Action: ${state.currentAction}, 응답: "${data2.data}"`);

        } catch (error) {
            // 2차 요청 실패
            setCardFailed(card);

            if (error.status === 403) {
                log('BLOCKED', `${logPrefix} 2차 요청 차단됨 - ${error.message}`);
                log('INFO', `${logPrefix} LLM이 '${state.currentAction}' Action을 결정하여 접근이 거부되었습니다.`);
            } else if (error.status === 401) {
                log('ERROR', `${logPrefix} 인증 실패 - ${error.message}`);
            } else {
                log('ERROR', `${logPrefix} 오류 - ${error.message}`);
            }

            console.error(`Test ${type} error:`, error);*/
        } finally {
            log('STEP', `========== 테스트 완료 ==========`);
            state.isTestRunning = false;
            setLoading(false);
        }
    }

    /**
     * 테스트 URL 구성
     *
     * @param {string} type - 테스트 유형
     * @param {string} resourceId - 리소스 ID
     * @returns {string|null} - URL 또는 null
     */
    function getTestUrl(type, resourceId) {
        switch (type) {
            case 'public':
                return API.TEST_PUBLIC + encodeURIComponent(resourceId);
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
     * 대기 함수
     *
     * @param {number} ms - 대기 시간 (밀리초)
     * @returns {Promise<void>}
     */
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * 테스트 카드 요소 가져오기
     */
    function getTestCard(type) {
        switch (type) {
            case 'public': return elements.cardPublic;
            case 'normal': return elements.cardNormal;
            case 'sensitive': return elements.cardSensitive;
            case 'critical': return elements.cardCritical;
            default: return null;
        }
    }

    /**
     * 카드 상태 초기화
     */
    function resetCardState(card) {
        if (!card) return;
        card.classList.remove('success', 'failed', 'testing');
    }

    /**
     * 카드 성공 상태 설정
     */
    function setCardSuccess(card) {
        if (!card) return;
        card.classList.remove('failed', 'testing');
        card.classList.add('success');
    }

    /**
     * 카드 실패 상태 설정
     */
    function setCardFailed(card) {
        if (!card) return;
        card.classList.remove('success', 'testing');
        card.classList.add('failed');
    }

    // ============================================================================
    // UI 갱신
    // ============================================================================

    /**
     * Action 상태 표시 갱신
     */
    function updateStatusDisplay() {
        // Action 배지
        const actionInfo = ACTION_INFO[state.currentAction] || ACTION_INFO['PENDING_ANALYSIS'];
        if (elements.currentAction) {
            elements.currentAction.textContent = state.currentAction;
            elements.currentAction.className = `value action-badge ${actionInfo.badgeClass}`;
        }

        // Risk Score
        if (elements.riskScore) {
            elements.riskScore.textContent = state.riskScore.toFixed(2);
        }

        // Confidence
        if (elements.confidence) {
            elements.confidence.textContent = state.confidence.toFixed(2);
        }

        // Threat Level 배지
        const threatInfo = THREAT_LEVEL_INFO[state.threatLevel] || THREAT_LEVEL_INFO['UNKNOWN'];
        if (elements.threatLevel) {
            elements.threatLevel.textContent = state.threatLevel;
            elements.threatLevel.className = `value threat-badge ${threatInfo.badgeClass}`;
        }

        // Is Anomaly
        if (elements.isAnomaly) {
            elements.isAnomaly.textContent = state.isAnomaly ? 'Yes' : 'No';
            elements.isAnomaly.style.color = state.isAnomaly ? '#c62828' : '#2e7d32';
        }

        // Analysis Status
        if (elements.analysisStatus) {
            elements.analysisStatus.textContent = state.analysisStatus === 'ANALYZED' ? 'Analyzed' : 'Not Analyzed';
            elements.analysisStatus.style.color = state.analysisStatus === 'ANALYZED' ? '#2e7d32' : '#666';
        }
    }

    /**
     * 로딩 상태 설정
     */
    function setLoading(loading) {
        state.isLoading = loading;

        const buttons = [
            elements.btnRefreshStatus,
            elements.btnResetAction,
            elements.btnTestPublic,
            elements.btnTestNormal,
            elements.btnTestSensitive,
            elements.btnTestCritical
        ];

        buttons.forEach(btn => {
            if (btn) {
                btn.disabled = loading;
                if (loading) {
                    btn.classList.add('loading');
                } else {
                    btn.classList.remove('loading');
                }
            }
        });
    }

    // ============================================================================
    // 로깅
    // ============================================================================

    /**
     * 로그 메시지 추가
     */
    function log(level, message) {
        const timestamp = new Date().toLocaleTimeString('ko-KR', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            fractionalSecondDigits: 3
        });

        const entry = {
            timestamp: timestamp,
            level: level,
            message: message
        };

        state.logEntries.push(entry);

        // DOM에 로그 엔트리 추가
        const logElement = document.createElement('div');
        logElement.className = `log-entry ${LOG_LEVELS[level] || LOG_LEVELS.INFO}`;
        logElement.innerHTML = `
            <span class="log-time">${escapeHtml(timestamp)}</span>
            <span class="log-message">${escapeHtml(message)}</span>
        `;

        if (elements.logContainer) {
            elements.logContainer.appendChild(logElement);

            // 자동 스크롤
            if (elements.autoScrollCheckbox && elements.autoScrollCheckbox.checked) {
                elements.logContainer.scrollTop = elements.logContainer.scrollHeight;
            }
        }
    }

    /**
     * 로그 전체 삭제
     */
    function clearLog() {
        state.logEntries = [];
        if (elements.logContainer) {
            elements.logContainer.innerHTML = '';
        }
        log('INFO', '로그가 초기화되었습니다.');
    }

    // ============================================================================
    // Admin Override (AI Native v3.5.0)
    // ============================================================================

    /**
     * 대기 중인 요청 조회
     */
    async function checkPendingRequest() {
        log('INFO', '[Admin Override] 대기 중인 요청 확인 중...');

        try {
            const data = await request(API.OVERRIDE_PENDING);

            state.hasPendingRequest = data.hasPending || false;
            state.pendingRequest = data;

            updatePendingDisplay();

            if (state.hasPendingRequest) {
                log('WARNING', `[Admin Override] 대기 중인 요청 발견: Action=${data.action}, Risk=${data.riskScore}`);
            } else {
                log('INFO', '[Admin Override] 대기 중인 요청 없음');
            }

        } catch (error) {
            log('ERROR', `[Admin Override] 대기 요청 조회 실패: ${error.message}`);
            state.hasPendingRequest = false;
            state.pendingRequest = null;
            updatePendingDisplay();
        }
    }

    /**
     * 대기 요청 표시 갱신
     */
    function updatePendingDisplay() {
        if (!elements.pendingStatus) return;

        if (!state.hasPendingRequest || !state.pendingRequest) {
            elements.pendingStatus.textContent = '없음';
            elements.pendingStatus.style.color = '#2e7d32';
            if (elements.pendingDetails) elements.pendingDetails.style.display = 'none';
            if (elements.overrideForm) elements.overrideForm.style.display = 'none';
            if (elements.overrideResult) elements.overrideResult.style.display = 'none';
            return;
        }

        const data = state.pendingRequest;

        elements.pendingStatus.textContent = '있음 (관리자 검토 필요)';
        elements.pendingStatus.style.color = '#c62828';

        if (elements.pendingDetails) {
            elements.pendingDetails.style.display = 'block';
        }

        if (elements.pendingRequestId) {
            elements.pendingRequestId.textContent = data.requestId || '-';
        }
        if (elements.pendingUserId) {
            elements.pendingUserId.textContent = data.userId || '-';
        }
        if (elements.pendingAction) {
            elements.pendingAction.textContent = data.action || '-';
            const actionInfo = ACTION_INFO[data.action] || {};
            elements.pendingAction.className = `value action-badge ${actionInfo.badgeClass || ''}`;
        }
        if (elements.pendingRiskScore) {
            elements.pendingRiskScore.textContent = (data.riskScore || 0).toFixed(2);
        }
        if (elements.pendingConfidence) {
            elements.pendingConfidence.textContent = (data.confidence || 0).toFixed(2);
        }
        if (elements.pendingReasoning) {
            elements.pendingReasoning.textContent = data.reasoning || '-';
        }

        if (elements.overrideForm) {
            elements.overrideForm.style.display = 'block';
        }
    }

    /**
     * 요청 승인 처리
     */
    async function approveRequest() {
        if (!state.pendingRequest) {
            log('WARNING', '[Admin Override] 승인할 요청이 없습니다.');
            return;
        }

        const reason = elements.overrideReason ? elements.overrideReason.value.trim() : '';
        if (!reason) {
            log('WARNING', '[Admin Override] 승인 사유를 입력하세요.');
            alert('승인 사유를 입력하세요.');
            return;
        }

        const baselineUpdateAllowed = elements.baselineUpdateAllowed ?
            elements.baselineUpdateAllowed.checked : false;

        const data = state.pendingRequest;
        const requestBody = {
            requestId: data.requestId,
            userId: data.userId,
            originalAction: data.action,
            originalRiskScore: data.riskScore || 0,
            originalConfidence: data.confidence || 0,
            reason: reason,
            baselineUpdateAllowed: baselineUpdateAllowed
        };

        log('INFO', `[Admin Override] 승인 처리 중... (baselineUpdateAllowed=${baselineUpdateAllowed})`);

        try {
            const result = await request(API.OVERRIDE_APPROVE, {
                method: 'POST',
                body: JSON.stringify(requestBody)
            });

            if (result.success) {
                log('SUCCESS', `[Admin Override] 승인 완료: ${result.message}`);
                showOverrideResult(result);

                // 상태 갱신
                state.hasPendingRequest = false;
                state.pendingRequest = null;
                updatePendingDisplay();

                // Action 상태 갱신
                await refreshActionStatus();
            } else {
                log('ERROR', `[Admin Override] 승인 실패: ${result.error}`);
            }

        } catch (error) {
            log('ERROR', `[Admin Override] 승인 처리 오류: ${error.message}`);
        }
    }

    /**
     * 요청 거부 처리
     */
    async function rejectRequest() {
        if (!state.pendingRequest) {
            log('WARNING', '[Admin Override] 거부할 요청이 없습니다.');
            return;
        }

        const reason = elements.overrideReason ? elements.overrideReason.value.trim() : '';
        if (!reason) {
            log('WARNING', '[Admin Override] 거부 사유를 입력하세요.');
            alert('거부 사유를 입력하세요.');
            return;
        }

        const data = state.pendingRequest;
        const requestBody = {
            requestId: data.requestId,
            userId: data.userId,
            originalAction: data.action,
            originalRiskScore: data.riskScore || 0,
            originalConfidence: data.confidence || 0,
            reason: reason
        };

        log('INFO', '[Admin Override] 거부 처리 중...');

        try {
            const result = await request(API.OVERRIDE_REJECT, {
                method: 'POST',
                body: JSON.stringify(requestBody)
            });

            if (result.success) {
                log('SUCCESS', `[Admin Override] 거부 완료: ${result.message}`);
                showOverrideResult(result);

                // 상태 갱신
                state.hasPendingRequest = false;
                state.pendingRequest = null;
                updatePendingDisplay();
            } else {
                log('ERROR', `[Admin Override] 거부 실패: ${result.error}`);
            }

        } catch (error) {
            log('ERROR', `[Admin Override] 거부 처리 오류: ${error.message}`);
        }
    }

    /**
     * Override 결과 표시
     */
    function showOverrideResult(result) {
        if (elements.overrideResult && elements.overrideResultContent) {
            elements.overrideResult.style.display = 'block';
            elements.overrideResultContent.textContent = JSON.stringify(result, null, 2);
        }
    }

    /**
     * HTML 특수문자 이스케이프
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ============================================================================
    // 이벤트 핸들러
    // ============================================================================

    /**
     * 이벤트 리스너 등록
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

        // 상태 새로고침 버튼
        if (elements.btnRefreshStatus) {
            elements.btnRefreshStatus.addEventListener('click', refreshActionStatus);
        }

        // 초기화 버튼
        if (elements.btnResetAction) {
            elements.btnResetAction.addEventListener('click', resetAction);
        }

        // 테스트 버튼
        if (elements.btnTestPublic) {
            elements.btnTestPublic.addEventListener('click', function() {
                const resourceId = elements.inputPublic ? elements.inputPublic.value : 'resource-001';
                executeTest('public', resourceId || 'resource-001');
            });
        }

        if (elements.btnTestNormal) {
            elements.btnTestNormal.addEventListener('click', function() {
                const resourceId = elements.inputNormal ? elements.inputNormal.value : 'resource-002';
                executeTest('normal', resourceId || 'resource-002');
            });
        }

        if (elements.btnTestSensitive) {
            elements.btnTestSensitive.addEventListener('click', function() {
                const resourceId = elements.inputSensitive ? elements.inputSensitive.value : 'resource-003';
                executeTest('sensitive', resourceId || 'resource-003');
            });
        }

        if (elements.btnTestCritical) {
            elements.btnTestCritical.addEventListener('click', function() {
                const resourceId = elements.inputCritical ? elements.inputCritical.value : 'resource-004';
                executeTest('critical', resourceId || 'resource-004');
            });
        }

        // 로그 삭제 버튼
        if (elements.btnClearLog) {
            elements.btnClearLog.addEventListener('click', clearLog);
        }

        // Admin Override 버튼 (AI Native v3.5.0)
        if (elements.btnApprove) {
            elements.btnApprove.addEventListener('click', approveRequest);
        }

        if (elements.btnReject) {
            elements.btnReject.addEventListener('click', rejectRequest);
        }

        if (elements.btnRefreshPending) {
            elements.btnRefreshPending.addEventListener('click', checkPendingRequest);
        }

        // 키보드 단축키
        document.addEventListener('keydown', function(event) {
            // Ctrl + R: 상태 새로고침
            if (event.ctrlKey && event.key === 'r') {
                event.preventDefault();
                refreshActionStatus();
            }

            // 숫자 키로 시나리오 선택
            if (event.key === '1') selectScenario('NORMAL_USER');
            if (event.key === '2') selectScenario('ACCOUNT_TAKEOVER');
            if (event.key === '3') selectScenario('BOT_ATTACK');
            if (event.key === '4') selectScenario('PRIVILEGE_ESCALATION');
        });
    }

    // ============================================================================
    // 초기화
    // ============================================================================

    /**
     * 애플리케이션 초기화
     */
    function initialize() {
        // DOM 요소 초기화
        initializeElements();

        // 이벤트 리스너 등록
        bindEventListeners();

        // 초기 로그 메시지
        log('INFO', '@Protectable 보안 플로우 테스트 페이지가 로드되었습니다.');
        log('INFO', '실제 LLM 분석을 통한 Zero Trust 테스트입니다.');
        log('INFO', '1. 시나리오를 선택하세요 (1-4 키 또는 카드 클릭)');
        log('INFO', '2. 테스트 버튼을 클릭하면 두 번의 요청이 자동 실행됩니다.');
        log('INFO', '');

        // 초기 상태 조회
        refreshActionStatus();

        // Admin Override 대기 요청 확인 (AI Native v3.5.0)
        checkPendingRequest();
    }

    // DOM 로드 완료 시 초기화
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
