/**
 * ============================================================================
 * @Protectable 보안 플로우 테스트 페이지 JavaScript
 * ============================================================================
 *
 * 이 스크립트는 @Protectable 어노테이션이 적용된 메서드들의 실제 보안 플로우를
 * 테스트하기 위한 UI 기능을 제공한다.
 *
 * 주요 기능:
 * 1. Action 상태 조회 및 갱신
 * 2. Action 강제 설정 (테스트용)
 * 3. 보안 API 테스트 실행
 * 4. 실행 결과 로깅
 *
 * API 엔드포인트:
 * - GET  /api/test-action/status  : 현재 Action 상태 조회
 * - POST /api/test-action/set     : Action 강제 설정
 * - DELETE /api/test-action/reset : Action 초기화 (PENDING_ANALYSIS로 복귀)
 * - GET  /api/security-test/*     : @Protectable 메서드 테스트
 *
 * Redis 구조:
 * - security:hcad:analysis:{userId} (Hash)
 *   - action: ALLOW, BLOCK, CHALLENGE, INVESTIGATE, ESCALATE, MONITOR
 *   - riskScore: 0.0 ~ 1.0
 *   - confidence: 0.0 ~ 1.0
 *   - threatLevel: CRITICAL, HIGH, MEDIUM, LOW, INFO
 *   - isAnomaly: true/false
 *   - updatedAt: ISO-8601 타임스탬프
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
        ACTION_SET: '/api/test-action/set',
        ACTION_RESET: '/api/test-action/reset',
        TEST_PUBLIC: '/api/security-test/public/',
        TEST_NORMAL: '/api/security-test/normal/',
        TEST_SENSITIVE: '/api/security-test/sensitive/',
        TEST_CRITICAL: '/api/security-test/critical/',
        TEST_BULK: '/api/security-test/bulk'
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
        BLOCKED: 'log-blocked'
    };

    /**
     * 테스트 유형 정보
     */
    const TEST_INFO = {
        'public': {
            name: '공개 데이터',
            analysisRequirement: 'NOT_REQUIRED',
            description: '인증만 확인, Action 무관'
        },
        'normal': {
            name: '일반 데이터',
            analysisRequirement: 'PREFERRED',
            description: 'ALLOW 또는 MONITOR Action 필요'
        },
        'sensitive': {
            name: '민감 데이터',
            analysisRequirement: 'REQUIRED',
            description: '분석 완료 + ALLOW/MONITOR 필수'
        },
        'critical': {
            name: '중요 데이터',
            analysisRequirement: 'STRICT',
            description: 'ADMIN + 분석 완료 + ALLOW만 허용'
        },
        'bulk': {
            name: '대량 데이터',
            analysisRequirement: 'PREFERRED + Runtime Interception',
            description: 'BLOCK 아니면 허용 (기본 MONITOR)'
        }
    };

    // ============================================================================
    // 상태 관리
    // ============================================================================

    /**
     * 애플리케이션 상태
     */
    const state = {
        currentAction: 'PENDING_ANALYSIS',
        riskScore: 0.0,
        confidence: 0.0,
        threatLevel: 'UNKNOWN',
        isAnomaly: false,
        analysisStatus: 'NOT_ANALYZED',
        isLoading: false,
        autoRefresh: false,
        autoRefreshInterval: null,
        logEntries: []
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

            // Action 컨트롤
            actionSelect: document.getElementById('action-select'),
            riskScoreInput: document.getElementById('risk-score-input'),
            riskScoreValue: document.getElementById('risk-score-value'),
            confidenceInput: document.getElementById('confidence-input'),
            confidenceValue: document.getElementById('confidence-value'),
            actionDescription: document.getElementById('action-description'),

            // 버튼
            btnRefreshStatus: document.getElementById('btn-refresh-status'),
            btnSetAction: document.getElementById('btn-set-action'),
            btnResetAction: document.getElementById('btn-reset-action'),
            btnClearLog: document.getElementById('btn-clear-log'),

            // 테스트 버튼
            btnTestPublic: document.getElementById('btn-test-public'),
            btnTestNormal: document.getElementById('btn-test-normal'),
            btnTestSensitive: document.getElementById('btn-test-sensitive'),
            btnTestCritical: document.getElementById('btn-test-critical'),
            btnTestBulk: document.getElementById('btn-test-bulk'),

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
            cardBulk: document.getElementById('card-bulk'),

            // 로그
            logContainer: document.getElementById('log-container'),
            autoScrollCheckbox: document.getElementById('auto-scroll')
        };
    }

    // ============================================================================
    // API 통신
    // ============================================================================

    /**
     * HTTP 요청 수행
     *
     * @param {string} url - 요청 URL
     * @param {Object} options - fetch 옵션
     * @returns {Promise<Object>} - 응답 JSON
     */
    async function request(url, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            credentials: 'same-origin'
        };

        const mergedOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
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
                // JSON이 아닌 응답 (HTML 에러 페이지 등)
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
     *
     * @param {string} html - HTML 응답 본문
     * @param {number} status - HTTP 상태 코드
     * @returns {string} - 추출된 에러 메시지
     */
    function extractErrorMessage(html, status) {
        // 403 Forbidden 특별 처리
        if (status === 403) {
            // ZeroTrustAccessDeniedException 메시지 확인
            if (html.includes('ZeroTrustAccessDeniedException')) {
                return 'Zero Trust 보안 정책에 의해 접근이 거부되었습니다.';
            }
            if (html.includes('AccessDeniedException')) {
                return '접근이 거부되었습니다. (AccessDeniedException)';
            }
            return '접근이 거부되었습니다. (HTTP 403)';
        }

        // 401 Unauthorized
        if (status === 401) {
            return '인증이 필요합니다. 로그인 후 다시 시도하세요.';
        }

        // 500 Internal Server Error
        if (status === 500) {
            // 스택 트레이스에서 예외 클래스 추출 시도
            const exceptionMatch = html.match(/([A-Za-z]+Exception)/);
            if (exceptionMatch) {
                return `서버 오류: ${exceptionMatch[1]}`;
            }
            return '서버 내부 오류가 발생했습니다. (HTTP 500)';
        }

        // 기타 상태 코드
        return `요청 처리 중 오류가 발생했습니다. (HTTP ${status})`;
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
        log('INFO', 'Action 상태 조회 중...');

        try {
            const data = await request(API.ACTION_STATUS);

            state.currentAction = data.action || 'PENDING_ANALYSIS';
            state.riskScore = data.riskScore || 0.0;
            state.confidence = data.confidence || 0.0;
            state.threatLevel = data.threatLevel || 'UNKNOWN';
            state.isAnomaly = data.isAnomaly || false;
            state.analysisStatus = data.analysisStatus || 'NOT_ANALYZED';

            updateStatusDisplay();

            log('SUCCESS', `Action 상태: ${state.currentAction}, Risk: ${state.riskScore.toFixed(2)}, Confidence: ${state.confidence.toFixed(2)}`);
        } catch (error) {
            log('ERROR', `Action 상태 조회 실패: ${error.message}`);
            console.error('Action status error:', error);
        } finally {
            setLoading(false);
        }
    }

    /**
     * Action 강제 설정
     */
    async function setAction() {
        if (state.isLoading) return;

        const action = elements.actionSelect.value;
        const riskScore = parseFloat(elements.riskScoreInput.value);
        const confidence = parseFloat(elements.confidenceInput.value);

        setLoading(true);
        log('INFO', `Action 설정 중: ${action}, Risk: ${riskScore.toFixed(2)}, Confidence: ${confidence.toFixed(2)}`);

        try {
            const data = await request(API.ACTION_SET, {
                method: 'POST',
                body: JSON.stringify({
                    action: action,
                    riskScore: riskScore,
                    confidence: confidence
                })
            });

            state.currentAction = data.action;
            state.riskScore = data.riskScore;
            state.confidence = confidence;
            state.threatLevel = data.threatLevel;
            state.isAnomaly = data.isAnomaly;
            state.analysisStatus = 'ANALYZED';

            updateStatusDisplay();

            log('SUCCESS', `Action이 '${data.action}'(으)로 설정되었습니다. TTL: ${data.ttlSeconds}초`);
        } catch (error) {
            log('ERROR', `Action 설정 실패: ${error.message}`);
            console.error('Set action error:', error);
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
        log('INFO', 'Action 초기화 중...');

        try {
            const data = await request(API.ACTION_RESET, {
                method: 'DELETE'
            });

            state.currentAction = 'PENDING_ANALYSIS';
            state.riskScore = 0.0;
            state.confidence = 0.0;
            state.threatLevel = 'UNKNOWN';
            state.isAnomaly = false;
            state.analysisStatus = 'NOT_ANALYZED';

            updateStatusDisplay();

            log('SUCCESS', 'Action이 초기화되었습니다. 현재 상태: PENDING_ANALYSIS');
        } catch (error) {
            log('ERROR', `Action 초기화 실패: ${error.message}`);
            console.error('Reset action error:', error);
        } finally {
            setLoading(false);
        }
    }

    // ============================================================================
    // 보안 API 테스트
    // ============================================================================

    /**
     * 보안 API 테스트 실행
     *
     * @param {string} type - 테스트 유형 (public, normal, sensitive, critical, bulk)
     * @param {string} resourceId - 리소스 ID (bulk 제외)
     */
    async function executeTest(type, resourceId) {
        if (state.isLoading) return;

        const testInfo = TEST_INFO[type];
        const card = getTestCard(type);

        // 카드 상태 초기화
        resetCardState(card);

        setLoading(true);

        const logPrefix = `[${testInfo.name}]`;
        log('INFO', `${logPrefix} 테스트 시작 (${testInfo.analysisRequirement})`);
        log('INFO', `${logPrefix} 현재 Action: ${state.currentAction}`);

        // URL 구성
        let url;
        switch (type) {
            case 'public':
                url = API.TEST_PUBLIC + encodeURIComponent(resourceId);
                break;
            case 'normal':
                url = API.TEST_NORMAL + encodeURIComponent(resourceId);
                break;
            case 'sensitive':
                url = API.TEST_SENSITIVE + encodeURIComponent(resourceId);
                break;
            case 'critical':
                url = API.TEST_CRITICAL + encodeURIComponent(resourceId);
                break;
            case 'bulk':
                url = API.TEST_BULK;
                break;
            default:
                log('ERROR', `${logPrefix} 알 수 없는 테스트 유형: ${type}`);
                setLoading(false);
                return;
        }

        try {
            const startTime = performance.now();
            const data = await request(url);
            const elapsed = (performance.now() - startTime).toFixed(0);

            // 성공
            setCardSuccess(card);

            if (type === 'bulk') {
                log('SUCCESS', `${logPrefix} 성공 - 데이터 길이: ${data.dataLength} bytes, 처리시간: ${elapsed}ms (서버: ${data.processingTime}ms)`);
            } else {
                log('SUCCESS', `${logPrefix} 성공 - 응답: "${data.data}", 처리시간: ${elapsed}ms (서버: ${data.processingTime}ms)`);
            }
        } catch (error) {
            // 실패
            setCardFailed(card);

            const errorMessage = error.message;

            // 보안 차단 여부 확인
            if (error.status === 403) {
                log('BLOCKED', `${logPrefix} 차단됨 - ${errorMessage}`);
                log('WARNING', `${logPrefix} 현재 Action '${state.currentAction}'이(가) 정책 조건을 충족하지 않습니다.`);
            } else if (error.status === 401) {
                log('ERROR', `${logPrefix} 인증 실패 - ${errorMessage}`);
            } else {
                log('ERROR', `${logPrefix} 오류 - ${errorMessage}`);
            }

            console.error(`Test ${type} error:`, error);
        } finally {
            setLoading(false);
        }
    }

    /**
     * 테스트 카드 요소 가져오기
     *
     * @param {string} type - 테스트 유형
     * @returns {HTMLElement} - 카드 요소
     */
    function getTestCard(type) {
        switch (type) {
            case 'public': return elements.cardPublic;
            case 'normal': return elements.cardNormal;
            case 'sensitive': return elements.cardSensitive;
            case 'critical': return elements.cardCritical;
            case 'bulk': return elements.cardBulk;
            default: return null;
        }
    }

    /**
     * 카드 상태 초기화
     *
     * @param {HTMLElement} card - 카드 요소
     */
    function resetCardState(card) {
        if (!card) return;
        card.classList.remove('success', 'failed');
    }

    /**
     * 카드 성공 상태 설정
     *
     * @param {HTMLElement} card - 카드 요소
     */
    function setCardSuccess(card) {
        if (!card) return;
        card.classList.remove('failed');
        card.classList.add('success');
    }

    /**
     * 카드 실패 상태 설정
     *
     * @param {HTMLElement} card - 카드 요소
     */
    function setCardFailed(card) {
        if (!card) return;
        card.classList.remove('success');
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
        elements.currentAction.textContent = state.currentAction;
        elements.currentAction.className = `value action-badge ${actionInfo.badgeClass}`;

        // Risk Score
        elements.riskScore.textContent = state.riskScore.toFixed(2);

        // Confidence
        elements.confidence.textContent = state.confidence.toFixed(2);

        // Threat Level 배지
        const threatInfo = THREAT_LEVEL_INFO[state.threatLevel] || THREAT_LEVEL_INFO['UNKNOWN'];
        elements.threatLevel.textContent = state.threatLevel;
        elements.threatLevel.className = `value threat-badge ${threatInfo.badgeClass}`;

        // Is Anomaly
        elements.isAnomaly.textContent = state.isAnomaly ? 'Yes' : 'No';
        elements.isAnomaly.style.color = state.isAnomaly ? '#c62828' : '#2e7d32';

        // Analysis Status
        elements.analysisStatus.textContent = state.analysisStatus === 'ANALYZED' ? 'Analyzed' : 'Not Analyzed';
        elements.analysisStatus.style.color = state.analysisStatus === 'ANALYZED' ? '#2e7d32' : '#666';
    }

    /**
     * Action 설명 갱신
     */
    function updateActionDescription() {
        const action = elements.actionSelect.value;
        const actionInfo = ACTION_INFO[action];

        if (actionInfo) {
            elements.actionDescription.textContent = actionInfo.description;
        } else {
            elements.actionDescription.textContent = '';
        }
    }

    /**
     * 슬라이더 값 표시 갱신
     */
    function updateSliderValues() {
        elements.riskScoreValue.textContent = parseFloat(elements.riskScoreInput.value).toFixed(2);
        elements.confidenceValue.textContent = parseFloat(elements.confidenceInput.value).toFixed(2);
    }

    /**
     * 로딩 상태 설정
     *
     * @param {boolean} loading - 로딩 여부
     */
    function setLoading(loading) {
        state.isLoading = loading;

        // 버튼 로딩 상태
        const buttons = [
            elements.btnRefreshStatus,
            elements.btnSetAction,
            elements.btnResetAction,
            elements.btnTestPublic,
            elements.btnTestNormal,
            elements.btnTestSensitive,
            elements.btnTestCritical,
            elements.btnTestBulk
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
     *
     * @param {string} level - 로그 레벨 (INFO, SUCCESS, WARNING, ERROR, BLOCKED)
     * @param {string} message - 로그 메시지
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

        elements.logContainer.appendChild(logElement);

        // 자동 스크롤
        if (elements.autoScrollCheckbox && elements.autoScrollCheckbox.checked) {
            elements.logContainer.scrollTop = elements.logContainer.scrollHeight;
        }
    }

    /**
     * 로그 전체 삭제
     */
    function clearLog() {
        state.logEntries = [];
        elements.logContainer.innerHTML = '';
        log('INFO', '로그가 초기화되었습니다.');
    }

    /**
     * HTML 특수문자 이스케이프
     *
     * @param {string} text - 원본 텍스트
     * @returns {string} - 이스케이프된 텍스트
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
        // Action 컨트롤 버튼
        if (elements.btnRefreshStatus) {
            elements.btnRefreshStatus.addEventListener('click', refreshActionStatus);
        }

        if (elements.btnSetAction) {
            elements.btnSetAction.addEventListener('click', setAction);
        }

        if (elements.btnResetAction) {
            elements.btnResetAction.addEventListener('click', resetAction);
        }

        // Action 선택 변경
        if (elements.actionSelect) {
            elements.actionSelect.addEventListener('change', updateActionDescription);
        }

        // 슬라이더 값 변경
        if (elements.riskScoreInput) {
            elements.riskScoreInput.addEventListener('input', updateSliderValues);
        }

        if (elements.confidenceInput) {
            elements.confidenceInput.addEventListener('input', updateSliderValues);
        }

        // 테스트 버튼
        if (elements.btnTestPublic) {
            elements.btnTestPublic.addEventListener('click', function() {
                const resourceId = elements.inputPublic ? elements.inputPublic.value : 'test-resource';
                executeTest('public', resourceId || 'test-resource');
            });
        }

        if (elements.btnTestNormal) {
            elements.btnTestNormal.addEventListener('click', function() {
                const resourceId = elements.inputNormal ? elements.inputNormal.value : 'test-resource';
                executeTest('normal', resourceId || 'test-resource');
            });
        }

        if (elements.btnTestSensitive) {
            elements.btnTestSensitive.addEventListener('click', function() {
                const resourceId = elements.inputSensitive ? elements.inputSensitive.value : 'test-resource';
                executeTest('sensitive', resourceId || 'test-resource');
            });
        }

        if (elements.btnTestCritical) {
            elements.btnTestCritical.addEventListener('click', function() {
                const resourceId = elements.inputCritical ? elements.inputCritical.value : 'test-resource';
                executeTest('critical', resourceId || 'test-resource');
            });
        }

        if (elements.btnTestBulk) {
            elements.btnTestBulk.addEventListener('click', function() {
                executeTest('bulk', null);
            });
        }

        // 로그 삭제 버튼
        if (elements.btnClearLog) {
            elements.btnClearLog.addEventListener('click', clearLog);
        }

        // 키보드 단축키
        document.addEventListener('keydown', function(event) {
            // Ctrl + R: 상태 새로고침 (기본 새로고침 방지)
            if (event.ctrlKey && event.key === 'r') {
                event.preventDefault();
                refreshActionStatus();
            }

            // Escape: 로딩 중이면 취소 (시뮬레이션)
            if (event.key === 'Escape' && state.isLoading) {
                setLoading(false);
                log('WARNING', '작업이 사용자에 의해 중단되었습니다.');
            }
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

        // 초기 슬라이더 값 표시
        updateSliderValues();

        // Action 설명 초기화
        updateActionDescription();

        // 초기 로그 메시지
        log('INFO', '@Protectable 보안 플로우 테스트 페이지가 로드되었습니다.');
        log('INFO', '현재 Action 상태를 조회합니다...');

        // 초기 상태 조회
        refreshActionStatus();
    }

    // DOM 로드 완료 시 초기화
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
