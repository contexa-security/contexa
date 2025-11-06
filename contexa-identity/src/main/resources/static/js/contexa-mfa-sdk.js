/**
 * Contexa MFA SDK - Unified JavaScript SDK for Multi-Factor Authentication
 *
 * Version: 2.0.0 (Complete Refactoring)
 * License: Apache 2.0
 *
 * This SDK consolidates 8 legacy JavaScript files (1,871 lines) into a clean,
 * production-ready implementation that includes ONLY the features necessary
 * for MFA server integration.
 *
 * Key Changes from v1.0:
 * - Fixed OTT verification Content-Type (application/x-www-form-urlencoded)
 * - Added X-MFA-Step-Id header support
 * - Expanded terminal states from 3 to 8 (matching server)
 * - Added session restoration (restoreFromSession)
 * - Added user action state helpers (isWaitingForUserAction, isProcessing)
 * - Complete state transition rules matching server State Machine
 *
 * Usage:
 *   const mfa = new ContexaMFA.Client();
 *   await mfa.init();
 *   await mfa.selectFactor('OTT');
 *   await mfa.verifyOtt('123456');
 *   await mfa.verifyPasskey();
 *
 * @module ContexaMFA
 */

(function(window) {
    'use strict';

    // ===========================
    // Custom Error Class
    // ===========================

    /**
     * 커스텀 에러 클래스 - 서버 응답 전체를 포함
     */
    class MFAError extends Error {
        constructor(message, response = null, status = null) {
            super(message);
            this.name = 'MFAError';
            this.response = response;  // 서버 응답 데이터 전체
            this.status = status;      // HTTP 상태 코드
        }
    }

    // ===========================
    // Module 1: Utils Module
    // ===========================

    const ContexaMFAUtils = {
        /**
         * CSRF 토큰 가져오기
         */
        getCsrfToken() {
            const meta = document.querySelector('meta[name="_csrf"]');
            return meta ? meta.getAttribute('content') : null;
        },

        /**
         * CSRF 헤더 이름 가져오기
         */
        getCsrfHeader() {
            const meta = document.querySelector('meta[name="_csrf_header"]');
            return meta ? meta.getAttribute('content') : 'X-CSRF-TOKEN';
        },

        /**
         * Device ID 생성 또는 가져오기
         * Legacy: 8개 파일 중 7개에서 동일한 코드 중복
         */
        getDeviceId() {
            const storageKey = 'deviceId';
            let deviceId = localStorage.getItem(storageKey);

            if (!deviceId) {
                deviceId = crypto.randomUUID();
                localStorage.setItem(storageKey, deviceId);
            }

            return deviceId;
        },

        /**
         * Base64URL to ArrayBuffer 변환 (WebAuthn 필수)
         * Legacy: 3개 파일에서 동일한 코드 중복
         */
        base64UrlToArrayBuffer(base64Url) {
            if (!base64Url) return new ArrayBuffer(0);

            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const padding = '='.repeat((4 - (base64.length % 4)) % 4);
            const base64Padded = base64 + padding;

            const binaryString = atob(base64Padded);
            const bytes = new Uint8Array(binaryString.length);

            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }

            return bytes.buffer;
        },

        /**
         * ArrayBuffer to Base64URL 변환 (WebAuthn 필수)
         * Legacy: 3개 파일에서 동일한 코드 중복
         */
        arrayBufferToBase64Url(buffer) {
            if (!buffer) return '';

            const bytes = new Uint8Array(buffer);
            let binaryString = '';

            for (let i = 0; i < bytes.length; i++) {
                binaryString += String.fromCharCode(bytes[i]);
            }

            const base64 = btoa(binaryString);
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        },

        /**
         * Fetch 공통 헤더 생성 (P0 수정: X-MFA-Step-Id 추가)
         * Legacy: 8개 파일에서 헤더 생성 로직 중복
         */
        createHeaders(options = {}) {
            const contentType = options.contentType || 'application/json';
            const mfaSessionId = options.mfaSessionId || sessionStorage.getItem('mfaSessionId');
            const stepId = options.stepId || sessionStorage.getItem('currentMfaStepId');

            const headers = {
                'Content-Type': contentType,
                'X-Device-Id': this.getDeviceId(),
                ...options.additionalHeaders
            };

            // P0 수정: X-MFA-Step-Id 헤더 추가
            if (stepId) {
                headers['X-MFA-Step-Id'] = stepId;
            }

            if (mfaSessionId) {
                headers['X-MFA-Session-Id'] = mfaSessionId;
            }

            const csrfToken = this.getCsrfToken();
            const csrfHeader = this.getCsrfHeader();
            if (csrfToken && csrfHeader) {
                headers[csrfHeader] = csrfToken;
            }

            return headers;
        },

        /**
         * 로깅 유틸리티
         */
        log(message, type = 'info', data = null) {
            const prefix = `[Contexa MFA SDK v2.0]`;
            if (data) {
                console[type](prefix, message, data);
            } else {
                console[type](prefix, message);
            }
        }
    };

    // ===========================
    // Module 2: State Tracker Module
    // ===========================

    class MfaStateTracker {
        constructor() {
            this.currentState = null;
            this.sessionId = null;
            this.stateMetadata = {};
            this.lastUpdate = null;

            // P1 수정: 서버 MfaStateMachineConfiguration과 완전히 일치
            // Legacy mfa-state-tracker.js:40-50 기반
            this.validTransitions = {
                'NONE': ['PRIMARY_AUTHENTICATION_COMPLETED'],
                'PRIMARY_AUTHENTICATION_COMPLETED': [
                    'MFA_NOT_REQUIRED',
                    'AWAITING_FACTOR_SELECTION',
                    'MFA_SYSTEM_ERROR'
                ],
                'AWAITING_FACTOR_SELECTION': [
                    'AWAITING_FACTOR_CHALLENGE_INITIATION',
                    'MFA_CANCELLED',
                    'MFA_SESSION_EXPIRED',
                    'MFA_SYSTEM_ERROR'
                ],
                'AWAITING_FACTOR_CHALLENGE_INITIATION': [
                    'FACTOR_CHALLENGE_INITIATED',
                    'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION',
                    'MFA_CANCELLED',
                    'MFA_SESSION_EXPIRED'
                ],
                'FACTOR_CHALLENGE_INITIATED': [
                    'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION',
                    'MFA_CANCELLED',
                    'MFA_SESSION_EXPIRED'
                ],
                'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION': [
                    'FACTOR_VERIFICATION_PENDING',
                    'MFA_CANCELLED',
                    'MFA_SESSION_EXPIRED',
                    'AWAITING_FACTOR_SELECTION'
                ],
                'FACTOR_VERIFICATION_PENDING': [
                    'FACTOR_VERIFICATION_COMPLETED',
                    'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION',
                    'MFA_RETRY_LIMIT_EXCEEDED',
                    'MFA_SYSTEM_ERROR'
                ],
                'FACTOR_VERIFICATION_COMPLETED': [
                    'ALL_FACTORS_COMPLETED',
                    'AWAITING_FACTOR_SELECTION'
                ],
                'ALL_FACTORS_COMPLETED': ['MFA_SUCCESSFUL'],
                'MFA_RETRY_LIMIT_EXCEEDED': ['MFA_FAILED_TERMINAL']
            };
        }

        /**
         * 서버 응답에서 State Machine 상태 업데이트
         * Legacy: mfa-state-tracker.js:11-36
         */
        updateFromServerResponse(response) {
            if (!response) return;

            const previousState = this.currentState;

            if (response.stateMachine) {
                const sm = response.stateMachine;
                this.currentState = sm.currentState;
                this.sessionId = sm.sessionId || this.sessionId;
                this.stateMetadata = sm.stateMetadata || {};
            }

            if (response.currentState) {
                this.currentState = response.currentState;
            }

            if (response.mfaSessionId) {
                this.sessionId = response.mfaSessionId;
            }

            this.lastUpdate = new Date();

            // SessionStorage 동기화
            this.saveToSession();

            if (previousState && previousState !== this.currentState) {
                ContexaMFAUtils.log(`State updated: ${previousState} → ${this.currentState}`, 'debug');
            }
        }

        /**
         * 특정 상태로 전환 가능한지 검증
         * Legacy: mfa-state-tracker.js:38-54
         */
        canTransitionTo(targetState) {
            if (!this.currentState) return true;

            const validTargets = this.validTransitions[this.currentState];
            if (!validTargets) return false;

            return validTargets.includes(targetState);
        }

        /**
         * P1 수정: 터미널 상태 여부 확인 (3개 → 8개)
         * Legacy: mfa-state-tracker.js:56-69
         * 서버 MfaState.isTerminal()과 완전히 일치
         */
        isTerminalState(state = this.currentState) {
            const terminalStates = [
                'MFA_SUCCESSFUL',
                'MFA_NOT_REQUIRED',
                'MFA_FAILED_TERMINAL',
                'MFA_CANCELLED',
                'MFA_SESSION_EXPIRED',
                'MFA_SESSION_INVALIDATED',
                'MFA_RETRY_LIMIT_EXCEEDED',
                'MFA_SYSTEM_ERROR'
            ];
            return terminalStates.includes(state);
        }

        /**
         * P2 추가: 사용자 액션 대기 상태 확인
         * Legacy: mfa-state-tracker.js:71-76
         * 서버 MfaState.isWaitingForUserAction()과 일치
         */
        isWaitingForUserAction() {
            return this.currentState === 'AWAITING_FACTOR_SELECTION' ||
                this.currentState === 'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION';
        }

        /**
         * P2 추가: 처리 중 상태 확인
         * Legacy: mfa-state-tracker.js:78-83
         * 서버 MfaState.isProcessing()과 일치
         */
        isProcessing() {
            return this.currentState === 'AWAITING_FACTOR_CHALLENGE_INITIATION' ||
                this.currentState === 'FACTOR_VERIFICATION_PENDING' ||
                this.currentState === 'PRIMARY_AUTHENTICATION_COMPLETED';
        }

        /**
         * P2 추가: 세션에 저장
         * Legacy: mfa-state-tracker.js:90-98
         */
        saveToSession() {
            try {
                const data = {
                    currentState: this.currentState,
                    sessionId: this.sessionId,
                    stateMetadata: this.stateMetadata,
                    lastUpdate: this.lastUpdate ? this.lastUpdate.toISOString() : null
                };
                sessionStorage.setItem('mfaStateTracker', JSON.stringify(data));

                // 호환성을 위한 개별 저장
                if (this.sessionId) {
                    sessionStorage.setItem('mfaSessionId', this.sessionId);
                }
                if (this.currentState) {
                    sessionStorage.setItem('currentMfaState', this.currentState);
                }
            } catch (error) {
                ContexaMFAUtils.log('Failed to save state to session storage', 'error', error);
            }
        }

        /**
         * P2 추가: 세션에서 복원
         * Legacy: mfa-state-tracker.js:100-112
         */
        restoreFromSession() {
            try {
                const stored = sessionStorage.getItem('mfaStateTracker');
                if (stored) {
                    const data = JSON.parse(stored);
                    this.currentState = data.currentState;
                    this.sessionId = data.sessionId;
                    this.stateMetadata = data.stateMetadata || {};
                    this.lastUpdate = data.lastUpdate ? new Date(data.lastUpdate) : null;

                    ContexaMFAUtils.log(`State restored from session: ${this.currentState}`, 'debug');
                    return true;
                }
            } catch (error) {
                ContexaMFAUtils.log('Failed to restore state from session storage', 'error', error);
            }
            return false;
        }

        /**
         * 상태 초기화
         * Legacy: mfa-state-tracker.js:114-122
         */
        reset() {
            this.currentState = null;
            this.sessionId = null;
            this.stateMetadata = {};
            this.lastUpdate = null;
            sessionStorage.removeItem('mfaStateTracker');
            sessionStorage.removeItem('mfaSessionId');
            sessionStorage.removeItem('currentMfaState');
            sessionStorage.removeItem('currentMfaFactor');
            sessionStorage.removeItem('currentMfaStepId');
            sessionStorage.removeItem('mfaUsername');
        }
    }

    // ===========================
    // Module 3: API Client Module
    // ===========================

    const ContexaMFAApiClient = {
        endpoints: {},
        initialized: false,

        /**
         * SDK 초기화 - 서버에서 엔드포인트 설정 로드
         *
         * 서버 응답 구조:
         * {
         *   mfa: { initiate, configure, selectFactor, failure, success, cancel, status },
         *   ott: { requestCodeUi, codeGeneration, challenge, loginProcessing, ... },
         *   passkey: { loginProcessing, challenge, ... },
         *   api: { selectFactor, cancel, status, requestOttCode, context, assertionOptions, config }
         * }
         */
        async init() {
            if (this.initialized) return;

            try {
                const response = await fetch('/api/mfa/config', {
                    method: 'GET',
                    headers: ContexaMFAUtils.createHeaders()
                });

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new MFAError(
                        errorData.message || `Failed to load MFA configuration: ${response.status}`,
                        errorData,
                        response.status
                    );
                }

                // 서버에서 받은 설정을 그대로 사용
                this.endpoints = await response.json();
                this.initialized = true;
                ContexaMFAUtils.log('✅ SDK initialized successfully with server configuration', 'info', this.endpoints);
            } catch (error) {
                ContexaMFAUtils.log('⚠️ Failed to initialize SDK from server, using fallback defaults', 'warn', error);
                this.endpoints = this._getDefaultEndpoints();
                this.initialized = true;
            }
        },

        /**
         * 기본 엔드포인트 설정 (fallback)
         *
         * ⚠️ 주의: 이 기본값들은 서버 설정과 정확히 일치해야 합니다.
         * 서버가 /api/mfa/config 엔드포인트를 통해 제공하는 구조와 동일한 형식을 유지합니다.
         *
         * 서버 설정은 AuthContextProperties (application.yml)에서 관리됩니다.
         */
        _getDefaultEndpoints() {
            return {
                primary: {
                    formLoginPage: '/loginForm',
                    formLoginProcessing: '/login',
                    restLoginProcessing: '/api/auth/login',
                    loginFailure: '/login?error',
                    loginSuccess: '/home'
                },
                mfa: {
                    initiate: '/mfa/initiate',
                    configure: '/mfa/configure',
                    selectFactor: '/mfa/select-factor',
                    failure: '/mfa/failure',
                    success: '/home', // AuthContextProperties 기본값
                    cancel: '/api/mfa/cancel',
                    status: '/api/mfa/status'
                },
                ott: {
                    requestCodeUi: '/mfa/ott/request-code-ui',
                    codeGeneration: '/mfa/ott/generate-code',
                    challengeUi: '/mfa/challenge/ott',
                    loginProcessing: '/login/mfa-ott',
                    codeSent: '/mfa/ott/code-sent',
                    defaultFailure: '/mfa/challenge/ott?error=true',
                    singleOttRequestEmail: '/loginOtt',
                    singleOttCodeGeneration: '/login/ott/generate',
                    singleOttChallenge: '/loginOttVerifyCode',
                    singleOttSent: '/ott/sent'
                },
                passkey: {
                    challengeUi: '/mfa/challenge/passkey',
                    loginProcessing: '/login/mfa-webauthn',
                    defaultFailure: '/mfa/challenge/passkey?error',
                    registrationRequest: '/mfa/passkey/register-request',
                    registrationProcessing: '/mfa/passkey/register'
                },
                api: {
                    selectFactor: '/mfa/select-factor',
                    cancel: '/mfa/cancel',
                    status: '/mfa/status',
                    requestOttCode: '/mfa/request-ott-code',
                    context: '/api/mfa/context',  // MfaApiController 경로와 일치
                    completeFactor: '/mfa/complete-factor',
                    config: '/api/mfa/config' // SDK 초기화 전용, /api 유지
                },
                webauthn: {
                    assertionOptions: '/webauthn/authenticate/options',
                    assertionVerify: '/login/webauthn'
                }
            };
        },

        /**
         * FactorContext 조회
         */
        async getContext() {
            await this.init();

            const response = await fetch(this.endpoints.api.context, {
                method: 'GET',
                headers: ContexaMFAUtils.createHeaders()
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new MFAError(
                    errorData.message || `Failed to get context: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        },

        /**
         * 1차 인증: 사용자명/비밀번호 로그인
         * REST API 기반 SPA에서 사용하기 위한 메서드
         *
         * @param {string} username - 사용자명
         * @param {string} password - 비밀번호
         * @returns {Promise<Object>} 로그인 결과
         *   - mfaRequired: MFA 필요 여부
         *   - nextStepUrl: 다음 단계 URL (MFA 필요 시)
         *   - success: 로그인 성공 여부 (MFA 불필요 시)
         *
         * @example
         * const mfa = new ContexaMFA.Client();
         * try {
         *     const result = await mfa.login('username', 'password');
         *     if (result.mfaRequired) {
         *         // MFA 필요: 다음 단계로 이동
         *         window.location.href = result.nextStepUrl;
         *     } else {
         *         // 로그인 성공: 홈으로 이동
         *         window.location.href = '/home';
         *     }
         * } catch (error) {
         *     console.error('Login failed:', error);
         * }
         */
        async login(username, password) {
            await this.init();

            const response = await fetch(this.endpoints.primary.restLoginProcessing, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders(),
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new MFAError(
                    errorData.message || `Login failed: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            const result = await response.json();

            // MFA 필요 여부에 따른 상태 처리
            if (result.status === 'MFA_REQUIRED_SELECT_FACTOR' ||
                result.status === 'MFA_REQUIRED') {
                // MFA 필요 - 세션에 username 저장
                sessionStorage.setItem('mfaUsername', username);
                sessionStorage.setItem('mfaSessionId', result.mfaSessionId);
                this.state = 'MFA_REQUIRED';
                const message = result.message || 'MFA required';
                ContexaMFAUtils.log(`✅ Primary authentication successful: ${message}`, 'info', result);
            } else if (result.status === 'MFA_COMPLETED') {
                // MFA 불필요 - 인증 완료 (서버가 토큰 발급 완료)
                this.state = 'AUTHENTICATED';
                const message = result.message || 'Login successful';
                ContexaMFAUtils.log(`✅ ${message} (MFA completed, tokens issued)`, 'info', result);
            } else {
                // 기타 상태
                this.state = 'AUTHENTICATED';
                const message = result.message || 'Login successful';
                ContexaMFAUtils.log(`✅ ${message}`, 'info', result);
            }

            return result;
        },

        /**
         * 팩터 선택
         * Legacy: mfa-select-factor.js:119-159
         */
        async selectFactor(factorType) {
            await this.init();

            const response = await fetch(this.endpoints.api.selectFactor, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders(),
                body: JSON.stringify({
                    factorType: factorType,
                    username: sessionStorage.getItem('mfaUsername')
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new MFAError(
                    errorData.message || `Failed to select factor: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        },

        /**
         * OTT 코드 재전송 요청
         * Legacy: mfa-ott-request-code.js (일부), mfa-verity-ott.js:98-150
         */
        async requestOttCode() {
            await this.init();

            const response = await fetch(this.endpoints.api.requestOttCode, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders(),
                body: JSON.stringify({
                    username: sessionStorage.getItem('mfaUsername')
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new MFAError(
                    errorData.message || `Failed to request OTT code: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        },

        /**
         * P0 수정: OTT 코드 검증 (Content-Type 수정)
         * Legacy: mfa-verity-ott.js:156-291
         *
         * CRITICAL: Spring Security oneTimeTokenLogin()은
         * application/x-www-form-urlencoded 형식 요구
         */
        async verifyOtt(code, username) {
            await this.init();

            // P0 수정: JSON 대신 FormData 사용
            const formData = new URLSearchParams();
            formData.append('username', username || sessionStorage.getItem('mfaUsername'));
            formData.append('token', code);

            const csrfToken = ContexaMFAUtils.getCsrfToken();
            if (csrfToken) {
                formData.append('_csrf', csrfToken);
            }

            const response = await fetch(this.endpoints.ott.loginProcessing, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders({
                    contentType: 'application/x-www-form-urlencoded'  // P0 수정
                }),
                body: formData.toString()
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'OTT verification failed' }));
                throw new MFAError(
                    errorData.message || `OTT verification failed: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        },

        /**
         * Passkey Assertion Options 가져오기
         * ⭐ Spring Security 6.4+ 표준 엔드포인트 사용
         */
        async getPasskeyOptions() {
            await this.init();

            const response = await fetch(this.endpoints.webauthn.assertionOptions, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders()
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Failed to get passkey options' }));
                throw new MFAError(
                    errorData.message || `Failed to get passkey options: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        },

        /**
         * Passkey 인증 수행
         * ⭐ Spring Security 6.4+ 표준 엔드포인트 사용
         */
        async verifyPasskey(publicKeyCredential) {
            await this.init();

            const response = await fetch(this.endpoints.webauthn.assertionVerify, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders(),
                body: JSON.stringify(publicKeyCredential)
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Passkey verification failed' }));
                throw new MFAError(
                    errorData.message || `Passkey verification failed: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        },

        /**
         * ⭐ 새로 추가: Factor 완료 알림 (MFA State Machine 통합)
         * Spring Security WebAuthn 인증 후 MFA State Machine에 완료 통보
         */
        async notifyFactorComplete(factorType = 'PASSKEY') {
            await this.init();

            const response = await fetch(this.endpoints.api.completeFactor, {
                method: 'POST',
                headers: {
                    ...ContexaMFAUtils.createHeaders(),
                    'X-Factor-Type': factorType
                }
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Factor completion notification failed' }));
                throw new MFAError(
                    errorData.message || `Factor completion failed: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        },

        /**
         * MFA 상태 조회
         */
        async getStatus() {
            await this.init();

            const response = await fetch(this.endpoints.api.status, {
                method: 'GET',
                headers: ContexaMFAUtils.createHeaders()
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new MFAError(
                    errorData.message || `Failed to get status: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        },

        /**
         * MFA 취소
         */
        async cancel() {
            await this.init();

            const response = await fetch(this.endpoints.api.cancel, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders()
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new MFAError(
                    errorData.message || `Failed to cancel MFA: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        }
    };

    // ===========================
    // Module 4: Main Client
    // ===========================

    class ContexaMFAClient {
        constructor(options = {}) {
            this.stateTracker = new MfaStateTracker();
            this.apiClient = ContexaMFAApiClient;
            this.options = {
                autoInit: true,
                autoRedirect: true,
                ...options
            };
            this.context = null;

            // P2 추가: 자동으로 세션 복원 시도
            if (this.options.autoInit) {
                this.stateTracker.restoreFromSession();
            }
        }

        /**
         * SDK 초기화
         */
        async init() {
            await this.apiClient.init();

            try {
                this.context = await this.apiClient.getContext();
                this.stateTracker.updateFromServerResponse(this.context);
                ContexaMFAUtils.log('MFA context loaded', 'info', this.context);
                return this.context;
            } catch (error) {
                ContexaMFAUtils.log('Failed to load MFA context', 'error', error);
                throw error;
            }
        }

        /**
         * 팩터 선택 (High-level API)
         * Legacy: mfa-select-factor.js 전체 로직 통합
         */
        async selectFactor(factorType) {
            try {
                const result = await this.apiClient.selectFactor(factorType);
                this.stateTracker.updateFromServerResponse(result);

                // P1 추가: nextStepId 저장
                if (result.nextStepId) {
                    sessionStorage.setItem('currentMfaStepId', result.nextStepId);
                }

                // nextFactorType 저장
                if (result.nextFactorType) {
                    sessionStorage.setItem('currentMfaFactor', result.nextFactorType);
                }

                if (this.options.autoRedirect && result.nextStepUrl) {
                    window.location.href = result.nextStepUrl;
                }

                return result;
            } catch (error) {
                // 에러 응답에 message가 있으면 포함
                const errorMsg = error.response?.message || 'Factor selection failed';
                ContexaMFAUtils.log(`${errorMsg}`, 'error', error);
                throw error;
            }
        }

        /**
         * OTT 검증 (High-level API)
         * Legacy: mfa-verity-ott.js 전체 로직 통합
         */
        async verifyOtt(code, username = null) {
            try {
                const result = await this.apiClient.verifyOtt(code, username);
                this.stateTracker.updateFromServerResponse(result);

                // 토큰 저장 (필요시)
                this.handleAuthenticationResult(result);

                // P1 추가: nextStepId 저장
                if (result.nextStepId) {
                    sessionStorage.setItem('currentMfaStepId', result.nextStepId);
                }

                // 자동 리다이렉트
                if (this.options.autoRedirect) {
                    if (result.status === 'MFA_COMPLETED' && result.redirectUrl) {
                        window.location.href = result.redirectUrl;
                    } else if (result.status === 'MFA_CONTINUE' && result.nextStepUrl) {
                        if (result.nextFactorType) {
                            sessionStorage.setItem('currentMfaFactor', result.nextFactorType);
                        }
                        window.location.href = result.nextStepUrl;
                    }
                }

                return result;
            } catch (error) {
                const errorMsg = error.response?.message || 'OTT verification failed';
                ContexaMFAUtils.log(`${errorMsg}`, 'error', error);
                throw error;
            }
        }

        /**
         * Passkey 인증 (High-level API)
         * Legacy: mfa-verity-passkey.js 전체 로직 통합
         */
        async verifyPasskey() {
            try {
                // 1. Spring Security 표준 엔드포인트에서 Assertion Options 가져오기
                const options = await this.apiClient.getPasskeyOptions();

                // 2. PublicKeyCredentialRequestOptions 구성
                const publicKey = {
                    challenge: ContexaMFAUtils.base64UrlToArrayBuffer(options.challenge),
                    rpId: options.rpId,
                    timeout: options.timeout || 60000,
                    userVerification: options.userVerification || 'preferred'
                };

                // allowCredentials 변환
                if (options.allowCredentials && Array.isArray(options.allowCredentials)) {
                    publicKey.allowCredentials = options.allowCredentials.map(cred => ({
                        type: cred.type || 'public-key',
                        id: ContexaMFAUtils.base64UrlToArrayBuffer(cred.id),
                        transports: cred.transports
                    }));
                }

                // 3. WebAuthn API 호출 (사용자 인증)
                ContexaMFAUtils.log('Starting WebAuthn authentication...', 'debug');
                const credential = await navigator.credentials.get({ publicKey });

                // 4. PublicKeyCredential 객체 생성 (Spring Security 6.4+ 형식)
                const publicKeyCredential = {
                    id: credential.id,
                    rawId: ContexaMFAUtils.arrayBufferToBase64Url(credential.rawId),
                    type: credential.type,
                    response: {
                        clientDataJSON: ContexaMFAUtils.arrayBufferToBase64Url(credential.response.clientDataJSON),
                        authenticatorData: ContexaMFAUtils.arrayBufferToBase64Url(credential.response.authenticatorData),
                        signature: ContexaMFAUtils.arrayBufferToBase64Url(credential.response.signature),
                        userHandle: credential.response.userHandle ?
                            ContexaMFAUtils.arrayBufferToBase64Url(credential.response.userHandle) : null
                    },
                    clientExtensionResults: credential.getClientExtensionResults()
                };

                // 5. Spring Security 표준 엔드포인트로 검증
                ContexaMFAUtils.log('Verifying credential with Spring Security...', 'debug');
                const verifyResult = await this.apiClient.verifyPasskey(publicKeyCredential);

                // 6. ⭐ MFA State Machine에 팩터 완료 알림
                ContexaMFAUtils.log('Notifying MFA State Machine...', 'debug');
                const mfaResult = await this.apiClient.notifyFactorComplete('PASSKEY');

                // 7. 상태 업데이트
                this.stateTracker.updateFromServerResponse(mfaResult);

                // 8. 토큰 저장 (필요시)
                this.handleAuthenticationResult(mfaResult);

                // 9. 자동 리다이렉트
                if (this.options.autoRedirect && mfaResult.redirectUrl) {
                    ContexaMFAUtils.log(`Redirecting to: ${mfaResult.redirectUrl}`, 'info');
                    window.location.href = mfaResult.redirectUrl;
                }

                return mfaResult;
            } catch (error) {
                const errorMsg = error.response?.message || 'Passkey verification failed';
                ContexaMFAUtils.log(`${errorMsg}`, 'error', error);
                throw error;
            }
        }

        /**
         * 인증 결과 처리 (토큰 저장)
         * Legacy: 여러 파일에 분산된 로직 통합
         */
        handleAuthenticationResult(result) {
            const authMode = localStorage.getItem('authMode') || 'header';

            if (authMode === 'header' || authMode === 'header_cookie') {
                if (result.accessToken && window.TokenMemory) {
                    window.TokenMemory.accessToken = result.accessToken;
                }

                if (authMode === 'header' && result.refreshToken && window.TokenMemory) {
                    window.TokenMemory.refreshToken = result.refreshToken;
                }
            }

            // 최종 성공 시 세션 정리
            if (result.status === 'MFA_COMPLETED') {
                this.stateTracker.reset();
            }
        }

        /**
         * 상태 조회
         */
        async getStatus() {
            try {
                const status = await this.apiClient.getStatus();
                this.stateTracker.updateFromServerResponse(status);
                return status;
            } catch (error) {
                ContexaMFAUtils.log('Failed to get status', 'error', error);
                throw error;
            }
        }

        /**
         * MFA 취소
         */
        async cancel() {
            try {
                const result = await this.apiClient.cancel();
                this.stateTracker.reset();

                if (this.options.autoRedirect && result.redirectUrl) {
                    window.location.href = result.redirectUrl;
                }

                return result;
            } catch (error) {
                ContexaMFAUtils.log('Failed to cancel MFA', 'error', error);
                throw error;
            }
        }

        /**
         * 현재 상태 조회 (편의 메서드)
         */
        getState() {
            return this.stateTracker.currentState;
        }

        getSessionId() {
            return this.stateTracker.sessionId;
        }

        isTerminal() {
            return this.stateTracker.isTerminalState();
        }

        isWaitingForUserAction() {
            return this.stateTracker.isWaitingForUserAction();
        }

        isProcessing() {
            return this.stateTracker.isProcessing();
        }
    }

    // ===========================
    // Public API Export
    // ===========================

    window.ContexaMFA = {
        Client: ContexaMFAClient,
        Utils: ContexaMFAUtils,
        StateTracker: MfaStateTracker,
        version: '2.0.0'
    };

    // Legacy 호환성: 전역 인스턴스 자동 생성
    if (!window.mfaStateTracker) {
        window.mfaStateTracker = new MfaStateTracker();
        window.mfaStateTracker.restoreFromSession();
    }

    ContexaMFAUtils.log(`Contexa MFA SDK v2.0.0 loaded successfully`, 'info');

})(window);
