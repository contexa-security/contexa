/**
 * Contexa MFA SDK - Unified JavaScript SDK for Multi-Factor Authentication
 *
 * Version: 2.1.0 (Zero Trust Global Interceptor)
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
                'Accept': 'application/json',
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
        },

        renderResponseBlockedPage() {
            document.documentElement.innerHTML = `
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Contexa - Access Blocked</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            padding: 20px;
                        }
                        .card {
                            background: white;
                            border-radius: 16px;
                            box-shadow: 0 20px 60px rgba(0,0,0,0.15);
                            padding: 48px 40px;
                            max-width: 480px;
                            width: 100%;
                            text-align: center;
                        }
                        .icon { font-size: 64px; margin-bottom: 24px; }
                        h1 { color: #1a1a2e; font-size: 22px; font-weight: 800; margin-bottom: 12px; }
                        .desc { color: #555; font-size: 15px; line-height: 1.7; margin-bottom: 32px; }
                        .btn {
                            display: inline-block;
                            padding: 14px 40px;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            border: none;
                            border-radius: 10px;
                            font-size: 16px;
                            font-weight: 700;
                            text-decoration: none;
                            cursor: pointer;
                            transition: transform 0.2s, box-shadow 0.2s;
                        }
                        .btn:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(102,126,234,0.4); }
                        .footer { margin-top: 24px; font-size: 12px; color: #999; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <div class="icon">&#128721;</div>
                        <h1>보안 정책에 의해 접근이 차단되었습니다</h1>
                        <p class="desc">
                            AI 보안 분석에 의해 현재 세션의 응답이 강제 종료되었습니다.<br>
                            정상적인 접근이라면 관리자에게 문의해 주세요.
                        </p>
                        <a class="btn" href="/">홈으로 이동</a>
                        <div class="footer">Contexa AI Native Zero Trust Security Platform</div>
                    </div>
                </body>
            `;
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
            // Synchronized with server MfaState.java and MfaStateMachineConfiguration.java
            this.validTransitions = {
                'NONE': ['PRIMARY_AUTHENTICATION_COMPLETED'],
                'PRIMARY_AUTHENTICATION_COMPLETED': [
                    'MFA_NOT_REQUIRED',
                    'AWAITING_FACTOR_SELECTION',
                    'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION',  // INITIATE_CHALLENGE_AUTO
                    'MFA_SYSTEM_ERROR'
                ],
                'AWAITING_FACTOR_SELECTION': [
                    'AWAITING_FACTOR_CHALLENGE_INITIATION',
                    'MFA_CANCELLED',
                    'MFA_SESSION_EXPIRED',
                    'MFA_SYSTEM_ERROR'
                ],
                'AWAITING_FACTOR_CHALLENGE_INITIATION': [
                    'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION',
                    'MFA_CANCELLED',
                    'MFA_SESSION_EXPIRED',
                    'MFA_SYSTEM_ERROR'
                ],
                'FACTOR_CHALLENGE_INITIATED': [
                    'MFA_SYSTEM_ERROR'
                ],
                'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION': [
                    'FACTOR_VERIFICATION_PENDING',
                    'AWAITING_FACTOR_SELECTION',  // CHALLENGE_TIMEOUT
                    'MFA_CANCELLED',
                    'MFA_SESSION_EXPIRED'
                ],
                'FACTOR_VERIFICATION_PENDING': [
                    'FACTOR_VERIFICATION_COMPLETED',
                    'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION',
                    'MFA_RETRY_LIMIT_EXCEEDED',
                    'MFA_SYSTEM_ERROR'
                ],
                'FACTOR_VERIFICATION_COMPLETED': [
                    'ALL_FACTORS_COMPLETED',
                    'AWAITING_FACTOR_SELECTION',
                    'AWAITING_FACTOR_CHALLENGE_INITIATION',
                    'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION'  // INITIATE_CHALLENGE_AUTO
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
         * Synchronized with server MfaState.isProcessing()
         */
        isProcessing() {
            return this.currentState === 'AWAITING_FACTOR_CHALLENGE_INITIATION' ||
                this.currentState === 'FACTOR_CHALLENGE_INITIATED' ||
                this.currentState === 'FACTOR_VERIFICATION_PENDING';
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
        configUrl: '/api/mfa/config',

        /**
         * SDK 초기화 - 서버에서 엔드포인트 설정 로드
         *
         * Multi MFA 지원: 서버의 /api/mfa/config는 현재 MFA 세션의 Flow에 해당하는
         * URL 설정을 반환합니다. MFA_SID 쿠키를 기반으로 Flow를 식별합니다.
         *
         * @param {Object} [options] - 초기화 옵션
         * @param {string} [options.configUrl] - config 엔드포인트 URL (기본: /api/mfa/config)
         */
        async init(options) {
            if (this.initialized) return;

            if (options && options.configUrl) {
                this.configUrl = options.configUrl;
            }

            try {
                const response = await fetch(this.configUrl, {
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
         * 기본 엔드포인트 설정 (fallback - 서버 미응답 시에만 사용)
         *
         * 정상 동작 시 서버의 /api/mfa/config에서 Flow별 동적 URL을 제공합니다.
         * 이 fallback은 서버가 응답하지 않는 극단적 상황에서만 사용되며,
         * Multi MFA 환경에서는 서버 설정이 반드시 우선합니다.
         */
        _getDefaultEndpoints() {
            return {
                primary: {
                    restLoginProcessing: '/api/login',
                    formLoginProcessing: '/mfa/login'
                },
                ott: {
                    loginProcessing: '/login/mfa-ott'
                },
                passkey: {
                    loginProcessing: '/login/mfa-webauthn'
                },
                api: {
                    selectFactor: '/mfa/select-factor',
                    requestOttCode: '/mfa/request-ott-code',
                    config: '/api/mfa/config',
                    logout: '/logout'
                },
                webauthn: {
                    assertionOptions: '/webauthn/authenticate/options',
                    assertionVerify: '/login/webauthn'
                }
            };
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
         * 1차 인증: Form 로그인 (MfaFormAuthenticationFilter 통신)
         *
         * Form 기반 MFA 인증을 위한 메서드입니다.
         * MfaFormAuthenticationFilter와 통신하여 application/x-www-form-urlencoded 형식으로 전송합니다.
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
         *     const result = await mfa.apiClient.loginForm('username', 'password');
         *     if (result.status === 'MFA_REQUIRED_SELECT_FACTOR') {
         *         window.location.href = result.nextStepUrl;
         *     } else {
         *         window.location.href = '/home';
         *     }
         * } catch (error) {
         *     console.error('Login failed:', error);
         * }
         */
        async loginForm(username, password) {
            await this.init();

            // Form 데이터 준비 (application/x-www-form-urlencoded)
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);

            const csrfToken = ContexaMFAUtils.getCsrfToken();
            if (csrfToken) {
                const csrfParamName = document.querySelector('meta[name="_csrf_parameter"]')?.content || '_csrf';
                formData.append(csrfParamName, csrfToken);
            }

            const response = await fetch(this.endpoints.primary.formLoginProcessing, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders({
                    contentType: 'application/x-www-form-urlencoded'
                }),
                body: formData.toString()
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: '로그인 실패: 사용자명 또는 비밀번호를 확인하세요.' }));
                throw new MFAError(
                    errorData.message || `Login failed: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            const result = await response.json();

            // MFA 필요 여부에 따른 상태 처리 (REST와 동일)
            if (result.status === 'MFA_REQUIRED_SELECT_FACTOR' ||
                result.status === 'MFA_REQUIRED') {
                // MFA 필요 - 세션에 username 저장
                sessionStorage.setItem('mfaUsername', username);
                sessionStorage.setItem('mfaSessionId', result.mfaSessionId);
                this.state = 'MFA_REQUIRED';
                const message = result.message || 'MFA required';
                ContexaMFAUtils.log(`✅ Primary authentication successful (Form): ${message}`, 'info', result);
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
         * Logout - Server-side token invalidation and session cleanup
         *
         * Sends POST to /logout with Authorization and X-Refresh-Token headers.
         * Server CompositeLogoutHandler processes:
         *   - SessionLogoutStrategy: session invalidation, CSRF cleanup
         *   - OAuth2LogoutStrategy: refresh/access token invalidation via OAuth2AuthorizationService
         *
         * @returns {Promise<Object>} Logout result with status field
         *
         * @example
         * const mfa = new ContexaMFA.Client();
         * try {
         *     const result = await mfa.logout();
         *     // result.status === 'LOGGED_OUT'
         *     window.location.href = '/loginForm';
         * } catch (error) {
         *     console.error('Logout failed:', error);
         * }
         */
        async logout() {
            await this.init();

            const authMode = localStorage.getItem('authMode') || 'header';
            const headers = ContexaMFAUtils.createHeaders();

            if (authMode === 'header' || authMode === 'header_cookie') {
                if (window.TokenMemory && window.TokenMemory.accessToken) {
                    headers['Authorization'] = `Bearer ${window.TokenMemory.accessToken}`;
                }
                if (window.TokenMemory && window.TokenMemory.refreshToken) {
                    headers['X-Refresh-Token'] = window.TokenMemory.refreshToken;
                }
            }

            const logoutUrl = this.endpoints.api?.logout || '/logout';

            const response = await fetch(logoutUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: headers
            });

            if (!response.ok && response.status !== 204) {
                const errorData = await response.json().catch(() => ({}));
                throw new MFAError(
                    errorData.message || `Logout failed: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json().catch(() => ({ status: 'LOGGED_OUT' }));
        }
    };

    // ===========================
    // Module 4: Main Client
    // ===========================

    /**
     * Token persistence storage key constants
     */
    const TOKEN_STORAGE_KEYS = {
        ACCESS_TOKEN: 'contexa_access_token',
        REFRESH_TOKEN: 'contexa_refresh_token',
        EXPIRES_AT: 'contexa_expires_at',
        REFRESH_EXPIRES_AT: 'contexa_refresh_expires_at'
    };

    class ContexaMFAClient {
        /**
         * @param {Object} options
         * @param {boolean} [options.autoInit=true] - Auto-restore MFA session state
         * @param {boolean} [options.autoRedirect=true] - Auto-redirect on MFA challenge
         * @param {'memory'|'localStorage'|'sessionStorage'} [options.tokenPersistence='memory']
         *        Token storage strategy:
         *        - 'memory': window.TokenMemory only (default, most secure, lost on page refresh)
         *        - 'localStorage': persist tokens across sessions (opt-in, XSS risk - use with CSP)
         *        - 'sessionStorage': persist tokens within tab session (moderate security)
         */
        constructor(options = {}) {
            this.stateTracker = new MfaStateTracker();
            this.apiClient = ContexaMFAApiClient;
            this.options = {
                autoInit: true,
                autoRedirect: true,
                tokenPersistence: 'memory',
                ...options
            };
            this.context = null;

            if (this.options.autoInit) {
                this.stateTracker.restoreFromSession();
            }
        }

        /**
         * SDK 초기화
         * @param {Object} [options] - 초기화 옵션
         * @param {string} [options.configUrl] - config 엔드포인트 URL (Multi MFA 시 Flow별 설정)
         */
        async init(options) {
            await this.apiClient.init(options);
            ContexaMFAUtils.log('MFA SDK initialized', 'info');
        }

        /**
         * 팩터 선택 (High-level API)
         * Legacy: mfa-select-factor.js 전체 로직 통합
         *
         * Note: autoRedirect 로직 제거됨 (race condition 방지)
         * 호출자가 result를 확인하고 명시적으로 리다이렉트해야 함
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

                // autoRedirect 로직 제거 - 템플릿에서 명시적으로 처리
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
         *
         * Note: autoRedirect 로직 제거됨 (race condition 방지)
         * 호출자가 result를 확인하고 명시적으로 리다이렉트해야 함
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

                // nextFactorType 저장
                if (result.nextFactorType) {
                    sessionStorage.setItem('currentMfaFactor', result.nextFactorType);
                }

                // autoRedirect 로직 제거 - 템플릿에서 명시적으로 처리
                return result;
            } catch (error) {
                const errorMsg = error.response?.message || 'OTT verification failed';
                ContexaMFAUtils.log(`${errorMsg}`, 'error', error);
                throw error;
            }
        }

        /**
         * Passkey 인증 (High-level API)
         *
         * Spring Security 표준 WebAuthn 플로우를 따르며, MfaFactorProcessingSuccessHandler가
         * State Machine 통합을 자동으로 처리합니다.
         *
         * 플로우:
         * 1. POST /webauthn/authenticate/options - Assertion Options 요청
         * 2. navigator.credentials.get() - 브라우저 생체 인증
         * 3. POST /login/webauthn - WebAuthnAuthenticationFilter 처리
         * 4. MfaFactorProcessingSuccessHandler 호출:
         *    - State Machine에 FACTOR_VERIFIED_SUCCESS 이벤트 전송
         *    - DETERMINE_NEXT_FACTOR 실행
         *    - OAuth2 토큰 발급 (필요시)
         *    - redirectUrl 결정 (다음 팩터 또는 최종 성공 URL)
         * 5. SDK는 redirectUrl을 받아 페이지 이동
         *
         * Note: MfaFactorProcessingSuccessHandler가 모든 State Machine 처리를 완료하므로
         *       SDK는 별도의 notifyFactorComplete() 호출이 불필요합니다.
         *
         * Legacy: mfa-verity-passkey.js 전체 로직 통합
         */
        async verifyPasskey() {
            try {
                ContexaMFAUtils.log('Starting Spring Security WebAuthn authentication flow...', 'debug');

                // 1. CSRF 헤더 준비
                const csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
                const csrfHeaderName = document.querySelector('meta[name="_csrf_header"]')?.content;
                const headers = csrfToken && csrfHeaderName ? { [csrfHeaderName]: csrfToken } : {};

                // 2. Spring Security 표준 WebAuthn 인증 실행
                const contextPath = this.apiClient.contextPath || '';
                const result = await this.performWebAuthnAuthentication(headers, contextPath);

                ContexaMFAUtils.log(`Spring Security authentication completed.`, 'debug');
                ContexaMFAUtils.log(`Status: ${result.status}, RedirectUrl: ${result.redirectUrl || result.nextStepUrl}`, 'debug');

                // 3. 상태 업데이트 (MfaFactorProcessingSuccessHandler 응답 반영)
                this.stateTracker.updateFromServerResponse(result);

                // 4. OAuth2 토큰 저장 (SuccessHandler가 발급한 경우)
                this.handleAuthenticationResult(result);

                // 5. MFA 플로우 결과 반환
                return result;
            } catch (error) {
                const errorMsg = error.response?.message || error.message || 'Passkey verification failed';
                ContexaMFAUtils.log(`Passkey verification failed: ${errorMsg}`, 'error', error);
                throw error;
            }
        }

        /**
         * Spring Security WebAuthn 인증 플로우 실행
         *
         * Spring Security의 webauthn.js 로직을 따르되, 자동 리다이렉트를 제거하여
         * SDK가 MFA 플로우 제어를 유지할 수 있도록 합니다.
         *
         * @param {Object} headers - CSRF 헤더
         * @param {string} contextPath - 애플리케이션 컨텍스트 경로
         * @returns {Promise<Object>} MfaFactorProcessingSuccessHandler 응답
         *
         * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
         * @see webauthn.js authenticate() function
         */
        async performWebAuthnAuthentication(headers, contextPath) {
            // Phase 1: Assertion Options 요청
            ContexaMFAUtils.log('Requesting assertion options...', 'debug');

            // SDK 초기화 확인
            await this.apiClient.init();

            // 동적 엔드포인트 사용 (URL 하드코딩 제거)
            const assertionOptionsUrl = this.apiClient.endpoints.webauthn?.assertionOptions || `${contextPath}/webauthn/authenticate/options`;
            const optionsResponse = await fetch(assertionOptionsUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    ...headers
                }
            });

            if (!optionsResponse.ok) {
                throw new Error(`Failed to fetch assertion options: HTTP ${optionsResponse.status}`);
            }

            const options = await optionsResponse.json();

            // Phase 2: Base64URL 디코딩 및 Credential Request Options 구성
            const decodedAllowCredentials = !options.allowCredentials ? [] :
                options.allowCredentials.map(cred => ({
                    ...cred,
                    id: ContexaMFAUtils.base64UrlToArrayBuffer(cred.id)
                }));

            const decodedOptions = {
                ...options,
                allowCredentials: decodedAllowCredentials,
                challenge: ContexaMFAUtils.base64UrlToArrayBuffer(options.challenge)
            };

            // Phase 3: WebAuthn API 호출 (브라우저 생체 인증)
            ContexaMFAUtils.log('Starting WebAuthn ceremony (user authentication)...', 'debug');
            const credential = await navigator.credentials.get({
                publicKey: decodedOptions
            });

            if (!credential) {
                throw new Error('WebAuthn authentication cancelled or failed');
            }

            ContexaMFAUtils.log('User authentication successful, preparing assertion...', 'debug');

            // Phase 4: Assertion 데이터 준비 (Base64URL 인코딩)
            const { response, type: credType } = credential;
            let userHandle;
            if (response.userHandle) {
                userHandle = ContexaMFAUtils.arrayBufferToBase64Url(response.userHandle);
            }

            const body = {
                id: credential.id,
                rawId: ContexaMFAUtils.arrayBufferToBase64Url(credential.rawId),
                response: {
                    authenticatorData: ContexaMFAUtils.arrayBufferToBase64Url(response.authenticatorData),
                    clientDataJSON: ContexaMFAUtils.arrayBufferToBase64Url(response.clientDataJSON),
                    signature: ContexaMFAUtils.arrayBufferToBase64Url(response.signature),
                    userHandle
                },
                credType,
                clientExtensionResults: credential.getClientExtensionResults(),
                authenticatorAttachment: credential.authenticatorAttachment
            };

            // Phase 5: Assertion POST (Spring Security WebAuthnAuthenticationFilter 처리)
            ContexaMFAUtils.log('Sending assertion to Spring Security...', 'debug');

            // 동적 엔드포인트 사용 (URL 하드코딩 제거)
            const loginProcessingUrl = this.apiClient.endpoints.passkey?.loginProcessing || `${contextPath}/login/webauthn`;
            const authenticationResponse = await fetch(loginProcessingUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    ...headers
                },
                body: JSON.stringify(body)
            });

            if (!authenticationResponse.ok) {
                throw new Error(`WebAuthn authentication failed: HTTP ${authenticationResponse.status}`);
            }

            const authenticationResult = await authenticationResponse.json();

            // Phase 6: 응답 검증 (MfaFactorProcessingSuccessHandler 응답 구조)
            // MFA_COMPLETED 상태에서만 authenticated 체크 (MFA_CONTINUE는 중간 단계이므로 체크 안함)
            if (authenticationResult.status === "MFA_COMPLETED" && !authenticationResult.authenticated) {
                throw new Error('WebAuthn authentication failed: Server returned authenticated=false for MFA_COMPLETED');
            }

            // 상태별 필수 속성 검증
            if (authenticationResult.status === "MFA_COMPLETED") {
                // 최종 완료: redirectUrl 필수
                if (!authenticationResult.redirectUrl) {
                    throw new Error('WebAuthn authentication failed: No redirectUrl for MFA_COMPLETED');
                }
            } else if (authenticationResult.status === "MFA_CONTINUE") {
                // 중간 단계: nextStepUrl 필수
                if (!authenticationResult.nextStepUrl) {
                    throw new Error('WebAuthn authentication failed: No nextStepUrl for MFA_CONTINUE');
                }
            }

            ContexaMFAUtils.log('Spring Security authentication successful', 'debug');
            return authenticationResult;
        }

        /**
         * Handle authentication result: store tokens to TokenMemory and persistent storage.
         *
         * authMode is derived from server response tokenTransportMethod field,
         * then persisted to localStorage for subsequent requests (logout, API calls).
         *
         * - header: accessToken + refreshToken in TokenMemory (sent via Authorization header)
         * - header_cookie: accessToken in TokenMemory, refreshToken managed by HttpOnly cookie
         * - cookie: all tokens managed by cookies, no TokenMemory storage needed
         */
        handleAuthenticationResult(result) {
            const authMode = result.tokenTransportMethod
                ? result.tokenTransportMethod.toLowerCase()
                : localStorage.getItem('authMode') || 'header';

            if (result.tokenTransportMethod) {
                localStorage.setItem('authMode', authMode);
            }

            if (authMode === 'header' || authMode === 'header_cookie') {
                if (result.accessToken && window.TokenMemory) {
                    window.TokenMemory.accessToken = result.accessToken;
                }

                if (authMode === 'header' && result.refreshToken && window.TokenMemory) {
                    window.TokenMemory.refreshToken = result.refreshToken;
                }
            }

            this.persistTokensToStorage(result);

            if (result.status === 'MFA_COMPLETED') {
                this.stateTracker.reset();
            }
        }

        /**
         * Persist tokens to configured storage (localStorage or sessionStorage)
         * Only activates when tokenPersistence option is not 'memory' (default)
         */
        persistTokensToStorage(result) {
            const persistence = (this.options.tokenPersistence || 'memory').toLowerCase();
            if (persistence === 'memory' || !result.accessToken) {
                return;
            }

            const storage = persistence === 'localstorage' ? localStorage
                          : persistence === 'sessionstorage' ? sessionStorage
                          : null;

            if (!storage) {
                return;
            }

            storage.setItem(TOKEN_STORAGE_KEYS.ACCESS_TOKEN, result.accessToken);

            if (result.refreshToken) {
                storage.setItem(TOKEN_STORAGE_KEYS.REFRESH_TOKEN, result.refreshToken);
            }

            if (result.expiresIn) {
                const expiresAt = Date.now() + result.expiresIn;
                storage.setItem(TOKEN_STORAGE_KEYS.EXPIRES_AT, String(expiresAt));
            }

            if (result.refreshExpiresIn) {
                const refreshExpiresAt = Date.now() + result.refreshExpiresIn;
                storage.setItem(TOKEN_STORAGE_KEYS.REFRESH_EXPIRES_AT, String(refreshExpiresAt));
            }
        }

        /**
         * Logout (High-level API)
         *
         * Server-side session/token invalidation via CompositeLogoutHandler.
         * Clears client-side state (TokenMemory, sessionStorage) regardless of outcome.
         *
         * @returns {Promise<Object>} Logout result with status field
         */
        async logout() {
            try {
                const result = await this.apiClient.logout();
                this.clearClientState();
                return result;
            } catch (error) {
                this.clearClientState();
                throw error;
            }
        }

        /**
         * Clear all client-side authentication state
         */
        clearClientState() {
            this.stateTracker.reset();
            if (window.TokenMemory) {
                window.TokenMemory.accessToken = null;
                window.TokenMemory.refreshToken = null;
            }

            this.clearPersistedTokens();
        }

        /**
         * Clear tokens from configured persistent storage
         */
        clearPersistedTokens() {
            const persistence = (this.options.tokenPersistence || 'memory').toLowerCase();
            if (persistence === 'memory') {
                return;
            }

            const storage = persistence === 'localstorage' ? localStorage
                          : persistence === 'sessionstorage' ? sessionStorage
                          : null;

            if (!storage) {
                return;
            }

            Object.values(TOKEN_STORAGE_KEYS).forEach(key => storage.removeItem(key));
        }
    }

    // ===========================
    // Module 5: Global Fetch Interceptor
    // ===========================

    /**
     * MFA Challenge automatic handling via global fetch wrapping
     *
     * When SDK is loaded, it automatically wraps window.fetch to detect
     * MFA_CHALLENGE_REQUIRED responses and redirect to MFA page.
     *
     * This allows users to use fetch() normally without additional code,
     * and MFA challenges are handled automatically.
     */
    (function installGlobalFetchInterceptor() {
        const originalFetch = window.fetch;

        window.fetch = async function(...args) {
            var response;
            try {
                response = await originalFetch.apply(this, args);
            } catch (networkError) {
                if (typeof ContexaMFAUtils !== 'undefined') {
                    ContexaMFAUtils.log('Network error during fetch - possible response blocking', 'warn');
                }
                throw networkError;
            }

            // Wrap only server-monitored responses (BlockableResponseWrapper sets this header)
            var isMonitored = response.headers.get('X-Contexa-Monitored') === 'true';
            if (response.ok && response.body && isMonitored) {
                var originalBody = response.body;
                var wrappedStream = new ReadableStream({
                    start: function(controller) {
                        var reader = originalBody.getReader();
                        function pump() {
                            reader.read().then(function(result) {
                                if (result.done) {
                                    controller.close();
                                    return;
                                }
                                controller.enqueue(result.value);
                                pump();
                            }).catch(function(streamError) {
                                // Stream terminated mid-flight - check if blocked by server
                                if (typeof ContexaMFAUtils !== 'undefined') {
                                    ContexaMFAUtils.log('Stream terminated - checking block status', 'warn');
                                    originalFetch.apply(window, ['/api/test-action/status', { credentials: 'same-origin' }])
                                        .then(function(r) { return r.json(); })
                                        .then(function(data) {
                                            if (data.action === 'BLOCK') {
                                                ContexaMFAUtils.renderResponseBlockedPage();
                                            }
                                        })
                                        .catch(function() { /* ignore */ });
                                }
                                controller.error(streamError);
                            });
                        }
                        pump();
                    }
                });

                return new Response(wrappedStream, {
                    status: response.status,
                    statusText: response.statusText,
                    headers: response.headers
                });
            }

            // Detect 401 MFA Challenge response
            if (response.status === 401) {
                try {
                    const clonedResponse = response.clone();
                    const data = await clonedResponse.json();

                    if ((data.error === 'MFA_CHALLENGE_REQUIRED' || data.error === 'BLOCK_MFA_REQUIRED')
                        && (data.challengeNoticeUrl || data.mfaUrl)) {
                        var redirectTarget = data.challengeNoticeUrl || data.mfaUrl;
                        ContexaMFAUtils.log(
                            `MFA Challenge detected, redirecting to: ${redirectTarget}`,
                            'info',
                            data
                        );
                        window.location.href = redirectTarget;
                        return new Promise(() => {});
                    }
                } catch (e) {
                    // Non-JSON 401 response, pass through
                }
            }

            // Detect 403 Account Blocked response
            if (response.status === 403) {
                try {
                    const clonedResponse = response.clone();
                    const data = await clonedResponse.json();

                    if (data.error === 'ACCOUNT_BLOCKED' && data.redirectUrl) {
                        ContexaMFAUtils.log(
                            `Account blocked detected, redirecting to: ${data.redirectUrl}`,
                            'info',
                            data
                        );
                        window.location.href = data.redirectUrl;
                        return new Promise(() => {});
                    }

                    if (data.error === 'RESPONSE_BLOCKED') {
                        ContexaMFAUtils.log('Response blocked by AI security decision', 'warn', data);
                        ContexaMFAUtils.renderResponseBlockedPage();
                        return new Promise(() => {});
                    }

                    if (data.error === 'BLOCK_MFA_FAILED' && data.redirectUrl) {
                        ContexaMFAUtils.log(
                            `Block MFA failed (${data.failCount}/${data.maxAttempts}), redirecting to: ${data.redirectUrl}`,
                            'info',
                            data
                        );
                        window.location.href = data.redirectUrl;
                        return new Promise(() => {});
                    }
                } catch (e) {
                    // Non-JSON 403 response, pass through
                }
            }

            // Detect 423 Security Review In Progress response
            if (response.status === 423) {
                try {
                    const clonedResponse = response.clone();
                    const data = await clonedResponse.json();

                    if (data.error === 'SECURITY_REVIEW_IN_PROGRESS' && data.redirectUrl) {
                        ContexaMFAUtils.log(
                            `Security review in progress, redirecting to: ${data.redirectUrl}`,
                            'info',
                            data
                        );
                        window.location.href = data.redirectUrl;
                        return new Promise(() => {});
                    }
                } catch (e) {
                    // Non-JSON 423 response, pass through
                }
            }

            return response;
        };

        ContexaMFAUtils.log(
            'Global fetch interceptor installed for MFA Challenge and Zero Trust handling', 'debug');
    })();

    // ===========================
    // Module 6: Global XHR Interceptor
    // ===========================

    /**
     * Intercepts XMLHttpRequest responses to detect security-related status codes
     * (401 MFA Challenge, 403 Account Blocked, 423 Security Review)
     * and automatically redirects to the appropriate page.
     */
    (function installGlobalXhrInterceptor() {
        var OriginalXHR = window.XMLHttpRequest;

        function InterceptedXHR() {
            var xhr = new OriginalXHR();
            var originalOpen = xhr.open;

            xhr.open = function() {
                return originalOpen.apply(xhr, arguments);
            };

            xhr.addEventListener('load', function() {
                try {
                    var status = xhr.status;
                    if (status !== 401 && status !== 403 && status !== 423) {
                        return;
                    }

                    var contentType = xhr.getResponseHeader('Content-Type');
                    if (!contentType || contentType.indexOf('application/json') === -1) {
                        return;
                    }

                    var data = JSON.parse(xhr.responseText);

                    // 401 MFA Challenge
                    if (status === 401 && (data.error === 'MFA_CHALLENGE_REQUIRED' || data.error === 'BLOCK_MFA_REQUIRED') && (data.challengeNoticeUrl || data.mfaUrl)) {
                        var xhrRedirectTarget = data.challengeNoticeUrl || data.mfaUrl;
                        ContexaMFAUtils.log(
                            'XHR: MFA Challenge detected, redirecting to: ' + xhrRedirectTarget,
                            'info', data);
                        window.location.href = xhrRedirectTarget;
                        return;
                    }

                    // 403 Response Blocked (in-flight termination)
                    if (status === 403 && data.error === 'RESPONSE_BLOCKED') {
                        ContexaMFAUtils.log('XHR: Response blocked by AI security decision', 'warn', data);
                        ContexaMFAUtils.renderResponseBlockedPage();
                        return;
                    }

                    // 403 Account Blocked
                    if (status === 403 && data.error === 'ACCOUNT_BLOCKED' && data.redirectUrl) {
                        ContexaMFAUtils.log(
                            'XHR: Account blocked detected, redirecting to: ' + data.redirectUrl,
                            'info', data);
                        window.location.href = data.redirectUrl;
                        return;
                    }

                    // 423 Security Review In Progress
                    if (status === 423 && data.error === 'SECURITY_REVIEW_IN_PROGRESS'
                            && data.redirectUrl) {
                        ContexaMFAUtils.log(
                            'XHR: Security review in progress, redirecting to: ' + data.redirectUrl,
                            'info', data);
                        window.location.href = data.redirectUrl;
                        return;
                    }
                } catch (e) {
                    // JSON parse failed, pass through
                }
            });

            return xhr;
        }

        InterceptedXHR.prototype = OriginalXHR.prototype;
        window.XMLHttpRequest = InterceptedXHR;

        ContexaMFAUtils.log(
            'Global XHR interceptor installed for MFA Challenge and Zero Trust handling', 'debug');
    })();

    // ===========================
    // Public API Export
    // ===========================

    window.ContexaMFA = {
        Client: ContexaMFAClient,
        Utils: ContexaMFAUtils,
        StateTracker: MfaStateTracker,
        TOKEN_STORAGE_KEYS: TOKEN_STORAGE_KEYS,
        version: '2.2.0'
    };

    // Legacy 호환성: 전역 인스턴스 자동 생성
    if (!window.mfaStateTracker) {
        window.mfaStateTracker = new MfaStateTracker();
        window.mfaStateTracker.restoreFromSession();
    }

    ContexaMFAUtils.log(`Contexa MFA SDK v2.1.0 loaded successfully`, 'info');

})(window);
