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
 *   await mfa.selectFactor('MFA_OTT');
 *   await mfa.verifyOtt('123456');
 *   await mfa.verifyPasskey();
 *
 * @module ContexaMFA
 */

(function(window) {
    'use strict';

    /**
     * Bundled i18n strings for user-facing texts the SDK renders directly
     * (the response-blocked page). Auto-selected by navigator.language.
     */
    const __ContexaMfaI18n = (function() {
        const messages = {
            en: {
                blockedTitle: 'Contexa - Access Blocked',
                blockedHeading: 'Access blocked by security policy',
                blockedDescLine1: 'Your session response was forcibly terminated by AI security analysis.',
                blockedDescLine2: 'If this is legitimate access, please contact your administrator.',
                blockedHomeButton: 'Go to Home',
                loginFailed: 'Login failed: please check username or password.',
                ottVerifyFailed: 'OTT verification failed',
                passkeyOptionsFailed: 'Failed to get passkey options',
                passkeyVerifyFailed: 'Passkey verification failed'
            },
            ko: {
                blockedTitle: 'Contexa - 접근 차단',
                blockedHeading: '보안 정책에 의해 접근이 차단되었습니다',
                blockedDescLine1: 'AI 보안 분석에 의해 현재 세션의 응답이 강제 종료되었습니다.',
                blockedDescLine2: '정상적인 접근이라면 관리자에게 문의해 주세요.',
                blockedHomeButton: '홈으로 이동',
                loginFailed: '로그인 실패: 아이디 또는 비밀번호를 확인하세요.',
                ottVerifyFailed: 'OTT 인증에 실패했습니다',
                passkeyOptionsFailed: 'Passkey 옵션을 가져오지 못했습니다',
                passkeyVerifyFailed: 'Passkey 인증에 실패했습니다'
            }
        };
        const lang = ((typeof navigator !== 'undefined' && navigator.language) || 'en')
                .slice(0, 2).toLowerCase();
        return messages[lang] || messages.en;
    })();


    /**
     * Custom error class containing the full server response
     */
    class MFAError extends Error {
        constructor(message, response = null, status = null) {
            super(message);
            this.name = 'MFAError';
            this.response = response;
            this.status = status;
        }
    }


    const ContexaMFAUtils = {
        /**
         * Retrieve CSRF token
         */
        getCsrfToken() {
            const meta = document.querySelector('meta[name="_csrf"]');
            return meta ? meta.getAttribute('content') : null;
        },

        /**
         * Retrieve CSRF header name
         */
        getCsrfHeader() {
            const meta = document.querySelector('meta[name="_csrf_header"]');
            return meta ? meta.getAttribute('content') : 'X-CSRF-TOKEN';
        },

        /**
         * Create or retrieve Device ID
         * Legacy: same code was duplicated across 7 of 8 files
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
         * Convert Base64URL to ArrayBuffer (required by WebAuthn)
         * Legacy: same code was duplicated across 3 files
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
         * Convert ArrayBuffer to Base64URL (required by WebAuthn)
         * Legacy: same code was duplicated across 3 files
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
         * Build common fetch headers (P0 fix: add X-MFA-Step-Id)
         * Legacy: header build logic was duplicated across 8 files
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
         * Logging utility
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
                    <title>${__ContexaMfaI18n.blockedTitle}</title>
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
                        <h1>${__ContexaMfaI18n.blockedHeading}</h1>
                        <p class="desc">
                            ${__ContexaMfaI18n.blockedDescLine1}<br>
                            ${__ContexaMfaI18n.blockedDescLine2}
                        </p>
                        <a class="btn" href="/">${__ContexaMfaI18n.blockedHomeButton}</a>
                        <div class="footer">Contexa AI Native Zero Trust Security Platform</div>
                    </div>
                </body>
            `;
        }
    };


    class MfaStateTracker {
        constructor() {
            this.currentState = null;
            this.sessionId = null;
            this.stateMetadata = {};
            this.lastUpdate = null;

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
         * Update state machine state from server response
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

            this.saveToSession();

            if (previousState && previousState !== this.currentState) {
                ContexaMFAUtils.log(`State updated: ${previousState} → ${this.currentState}`, 'debug');
            }
        }

        /**
         * Validate whether transition to a given state is allowed
         * Legacy: mfa-state-tracker.js:38-54
         */
        canTransitionTo(targetState) {
            if (!this.currentState) return true;

            const validTargets = this.validTransitions[this.currentState];
            if (!validTargets) return false;

            return validTargets.includes(targetState);
        }

        /**
         * P1 fix: verify terminal state (extended from 3 to 8)
         * Legacy: mfa-state-tracker.js:56-69
         * Aligned exactly with server-side MfaState.isTerminal()
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
         * P2 added: check waiting-for-user-action state
         * Legacy: mfa-state-tracker.js:71-76
         * Aligned with server-side MfaState.isWaitingForUserAction()
         */
        isWaitingForUserAction() {
            return this.currentState === 'AWAITING_FACTOR_SELECTION' ||
                this.currentState === 'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION';
        }

        /**
         * P2 added: check in-progress state
         * Legacy: mfa-state-tracker.js:78-83
         * Synchronized with server MfaState.isProcessing()
         */
        isProcessing() {
            return this.currentState === 'AWAITING_FACTOR_CHALLENGE_INITIATION' ||
                this.currentState === 'FACTOR_CHALLENGE_INITIATED' ||
                this.currentState === 'FACTOR_VERIFICATION_PENDING';
        }

        /**
         * P2 added: persist to session
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
         * P2 added: restore from session
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
         * Reset state
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


    const ContexaMFAApiClient = {
        endpoints: {},
        initialized: false,
        configUrl: '/api/mfa/config',

        /**
         * Initialize SDK - load endpoint configuration from the server
         *
         * Multi-MFA support: /api/mfa/config returns URL settings matching the current MFA session Flow.
         * The Flow is identified by the MFA_SID cookie.
         *
         * @param {Object} [options] - Initialization options
         * @param {string} [options.configUrl] - Config endpoint URL (default: /api/mfa/config)
         */
        async init(options) {
            if (this.initialized) return;

            if (options && options.configUrl) {
                this.configUrl = options.configUrl;
            }

            if (window.__MFA_CONFIG__) {
                this.endpoints = window.__MFA_CONFIG__;
                this.initialized = true;
                return;
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

                this.endpoints = await response.json();
                this.initialized = true;
            } catch (error) {
                this.endpoints = this._getDefaultEndpoints();
                this.initialized = true;
            }
        },

        /**
         * Default endpoint configuration (fallback - used only when the server is unreachable)
         *
         * During normal operation, /api/mfa/config supplies dynamic per-Flow URLs.
         * This fallback is only used in extreme situations when the server does not respond,
         * server-supplied configuration always takes precedence in Multi-MFA environments.
         */
        _getDefaultEndpoints() {
            var cfg = window.__MFA_CONFIG__;
            var prefix = (cfg && cfg.urlPrefix) ? cfg.urlPrefix : '';
            return {
                primary: {
                    restLoginProcessing: prefix + '/api/login',
                    formLoginProcessing: prefix + '/mfa/login'
                },
                ott: {
                    loginProcessing: prefix + '/login/mfa-ott'
                },
                passkey: {
                    loginProcessing: prefix + '/login/mfa-webauthn'
                },
                api: {
                    selectFactor: prefix + '/mfa/select-factor',
                    requestOttCode: prefix + '/mfa/request-ott-code',
                    config: '/api/mfa/config',
                    logout: prefix + '/logout'
                },
                webauthn: {
                    assertionOptions: prefix + '/webauthn/authenticate/options',
                    assertionVerify: prefix + '/login/webauthn'
                }
            };
        },

        /**
         * Primary authentication: username/password login
         * Method intended for REST-API-based SPA clients
         *
         * @param {string} username - username
         * @param {string} password - password
         * @returns {Promise<Object>} Login result
         *   - mfaRequired: Whether MFA is required
         *   - nextStepUrl: Next-step URL (when MFA is required)
         *   - success: Login success flag (when MFA is not required)
         *
         * @example
         * const mfa = new ContexaMFA.Client();
         * try {
         *     const result = await mfa.login('username', 'password');
         *     if (result.mfaRequired) {
         *         // MFA required: navigate to the next step
         *         window.location.href = result.nextStepUrl;
         *     } else {
         *         // Login succeeded: navigate to home
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

            if (result.status === 'MFA_REQUIRED_SELECT_FACTOR' ||
                result.status === 'MFA_REQUIRED') {
                sessionStorage.setItem('mfaUsername', username);
                sessionStorage.setItem('mfaSessionId', result.mfaSessionId);
                this.state = 'MFA_REQUIRED';
                const message = result.message || 'MFA required';
                ContexaMFAUtils.log(`✅ Primary authentication successful: ${message}`, 'info', result);
            } else if (result.status === 'MFA_COMPLETED') {
                this.state = 'AUTHENTICATED';
                const message = result.message || 'Login successful';
                ContexaMFAUtils.log(`✅ ${message} (MFA completed, tokens issued)`, 'info', result);
            } else {
                this.state = 'AUTHENTICATED';
                const message = result.message || 'Login successful';
                ContexaMFAUtils.log(`✅ ${message}`, 'info', result);
            }

            return result;
        },

        /**
         * Primary authentication: Form login (talks to MfaFormAuthenticationFilter)
         *
         * Method for Form-based MFA authentication.
         * Sends application/x-www-form-urlencoded payloads to MfaFormAuthenticationFilter.
         *
         * @param {string} username - username
         * @param {string} password - password
         * @returns {Promise<Object>} Login result
         *   - mfaRequired: Whether MFA is required
         *   - nextStepUrl: Next-step URL (when MFA is required)
         *   - success: Login success flag (when MFA is not required)
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
                const errorData = await response.json().catch(() => ({ message: __ContexaMfaI18n.loginFailed }));
                throw new MFAError(
                    errorData.message || `Login failed: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            const result = await response.json();

            if (result.status === 'MFA_REQUIRED_SELECT_FACTOR' ||
                result.status === 'MFA_REQUIRED') {
                sessionStorage.setItem('mfaUsername', username);
                sessionStorage.setItem('mfaSessionId', result.mfaSessionId);
                this.state = 'MFA_REQUIRED';
                const message = result.message || 'MFA required';
                ContexaMFAUtils.log(`✅ Primary authentication successful (Form): ${message}`, 'info', result);
            } else if (result.status === 'MFA_COMPLETED') {
                this.state = 'AUTHENTICATED';
                const message = result.message || 'Login successful';
                ContexaMFAUtils.log(`✅ ${message} (MFA completed, tokens issued)`, 'info', result);
            } else {
                this.state = 'AUTHENTICATED';
                const message = result.message || 'Login successful';
                ContexaMFAUtils.log(`✅ ${message}`, 'info', result);
            }

            return result;
        },

        /**
         * Select factor
         * Legacy: mfa-select-factor.js:119-159
         */
        async selectFactor(factorType) {
            await this.init();
            const normalizedFactorType = factorType === 'OTT' ? 'MFA_OTT' : factorType;

            const response = await fetch(this.endpoints.api.selectFactor, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders(),
                body: JSON.stringify({
                    factorType: normalizedFactorType,
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
         * Request OTT code resend
         * Legacy: mfa-ott-request-code.js (partial), mfa-verity-ott.js:98-150
         */
        async requestOttCode() {
            await this.init();
            const username = sessionStorage.getItem('mfaUsername');
            const generationEndpoint = (this.endpoints.ott && this.endpoints.ott.codeGeneration)
                || this.endpoints.api.requestOttCode;
            const usesGenerationFilter = generationEndpoint !== this.endpoints.api.requestOttCode
                || generationEndpoint.indexOf('/generate') >= 0;
            const headers = ContexaMFAUtils.createHeaders({
                contentType: usesGenerationFilter ? 'application/x-www-form-urlencoded' : 'application/json'
            });
            const body = usesGenerationFilter
                ? new URLSearchParams({ username: username || '' }).toString()
                : JSON.stringify({ username: username });

            const response = await fetch(generationEndpoint, {
                method: 'POST',
                headers: headers,
                body: body
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new MFAError(
                    errorData.message || `Failed to request OTT code: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            const contentType = response.headers.get('Content-Type') || '';
            if (contentType.indexOf('application/json') >= 0) {
                return await response.json();
            }

            return {
                status: 'CODE_REQUESTED',
                redirectUrl: response.url || null
            };
        },

        /**
         * P0 fix: OTT code verification (Content-Type corrected)
         * Legacy: mfa-verity-ott.js:156-291
         *
         * CRITICAL: Spring Security oneTimeTokenLogin()
         * requires application/x-www-form-urlencoded format
         */
        async verifyOtt(code, username) {
            await this.init();

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
                    contentType: 'application/x-www-form-urlencoded'  // P0 fix
                }),
                body: formData.toString()
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: __ContexaMfaI18n.ottVerifyFailed }));
                throw new MFAError(
                    errorData.message || `OTT verification failed: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        },

        /**
         * Retrieve Passkey assertion options
         * ⭐ Uses Spring Security 6.4+ standard endpoint
         */
        async getPasskeyOptions() {
            await this.init();

            const response = await fetch(this.endpoints.webauthn.assertionOptions, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders()
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: __ContexaMfaI18n.passkeyOptionsFailed }));
                throw new MFAError(
                    errorData.message || `Failed to get passkey options: ${response.status}`,
                    errorData,
                    response.status
                );
            }

            return await response.json();
        },

        /**
         * Perform Passkey authentication
         * ⭐ Uses Spring Security 6.4+ standard endpoint
         */
        async verifyPasskey(publicKeyCredential) {
            await this.init();

            const response = await fetch(this.endpoints.webauthn.assertionVerify, {
                method: 'POST',
                headers: ContexaMFAUtils.createHeaders(),
                body: JSON.stringify(publicKeyCredential)
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: __ContexaMfaI18n.passkeyVerifyFailed }));
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
                this._restoreTokensFromStorage();
            }
        }

        /**
         * Initialize SDK
         * @param {Object} [options] - Initialization options
         * @param {string} [options.configUrl] - Config endpoint URL (per-Flow configuration in Multi-MFA)
         */
        async init(options) {
            await this.apiClient.init(options);
            ContexaMFAUtils.log('MFA SDK initialized', 'info');
        }

        _restoreTokensFromStorage() {
            const persistence = (this.options.tokenPersistence || 'memory').toLowerCase();
            if (persistence === 'memory') return;

            const storage = persistence === 'localstorage' ? localStorage : sessionStorage;
            const accessToken = storage.getItem(TOKEN_STORAGE_KEYS.ACCESS_TOKEN);
            const refreshToken = storage.getItem(TOKEN_STORAGE_KEYS.REFRESH_TOKEN);

            if (accessToken) {
                if (!window.TokenMemory) {
                    window.TokenMemory = { accessToken: null, refreshToken: null };
                }
                window.TokenMemory.accessToken = accessToken;
                if (refreshToken) {
                    window.TokenMemory.refreshToken = refreshToken;
                }
            }
        }

        /**
         * Select factor (High-level API)
         * Legacy: mfa-select-factor.js consolidated entire logic
         *
         * Note: autoRedirect logic removed (prevents race condition)
         * Caller must inspect result and redirect explicitly
         */
        async selectFactor(factorType) {
            try {
                const result = await this.apiClient.selectFactor(factorType);
                this.stateTracker.updateFromServerResponse(result);

                if (result.nextStepId) {
                    sessionStorage.setItem('currentMfaStepId', result.nextStepId);
                }

                if (result.nextFactorType) {
                    sessionStorage.setItem('currentMfaFactor', result.nextFactorType);
                }

                return result;
            } catch (error) {
                const errorMsg = error.response?.message || 'Factor selection failed';
                ContexaMFAUtils.log(`${errorMsg}`, 'error', error);
                throw error;
            }
        }

        /**
         * OTT verification (High-level API)
         * Legacy: mfa-verity-ott.js consolidated entire logic
         *
         * Note: autoRedirect logic removed (prevents race condition)
         * Caller must inspect result and redirect explicitly
         */
        async verifyOtt(code, username = null) {
            try {
                const result = await this.apiClient.verifyOtt(code, username);
                this.stateTracker.updateFromServerResponse(result);

                this.handleAuthenticationResult(result);

                if (result.nextStepId) {
                    sessionStorage.setItem('currentMfaStepId', result.nextStepId);
                }

                if (result.nextFactorType) {
                    sessionStorage.setItem('currentMfaFactor', result.nextFactorType);
                }

                return result;
            } catch (error) {
                const errorMsg = error.response?.message || 'OTT verification failed';
                ContexaMFAUtils.log(`${errorMsg}`, 'error', error);
                throw error;
            }
        }

        /**
         * Passkey authentication (High-level API)
         *
         * Follows the standard Spring Security WebAuthn flow; MfaFactorProcessingSuccessHandler
         * handles state machine integration automatically.
         *
         * Flow:
         * 1. POST /webauthn/authenticate/options - request assertion options
         * 2. navigator.credentials.get() - browser biometric authentication
         * 3. POST /login/webauthn - WebAuthnAuthenticationFilter processing
         * 4. Invoke MfaFactorProcessingSuccessHandler:
         *    - Sends FACTOR_VERIFIED_SUCCESS event to the state machine
         *    - Runs DETERMINE_NEXT_FACTOR
         *    - Issues OAuth2 token (when needed)
         *    - Resolves redirectUrl (next factor or final success URL)
         * 5. SDK receives redirectUrl and navigates
         *
         * Note: Because MfaFactorProcessingSuccessHandler completes all state machine processing,
         *       the SDK does not need a separate notifyFactorComplete() call.
         *
         * Legacy: mfa-verity-passkey.js consolidated entire logic
         */
        async verifyPasskey() {
            try {
                ContexaMFAUtils.log('Starting Spring Security WebAuthn authentication flow...', 'debug');

                const csrfToken = document.querySelector('meta[name="_csrf"]')?.content;
                const csrfHeaderName = document.querySelector('meta[name="_csrf_header"]')?.content;
                const headers = csrfToken && csrfHeaderName ? { [csrfHeaderName]: csrfToken } : {};

                const contextPath = this.apiClient.contextPath || '';
                const result = await this.performWebAuthnAuthentication(headers, contextPath);

                ContexaMFAUtils.log(`Spring Security authentication completed.`, 'debug');
                ContexaMFAUtils.log(`Status: ${result.status}, RedirectUrl: ${result.redirectUrl || result.nextStepUrl}`, 'debug');

                this.stateTracker.updateFromServerResponse(result);

                this.handleAuthenticationResult(result);

                return result;
            } catch (error) {
                const errorMsg = error.response?.message || error.message || 'Passkey verification failed';
                ContexaMFAUtils.log(`Passkey verification failed: ${errorMsg}`, 'error', error);
                throw error;
            }
        }

        /**
         * Execute the Spring Security WebAuthn authentication flow
         *
         * Follows the Spring Security webauthn.js logic but removes the automatic redirect
         * so the SDK retains control of the MFA flow.
         *
         * @param {Object} headers - CSRF headers
         * @param {string} contextPath - application context path
         * @returns {Promise<Object>} MfaFactorProcessingSuccessHandler response
         *
         * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
         * @see webauthn.js authenticate() function
         */
        async performWebAuthnAuthentication(headers, contextPath) {
            ContexaMFAUtils.log('Requesting assertion options...', 'debug');

            await this.apiClient.init();

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

            ContexaMFAUtils.log('Starting WebAuthn ceremony (user authentication)...', 'debug');
            const credential = await navigator.credentials.get({
                publicKey: decodedOptions
            });

            if (!credential) {
                throw new Error('WebAuthn authentication cancelled or failed');
            }

            ContexaMFAUtils.log('User authentication successful, preparing assertion...', 'debug');

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

            ContexaMFAUtils.log('Sending assertion to Spring Security...', 'debug');

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

            if (authenticationResult.status === "MFA_COMPLETED" && !authenticationResult.authenticated) {
                throw new Error('WebAuthn authentication failed: Server returned authenticated=false for MFA_COMPLETED');
            }

            if (authenticationResult.status === "MFA_COMPLETED") {
                if (!authenticationResult.redirectUrl) {
                    throw new Error('WebAuthn authentication failed: No redirectUrl for MFA_COMPLETED');
                }
            } else if (authenticationResult.status === "MFA_CONTINUE") {
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

            var isMonitored = response.headers.get('X-Contexa-Monitored') === 'true';
            if (response.ok && response.body && isMonitored) {
                var BLOCK_SIGNAL = '__CONTEXA_RESPONSE_BLOCKED__';
                var BLOCK_SIGNAL_PATTERN = /__CONTEXA_RESPONSE_BLOCKED__:(\w+)/;
                var blockSignalDecoder = new TextDecoder();
                var originalBody = response.body;
                var wrappedStream = new ReadableStream({
                    start: function(controller) {
                        var reader = originalBody.getReader();

                        function handleBlocked(action) {
                            var effectiveAction = action || 'BLOCK';
                            if (!window.__CONTEXA_SKIP_STREAM_REDIRECT) {
                                var prefix = '';
                                var cfg = window.__MFA_CONFIG__;
                                if (cfg && cfg.urlPrefix) {
                                    prefix = cfg.urlPrefix;
                                } else {
                                    var path = window.location.pathname;
                                    var segments = path.split('/').filter(Boolean);
                                    if (segments.length > 0 && segments[0] !== 'api') {
                                        var firstSegment = '/' + segments[0];
                                        if (firstSegment !== '/mfa' && firstSegment !== '/login'
                                            && firstSegment !== '/zero-trust' && firstSegment !== '/logout') {
                                            prefix = firstSegment;
                                        }
                                    }
                                }
                                window.location.href = prefix + '/';
                            }
                            controller.error(new Error('Response blocked: ' + effectiveAction));
                        }

                        function pump() {
                            reader.read().then(function(result) {
                                if (result.done) {
                                    controller.close();
                                    return;
                                }
                                var text = blockSignalDecoder.decode(result.value, { stream: true });
                                if (text.indexOf(BLOCK_SIGNAL) !== -1) {
                                    var match = text.match(BLOCK_SIGNAL_PATTERN);
                                    handleBlocked(match ? match[1] : null);
                                    return;
                                }
                                controller.enqueue(result.value);
                                pump();
                            }).catch(function(streamError) {
                                handleBlocked(null);
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
                }
            }

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
                }
            }

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
                }
            }

            return response;
        };

        ContexaMFAUtils.log(
            'Global fetch interceptor installed for MFA Challenge and Zero Trust handling', 'debug');
    })();


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
            var isMonitored = false;
            var blockedRedirectUrl = null;

            xhr.open = function() {
                return originalOpen.apply(xhr, arguments);
            };

            var BLOCK_SIGNAL = '__CONTEXA_RESPONSE_BLOCKED__';
            var BLOCK_SIGNAL_PATTERN = /__CONTEXA_RESPONSE_BLOCKED__:(\w+)/;
            var xhrBlockHandled = false;

            xhr.addEventListener('readystatechange', function() {
                if (xhr.readyState >= 2) {
                    try {
                        var monitored = xhr.getResponseHeader('X-Contexa-Monitored');
                        if (monitored === 'true') {
                            isMonitored = true;
                            blockedRedirectUrl = xhr.getResponseHeader('X-Contexa-Blocked-Redirect');
                        }
                    } catch (e) {
                    }
                }
                if (xhr.readyState >= 3 && isMonitored && !xhrBlockHandled) {
                    try {
                        if (xhr.responseText && xhr.responseText.indexOf(BLOCK_SIGNAL) !== -1) {
                            xhrBlockHandled = true;
                            var match = xhr.responseText.match(BLOCK_SIGNAL_PATTERN);
                            var action = match ? match[1] : 'BLOCK';
                            ContexaMFAUtils.log('XHR: In-band block signal detected: ' + action, 'warn');
                            if (!window.__CONTEXA_SKIP_STREAM_REDIRECT) {
                                var xhrPrefix = '';
                                var xhrCfg = window.__MFA_CONFIG__;
                                if (xhrCfg && xhrCfg.urlPrefix) {
                                    xhrPrefix = xhrCfg.urlPrefix;
                                }
                                window.location.href = xhrPrefix + '/';
                            }
                            xhr.abort();
                        }
                    } catch (e) {
                    }
                }
            });

            xhr.addEventListener('error', function() {
                if (isMonitored && !window.__CONTEXA_SKIP_STREAM_REDIRECT) {
                    ContexaMFAUtils.log('XHR: Monitored response terminated by security decision', 'warn');
                    if (blockedRedirectUrl) {
                        window.location.href = blockedRedirectUrl;
                    } else {
                        ContexaMFAUtils.renderResponseBlockedPage();
                    }
                }
            });

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

                    if (status === 401 && (data.error === 'MFA_CHALLENGE_REQUIRED' || data.error === 'BLOCK_MFA_REQUIRED') && (data.challengeNoticeUrl || data.mfaUrl)) {
                        var xhrRedirectTarget = data.challengeNoticeUrl || data.mfaUrl;
                        ContexaMFAUtils.log(
                            'XHR: MFA Challenge detected, redirecting to: ' + xhrRedirectTarget,
                            'info', data);
                        window.location.href = xhrRedirectTarget;
                        return;
                    }

                    if (status === 403 && data.error === 'RESPONSE_BLOCKED') {
                        ContexaMFAUtils.log('XHR: Response blocked by AI security decision', 'warn', data);
                        if (blockedRedirectUrl && !window.__CONTEXA_SKIP_STREAM_REDIRECT) {
                            window.location.href = blockedRedirectUrl;
                        } else {
                            ContexaMFAUtils.renderResponseBlockedPage();
                        }
                        return;
                    }

                    if (status === 403 && data.error === 'ACCOUNT_BLOCKED' && data.redirectUrl) {
                        ContexaMFAUtils.log(
                            'XHR: Account blocked detected, redirecting to: ' + data.redirectUrl,
                            'info', data);
                        window.location.href = data.redirectUrl;
                        return;
                    }

                    if (status === 423 && data.error === 'SECURITY_REVIEW_IN_PROGRESS'
                            && data.redirectUrl) {
                        ContexaMFAUtils.log(
                            'XHR: Security review in progress, redirecting to: ' + data.redirectUrl,
                            'info', data);
                        window.location.href = data.redirectUrl;
                        return;
                    }
                } catch (e) {
                }
            });

            return xhr;
        }

        InterceptedXHR.prototype = OriginalXHR.prototype;
        window.XMLHttpRequest = InterceptedXHR;

        ContexaMFAUtils.log(
            'Global XHR interceptor installed for MFA Challenge and Zero Trust handling', 'debug');
    })();


    window.ContexaMFA = {
        Client: ContexaMFAClient,
        Utils: ContexaMFAUtils,
        StateTracker: MfaStateTracker,
        TOKEN_STORAGE_KEYS: TOKEN_STORAGE_KEYS,
        version: '2.2.0'
    };

    if (!window.mfaStateTracker) {
        window.mfaStateTracker = new MfaStateTracker();
        window.mfaStateTracker.restoreFromSession();
    }

    ContexaMFAUtils.log(`Contexa MFA SDK v2.1.0 loaded successfully`, 'info');

})(window);
