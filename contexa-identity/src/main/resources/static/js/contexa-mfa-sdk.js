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

    class MFAError extends Error {
        constructor(message, response = null, status = null) {
            super(message);
            this.name = 'MFAError';
            this.response = response;  // 서버 응답 데이터 전체
            this.status = status;      // HTTP 상태 코드
        }
    }

    const ContexaMFAUtils = {
        getCsrfToken() {
            const meta = document.querySelector('meta[name="_csrf"]');
            return meta ? meta.getAttribute('content') : null;
        },

        getCsrfHeader() {
            const meta = document.querySelector('meta[name="_csrf_header"]');
            return meta ? meta.getAttribute('content') : 'X-CSRF-TOKEN';
        },

        getDeviceId() {
            const storageKey = 'deviceId';
            let deviceId = localStorage.getItem(storageKey);

            if (!deviceId) {
                deviceId = crypto.randomUUID();
                localStorage.setItem(storageKey, deviceId);
            }

            return deviceId;
        },
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

        createHeaders(options = {}) {
            const contentType = options.contentType || 'application/json';
            const mfaSessionId = options.mfaSessionId || sessionStorage.getItem('mfaSessionId');
            const stepId = options.stepId || sessionStorage.getItem('currentMfaStepId');

            const headers = {
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

        log(message, type = 'info', data = null) {
            const prefix = `[Contexa MFA SDK v2.0]`;
            if (data) {
                console[type](prefix, message, data);
            } else {
                console[type](prefix, message);
            }
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

        canTransitionTo(targetState) {
            if (!this.currentState) return true;

            const validTargets = this.validTransitions[this.currentState];
            if (!validTargets) return false;

            return validTargets.includes(targetState);
        }

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

        isWaitingForUserAction() {
            return this.currentState === 'AWAITING_FACTOR_SELECTION' ||
                this.currentState === 'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION';
        }

        isProcessing() {
            return this.currentState === 'AWAITING_FACTOR_CHALLENGE_INITIATION' ||
                this.currentState === 'FACTOR_CHALLENGE_INITIATED' ||
                this.currentState === 'FACTOR_VERIFICATION_PENDING';
        }

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

                this.endpoints = await response.json();
                this.initialized = true;
                ContexaMFAUtils.log('✅ SDK initialized successfully with server configuration', 'info', this.endpoints);
            } catch (error) {
                ContexaMFAUtils.log('⚠️ Failed to initialize SDK from server, using fallback defaults', 'warn', error);
                this.endpoints = this._getDefaultEndpoints();
                this.initialized = true;
            }
        },

        _getDefaultEndpoints() {
            return {
                primary: {
                    restLoginProcessing: '/api/auth/login',
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
                    config: '/api/mfa/config'
                },
                webauthn: {
                    assertionOptions: '/webauthn/authenticate/options',
                    assertionVerify: '/login/webauthn'
                }
            };
        },

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
        }
    };

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

            if (this.options.autoInit) {
                this.stateTracker.restoreFromSession();
            }
        }

        async init() {
            await this.apiClient.init();
            ContexaMFAUtils.log('MFA SDK initialized', 'info');
        }

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

        async performWebAuthnAuthentication(headers, contextPath) {
            ContexaMFAUtils.log('Requesting assertion options...', 'debug');
            await this.apiClient.init();
            const assertionOptionsUrl = this.apiClient.endpoints.webauthn?.assertionOptions || `${contextPath}/webauthn/authenticate/options`;
            const optionsResponse = await fetch(assertionOptionsUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
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

            if (result.status === 'MFA_COMPLETED') {
                this.stateTracker.reset();
            }
        }

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

    (function installGlobalFetchInterceptor() {
        const originalFetch = window.fetch;

        window.fetch = async function(...args) {
            const response = await originalFetch.apply(this, args);

            if (response.status === 401) {
                try {
                    const clonedResponse = response.clone();
                    const data = await clonedResponse.json();

                    if (data.error === 'MFA_CHALLENGE_REQUIRED' && data.mfaUrl) {
                        ContexaMFAUtils.log(
                            `MFA Challenge detected, redirecting to: ${data.mfaUrl}`,
                            'info',
                            data
                        );

                        window.location.href = data.mfaUrl;

                        return new Promise(() => {});
                    }
                } catch (e) {
                }
            }

            return response;
        };

        ContexaMFAUtils.log('Global fetch interceptor installed for MFA Challenge handling', 'debug');
    })();

    window.ContexaMFA = {
        Client: ContexaMFAClient,
        Utils: ContexaMFAUtils,
        StateTracker: MfaStateTracker,
        version: '2.0.0'
    };

    if (!window.mfaStateTracker) {
        window.mfaStateTracker = new MfaStateTracker();
        window.mfaStateTracker.restoreFromSession();
    }

    ContexaMFAUtils.log(`Contexa MFA SDK v2.0.0 loaded successfully`, 'info');

})(window);
