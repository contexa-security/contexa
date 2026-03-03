/**
 * ============================================================================
 * Contexa Token Authentication Test
 * ============================================================================
 *
 * Reads tokens from localStorage (stored by MFA SDK with tokenPersistence='localStorage')
 * and provides UI for testing token-based API calls.
 *
 * Flow:
 * 1. User logs in via existing login page (MFA SDK handles authentication)
 * 2. MFA SDK stores tokens in localStorage (tokenPersistence option)
 * 3. This page reads tokens from localStorage
 * 4. Test protected API calls with Authorization: Bearer <accessToken>
 * 5. Test token refresh, validation
 */

'use strict';

(function() {

    const STORAGE_KEYS = {
        ACCESS_TOKEN: 'contexa_access_token',
        REFRESH_TOKEN: 'contexa_refresh_token',
        EXPIRES_AT: 'contexa_expires_at',
        REFRESH_EXPIRES_AT: 'contexa_refresh_expires_at'
    };

    const API = {
        TOKEN_REFRESH: '/api/token-test/refresh',
        TOKEN_VALIDATE: '/api/token-test/validate',
        TOKEN_USERINFO: '/api/token-test/userinfo',
        TEST_NORMAL: '/api/security-test/normal/',
        TEST_SENSITIVE: '/api/security-test/sensitive/',
        TEST_CRITICAL: '/api/security-test/critical/'
    };

    const state = {
        accessToken: null,
        refreshToken: null,
        expiresAt: null,
        refreshExpiresAt: null,
        isLoggedIn: false,
        expiryTimerId: null
    };

    let elements = {};

    // ========================================================================
    // Initialization
    // ========================================================================

    function initializeElements() {
        elements = {
            authIndicator: document.getElementById('auth-indicator'),
            authText: document.getElementById('auth-text'),

            noTokenNotice: document.getElementById('no-token-notice'),

            accessTokenRaw: document.getElementById('access-token-raw'),
            accessTokenStatus: document.getElementById('access-token-status'),
            accessTokenExpiry: document.getElementById('access-token-expiry'),
            accessTokenCard: document.getElementById('access-token-card'),

            refreshTokenRaw: document.getElementById('refresh-token-raw'),
            refreshTokenStatus: document.getElementById('refresh-token-status'),
            refreshTokenExpiry: document.getElementById('refresh-token-expiry'),
            refreshTokenCard: document.getElementById('refresh-token-card'),

            btnRefreshToken: document.getElementById('btn-refresh-token'),
            btnValidateToken: document.getElementById('btn-validate-token'),
            btnLogout: document.getElementById('btn-logout'),

            jwtPayloadPanel: document.getElementById('jwt-payload-panel'),
            jwtPayloadContent: document.getElementById('jwt-payload-content'),

            btnApiNormal: document.getElementById('btn-api-normal'),
            btnApiSensitive: document.getElementById('btn-api-sensitive'),
            btnApiCritical: document.getElementById('btn-api-critical'),
            btnApiUserinfo: document.getElementById('btn-api-userinfo'),

            apiResponsePanel: document.getElementById('api-response-panel'),
            apiResponseStatus: document.getElementById('api-response-status'),
            apiResponseBody: document.getElementById('api-response-body'),

            timelineContainer: document.getElementById('timeline-container'),
            btnClearTimeline: document.getElementById('btn-clear-timeline')
        };
    }

    function bindEventListeners() {
        if (elements.btnRefreshToken) {
            elements.btnRefreshToken.addEventListener('click', refreshTokens);
        }
        if (elements.btnValidateToken) {
            elements.btnValidateToken.addEventListener('click', validateToken);
        }
        if (elements.btnLogout) {
            elements.btnLogout.addEventListener('click', logout);
        }

        if (elements.btnApiNormal) {
            elements.btnApiNormal.addEventListener('click', function() { callProtectedApi('normal'); });
        }
        if (elements.btnApiSensitive) {
            elements.btnApiSensitive.addEventListener('click', function() { callProtectedApi('sensitive'); });
        }
        if (elements.btnApiCritical) {
            elements.btnApiCritical.addEventListener('click', function() { callProtectedApi('critical'); });
        }
        if (elements.btnApiUserinfo) {
            elements.btnApiUserinfo.addEventListener('click', getUserInfo);
        }

        if (elements.btnClearTimeline) {
            elements.btnClearTimeline.addEventListener('click', clearTimeline);
        }
    }

    function initialize() {
        initializeElements();
        bindEventListeners();

        loadTokensFromStorage();

        if (state.isLoggedIn) {
            addLog('info', 'Tokens loaded from localStorage');
            updateTokenDisplay();
            startExpiryTimer();
            if (elements.noTokenNotice) elements.noTokenNotice.style.display = 'none';
        } else {
            addLog('info', 'No tokens found - login via login page first');
            if (elements.noTokenNotice) elements.noTokenNotice.style.display = 'block';
        }

        updateAuthStatus();
        updateButtonStates();
    }

    // ========================================================================
    // Token Storage (read from localStorage written by MFA SDK)
    // ========================================================================

    function storeTokens(accessToken, refreshToken, expiresIn, refreshExpiresIn) {
        var now = Date.now();

        state.accessToken = accessToken;
        state.refreshToken = refreshToken;
        state.expiresAt = now + expiresIn;
        state.refreshExpiresAt = refreshToken ? now + refreshExpiresIn : null;
        state.isLoggedIn = true;

        localStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, accessToken);
        if (refreshToken) {
            localStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, refreshToken);
        }
        localStorage.setItem(STORAGE_KEYS.EXPIRES_AT, String(state.expiresAt));
        if (state.refreshExpiresAt) {
            localStorage.setItem(STORAGE_KEYS.REFRESH_EXPIRES_AT, String(state.refreshExpiresAt));
        }

        if (elements.noTokenNotice) elements.noTokenNotice.style.display = 'none';
        updateTokenDisplay();
        updateAuthStatus();
        updateButtonStates();
        startExpiryTimer();
    }

    function loadTokensFromStorage() {
        var accessToken = localStorage.getItem(STORAGE_KEYS.ACCESS_TOKEN);
        var refreshToken = localStorage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
        var expiresAt = localStorage.getItem(STORAGE_KEYS.EXPIRES_AT);
        var refreshExpiresAt = localStorage.getItem(STORAGE_KEYS.REFRESH_EXPIRES_AT);

        if (accessToken) {
            state.accessToken = accessToken;
            state.refreshToken = refreshToken;
            state.expiresAt = expiresAt ? parseInt(expiresAt, 10) : null;
            state.refreshExpiresAt = refreshExpiresAt ? parseInt(refreshExpiresAt, 10) : null;
            state.isLoggedIn = true;
        }
    }

    function clearTokenStorage() {
        Object.values(STORAGE_KEYS).forEach(function(key) { localStorage.removeItem(key); });

        state.accessToken = null;
        state.refreshToken = null;
        state.expiresAt = null;
        state.refreshExpiresAt = null;
        state.isLoggedIn = false;

        if (state.expiryTimerId) {
            clearInterval(state.expiryTimerId);
            state.expiryTimerId = null;
        }
    }

    // ========================================================================
    // Token Display
    // ========================================================================

    function updateTokenDisplay() {
        // Access Token
        if (state.accessToken) {
            elements.accessTokenRaw.textContent = truncateToken(state.accessToken);
            elements.accessTokenCard.classList.add('active');
            elements.accessTokenCard.classList.remove('expired');

            var now = Date.now();
            if (state.expiresAt && state.expiresAt <= now) {
                elements.accessTokenStatus.textContent = 'EXPIRED';
                elements.accessTokenStatus.className = 'token-status expired';
                elements.accessTokenCard.classList.remove('active');
                elements.accessTokenCard.classList.add('expired');
            } else {
                elements.accessTokenStatus.textContent = 'VALID';
                elements.accessTokenStatus.className = 'token-status valid';
            }

            showJwtPayload(state.accessToken);
        } else {
            elements.accessTokenRaw.textContent = '-';
            elements.accessTokenStatus.textContent = '-';
            elements.accessTokenStatus.className = 'token-status';
            elements.accessTokenCard.classList.remove('active', 'expired');
            hideJwtPayload();
        }

        // Refresh Token
        if (state.refreshToken) {
            elements.refreshTokenRaw.textContent = truncateToken(state.refreshToken);
            elements.refreshTokenCard.classList.add('active');
            elements.refreshTokenCard.classList.remove('expired');

            var now2 = Date.now();
            if (state.refreshExpiresAt && state.refreshExpiresAt <= now2) {
                elements.refreshTokenStatus.textContent = 'EXPIRED';
                elements.refreshTokenStatus.className = 'token-status expired';
                elements.refreshTokenCard.classList.remove('active');
                elements.refreshTokenCard.classList.add('expired');
            } else {
                elements.refreshTokenStatus.textContent = 'VALID';
                elements.refreshTokenStatus.className = 'token-status valid';
            }
        } else {
            elements.refreshTokenRaw.textContent = '-';
            elements.refreshTokenStatus.textContent = '-';
            elements.refreshTokenStatus.className = 'token-status';
            elements.refreshTokenCard.classList.remove('active', 'expired');
        }

        updateExpiryDisplay();
    }

    function updateExpiryDisplay() {
        var now = Date.now();

        if (state.expiresAt) {
            var remaining = state.expiresAt - now;
            elements.accessTokenExpiry.textContent = formatDuration(remaining);
            elements.accessTokenExpiry.className = 'expiry-value' +
                (remaining <= 0 ? ' critical' : remaining <= 60000 ? ' warning' : '');
        } else {
            elements.accessTokenExpiry.textContent = '-';
            elements.accessTokenExpiry.className = 'expiry-value';
        }

        if (state.refreshExpiresAt) {
            var rRemaining = state.refreshExpiresAt - now;
            elements.refreshTokenExpiry.textContent = formatDuration(rRemaining);
            elements.refreshTokenExpiry.className = 'expiry-value' +
                (rRemaining <= 0 ? ' critical' : rRemaining <= 300000 ? ' warning' : '');
        } else {
            elements.refreshTokenExpiry.textContent = '-';
            elements.refreshTokenExpiry.className = 'expiry-value';
        }
    }

    function startExpiryTimer() {
        if (state.expiryTimerId) {
            clearInterval(state.expiryTimerId);
        }

        state.expiryTimerId = setInterval(function() {
            updateExpiryDisplay();

            var now = Date.now();
            if (state.expiresAt && state.expiresAt <= now) {
                elements.accessTokenStatus.textContent = 'EXPIRED';
                elements.accessTokenStatus.className = 'token-status expired';
                elements.accessTokenCard.classList.remove('active');
                elements.accessTokenCard.classList.add('expired');
            }

            if (state.refreshExpiresAt && state.refreshExpiresAt <= now) {
                elements.refreshTokenStatus.textContent = 'EXPIRED';
                elements.refreshTokenStatus.className = 'token-status expired';
                elements.refreshTokenCard.classList.remove('active');
                elements.refreshTokenCard.classList.add('expired');
            }
        }, 1000);
    }

    // ========================================================================
    // JWT Decode
    // ========================================================================

    function decodeJwt(token) {
        try {
            var parts = token.split('.');
            if (parts.length !== 3) return null;

            var payload = parts[1];
            var decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
            return JSON.parse(decoded);
        } catch (e) {
            return null;
        }
    }

    function showJwtPayload(token) {
        var payload = decodeJwt(token);
        if (payload && elements.jwtPayloadPanel) {
            elements.jwtPayloadPanel.style.display = 'block';
            elements.jwtPayloadContent.textContent = JSON.stringify(payload, null, 2);
        }
    }

    function hideJwtPayload() {
        if (elements.jwtPayloadPanel) {
            elements.jwtPayloadPanel.style.display = 'none';
        }
    }

    // ========================================================================
    // Auth Status
    // ========================================================================

    function updateAuthStatus() {
        if (state.isLoggedIn) {
            elements.authIndicator.className = 'auth-indicator authenticated';
            var payload = decodeJwt(state.accessToken);
            var username = payload ? (payload.sub || payload.username || 'User') : 'Authenticated';
            elements.authText.textContent = username;
        } else {
            elements.authIndicator.className = 'auth-indicator disconnected';
            elements.authText.textContent = 'Not Authenticated';
        }
    }

    function updateButtonStates() {
        var hasToken = state.isLoggedIn && state.accessToken;
        var hasRefresh = state.isLoggedIn && state.refreshToken;

        [elements.btnApiNormal, elements.btnApiSensitive,
         elements.btnApiCritical, elements.btnApiUserinfo].forEach(function(btn) {
            if (btn) btn.disabled = !hasToken;
        });

        if (elements.btnRefreshToken) elements.btnRefreshToken.disabled = !hasRefresh;
        if (elements.btnValidateToken) elements.btnValidateToken.disabled = !hasToken;
    }

    // ========================================================================
    // Token Operations
    // ========================================================================

    async function refreshTokens() {
        if (!state.refreshToken) {
            addLog('error', 'No refresh token available');
            return;
        }

        addLog('request', 'POST ' + API.TOKEN_REFRESH);

        try {
            var response = await fetch(API.TOKEN_REFRESH, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refreshToken: state.refreshToken })
            });

            var data = await response.json();

            if (response.ok) {
                storeTokens(
                    data.accessToken,
                    data.refreshToken,
                    data.expiresIn || 3600000,
                    data.refreshExpiresIn || 604800000
                );
                addLog('success', 'Token refreshed successfully');
                showApiResponse(response.status, data);
            } else {
                addLog('error', 'Token refresh failed: ' + (data.error || response.status));
                showApiResponse(response.status, data);
            }
        } catch (e) {
            addLog('error', 'Token refresh error: ' + e.message);
        }
    }

    async function validateToken() {
        if (!state.accessToken) {
            addLog('error', 'No access token available');
            return;
        }

        addLog('request', 'GET ' + API.TOKEN_VALIDATE);

        try {
            var response = await fetch(API.TOKEN_VALIDATE, {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer ' + state.accessToken
                }
            });

            var data = await response.json();
            var validText = data.valid ? 'VALID' : 'INVALID';
            addLog(data.valid ? 'success' : 'warning', 'Token validation: ' + validText);
            showApiResponse(response.status, data);
        } catch (e) {
            addLog('error', 'Token validation error: ' + e.message);
        }
    }

    function logout() {
        clearTokenStorage();
        updateTokenDisplay();
        updateAuthStatus();
        updateButtonStates();
        hideApiResponse();
        if (elements.noTokenNotice) elements.noTokenNotice.style.display = 'block';
        addLog('info', 'Logged out - tokens cleared from localStorage');
    }

    // ========================================================================
    // Protected API Calls
    // ========================================================================

    async function callProtectedApi(level) {
        if (!state.accessToken) {
            addLog('error', 'No access token - login required');
            return;
        }

        var resourceId = 'resource-' + Date.now();
        var url;
        switch (level) {
            case 'normal': url = API.TEST_NORMAL + resourceId; break;
            case 'sensitive': url = API.TEST_SENSITIVE + resourceId; break;
            case 'critical': url = API.TEST_CRITICAL + resourceId; break;
            default: return;
        }

        addLog('request', 'GET ' + url.replace(resourceId, '{id}'));

        try {
            var response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer ' + state.accessToken,
                    'Accept': 'application/json'
                }
            });

            if (response.ok) {
                var data = await response.json();
                addLog('success', level.toUpperCase() + ' API: HTTP ' + response.status);
                showApiResponse(response.status, data);
            } else {
                var errorBody;
                try {
                    errorBody = await response.json();
                } catch (_) {
                    errorBody = { status: response.status, error: response.statusText };
                }

                if (response.status === 401) {
                    addLog('error', level.toUpperCase() + ' API: 401 Unauthorized - token may be expired');
                } else if (response.status === 403) {
                    addLog('error', level.toUpperCase() + ' API: 403 Forbidden - access denied');
                } else {
                    addLog('error', level.toUpperCase() + ' API: HTTP ' + response.status);
                }
                showApiResponse(response.status, errorBody);
            }
        } catch (e) {
            addLog('error', 'Network error: ' + e.message);
        }
    }

    async function getUserInfo() {
        if (!state.accessToken) {
            addLog('error', 'No access token available');
            return;
        }

        addLog('request', 'GET ' + API.TOKEN_USERINFO);

        try {
            var response = await fetch(API.TOKEN_USERINFO, {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer ' + state.accessToken
                }
            });

            var data = await response.json();

            if (response.ok) {
                addLog('success', 'User info: ' + (data.username || 'unknown'));
            } else {
                addLog('error', 'User info failed: ' + (data.error || response.status));
            }
            showApiResponse(response.status, data);
        } catch (e) {
            addLog('error', 'User info error: ' + e.message);
        }
    }

    // ========================================================================
    // API Response Display
    // ========================================================================

    function showApiResponse(status, data) {
        if (!elements.apiResponsePanel) return;

        elements.apiResponsePanel.style.display = 'block';

        elements.apiResponseStatus.textContent = 'HTTP ' + status;
        elements.apiResponseStatus.className = 'api-response-status ' +
            (status >= 200 && status < 300 ? 'success' : 'error');

        elements.apiResponseBody.textContent = JSON.stringify(data, null, 2);
    }

    function hideApiResponse() {
        if (elements.apiResponsePanel) {
            elements.apiResponsePanel.style.display = 'none';
        }
    }

    // ========================================================================
    // Timeline
    // ========================================================================

    function addLog(type, message) {
        if (!elements.timelineContainer) return;

        var now = new Date();
        var timeStr = now.toLocaleTimeString('ko-KR', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });

        var entry = document.createElement('div');
        entry.className = 'timeline-entry ' + type;
        entry.innerHTML =
            '<span class="timeline-time">' + timeStr + '</span>' +
            '<span class="timeline-message">' + escapeHtml(message) + '</span>';

        elements.timelineContainer.appendChild(entry);
        elements.timelineContainer.scrollTop = elements.timelineContainer.scrollHeight;
    }

    function clearTimeline() {
        if (elements.timelineContainer) {
            elements.timelineContainer.innerHTML =
                '<div class="timeline-entry info">' +
                '    <span class="timeline-time">--:--:--</span>' +
                '    <span class="timeline-message">Timeline cleared</span>' +
                '</div>';
        }
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    function truncateToken(token) {
        if (!token) return '-';
        if (token.length <= 40) return token;
        return token.substring(0, 20) + '...' + token.substring(token.length - 20);
    }

    function formatDuration(ms) {
        if (ms <= 0) return 'Expired';

        var seconds = Math.floor(ms / 1000);
        var minutes = Math.floor(seconds / 60);
        var hours = Math.floor(minutes / 60);
        var days = Math.floor(hours / 24);

        if (days > 0) return days + 'd ' + (hours % 24) + 'h';
        if (hours > 0) return hours + 'h ' + (minutes % 60) + 'm';
        if (minutes > 0) return minutes + 'm ' + (seconds % 60) + 's';
        return seconds + 's';
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ========================================================================
    // Bootstrap
    // ========================================================================

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }

})();
