(function () {
    var container = document.getElementById('pending-container');
    var returnUrl = container ? container.getAttribute('data-return-url') : '/';
    var eventSource = null;
    var reconnectTimeout = null;
    var noResponseTimeout = null;

    function _i18n(key, fallback) {
        var el = document.getElementById('i18nZeroTrustPending');
        if (el && el.dataset[key]) return el.dataset[key];
        return fallback || key;
    }

    function updateSseStatus(connected) {
        var indicator = document.getElementById('sse-indicator');
        var text = document.getElementById('sse-text');
        if (connected) {
            indicator.style.color = '#4ade80';
            text.textContent = _i18n('sseConnected', 'Real-time connected');
        } else {
            indicator.style.color = '#f87171';
            text.textContent = _i18n('sseDisconnected', 'Disconnected - reconnecting');
        }
    }

    function updateStep(stepId, status) {
        var icon = document.getElementById(stepId + '-icon');
        if (!icon) return;
        if (status === 'complete') {
            icon.style.color = '#4ade80';
        } else if (status === 'active') {
            icon.style.color = '#6366f1';
        }
    }

    function showError(message) {
        var errorDiv = document.getElementById('error-message');
        errorDiv.textContent = message;
        errorDiv.classList.remove('hidden');
    }

    function handleDecision(data) {
        var action = data.action;
        updateStep('step-decision', 'complete');

        if (action === 'ALLOW') {
            window.location.href = decodeURIComponent(returnUrl);
        } else if (action === 'BLOCK') {
            window.location.href = '/contexa/zero-trust/blocked';
        } else if (action === 'CHALLENGE') {
            showError(_i18n('mfaRequired', 'Additional authentication required. Redirecting to MFA login page.'));
            setTimeout(function () {
                var cfg = window.__MFA_CONFIG__;
                var loginPage = (cfg && cfg.primary && cfg.primary.formLoginPage)
                    ? cfg.primary.formLoginPage : '/mfa/login';
                window.location.href = loginPage;
            }, 2000);
        }
    }

    function resetNoResponseTimeout() {
        if (noResponseTimeout) clearTimeout(noResponseTimeout);
        noResponseTimeout = setTimeout(function () {
            showError(_i18n('noResponse', 'Analysis is delayed. Please refresh the page.'));
        }, 30000);
    }

    function connect() {
        if (eventSource) {
            eventSource.close();
        }

        eventSource = new EventSource('/contexa/admin/api/aiam/sse/zero-trust/subscribe');

        eventSource.addEventListener('connected', function () {
            updateSseStatus(true);
            resetNoResponseTimeout();
        });

        eventSource.addEventListener('ANALYSIS_PROGRESS', function (e) {
            resetNoResponseTimeout();
            try {
                var data = JSON.parse(e.data);
                if (data.layer === 'LAYER1') {
                    updateStep('step-layer1', 'complete');
                    updateStep('step-layer2', 'active');
                } else if (data.layer === 'LAYER2') {
                    updateStep('step-layer2', 'complete');
                    updateStep('step-decision', 'active');
                }
            } catch (err) {
            }
        });

        eventSource.addEventListener('DECISION_COMPLETE', function (e) {
            if (noResponseTimeout) clearTimeout(noResponseTimeout);
            try {
                var data = JSON.parse(e.data);
                handleDecision(data);
            } catch (err) {
                showError(_i18n('decisionError', 'An error occurred while processing the analysis result.'));
            }
        });

        eventSource.addEventListener('ERROR', function (e) {
            try {
                var data = JSON.parse(e.data);
                showError(data.reasoning || _i18n('analysisError', 'An error occurred during analysis.'));
            } catch (err) {
                showError(_i18n('analysisError', 'An error occurred during analysis.'));
            }
        });

        eventSource.onerror = function () {
            updateSseStatus(false);
            eventSource.close();
            reconnectTimeout = setTimeout(connect, 5000);
        };
    }

    connect();
})();
