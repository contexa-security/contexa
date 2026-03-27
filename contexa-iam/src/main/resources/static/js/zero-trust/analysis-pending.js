(function () {
    var container = document.getElementById('pending-container');
    var returnUrl = container ? container.getAttribute('data-return-url') : '/';
    var eventSource = null;
    var reconnectTimeout = null;
    var noResponseTimeout = null;

    function updateSseStatus(connected) {
        var indicator = document.getElementById('sse-indicator');
        var text = document.getElementById('sse-text');
        if (connected) {
            indicator.style.color = '#4ade80';
            text.textContent = '실시간 연결됨';
        } else {
            indicator.style.color = '#f87171';
            text.textContent = '연결 끊김 - 재연결 중';
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
            window.location.href = '/zero-trust/blocked';
        } else if (action === 'CHALLENGE') {
            showError('추가 인증이 필요합니다. MFA 인증 페이지로 이동합니다.');
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
            showError('분석 응답이 지연되고 있습니다. 페이지를 새로고침 해 주세요.');
        }, 30000);
    }

    function connect() {
        if (eventSource) {
            eventSource.close();
        }

        eventSource = new EventSource('/admin/api/aiam/sse/zero-trust/subscribe');

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
                // ignore parse errors
            }
        });

        eventSource.addEventListener('DECISION_COMPLETE', function (e) {
            if (noResponseTimeout) clearTimeout(noResponseTimeout);
            try {
                var data = JSON.parse(e.data);
                handleDecision(data);
            } catch (err) {
                showError('분석 결과 처리 중 오류가 발생했습니다.');
            }
        });

        eventSource.addEventListener('ERROR', function (e) {
            try {
                var data = JSON.parse(e.data);
                showError(data.reasoning || '분석 중 오류가 발생했습니다.');
            } catch (err) {
                showError('분석 중 오류가 발생했습니다.');
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
