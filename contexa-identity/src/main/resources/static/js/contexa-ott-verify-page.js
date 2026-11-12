(function () {
    var configEl = document.getElementById('contexa-page-config');
    if (!configEl) {
        var missingMessage = document.getElementById('errorMessage');
        var missing = 'This page needs the element id="contexa-page-config" (see "Rules for your own MFA pages").';
        if (missingMessage) {
            missingMessage.style.display = 'block';
            missingMessage.textContent = missing;
        }
        console.error('[Contexa] ' + missing);
        return;
    }
    var tokenPersistence = configEl.dataset.tokenPersistence || 'memory';
    var maxAttempts = parseInt(configEl.dataset.maxAttempts || '5', 10);
    var attemptsMade = parseInt(configEl.dataset.attemptsMade || '0', 10);
    var mfaConfig = window.__MFA_CONFIG__;
    var fallbackFailureUrl = configEl.dataset.failureUrl
        || (mfaConfig && mfaConfig.mfa && mfaConfig.mfa.failure)
        || '/mfa/failure';

    var verifyForm = document.getElementById('verifyForm');
    var resendForm = document.getElementById('resendForm');
    var tokenInput = document.getElementById('token');
    var verifyButton = document.getElementById('verifyButton');
    var resendButton = document.getElementById('resendButton');
    var errorMessage = document.getElementById('errorMessage');

    if (typeof ContexaMFA === 'undefined') {
        errorMessage.style.display = 'block';
        errorMessage.textContent = 'Contexa MFA SDK is required.';
        verifyButton.disabled = true;
        resendButton.disabled = true;
        return;
    }

    var mfa = new ContexaMFA.Client({
        autoRedirect: false,
        tokenPersistence: tokenPersistence
    });
    mfa.init().catch(function () {});

    function disableAll(reason) {
        tokenInput.disabled = true;
        verifyButton.disabled = true;
        resendButton.disabled = true;
        errorMessage.style.display = 'block';
        errorMessage.textContent = reason;
    }

    function renderAttemptsMessage() {
        if (attemptsMade <= 0) {
            return;
        }
        var remaining = maxAttempts - attemptsMade;
        errorMessage.style.display = 'block';
        if (remaining <= 0) {
            disableAll('Maximum verification attempts exceeded.');
        } else {
            errorMessage.textContent = remaining + ' attempt(s) remaining out of ' + maxAttempts + '.';
        }
    }

    renderAttemptsMessage();

    verifyForm.addEventListener('submit', async function (e) {
        e.preventDefault();

        var code = tokenInput.value.trim();
        if (!code) {
            errorMessage.style.display = 'block';
            errorMessage.textContent = 'Code is required.';
            return;
        }

        verifyButton.disabled = true;
        verifyButton.textContent = 'Verifying...';
        errorMessage.style.display = 'none';

        try {
            var result = await mfa.verifyOtt(code);

            if (result.status === 'MFA_COMPLETED' && result.redirectUrl) {
                window.location.href = result.redirectUrl;
                return;
            }
            if (result.status === 'MFA_CONTINUE' && result.nextStepUrl) {
                window.location.href = result.nextStepUrl;
                return;
            }
            if (result.nextStepUrl) {
                window.location.href = result.nextStepUrl;
                return;
            }
            if (result.redirectUrl) {
                window.location.href = result.redirectUrl;
                return;
            }

            verifyButton.disabled = false;
            verifyButton.textContent = 'Verify';
        } catch (error) {
            var answer = error.response || {};
            var reason = answer.error || answer.errorCode;
            if (answer.blockMfaFailed && answer.redirectUrl) {
                window.location.href = answer.redirectUrl;
                return;
            }
            if (reason === 'MFA_RETRY_LIMIT_EXCEEDED') {
                disableAll('Maximum verification attempts exceeded.');
                return;
            }
            if (reason === 'MFA_BUSY_RETRY' || error.status === 429) {
                errorMessage.style.display = 'block';
                errorMessage.textContent = 'The code is still being checked. Try again in a moment.';
                verifyButton.disabled = false;
                verifyButton.textContent = 'Verify';
                return;
            }
            // CL-1: only a wrong code is an attempt. Anything else (the time ran out, the sign-in ended) says so
            // and goes on where the server says.
            if (reason !== 'MFA_FACTOR_VERIFICATION_FAILED' && !(error.status === 401 && !reason)) {
                disableAll(answer.message || 'This sign-in has ended. You will be taken to sign in again.');
                if (answer.redirectUrl) {
                    setTimeout(function () {
                        window.location.href = answer.redirectUrl;
                    }, 1500);
                }
                return;
            }

            if (answer.attemptsMade != null) {
                attemptsMade = parseInt(answer.attemptsMade, 10);
            } else {
                attemptsMade += 1;
            }

            var remaining = maxAttempts - attemptsMade;
            if (remaining <= 0) {
                disableAll('Maximum verification attempts exceeded.');
                if (fallbackFailureUrl) {
                    setTimeout(function () {
                        window.location.href = fallbackFailureUrl;
                    }, 700);
                }
            } else {
                errorMessage.style.display = 'block';
                errorMessage.textContent = 'Verification failed. ' + remaining + ' attempt(s) remaining out of ' + maxAttempts + '.';
                verifyButton.disabled = false;
                verifyButton.textContent = 'Verify';
                tokenInput.value = '';
                tokenInput.focus();
            }
        }
    });

    resendForm.addEventListener('submit', function () {
        resendButton.disabled = true;
        resendButton.textContent = 'Sending...';
    });
})();
