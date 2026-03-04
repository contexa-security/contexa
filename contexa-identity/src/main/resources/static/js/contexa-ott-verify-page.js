(function () {
    var configEl = document.getElementById('contexa-page-config');
    var tokenPersistence = configEl.dataset.tokenPersistence || 'memory';
    var maxAttempts = parseInt(configEl.dataset.maxAttempts || '5', 10);
    var attemptsMade = parseInt(configEl.dataset.attemptsMade || '0', 10);
    var fallbackFailureUrl = configEl.dataset.failureUrl || '/mfa/failure';

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
            if (error.response && error.response.blockMfaFailed && error.response.redirectUrl) {
                window.location.href = error.response.redirectUrl;
                return;
            }

            if (error.response && error.response.attemptsMade != null) {
                attemptsMade = parseInt(error.response.attemptsMade, 10);
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
