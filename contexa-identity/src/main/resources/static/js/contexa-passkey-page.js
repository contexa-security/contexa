(function () {
    var authButton = document.getElementById('authButton');
    var errorMessage = document.getElementById('errorMessage');
    var configEl = document.getElementById('contexa-page-config');
    var tokenPersistence = configEl.dataset.tokenPersistence || 'memory';
    var failureUrl = configEl.dataset.failureUrl || '/mfa/failure';

    if (typeof ContexaMFA === 'undefined') {
        authButton.disabled = true;
        errorMessage.style.display = 'block';
        errorMessage.textContent = 'Contexa MFA SDK is required.';
        return;
    }

    var mfa = new ContexaMFA.Client({
        autoRedirect: false,
        tokenPersistence: tokenPersistence
    });

    authButton.disabled = true;
    authButton.textContent = 'Initializing...';

    (async function init() {
        try {
            await mfa.init();
        } finally {
            authButton.disabled = false;
            authButton.textContent = 'Authenticate with Passkey';
        }
    })();

    authButton.addEventListener('click', async function () {
        authButton.disabled = true;
        authButton.textContent = 'Authenticating...';
        errorMessage.style.display = 'none';

        try {
            var result = await mfa.verifyPasskey();

            if (result.status === 'MFA_COMPLETED' && result.redirectUrl) {
                window.location.href = result.redirectUrl;
                return;
            }
            if (result.status === 'MFA_CONTINUE' && result.nextStepUrl) {
                window.location.href = result.nextStepUrl;
                return;
            }
            if (result.redirectUrl) {
                window.location.href = result.redirectUrl;
                return;
            }
            if (result.nextStepUrl) {
                window.location.href = result.nextStepUrl;
                return;
            }

            authButton.disabled = false;
            authButton.textContent = 'Authenticate with Passkey';
        } catch (error) {
            var errorText = error && error.message ? error.message : 'Passkey verification failed.';
            errorMessage.style.display = 'block';
            errorMessage.textContent = errorText;
            authButton.disabled = false;
            authButton.textContent = 'Authenticate with Passkey';

            setTimeout(function () {
                window.location.href = failureUrl + '?error=' + encodeURIComponent(errorText);
            }, 700);
        }
    });
})();
