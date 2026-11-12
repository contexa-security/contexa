(function () {
    var authButton = document.getElementById('authButton');
    var errorMessage = document.getElementById('errorMessage');
    var configEl = document.getElementById('contexa-page-config');
    if (!configEl) {
        var missing = 'This page needs the element id="contexa-page-config" (see "Rules for your own MFA pages").';
        if (errorMessage) {
            errorMessage.style.display = 'block';
            errorMessage.textContent = missing;
        }
        console.error('[Contexa] ' + missing);
        return;
    }
    var tokenPersistence = configEl.dataset.tokenPersistence || 'memory';
    var mfaConfig = window.__MFA_CONFIG__;
    var failureUrl = configEl.dataset.failureUrl
        || (mfaConfig && mfaConfig.mfa && mfaConfig.mfa.failure)
        || '/mfa/failure';

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
            // CL-2: the browser's own sentence is no message for the person and does not belong in the address.
            console.error('[Contexa] Passkey verification failed', error);
            var errorText = 'The passkey could not be used. Try again, or choose another way to sign in.';
            errorMessage.style.display = 'block';
            errorMessage.textContent = errorText;
            authButton.disabled = false;
            authButton.textContent = 'Authenticate with Passkey';

            setTimeout(function () {
                window.location.href = failureUrl + '?error=passkey_failed';
            }, 700);
        }
    });
})();
