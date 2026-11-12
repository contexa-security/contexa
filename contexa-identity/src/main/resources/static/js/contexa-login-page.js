(function () {
    var configEl = document.getElementById('contexa-page-config');
    if (!configEl) {
        // CL-11: without it the script stopped with a TypeError and the button did nothing.
        var area = document.getElementById('message-area');
        var missing = 'This page needs the element id="contexa-page-config" (see "Rules for your own MFA pages").';
        if (area) {
            area.textContent = missing;
        }
        console.error('[Contexa] ' + missing);
        return;
    }
    var tokenPersistence = configEl.dataset.tokenPersistence || 'memory';
    var mfaConfig = window.__MFA_CONFIG__;
    var fallbackSelectFactorUrl = configEl.dataset.selectFactorUrl
        || (mfaConfig && mfaConfig.mfa && mfaConfig.mfa.selectFactor)
        || '/mfa/select-factor';

    var messageArea = document.getElementById('message-area');
    var loginButton = document.getElementById('loginButton');
    var usernameInput = document.getElementById('username');
    var passwordInput = document.getElementById('password');

    // A message may come from the server or the network, so it is always written as text.
    function showMessage(kind, text) {
        var toast = document.createElement('div');
        toast.className = 'toast ' + kind;
        toast.textContent = text;
        messageArea.replaceChildren(toast);
    }

    if (typeof ContexaMFA === 'undefined') {
        showMessage('error', 'Contexa MFA SDK is required.');
        loginButton.disabled = true;
        return;
    }

    var mfa = new ContexaMFA.Client({
        autoRedirect: true,
        tokenPersistence: tokenPersistence
    });

    async function doLogin() {
        var username = usernameInput.value.trim();
        var password = passwordInput.value;

        if (!username || !password) {
            showMessage('error', 'Username and password are required.');
            return;
        }

        loginButton.disabled = true;
        loginButton.textContent = 'Signing in...';
        messageArea.replaceChildren();

        try {
            var result = await mfa.apiClient.loginForm(username, password);

            if (result.status === 'MFA_COMPLETED') {
                window.location.href = result.redirectUrl || '/';
                return;
            }

            if (result.status === 'MFA_REQUIRED' || result.status === 'MFA_REQUIRED_SELECT_FACTOR') {
                window.location.href = result.nextStepUrl || fallbackSelectFactorUrl;
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

            showMessage('success', result.message || 'Login succeeded.');
            loginButton.disabled = false;
            loginButton.textContent = 'Sign In';
        } catch (error) {
            var refused = error.response || {};
            if ((refused.error === 'CREDENTIALS_EXPIRED' || refused.errorCode === 'CREDENTIALS_EXPIRED') && refused.nextStepUrl) {
                // The password is right and has expired: on to the page that changes it.
                showMessage('error', error.message || 'Password has expired');
                window.location.href = refused.nextStepUrl;
                return;
            }
            showMessage('error', error.message || 'Login failed.');
            loginButton.disabled = false;
            loginButton.textContent = 'Sign In';
        }
    }

    loginButton.addEventListener('click', doLogin);
    passwordInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            doLogin();
        }
    });
})();
