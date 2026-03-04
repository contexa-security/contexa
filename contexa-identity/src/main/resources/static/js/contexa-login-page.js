(function () {
    var configEl = document.getElementById('contexa-page-config');
    var tokenPersistence = configEl.dataset.tokenPersistence || 'memory';
    var fallbackSelectFactorUrl = configEl.dataset.selectFactorUrl || '/mfa/select-factor';

    var messageArea = document.getElementById('message-area');
    var loginButton = document.getElementById('loginButton');
    var usernameInput = document.getElementById('username');
    var passwordInput = document.getElementById('password');

    if (typeof ContexaMFA === 'undefined') {
        messageArea.innerHTML = '<div class="toast error">Contexa MFA SDK is required.</div>';
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
            messageArea.innerHTML = '<div class="toast error">Username and password are required.</div>';
            return;
        }

        loginButton.disabled = true;
        loginButton.textContent = 'Signing in...';
        messageArea.innerHTML = '';

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

            messageArea.innerHTML = '<div class="toast success">' + (result.message || 'Login succeeded.') + '</div>';
            loginButton.disabled = false;
            loginButton.textContent = 'Sign In';
        } catch (error) {
            messageArea.innerHTML = '<div class="toast error">' + (error.message || 'Login failed.') + '</div>';
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
