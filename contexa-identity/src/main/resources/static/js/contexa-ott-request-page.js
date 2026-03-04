(function () {
    var sendButton = document.getElementById('sendCodeButton');

    if (typeof ContexaMFA !== 'undefined') {
        var configEl = document.getElementById('contexa-page-config');
        var tokenPersistence = configEl.dataset.tokenPersistence || 'memory';
        var mfa = new ContexaMFA.Client({
            autoRedirect: false,
            tokenPersistence: tokenPersistence
        });
        mfa.init().catch(function () {});
    }

    document.getElementById('ottRequestForm').addEventListener('submit', function () {
        sendButton.disabled = true;
        sendButton.textContent = 'Sending...';
    });
})();
