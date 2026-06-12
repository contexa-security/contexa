document.addEventListener('DOMContentLoaded', function () {
    var initiateBtn = document.getElementById('initiate-mfa-btn');
    var unblockBtn = document.getElementById('unblock-btn');

    if (initiateBtn) {
        initiateBtn.addEventListener('click', initiateBlockMfa);
    }
    if (unblockBtn) {
        unblockBtn.addEventListener('click', requestUnblock);
    }
});

function _i18n(key, fallback) {
    var el = document.getElementById('i18nZeroTrustBlocked');
    if (el && el.dataset[key]) return el.dataset[key];
    return fallback || key;
}

function getHeaders() {
    var csrfMeta = document.querySelector('meta[name="_csrf"]');
    var csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    var headers = {'Content-Type': 'application/json'};
    if (csrfMeta && csrfHeaderMeta) {
        headers[csrfHeaderMeta.content] = csrfMeta.content;
    }
    return headers;
}

function showResult(success, message) {
    var resultDiv = document.getElementById('request-result');
    var resultMsg = document.getElementById('result-message');
    resultDiv.classList.remove('hidden');

    if (success) {
        resultMsg.style.color = '#4ade80';
    } else {
        resultMsg.style.color = '#f87171';
    }
    resultMsg.textContent = message;
}

function initiateBlockMfa() {
    var btn = document.getElementById('initiate-mfa-btn');
    btn.disabled = true;
    btn.textContent = _i18n('mfaInitializing', 'Initializing MFA...');
    btn.style.opacity = '0.5';

    fetch('/contexa/admin/api/aiam/zero-trust/initiate-block-mfa', {
        method: 'POST',
        headers: getHeaders()
    })
    .then(function (res) { return res.json(); })
    .then(function (data) {
        if (data.success) {
            window.location.href = '/';
        } else {
            showResult(false, data.message || _i18n('mfaInitFailed', 'MFA initialization failed.'));
            btn.disabled = false;
            btn.textContent = _i18n('btnStartMfa', 'Start MFA Authentication');
            btn.style.opacity = '1';
        }
    })
    .catch(function () {
        showResult(false, _i18n('serverConnectFailed', 'Server connection failed.'));
        btn.disabled = false;
        btn.textContent = _i18n('btnStartMfa', 'Start MFA Authentication');
        btn.style.opacity = '1';
    });
}

function requestUnblock() {
    var btn = document.getElementById('unblock-btn');
    var reason = document.getElementById('reason-input').value.trim();

    if (!reason) {
        showResult(false, _i18n('reasonRequired', 'Please enter the unblock reason.'));
        return;
    }

    btn.disabled = true;
    btn.textContent = _i18n('requesting', 'Requesting...');
    btn.style.opacity = '0.5';

    fetch('/contexa/admin/api/aiam/zero-trust/unblock-request', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({reason: reason})
    })
    .then(function (res) { return res.json(); })
    .then(function (data) {
        if (data.success) {
            var formDiv = document.getElementById('request-form');
            formDiv.classList.add('hidden');
            showResult(true, _i18n('requestAccepted', 'Request submitted. It will be released after admin review.'));
        } else {
            showResult(false, data.message || _i18n('requestFailed', 'Request failed.'));
            btn.disabled = false;
            btn.textContent = _i18n('btnUnblockRequest', 'Request Unblock');
            btn.style.opacity = '1';
        }
    })
    .catch(function () {
        showResult(false, _i18n('serverConnectFailed', 'Server connection failed.'));
        btn.disabled = false;
        btn.textContent = _i18n('btnUnblockRequest', 'Request Unblock');
        btn.style.opacity = '1';
    });
}
