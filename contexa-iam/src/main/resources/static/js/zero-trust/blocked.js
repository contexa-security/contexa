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
    btn.textContent = 'MFA 초기화 중...';
    btn.style.opacity = '0.5';

    fetch('/api/aiam/zero-trust/initiate-block-mfa', {
        method: 'POST',
        headers: getHeaders()
    })
    .then(function (res) { return res.json(); })
    .then(function (data) {
        if (data.success) {
            window.location.href = '/';
        } else {
            showResult(false, data.message || 'MFA 초기화에 실패했습니다.');
            btn.disabled = false;
            btn.textContent = 'MFA 인증 시작';
            btn.style.opacity = '1';
        }
    })
    .catch(function () {
        showResult(false, '서버 연결에 실패했습니다.');
        btn.disabled = false;
        btn.textContent = 'MFA 인증 시작';
        btn.style.opacity = '1';
    });
}

function requestUnblock() {
    var btn = document.getElementById('unblock-btn');
    var reason = document.getElementById('reason-input').value.trim();

    if (!reason) {
        showResult(false, '차단 해제 사유를 입력하세요.');
        return;
    }

    btn.disabled = true;
    btn.textContent = '요청 중...';
    btn.style.opacity = '0.5';

    fetch('/api/aiam/zero-trust/unblock-request', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({reason: reason})
    })
    .then(function (res) { return res.json(); })
    .then(function (data) {
        if (data.success) {
            var formDiv = document.getElementById('request-form');
            formDiv.classList.add('hidden');
            showResult(true, '요청이 접수되었습니다. 관리자 검토 후 해제됩니다.');
        } else {
            showResult(false, data.message || '요청에 실패했습니다.');
            btn.disabled = false;
            btn.textContent = '차단 해제 요청';
            btn.style.opacity = '1';
        }
    })
    .catch(function () {
        showResult(false, '서버 연결에 실패했습니다.');
        btn.disabled = false;
        btn.textContent = '차단 해제 요청';
        btn.style.opacity = '1';
    });
}
