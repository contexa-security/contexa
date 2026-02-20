document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('unblock-btn');
    if (btn) {
        btn.addEventListener('click', requestUnblock);
    }
});

function requestUnblock() {
    var btn = document.getElementById('unblock-btn');
    var reason = document.getElementById('reason-input').value.trim();

    btn.disabled = true;
    btn.textContent = '요청 중...';
    btn.style.opacity = '0.5';

    var csrfMeta = document.querySelector('meta[name="_csrf"]');
    var csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');

    var headers = {'Content-Type': 'application/json'};
    if (csrfMeta && csrfHeaderMeta) {
        headers[csrfHeaderMeta.content] = csrfMeta.content;
    }

    fetch('/api/aiam/zero-trust/unblock-request', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({reason: reason || null})
    })
    .then(function (res) { return res.json(); })
    .then(function (data) {
        var resultDiv = document.getElementById('request-result');
        var resultMsg = document.getElementById('result-message');
        var formDiv = document.getElementById('request-form');

        resultDiv.classList.remove('hidden');

        if (data.success) {
            formDiv.classList.add('hidden');
            resultMsg.style.color = '#4ade80';
            resultMsg.textContent = '요청이 접수되었습니다. 관리자 검토 후 해제됩니다.';
        } else {
            resultMsg.style.color = '#f87171';
            resultMsg.textContent = data.message || '요청에 실패했습니다.';
            btn.disabled = false;
            btn.textContent = '차단 해제 요청';
            btn.style.opacity = '1';
        }
    })
    .catch(function () {
        btn.disabled = false;
        btn.textContent = '차단 해제 요청';
        btn.style.opacity = '1';

        var resultDiv = document.getElementById('request-result');
        var resultMsg = document.getElementById('result-message');
        resultDiv.classList.remove('hidden');
        resultMsg.style.color = '#f87171';
        resultMsg.textContent = '서버 연결에 실패했습니다.';
    });
}
