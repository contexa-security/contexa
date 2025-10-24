// static/js/mfa-ott-request-code.js
document.addEventListener("DOMContentLoaded", () => {
    const requestCodeForm = document.getElementById("mfaOttRequestCodeForm");
    const emailInput = document.getElementById("mfaUsername"); // 서버에서 전달된 username (readonly)
    const messageDiv = document.getElementById("mfaOttRequestMessage");
    const sendButton = requestCodeForm ? requestCodeForm.querySelector("button[type='submit']") : null;

    if (!requestCodeForm || !emailInput || !sendButton) {
        console.warn("MFA OTT Request Code form elements not found. Ensure form ID is 'mfaOttRequestCodeForm', email input ID is 'mfaUsername', and there is a submit button.");
        const mainMessageDiv = document.getElementById("mfaOttRequestMessage") || document.body;
        if (mainMessageDiv) {
            mainMessageDiv.innerHTML = '<p class="text-error font-medium">페이지 구성 오류. 관리자에게 문의하세요.</p>';
            if(typeof showToast === 'function') showToast("페이지 구성 오류", "error");
        }
        return;
    }

    // State Machine 상태 확인
    if (window.mfaStateTracker && !window.mfaStateTracker.isValid()) {
        window.mfaStateTracker.restoreFromSession();
    }

    // 유효한 상태인지 확인 (AWAITING_FACTOR_CHALLENGE_INITIATION 또는 FACTOR_CHALLENGE_INITIATED)
    if (window.mfaStateTracker &&
        window.mfaStateTracker.currentState !== 'AWAITING_FACTOR_CHALLENGE_INITIATION' &&
        window.mfaStateTracker.currentState !== 'FACTOR_CHALLENGE_INITIATED') {
        console.warn(`Invalid state for OTT code request. Current state: ${window.mfaStateTracker.currentState}`);
        displayMessage("잘못된 인증 상태입니다. 팩터 선택 페이지로 돌아갑니다.", "error");
        sendButton.disabled = true;
        setTimeout(() => {
            window.location.href = "/mfa/select-factor";
        }, 2000);
        return;
    }

    const formActionUrl = requestCodeForm.getAttribute("action");

    if (!formActionUrl) {
        displayMessage("코드 생성 요청 URL이 설정되지 않았습니다. 관리자에게 문의하세요.", "error");
        sendButton.disabled = true;
        return;
    }

    logClientSideMfaOttRequest(`MFA OTT Code Request UI loaded. Form will POST to: ${formActionUrl} for user: ${emailInput.value}, State: ${window.mfaStateTracker?.currentState || 'N/A'}`);

    function displayMessage(message, type = 'info', clearAfter = 0) {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="text-sm text-center ${type === 'error' ? 'text-red-500' : (type === 'success' ? 'text-green-500' : 'text-blue-500')}">${message}</p>`;
            messageDiv.classList.remove('hidden');
            if (clearAfter > 0) {
                setTimeout(() => {
                    messageDiv.innerHTML = '';
                    messageDiv.classList.add('hidden');
                }, clearAfter);
            }
        }
        if (typeof showToast === 'function') showToast(message, type);
    }

    requestCodeForm.addEventListener("submit", (event) => {
        // State Machine 전이 가능 여부 확인
        if (window.mfaStateTracker &&
            window.mfaStateTracker.currentState === 'AWAITING_FACTOR_CHALLENGE_INITIATION' &&
            !window.mfaStateTracker.canTransitionTo('FACTOR_CHALLENGE_INITIATED')) {
            event.preventDefault();
            displayMessage("현재 상태에서 OTT 코드를 요청할 수 없습니다.", "error");
            return;
        }

        // 폼 제출 시 버튼 비활성화 및 로딩 메시지 표시
        sendButton.disabled = true;
        sendButton.classList.add("opacity-50", "cursor-not-allowed");
        sendButton.innerHTML = `
            <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            처리 중...
        `;
        displayMessage("인증 코드를 요청 중입니다...", "info");
        logClientSideMfaOttRequest("Form is being submitted to " + formActionUrl + " for OTT code generation.");
    });

    const usernameFromModel = emailInput.value;
    if (!usernameFromModel) {
        displayMessage("사용자 정보를 가져올 수 없습니다. 다시 로그인해주세요.", "error");
        if(typeof showToast === 'function') showToast("사용자 정보 없음", "error");
        sendButton.disabled = true;
    }

    // URL 파라미터에 에러가 있는 경우
    const urlParams = new URLSearchParams(window.location.search);
    const errorParam = urlParams.get('error');
    const messageParam = urlParams.get('message');

    if (errorParam || messageParam) {
        let displayErrorMessage = messageParam || "코드 발송에 실패했습니다. 잠시 후 다시 시도해주세요.";
        if (errorParam === 'token_generation_failed') {
            displayErrorMessage = "인증 코드 생성에 실패했습니다. 입력 정보를 확인하거나 잠시 후 다시 시도해주세요.";
        } else if (errorParam === 'invalid_ott_request_ui_context') {
            displayErrorMessage = "잘못된 OTT 코드 요청입니다. 인증을 다시 시작해주세요.";
        }

        displayMessage(displayErrorMessage, "error");
        if(sendButton) {
            sendButton.disabled = false;
            sendButton.classList.remove("opacity-50", "cursor-not-allowed");
            sendButton.innerHTML = '인증 코드 발송';
        }

        // 터미널 상태인 경우 처리
        if (window.mfaStateTracker && window.mfaStateTracker.isTerminalState()) {
            setTimeout(() => {
                window.location.href = "/loginForm";
            }, 3000);
        }
    }
});

function logClientSideMfaOttRequest(message) {
    console.log("[Client MFA OTT Request Code] " + message);
}