document.addEventListener("DOMContentLoaded", () => {
    const isMfaFlow = document.body.dataset.isMfaFlow === 'true';
    const formId = isMfaFlow ? "mfaVerifyOttForm" : "singleOttVerifyForm";
    const codeInputId = isMfaFlow ? "mfaOttCode" : "singleOttCode";
    const messageDivId = isMfaFlow ? "ottVerifyMessage" : "singleOttVerifyMessage";
    const resendButtonId = isMfaFlow ? "resendMfaOttCode" : "resendSingleOttCode";

    const ottVerifyForm = document.getElementById(formId);
    const ottCodeInput = document.getElementById(codeInputId);
    const messageDiv = document.getElementById(messageDivId);
    const resendButton = document.getElementById(resendButtonId);
    const userIdentifierDisplay = document.getElementById("userIdentifier");

    if (!ottVerifyForm || !ottCodeInput) {
        console.warn(`OTT verification form elements (${formId} or ${codeInputId}) not found.`);
        return;
    }

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfParameterMeta = document.querySelector('meta[name="_csrf_parameter"]');

    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;
    const csrfParameterName = csrfParameterMeta ? csrfParameterMeta.getAttribute("content") : "_csrf";

    let username = "";
    const mfaSessionId = isMfaFlow ? sessionStorage.getItem("mfaSessionId") : null;

    // State Machine 상태 확인 (MFA 플로우일 때만)
    if (isMfaFlow && window.mfaStateTracker) {
        if (!window.mfaStateTracker.isValid()) {
            window.mfaStateTracker.restoreFromSession();
        }

        const validStatesForOttVerification = [
            'FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION',  // 정상적인 검증 대기 상태
            'FACTOR_VERIFICATION_PENDING'                        // 검증 진행 중
        ];

        if (!validStatesForOttVerification.includes(window.mfaStateTracker.currentState)) {
            console.warn(`Invalid state for OTT verification. Current state: ${window.mfaStateTracker.currentState}`);
            displayMessage("잘못된 인증 상태입니다. 다시 시도해주세요.", "error");
            setTimeout(() => {
                window.location.href = "/mfa/select-factor";
            }, 2000);
            return;
        }

        // 남은 시도 횟수 표시
        const attemptsRemaining = window.mfaStateTracker.stateMetadata?.attemptsRemaining;
        if (attemptsRemaining !== undefined && attemptsRemaining < 3) {
            displayMessage(`남은 시도 횟수: ${attemptsRemaining}회`, "info");
        }
    }

    if (isMfaFlow) {
        username = sessionStorage.getItem("mfaUsername");
        if (userIdentifierDisplay && userIdentifierDisplay.textContent && userIdentifierDisplay.textContent.trim() !== '') {
            username = userIdentifierDisplay.textContent.trim();
        } else if (username && userIdentifierDisplay) {
            userIdentifierDisplay.textContent = username;
        }
        if (!mfaSessionId || !username) {
            displayMessage("MFA 세션 또는 사용자 정보가 없습니다. 다시 로그인해주세요.", "error");
            if (typeof showToast === 'function') showToast("MFA 세션 또는 사용자 정보가 없습니다.", "error", 3000);
            const submitButton = ottVerifyForm.querySelector('button[type="submit"]');
            if (submitButton) submitButton.disabled = true;
            return;
        }
    } else {
        // 단일 OTT 플로우
        const hiddenUsernameInput = ottVerifyForm.querySelector('input[name="username"]');
        if (hiddenUsernameInput && hiddenUsernameInput.value) {
            username = hiddenUsernameInput.value;
        } else if (userIdentifierDisplay && userIdentifierDisplay.textContent && userIdentifierDisplay.textContent.trim() !== '') {
            username = userIdentifierDisplay.textContent.trim();
        }
        if (!username) {
            displayMessage("사용자 이메일 정보가 없습니다. 이전 단계로 돌아가세요.", "error");
            if (typeof showToast === 'function') showToast("사용자 이메일 정보가 없습니다.", "error", 3000);
            const submitButton = ottVerifyForm.querySelector('button[type="submit"]');
            if (submitButton) submitButton.disabled = true;
            return;
        }
    }

    logClientSideMfaVerify(`OTT Verification page loaded. MFA Flow: ${isMfaFlow}, User: ${username}, Session ID: ${mfaSessionId || 'N/A'}, State: ${window.mfaStateTracker?.currentState || 'N/A'}`);

    function displayMessage(message, type = 'info') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="text-sm text-center ${type === 'error' ? 'text-red-500' : (type === 'success' ? 'text-green-500' : 'text-blue-500')}">${message}</p>`;
            messageDiv.classList.remove('hidden');
        }
        if (typeof showToast === 'function') showToast(message, type);
    }

    async function requestNewOttCode() {
        const resendUrl = isMfaFlow ?
            (document.body.dataset.mfaResendOttUrl || "/api/mfa/request-ott-code") :
            (document.body.dataset.singleOttResendUrl || "/api/ott/generate-code");

        if (!resendUrl) {
            displayMessage("코드 재전송 URL이 설정되지 않았습니다.", "error");
            return;
        }

        if (resendButton) resendButton.disabled = true;
        displayMessage("새로운 인증 코드를 요청 중입니다...", "info");

        const headers = {
            "Content-Type": "application/json",
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (isMfaFlow && mfaSessionId) {
            headers["X-MFA-Session-Id"] = mfaSessionId;
        }
        if (csrfToken && csrfHeader) {
            headers[csrfHeader] = csrfToken;
        }

        try {
            const response = await fetch(resendUrl, {
                method: "POST",
                headers: headers,
                body: JSON.stringify({ username: username })
            });

            const result = await response.json();
            const successStatus = isMfaFlow ? "MFA_OTT_CODE_SENT" : "OTT_CODE_SENT";

            // State Machine 상태 업데이트
            if (window.mfaStateTracker && result.stateMachine) {
                window.mfaStateTracker.updateFromServerResponse(result);
            }

            if (response.ok && result.status === successStatus) {
                displayMessage(result.message || `새로운 인증 코드가 ${username}(으)로 발송되었습니다.`, "success");
            } else {
                displayMessage(`코드 재전송 실패: ${result.message || response.statusText || '알 수 없는 오류'}`, "error");
            }
        } catch (error) {
            console.error("Error resending OTT code:", error);
            displayMessage("코드 재전송 중 네트워크 오류 발생", "error");
        } finally {
            if (resendButton) {
                setTimeout(() => { resendButton.disabled = false; }, 30000);
            }
        }
    }

    if (resendButton) {
        resendButton.addEventListener("click", requestNewOttCode);
    }

    ottVerifyForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const ottCode = ottCodeInput.value;
        if (!ottCode || ottCode.length !== 6 || !/^\d{6}$/.test(ottCode)) {
            displayMessage("6자리 숫자로 된 인증 코드를 입력해주세요.", "error");
            ottCodeInput.focus();
            return;
        }

        // State Machine 전이 가능 여부 확인
        if (isMfaFlow && window.mfaStateTracker && !window.mfaStateTracker.canTransitionTo('FACTOR_VERIFICATION_PENDING')) {
            displayMessage("현재 상태에서 OTT 검증을 수행할 수 없습니다.", "error");
            return;
        }

        displayMessage("OTT 코드 검증 중...", "info");

        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('token', ottCode);
        if (csrfToken) {
            formData.append(csrfParameterName, csrfToken);
        }

        const headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (isMfaFlow && mfaSessionId) {
            headers["X-MFA-Session-Id"] = mfaSessionId;
        }

        const processingUrl = isMfaFlow ?
            (ottVerifyForm.dataset.mfaOttProcessingUrl || document.body.dataset.mfaOttProcessingUrl) :
            (ottVerifyForm.dataset.singleOttProcessingUrl || ottVerifyForm.getAttribute('action'));

        if (!processingUrl) {
            displayMessage("처리 URL을 찾을 수 없습니다. 관리자에게 문의하세요.", "error");
            return;
        }
        logClientSideMfaVerify(`Submitting OTT code to: ${processingUrl}. MFA: ${isMfaFlow}`);

        try {
            const response = await fetch(processingUrl, {
                method: "POST",
                headers: headers,
                body: formData.toString()
            });

            const result = await response.json();
            logClientSideMfaVerify(`OTT verification response status: ${response.status}, body: ${JSON.stringify(result)}`);

            // State Machine 상태 업데이트
            if (window.mfaStateTracker && result.stateMachine) {
                window.mfaStateTracker.updateFromServerResponse(result);
                logClientSideMfaVerify(`State updated to: ${result.stateMachine.currentState}`);
            }

            if (response.ok) {
                if (isMfaFlow) {
                    if (result.status === "MFA_COMPLETED") {
                        // State Machine이 MFA_SUCCESSFUL 상태인지 확인
                        if (window.mfaStateTracker && window.mfaStateTracker.currentState !== 'MFA_SUCCESSFUL' &&
                            window.mfaStateTracker.currentState !== 'ALL_FACTORS_COMPLETED') {
                            console.warn(`State mismatch. Expected: MFA_SUCCESSFUL or ALL_FACTORS_COMPLETED, Actual: ${window.mfaStateTracker.currentState}`);
                        }

                        const authMode = localStorage.getItem("authMode") || "header";
                        if (authMode === "header" || authMode === "header_cookie") {
                            if(result.accessToken) TokenMemory.accessToken = result.accessToken;
                            if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                        }
                        displayMessage("MFA 인증 성공!", "success");

                        // State Machine 정리
                        if (window.mfaStateTracker) {
                            window.mfaStateTracker.clear();
                        }

                        setTimeout(() => { window.location.href = result.redirectUrl || "/home"; }, 1000);
                    } else if (result.status === "MFA_CONTINUE" && result.nextStepUrl) {
                        displayMessage("OTT 인증 성공. 다음 MFA 단계로 이동합니다.", "info");
                        sessionStorage.setItem("currentMfaFactor", result.nextFactorType);
                        if (result.nextStepId) sessionStorage.setItem("currentMfaStepId", result.nextStepId);
                        setTimeout(() => { window.location.href = result.nextStepUrl; }, 1000);
                    } else if (result.status === "MFA_FACTOR_VERIFICATION_FAILED") {
                        let failureMsg = result.message || "인증 코드가 잘못되었거나 만료되었습니다.";
                        if (result.remainingAttempts != null) {
                            failureMsg += ` (남은 시도 횟수: ${result.remainingAttempts})`;
                        }
                        displayMessage(failureMsg, "error");
                        ottCodeInput.focus();
                        ottCodeInput.value = "";

                        // State Machine 실패 처리
                        if (window.mfaStateTracker &&
                            (window.mfaStateTracker.currentState === 'MFA_FAILED_TERMINAL' ||
                                window.mfaStateTracker.currentState === 'MFA_RETRY_LIMIT_EXCEEDED')) {
                            const maxAttemptsExceeded = window.mfaStateTracker.stateMetadata?.failureReason === 'MAX_ATTEMPTS_EXCEEDED';
                            if (maxAttemptsExceeded && result.nextStepUrl) {
                                setTimeout(() => { window.location.href = result.nextStepUrl; }, 2000);
                            }
                        }
                    } else {
                        displayMessage(result.message || "인증 처리 중 알 수 없는 상태입니다: " + result.status, "error");
                    }
                } else {
                    // 단일 OTT 성공
                    displayMessage("로그인 성공!", "success");
                    const authMode = localStorage.getItem("authMode") || "header";
                    if (authMode === "header" || authMode === "header_cookie") {
                        if(result.accessToken) TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                    }
                    setTimeout(() => { window.location.href = result.redirectUrl || "/home"; }, 1000);
                }
            } else {
                let message = "코드 검증에 실패했습니다.";
                if (result && result.message) {
                    message = result.message;
                } else if (response.status === 401) {
                    message = "인증 코드가 잘못되었거나 만료되었습니다.";
                }
                displayMessage(message, "error");
                ottCodeInput.value = "";
                ottCodeInput.focus();

                if (isMfaFlow && result && result.remainingAttempts === 0 && result.nextStepUrl) {
                    setTimeout(() => { window.location.href = result.nextStepUrl; }, 2000);
                }
            }
        } catch (error) {
            console.error("Error verifying OTT code:", error);
            displayMessage("OTT 코드 검증 중 오류가 발생했습니다. 네트워크 연결을 확인해주세요.", "error");
        }
    });

    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
        }
        return deviceId;
    }
});

function logClientSideMfaVerify(message) {
    console.log("[Client OTT Verify] " + message);
}