const TokenMemory = {
    storage: sessionStorage, // 기본은 sessionStorage

    useLocalStorage() {
        this.storage = localStorage;
    },

    useSessionStorage() {
        this.storage = sessionStorage;
    },

    get accessToken() {
        return this.storage.getItem("accessToken");
    },

    set accessToken(token) {
        if (token === null || token === undefined) {
            this.storage.removeItem("accessToken");
        } else {
            this.storage.setItem("accessToken", token);
        }
    },

    get refreshToken() {
        return this.storage.getItem("refreshToken");
    },

    set refreshToken(token) {
        if (token === null || token === undefined) {
            this.storage.removeItem("refreshToken");
        } else {
            this.storage.setItem("refreshToken", token);
        }
    }
};

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
    const csrfParameterMeta = document.querySelector('meta[name="_csrf_parameter"]'); // CSRF 파라미터 이름

    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;
    const csrfParameterName = csrfParameterMeta ? csrfParameterMeta.getAttribute("content") : "_csrf";


    let username = "";
    const mfaSessionId = isMfaFlow ? sessionStorage.getItem("mfaSessionId") : null;

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
    } else { // Single OTT
        // 단일 OTT의 경우 username (email)은 hidden input 또는 userIdentifierDisplay 에서 가져올 수 있음
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

    logClientSideMfaVerify(`OTT Verification page loaded. MFA Flow: ${isMfaFlow}, User: ${username}, Session ID: ${mfaSessionId || 'N/A'}`);

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
            (document.body.dataset.singleOttResendUrl || "/api/ott/generate-code"); // 단일 OTT 재전송 URL

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
            const successStatus = isMfaFlow ? "MFA_OTT_CODE_SENT" : "OTT_CODE_SENT"; // API 응답에 따라 조정

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
        displayMessage("OTT 코드 검증 중...", "info");

        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('token', ottCode);
        if (csrfToken) {
            formData.append(csrfParameterName, csrfToken);
        }

        const headers = {
            "Content-Type": "application/x-www-form-urlencoded", // Spring Security 필터는 기본적으로 이 Content-Type을 기대
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (isMfaFlow && mfaSessionId) {
            headers["X-MFA-Session-Id"] = mfaSessionId;
        }
        // AJAX POST 시에는 CSRF 토큰을 헤더로 보내는 것이 일반적이지만,
        // Spring Security의 폼 기반 필터는 파라미터로도 CSRF 토큰을 받습니다.
        // 여기서는 formData에 포함했으므로 헤더에서는 생략해도 무방할 수 있습니다.
        // 만약 DSL에서 csrf().requireCsrfProtectionMatcher() 등으로 AJAX 요청에 대한 처리가 있다면 헤더가 필요.
        // if (csrfToken && csrfHeader) headers[csrfHeader] = csrfToken;


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

            if (response.ok) {
                if (isMfaFlow) {
                    if (result.status === "MFA_COMPLETE") {
                        const authMode = localStorage.getItem("authMode") || "header";
                        if (authMode === "header" || authMode === "header_cookie") {
                            if(result.accessToken) TokenMemory.accessToken = result.accessToken;
                            if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                        }
                        displayMessage("MFA 인증 성공!", "success");
                        sessionStorage.removeItem("mfaSessionId");
                        sessionStorage.removeItem("mfaUsername");
                        sessionStorage.removeItem("currentMfaFactor");
                        sessionStorage.removeItem("currentMfaStepId");
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
                        if (result.remainingAttempts === 0 && result.nextStepUrl) {
                            setTimeout(() => { window.location.href = result.nextStepUrl; }, 2000);
                        }
                    } else {
                        displayMessage(result.message || "인증 처리 중 알 수 없는 상태입니다: " + result.status, "error");
                    }
                } else { // Single OTT success
                    displayMessage("로그인 성공!", "success");
                    const authMode = localStorage.getItem("authMode") || "header";
                    if (authMode === "header" || authMode === "header_cookie") {
                        if(result.accessToken) TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                    }
                    setTimeout(() => { window.location.href = result.redirectUrl || "/home"; }, 1000);
                }
            } else { // response.ok 가 false 인 경우
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
                } else if (!isMfaFlow && response.status === 401) { // 단일 OTT 실패
                    // 실패 시 특별한 처리 (예: 로그인 페이지로 리다이렉트)
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