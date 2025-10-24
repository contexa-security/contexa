// src/main/resources/static/js/mfa-verify-passkey.js
// State Machine 통합 버전

document.addEventListener("DOMContentLoaded", () => {
    const passkeyVerifyButton = document.getElementById("mfaPasskeyVerifyBtn");
    const messageDiv = document.getElementById("mfaPasskeyVerifyMessage");
    const otherFactorLink = document.querySelector('a[href="/mfa/select-factor"]'); // 다른 인증 수단 선택 링크

    if (!passkeyVerifyButton) {
        console.warn("Passkey verify button 'mfaPasskeyVerifyBtn' not found.");
        return;
    }

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    const username = sessionStorage.getItem("mfaUsername");
    const currentFactor = sessionStorage.getItem("currentMfaFactor"); // "PASSKEY" 값이어야 함
    const currentStepId = sessionStorage.getItem("currentMfaStepId"); // MfaApiController.selectFactor에서 설정된 값

    // State Machine 상태 확인
    if (window.mfaStateTracker && !window.mfaStateTracker.isValid()) {
        window.mfaStateTracker.restoreFromSession();
    }

    // 유효한 상태인지 확인
    const validStates = ['FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION', 'FACTOR_CHALLENGE_INITIATED'];
    if (window.mfaStateTracker && !validStates.includes(window.mfaStateTracker.currentState)) {
        console.warn(`Invalid state for Passkey verification. Current state: ${window.mfaStateTracker.currentState}`);
        displayMessage("잘못된 인증 상태입니다. 다시 시도해주세요.", "error");
        passkeyVerifyButton.disabled = true;
        setTimeout(() => {
            window.location.href = "/mfa/select-factor";
        }, 2000);
        return;
    }

    if (!mfaSessionId || !username || currentFactor !== "PASSKEY" || !currentStepId) {
        displayMessage("잘못된 접근입니다. MFA 세션 또는 단계 정보가 올바르지 않습니다. 다시 로그인해주세요.", "error");
        if (typeof showToast === 'function') showToast("잘못된 접근입니다. MFA 세션을 확인해주세요.", "error", 3000);
        if (otherFactorLink) otherFactorLink.style.display = 'none'; // 오류 시 다른 수단 선택 숨김
        passkeyVerifyButton.disabled = true;
        return;
    }

    logClientSidePasskey(`Passkey Verification page loaded. User: ${username}, Session: ${mfaSessionId}, Factor: ${currentFactor}, StepId: ${currentStepId}, State: ${window.mfaStateTracker?.currentState}`);

    function displayMessage(message, type = 'info') {
        if (messageDiv) {
            messageDiv.textContent = message;
            messageDiv.className = `mt-4 text-sm text-center ${type === 'error' ? 'text-red-500' : (type === 'success' ? 'text-green-600' : 'text-gray-500')}`;
        }
        if (typeof showToast === 'function') showToast(message, type);
        else alert(message);
    }

    passkeyVerifyButton.addEventListener("click", async () => {
        // State Machine 전이 가능 여부 확인
        if (window.mfaStateTracker && !window.mfaStateTracker.canTransitionTo('FACTOR_VERIFICATION_PENDING')) {
            displayMessage("현재 상태에서 Passkey 검증을 수행할 수 없습니다.", "error");
            return;
        }

        displayMessage("Passkey 인증을 시작합니다...", "info");
        passkeyVerifyButton.disabled = true;

        const headers = {
            "Content-Type": "application/json",
            "X-MFA-Session-Id": mfaSessionId,
            "X-Device-Id": getOrCreateDeviceId(),
            "X-MFA-Step-Id": currentStepId // 현재 처리 중인 stepId 헤더에 추가
        };
        if (csrfToken && csrfHeader) headers[csrfHeader] = csrfToken;

        try {
            // 1. Passkey Assertion Options 요청
            const optionsResponse = await fetch(`/api/mfa/assertion/options`, {
                method: "POST",
                headers: headers,
                body: JSON.stringify({ username: username })
            });

            if (!optionsResponse.ok) {
                const errorData = await optionsResponse.json().catch(() => ({ message: "Passkey 옵션 요청에 실패했습니다." }));
                throw new Error(`옵션 요청 실패 (${optionsResponse.status}): ${errorData.message || optionsResponse.statusText}`);
            }
            const publicKeyCredentialRequestOptions = await optionsResponse.json();
            logClientSidePasskey("Received PKCRO: " + JSON.stringify(publicKeyCredentialRequestOptions));

            // Base64URL -> ArrayBuffer 변환
            if (publicKeyCredentialRequestOptions.challenge) {
                publicKeyCredentialRequestOptions.challenge = base64UrlToArrayBuffer(publicKeyCredentialRequestOptions.challenge);
            }
            if (publicKeyCredentialRequestOptions.allowCredentials) {
                publicKeyCredentialRequestOptions.allowCredentials.forEach(cred => {
                    if (cred.id) cred.id = base64UrlToArrayBuffer(cred.id);
                });
            }

            displayMessage("Passkey 장치(생체인증/보안키)로 인증을 확인해주세요...", "info");
            const assertion = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });

            displayMessage("인증 결과를 서버로 전송 중...", "info");
            const assertionResponseForServer = {
                id: arrayBufferToBase64Url(assertion.rawId),
                rawId: arrayBufferToBase64Url(assertion.rawId),
                type: assertion.type,
                clientDataJSON: arrayBufferToBase64Url(assertion.response.clientDataJSON),
                authenticatorData: arrayBufferToBase64Url(assertion.response.authenticatorData),
                signature: arrayBufferToBase64Url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? arrayBufferToBase64Url(assertion.response.userHandle) : null,
            };

            // 서버 API: MFA Passkey 검증
            const passkeyProcessingUrl = document.body.dataset.mfaPasskeyProcessingUrl || "/login/mfa-passkey";
            logClientSidePasskey("Submitting Passkey assertion to: " + passkeyProcessingUrl);

            const verificationHeaders = {
                "Content-Type": "application/json",
                "X-MFA-Session-Id": mfaSessionId,
                "X-Device-Id": getOrCreateDeviceId(),
                "X-MFA-Step-Id": currentStepId
            };
            if (csrfToken && csrfHeader) verificationHeaders[csrfHeader] = csrfToken;

            const loginResponse = await fetch(passkeyProcessingUrl, {
                method: "POST",
                headers: verificationHeaders,
                body: JSON.stringify(assertionResponseForServer)
            });

            const result = await loginResponse.json();
            logClientSidePasskey(`Passkey verification response: Status=${loginResponse.status}, Body=${JSON.stringify(result)}`);

            // State Machine 상태 업데이트
            if (window.mfaStateTracker && result.stateMachine) {
                window.mfaStateTracker.updateFromServerResponse(result);
                logClientSidePasskey(`State updated to: ${result.stateMachine.currentState}`);
            }

            if (loginResponse.ok) {
                if (result.status === "MFA_COMPLETE") {
                    // State Machine이 MFA_SUCCESSFUL 또는 ALL_FACTORS_COMPLETED 상태인지 확인
                    if (window.mfaStateTracker &&
                        window.mfaStateTracker.currentState !== 'MFA_SUCCESSFUL' &&
                        window.mfaStateTracker.currentState !== 'ALL_FACTORS_COMPLETED') {
                        console.warn(`State mismatch. Expected: MFA_SUCCESSFUL or ALL_FACTORS_COMPLETED, Actual: ${window.mfaStateTracker.currentState}`);
                    }

                    const authMode = localStorage.getItem("authMode") || "header";
                    if (authMode === "header" || authMode === "header_cookie") {
                        if (result.accessToken) TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                    }
                    displayMessage("MFA 인증 성공!", "success");
                    showToast("MFA 인증 성공!", "success");

                    // State Machine 정리
                    if (window.mfaStateTracker) {
                        window.mfaStateTracker.clear();
                    }

                    sessionStorage.removeItem("mfaSessionId");
                    sessionStorage.removeItem("mfaUsername");
                    sessionStorage.removeItem("currentMfaFactor");
                    sessionStorage.removeItem("currentMfaStepId");
                    setTimeout(() => { window.location.href = result.redirectUrl || "/"; }, 1000);
                } else if (result.status === "MFA_CONTINUE" && result.nextStepUrl) {
                    displayMessage("Passkey 인증 성공. 다음 MFA 단계로 이동합니다.", "info");
                    showToast("Passkey 인증 성공. 다음 MFA 단계로 이동합니다.", "info");
                    sessionStorage.setItem("currentMfaFactor", result.nextFactorType);
                    if (result.nextStepId) sessionStorage.setItem("currentMfaStepId", result.nextStepId);
                    setTimeout(() => { window.location.href = result.nextStepUrl; }, 1000);
                } else {
                    displayMessage(result.message || "Passkey 인증 처리 중 알 수 없는 응답입니다.", "error");
                    passkeyVerifyButton.disabled = false;
                }
            } else {
                const message = result.message || (loginResponse.status === 401 ? "Passkey 인증에 실패했습니다." : "Passkey 검증 실패 (" + loginResponse.status + ")");
                displayMessage(message, "error");

                // 최대 시도 횟수 초과 체크
                if (window.mfaStateTracker &&
                    (window.mfaStateTracker.currentState === 'MFA_RETRY_LIMIT_EXCEEDED' ||
                        window.mfaStateTracker.currentState === 'MFA_FAILED_TERMINAL')) {
                    showToast("최대 인증 시도 횟수를 초과했습니다.", "error", 5000);
                    if (result.nextStepUrl) {
                        setTimeout(() => { window.location.href = result.nextStepUrl; }, 2000);
                    } else {
                        setTimeout(() => { window.location.href = "/mfa/failure?error=PASSKEY_LOCKED"; }, 2000);
                    }
                } else {
                    passkeyVerifyButton.disabled = false;
                }
            }

        } catch (error) {
            console.error("Error during MFA Passkey verification:", error);
            let errorMessage = `오류: ${error.message}`;
            if (error.name === "NotAllowedError") {
                errorMessage = "Passkey 인증이 사용자에 의해 취소되었거나, 허용되지 않은 작업입니다.";
            } else if (error.name === "AbortError" || error.name === "SecurityError") {
                errorMessage = "Passkey 인증 작업이 중단되었거나 보안상의 이유로 실패했습니다.";
            }
            displayMessage(errorMessage, error.name === "NotAllowedError" || error.name === "AbortError" ? "info" : "error");
            passkeyVerifyButton.disabled = false;
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

    function base64UrlToArrayBuffer(base64Url) {
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const padding = '='.repeat((4 - base64.length % 4) % 4);
        const raw = window.atob(base64 + padding);
        const buffer = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) { buffer[i] = raw.charCodeAt(i); }
        return buffer.buffer;
    }

    function arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let str = '';
        for (const charCode of bytes) { str += String.fromCharCode(charCode); }
        const base64 = window.btoa(str);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function logClientSidePasskey(message) {
        console.log("[Client MFA Passkey Verify] " + message);
    }
});