// resources/static/js/mfa-login.js (개선된 버전)
document.addEventListener("DOMContentLoaded", () => {
    const restForm = document.getElementById("restForm");
    const ottForm = document.getElementById("ottForm");
    const passkeySection = document.getElementById("passkeySection");
    const mfaStepIndicator = document.getElementById("mfaStepIndicator");
    const mfaResultSection = document.getElementById("mfaResultSection");

    const restFormMessage = document.getElementById("restFormMessage");
    const ottFormMessage = document.getElementById("ottFormMessage");
    const mfaOttEmailDisplay = document.getElementById("mfaOttEmail");
    const passkeySectionMessage = document.getElementById("passkeySectionMessage");
    const resendOttCodeButton = document.getElementById("resendOttCode");

    if (!restForm || !ottForm || !passkeySection || !mfaResultSection) {
        console.error("MFA Login: One or more MFA step elements not found.");
        return;
    }

    const steps = {
        PRIMARY: restForm,
        OTT: ottForm,
        PASSKEY: passkeySection,
        COMPLETE: mfaResultSection // 최종 결과 표시용
    };
    let currentMfaSessionId = null;
    let currentMfaUsername = null;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;
    const authMode = localStorage.getItem("authMode") || "header";

    function displayStepMessage(stepKey, message, type = 'error') {
        let targetElement;
        if (stepKey === 'PRIMARY') targetElement = restFormMessage;
        else if (stepKey === 'OTT') targetElement = ottFormMessage;
        else if (stepKey === 'PASSKEY') targetElement = passkeySectionMessage;
        else if (stepKey === 'COMPLETE') { // 결과 섹션에 메시지 표시
            mfaResultSection.innerHTML = `<p class="text-lg font-semibold ${type === 'success' ? 'text-green-600' : 'text-red-600'}">${message}</p>`;
            if (type === 'success') {
                mfaResultSection.innerHTML += '<p class="mt-4"><a href="/" class="text-app-accent hover:underline">홈으로 이동</a></p>';
            }
            return; // 메시지 영역이 다르므로 여기서 반환
        }


        if (targetElement) {
            targetElement.textContent = message;
            targetElement.className = `text-sm text-center min-h-[1.25rem] ${type === 'error' ? 'text-red-500' : (type === 'info' ? 'text-blue-500' : 'text-green-500')}`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
    }

    function updateStepIndicator(stepName) {
        if (mfaStepIndicator) mfaStepIndicator.textContent = stepName;
    }

    function showStep(stepKeyToShow) {
        for (const key in steps) {
            steps[key].style.display = key === stepKeyToShow ? "" : "none";
        }
        if (stepKeyToShow === 'PRIMARY') updateStepIndicator("1단계: 계정 정보 입력");
        else if (stepKeyToShow === 'OTT') updateStepIndicator("2단계: 이메일 코드 인증");
        else if (stepKeyToShow === 'PASSKEY') updateStepIndicator("3단계: Passkey 인증");
        else if (stepKeyToShow === 'COMPLETE') updateStepIndicator("인증 완료");
    }

    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
        }
        return deviceId;
    }

    function createApiHeaders(includeMfaSession = false) {
        const headers = {
            "Content-Type": "application/json",
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (csrfToken && csrfHeader) headers[csrfHeader] = csrfToken;
        if (includeMfaSession && currentMfaSessionId) {
            headers["X-MFA-Session-Id"] = currentMfaSessionId;
        }
        return headers;
    }

    function createFilterHeaders(includeMfaSession = false) {
        // Spring Security Filter는 Content-Type을 다르게 요구할 수 있음.
        // 예: application/x-www-form-urlencoded 또는 특정 커스텀 헤더.
        // 여기서는 API와 유사하게 JSON으로 가정하나, 실제 필터 구현에 따라 조정 필요.
        const headers = {
            "Content-Type": "application/json", // 필터가 JSON을 받는다고 가정
            "X-Device-Id": getOrCreateDeviceId()
        };
        if (csrfToken && csrfHeader) headers[csrfHeader] = csrfToken;
        if (includeMfaSession && currentMfaSessionId) {
            headers["X-MFA-Session-Id"] = currentMfaSessionId;
        }
        return headers;
    }


    // --- 1단계: 기본 로그인 (ID/PW) ---
    if (restForm) {
        restForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            const username = restForm.username.value;
            const password = restForm.password.value;
            currentMfaUsername = username; // MFA 흐름에서 사용할 사용자 이름 저장

            displayStepMessage('PRIMARY', "1차 인증 중...", "info");

            try {
                // 이 API는 MfaCapableRestSuccessHandler가 처리
                const response = await fetch("/api/auth/login", {
                    method: "POST",
                    headers: createApiHeaders(),
                    body: JSON.stringify({ username, password })
                });
                const result = await response.json();

                if (response.ok && result.status === "MFA_REQUIRED") {
                    currentMfaSessionId = result.mfaSessionId;
                    if (mfaOttEmailDisplay) mfaOttEmailDisplay.textContent = username;

                    displayStepMessage('PRIMARY', "1차 인증 성공. 다음 MFA 단계를 진행합니다.", "success");
                    // 서버 응답에 다음 단계 정보(nextFactorType 또는 nextStepUrl)가 있다면 그것을 따름
                    // 여기서는 예시로 OTT로 바로 진행한다고 가정하고 OTT 챌린지 요청
                    // 실제로는 result.nextFactorType에 따라 분기해야 함
                    showToast("1차 인증 성공. 다음 인증으로 이동합니다.", "success", 1500);
                    // MfaCapableRestSuccessHandler가 nextStepUrl("/mfa/select-factor")을 내려주면 그곳으로 이동.
                    // 이 페이지는 이미 select-factor를 거쳐 특정 factor로 온 경우이므로, 바로 다음 factor로 진행.
                    // 이 페이지의 설계 자체가 1차->OTT->Passkey 순으로 고정된 흐름을 가정하고 있음.
                    // 서버에서 다음 Factor 정보를 받아와야 더 유연해짐.
                    // 현재는 예시로 OTT를 다음으로 가정함.
                    if (await requestOttChallengeForMfaFlow()) {
                        showStep('OTT');
                    } else {
                        displayStepMessage('PRIMARY', "OTT 코드 요청에 실패했습니다. 관리자에게 문의하세요.", "error");
                    }
                } else if (response.ok && result.status === "SUCCESS") { // MFA 불필요, 바로 로그인 성공
                    if (authMode === "header" || authMode === "header_cookie") {
                        TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                    }
                    displayStepMessage('COMPLETE', "로그인 성공!", "success");
                    showStep('COMPLETE');
                    setTimeout(() => { window.location.href = result.redirectUrl || "/"; }, 2000);
                } else {
                    displayStepMessage('PRIMARY', `1차 인증 실패: ${result.message || response.statusText}`, "error");
                }
            } catch (error) {
                console.error("MFA Login - Step 1 (REST) error:", error);
                displayStepMessage('PRIMARY', "1차 인증 요청 중 오류 발생", "error");
            }
        });
    }

    async function requestOttChallengeForMfaFlow() {
        if (!currentMfaUsername || !currentMfaSessionId) {
            displayStepMessage('OTT', "OTT 코드 요청 실패: 사용자 또는 세션 정보 없음", "error");
            return false;
        }
        displayStepMessage('OTT', "OTT 인증 코드를 요청 중입니다...", "info");
        try {
            // MfaApiController의 /api/mfa/request-ott-code 사용
            const response = await fetch(`/api/mfa/request-ott-code`, {
                method: "POST",
                headers: createApiHeaders(true), // MFA 세션 ID 포함
                body: JSON.stringify({ username: currentMfaUsername, factorType: "OTT" })
            });

            if (response.ok) {
                const challengeResult = await response.json();
                displayStepMessage('OTT', challengeResult.message || `이메일(${currentMfaUsername})로 인증 코드가 발송되었습니다.`, "success");
                if (mfaOttEmailDisplay) mfaOttEmailDisplay.textContent = currentMfaUsername;
                return true;
            } else {
                const errorData = await response.json().catch(() => ({message: "OTT 코드 요청 실패"}));
                displayStepMessage('OTT', `OTT 코드 요청 실패: ${errorData.message || response.statusText}`, "error");
                return false;
            }
        } catch (error) {
            console.error("MFA Login - Request OTT Challenge error:", error);
            displayStepMessage('OTT', "OTT 코드 요청 중 오류 발생", "error");
            return false;
        }
    }

    if(resendOttCodeButton) {
        resendOttCodeButton.addEventListener("click", async () => {
            resendOttCodeButton.disabled = true;
            await requestOttChallengeForMfaFlow();
            setTimeout(() => { resendOttCodeButton.disabled = false; }, 30000);
        });
    }

    // --- 2단계: OTT 코드 인증 ---
    if (ottForm) {
        ottForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            const ottCode = ottForm.token.value;
            if (!ottCode || ottCode.length !== 6 || !/^\d{6}$/.test(ottCode)) {
                displayStepMessage('OTT', "6자리 숫자로 된 인증 코드를 입력해주세요.", "error");
                return;
            }
            displayStepMessage('OTT', "OTT 코드 인증 중...", "info");

            try {
                // 이 요청은 /login/mfa-ott 로 가서 MfaStepBasedSuccessHandler 가 처리
                const response = await fetch(`/login/mfa-ott`, {
                    method: "POST",
                    headers: createFilterHeaders(true), // MFA 세션 ID 포함
                    body: JSON.stringify({ token: ottCode, username: currentMfaUsername })
                });
                const result = await response.json();

                if (response.ok && result.status === "MFA_CONTINUE" && result.nextFactorType === "PASSKEY") {
                    displayStepMessage('OTT', "OTT 코드 인증 성공. Passkey 인증으로 이동합니다.", "success");
                    showToast("OTT 코드 인증 성공. 다음 인증으로 이동합니다.", "success", 1500);
                    // Passkey 챌린지 자동 요청
                    if (await requestPasskeyChallengeForMfaFlow()) {
                        showStep('PASSKEY');
                    } else {
                        displayStepMessage('OTT', "Passkey 옵션 요청에 실패했습니다.", "error");
                    }
                } else if (response.ok && result.status === "MFA_COMPLETE") {
                    if (authMode === "header" || authMode === "header_cookie") {
                        TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                    }
                    displayStepMessage('COMPLETE', "MFA 로그인 성공!", "success");
                    showStep('COMPLETE');
                    setTimeout(() => { window.location.href = result.redirectUrl || "/"; }, 2000);
                } else {
                    displayStepMessage('OTT', `OTT 코드 인증 실패: ${result.message || response.statusText}`, "error");
                }
            } catch (error) {
                console.error("MFA Login - Step 2 (OTT) error:", error);
                displayStepMessage('OTT', "OTT 코드 인증 요청 중 오류 발생", "error");
            }
        });
    }

    async function requestPasskeyChallengeForMfaFlow() {
        if (!currentMfaUsername || !currentMfaSessionId) {
            displayStepMessage('PASSKEY', "Passkey 옵션 요청 실패: 사용자 또는 세션 정보 없음", "error");
            return false;
        }
        displayStepMessage('PASSKEY', "Passkey 인증 옵션을 요청 중입니다...", "info");
        try {
            const response = await fetch(`/api/mfa/assertion/options`, {
                method: "POST",
                headers: createApiHeaders(true),
                body: JSON.stringify({ username: currentMfaUsername })
            });
            if (response.ok) {
                const pkOptions = await response.json();
                // JS WebAuthn API가 사용할 수 있도록 challenge와 id를 ArrayBuffer로 변환
                if (pkOptions.challenge) pkOptions.challenge = base64UrlToArraryBuffer(pkOptions.challenge);
                if (pkOptions.allowCredentials) {
                    pkOptions.allowCredentials.forEach(cred => {
                        if (cred.id) cred.id = base64UrlToArraryBuffer(cred.id);
                    });
                }
                // 이 옵션을 passkeyButton 클릭 핸들러에서 사용할 수 있도록 저장 (예: 전역 변수 또는 data attribute)
                passkeySection.dataset.pkOptions = JSON.stringify(pkOptions);
                displayStepMessage('PASSKEY', "Passkey 인증 장치를 확인하세요.", "info");
                return true;
            } else {
                const errorData = await response.json().catch(() => ({message: "Passkey 옵션 요청 실패"}));
                displayStepMessage('PASSKEY', `Passkey 옵션 요청 실패: ${errorData.message || response.statusText}`, "error");
                return false;
            }
        } catch (error) {
            console.error("MFA Login - Request Passkey Challenge error:", error);
            displayStepMessage('PASSKEY', "Passkey 옵션 요청 중 오류 발생", "error");
            return false;
        }
    }


    // --- 3단계: Passkey 인증 ---
    const passkeyButton = document.getElementById("webauthnBtn");
    if (passkeyButton) {
        passkeyButton.addEventListener("click", async () => {
            displayStepMessage('PASSKEY', "Passkey 인증을 시작합니다...", "info");
            passkeyButton.disabled = true;

            const pkOptionsString = passkeySection.dataset.pkOptions;
            if (!pkOptionsString) {
                displayStepMessage('PASSKEY', "Passkey 인증 옵션이 없습니다. 이전 단계를 확인하세요.", "error");
                passkeyButton.disabled = false;
                return;
            }
            const publicKeyCredentialRequestOptions = JSON.parse(pkOptionsString);
            // dataset에서 가져온 후에도 ArrayBuffer 변환이 필요할 수 있음 (문자열화 되었으므로)
            if (typeof publicKeyCredentialRequestOptions.challenge === 'string') {
                publicKeyCredentialRequestOptions.challenge = base64UrlToArraryBuffer(publicKeyCredentialRequestOptions.challenge);
            }
            if (publicKeyCredentialRequestOptions.allowCredentials) {
                publicKeyCredentialRequestOptions.allowCredentials.forEach(cred => {
                    if (typeof cred.id === 'string') cred.id = base64UrlToArraryBuffer(cred.id);
                });
            }


            try {
                displayStepMessage('PASSKEY', "Passkey 장치로 인증을 확인해주세요...", "info");
                const assertion = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });

                displayStepMessage('PASSKEY', "Passkey 인증 결과를 서버로 전송 중...", "info");
                const assertionResponseForServer = {
                    id: arrayBufferToBase64Url(assertion.rawId),
                    rawId: arrayBufferToBase64Url(assertion.rawId),
                    type: assertion.type,
                    clientDataJSON: arrayBufferToBase64Url(assertion.response.clientDataJSON),
                    authenticatorData: arrayBufferToBase64Url(assertion.response.authenticatorData),
                    signature: arrayBufferToBase64Url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? arrayBufferToBase64Url(assertion.response.userHandle) : null,
                };

                // 이 요청은 /login/mfa-passkey 로 가서 MfaStepBasedSuccessHandler 가 처리
                const loginResponse = await fetch(`/login/mfa-passkey`, {
                    method: "POST",
                    headers: createFilterHeaders(true), // MFA 세션 ID 포함
                    body: JSON.stringify(assertionResponseForServer)
                });
                const result = await loginResponse.json();

                if (loginResponse.ok && result.status === "MFA_COMPLETE") {
                    if (authMode === "header" || authMode === "header_cookie") {
                        TokenMemory.accessToken = result.accessToken;
                        if (authMode === "header" && result.refreshToken) TokenMemory.refreshToken = result.refreshToken;
                    }
                    displayStepMessage('COMPLETE', "MFA 로그인 성공!", "success");
                    showStep('COMPLETE');
                    setTimeout(() => { window.location.href = result.redirectUrl || "/"; }, 2000);
                } else {
                    displayStepMessage('PASSKEY', `Passkey 인증 실패: ${result.message || loginResponse.statusText}`, "error");
                }
            } catch (error) {
                console.error("MFA Login - Step 3 (Passkey) error:", error);
                displayStepMessage('PASSKEY', `Passkey 인증 오류: ${error.message}`, "error");
                if (error.name === "NotAllowedError") {
                    displayStepMessage('PASSKEY', "Passkey 인증이 사용자에 의해 취소되었거나, 허용되지 않은 작업입니다.", "info");
                }
            } finally {
                passkeyButton.disabled = false;
            }
        });
    }

    function base64UrlToArraryBuffer(base64Url) {
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const raw = window.atob(base64);
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

    showStep('PRIMARY'); // 초기 화면은 1단계(ID/PW)
});