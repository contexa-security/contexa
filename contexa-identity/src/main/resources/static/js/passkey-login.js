document.addEventListener("DOMContentLoaded", () => {
    const passkeyButton = document.getElementById("passkeyBtn");
    const messageElement = document.getElementById("passkeyMessage");

    if (!passkeyButton) return;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');

    function displayMessage(message, type = 'info') {
        if (messageElement) {
            messageElement.textContent = message;
            messageElement.className = `mt-4 text-sm ${type === 'error' ? 'text-red-500' : (type === 'success' ? 'text-green-600' : 'text-gray-500')}`;
        } else if (typeof showToast === 'function') {
            showToast(message, type);
        } else {
            alert(message);
        }
    }

    passkeyButton.addEventListener("click", async () => {
        displayMessage("Passkey 인증을 시작합니다...", "info");
        passkeyButton.disabled = true;

        const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
        const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

        // CSRF 토큰은 일반적으로 WebAuthn assertion options 요청 시 POST라면 필요.
        // GET이라면 생략 가능. 서버 구현에 따라 다름.
        if ((!csrfToken || !csrfHeader) && (optionsResponse?.method?.toUpperCase() === "POST")) {
            displayMessage("오류: 보안 토큰을 찾을 수 없습니다. 페이지를 새로고침 해주세요.", "error");
            passkeyButton.disabled = false;
            return;
        }

        const deviceId = getOrCreateDeviceId(); // Device ID 추가

        try {
            // 1. Assertion Options 요청
            // 서버 엔드포인트는 Spring Security WebAuthn이 기본 제공하는 /webauthn/assertion/options 또는 커스텀 엔드포인트
            // 현재 PlatformSecurityConfig에는 `/webauthn/assertion/options`로 단일 Passkey 로그인 옵션 요청 경로가 설정됨
            const optionsResponse = await fetch("/webauthn/assertion/options", {
                method: "POST", // Spring Security WebAuthn 기본은 POST
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    ...( (csrfToken && csrfHeader) && { [csrfHeader]: csrfToken } ), // CSRF 토큰 동적 추가
                    "X-Device-Id": deviceId // Device ID 헤더 추가
                    // username을 body로 보내야 할 수도 있음 (서버 구현 확인 - Spring Security WebAuthn은 username 자동 감지 시도)
                },
                // body: JSON.stringify({ username: "user_identifier_if_needed" }) // 필요시 username 전달
            });

            if (!optionsResponse.ok) {
                const errorData = await optionsResponse.json().catch(() => ({message: "Passkey 옵션 요청 실패"}));
                throw new Error(`옵션 요청 실패: ${errorData.message || optionsResponse.statusText}`);
            }

            const publicKeyCredentialRequestOptions = await optionsResponse.json();
            console.log("Received PublicKeyCredentialRequestOptions:", publicKeyCredentialRequestOptions);

            if (publicKeyCredentialRequestOptions.challenge) {
                publicKeyCredentialRequestOptions.challenge = base64UrlToArraryBuffer(publicKeyCredentialRequestOptions.challenge);
            }
            if (publicKeyCredentialRequestOptions.allowCredentials) {
                publicKeyCredentialRequestOptions.allowCredentials.forEach(cred => {
                    if (cred.id) {
                        cred.id = base64UrlToArraryBuffer(cred.id);
                    }
                });
            }

            displayMessage("Passkey 장치로 인증을 확인해주세요...", "info");
            const assertion = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });
            console.log("Received assertion from authenticator:", assertion);

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

            // 로그인 처리 URL은 Spring Security WebAuthn이 기본 제공하는 /login/webauthn 또는 커스텀 엔드포인트
            // 현재 PlatformSecurityConfig에는 `/login/webauthn`으로 단일 Passkey 로그인 처리 경로가 설정됨
            const loginResponse = await fetch("/login/webauthn", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    ...( (csrfToken && csrfHeader) && { [csrfHeader]: csrfToken } ),
                    "X-Device-Id": deviceId
                },
                body: JSON.stringify(assertionResponseForServer)
            });

            const result = await loginResponse.json().catch(() => null); // 모든 응답을 JSON으로 파싱 시도

            if (loginResponse.ok && result) {
                if (result.status === "MFA_REQUIRED") {
                    sessionStorage.setItem("mfaSessionId", result.mfaSessionId);
                    // Passkey 인증은 username을 직접 입력받지 않으므로, 서버가 인증된 username을 내려주거나,
                    // mfaUsername을 비워두고 mfa-select-factor.js 에서 서버에 mfaSessionId만으로 사용자 정보를 요청해야 할 수 있음.
                    // 여기서는 서버가 result.username 등을 내려준다고 가정하거나, mfaUsername 없이 진행.
                    // 일반적으로 Passkey 인증 후에는 username을 알 수 있으므로, 서버가 result.username을 포함해주는 것이 좋음.
                    const mfaUsername = result.username || 'PasskeyUser'; // 서버 응답에 username이 있다고 가정
                    sessionStorage.setItem("mfaUsername", mfaUsername);

                    showToast("Passkey 인증 성공. 2차 인증이 필요합니다.", "info", 2000);
                    setTimeout(() => {
                        window.location.href = result.nextStepUrl || "/mfa/select-factor";
                    }, 1500);
                    return;
                }

                // MFA가 필요 없는 일반 성공
                const authMode = localStorage.getItem("authMode") || "header";
                if (authMode === "header" || authMode === "header_cookie") {
                    if(result.accessToken) TokenMemory.accessToken = result.accessToken;
                    if (authMode === "header" && result.refreshToken) {
                        TokenMemory.refreshToken = result.refreshToken;
                    }
                }
                displayMessage("Passkey 인증 성공!", "success");
                showToast("Passkey 인증 성공!", "success");
                setTimeout(() => {
                    window.location.href = result.redirectUrl || "/";
                }, 1000);
            } else {
                const errorMessage = result?.message || (loginResponse.status === 401 ? "Passkey 인증에 실패했습니다." : "알 수 없는 오류.");
                throw new Error(`인증 실패: ${errorMessage}`);
            }

        } catch (error) {
            console.error("Passkey login error:", error);
            displayMessage(`오류: ${error.message}`, "error");
            if (error.name === "NotAllowedError") {
                displayMessage("Passkey 인증이 사용자에 의해 취소되었거나, 허용되지 않은 작업입니다.", "info");
            } else if (error.name === "AbortError") {
                displayMessage("Passkey 인증 작업이 중단되었습니다.", "info");
            }
        } finally {
            passkeyButton.disabled = false;
        }
    });

    function base64UrlToArraryBuffer(base64Url) {
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const raw = window.atob(base64);
        const buffer = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) {
            buffer[i] = raw.charCodeAt(i);
        }
        return buffer.buffer;
    }

    function arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let str = '';
        for (const charCode of bytes) {
            str += String.fromCharCode(charCode);
        }
        const base64 = window.btoa(str);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
        }
        return deviceId;
    }
});