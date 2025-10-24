// src/main/resources/static/js/mfa-configure.js
document.addEventListener("DOMContentLoaded", () => {
    const messageDiv = document.getElementById("mfaConfigureMessage");
    const registeredFactorsContainer = document.getElementById("registeredFactorsContainer");
    const registeredFactorsList = document.getElementById("registeredFactorsList");
    const completeRegistrationBtn = document.getElementById("completeRegistrationBtn");
    const skipRegistrationLink = document.getElementById("skipRegistrationLink");

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    const username = sessionStorage.getItem("mfaUsername");

    let registeredFactors = [];

    // State Machine 상태 확인
    if (window.mfaStateTracker && window.mfaStateTracker.currentState !== 'MFA_CONFIGURATION_REQUIRED') {
        console.warn(`Invalid state for MFA configuration. Current state: ${window.mfaStateTracker.currentState}`);
        displayMessage("잘못된 인증 상태입니다. 다시 로그인해주세요.", "error");
        setTimeout(() => {
            window.location.href = "/loginForm";
        }, 2000);
        return;
    }

    function displayMessage(message, type = 'error') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="text-sm text-center ${type === 'error' ? 'text-red-500' : (type === 'info' ? 'text-blue-500' : 'text-green-500')}">${message}</p>`;
        }
        if (typeof showToast === 'function') showToast(message, type);
    }

    // 기존 등록된 팩터 조회
    async function loadRegisteredFactors() {
        try {
            const response = await fetch('/api/mfa/registered-factors', {
                method: 'GET',
                headers: {
                    'X-MFA-Session-Id': mfaSessionId,
                    'X-Device-Id': getOrCreateDeviceId()
                }
            });

            if (response.ok) {
                const result = await response.json();
                registeredFactors = result.registeredFactors || [];
                updateRegisteredFactorsDisplay();
            }
        } catch (error) {
            console.error("Failed to load registered factors:", error);
        }
    }

    function updateRegisteredFactorsDisplay() {
        if (registeredFactors.length > 0) {
            registeredFactorsContainer.classList.remove('hidden');
            registeredFactorsList.innerHTML = registeredFactors.map(factor => `
                <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div class="flex items-center">
                        ${getFactorIcon(factor.type)}
                        <span class="ml-2 font-medium">${getFactorDisplayName(factor.type)}</span>
                        ${factor.verified ? '<span class="ml-2 text-xs text-green-600">(확인됨)</span>' : ''}
                    </div>
                    <button data-factor="${factor.type}" class="remove-factor-btn text-red-500 hover:text-red-700">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
            `).join('');

            // 등록 완료 버튼 활성화
            completeRegistrationBtn.disabled = false;

            // 삭제 버튼 이벤트 리스너
            document.querySelectorAll('.remove-factor-btn').forEach(btn => {
                btn.addEventListener('click', () => removeFactor(btn.dataset.factor));
            });
        } else {
            registeredFactorsContainer.classList.add('hidden');
            completeRegistrationBtn.disabled = true;
        }
    }

    function getFactorIcon(type) {
        switch(type) {
            case 'OTT':
                return '<svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>';
            case 'PASSKEY':
                return '<svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>';
            default:
                return '';
        }
    }

    function getFactorDisplayName(type) {
        switch(type) {
            case 'OTT': return '이메일 OTP';
            case 'PASSKEY': return 'Passkey (FIDO2)';
            default: return type;
        }
    }

    // 등록 버튼 클릭 처리
    document.querySelectorAll('.mfa-register-button').forEach(button => {
        button.addEventListener('click', async () => {
            const action = button.dataset.action;

            if (action === 'register-ott') {
                await registerOtt();
            } else if (action === 'register-passkey') {
                await registerPasskey();
            }
        });
    });

    async function registerOtt() {
        displayMessage("OTT 등록을 시작합니다...", "info");

        try {
            const response = await fetch('/api/mfa/register/ott', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-MFA-Session-Id': mfaSessionId,
                    'X-Device-Id': getOrCreateDeviceId(),
                    [csrfHeader]: csrfToken
                },
                body: JSON.stringify({
                    username: username,
                    email: username // 사용자명이 이메일인 경우
                })
            });

            const result = await response.json();

            if (response.ok) {
                displayMessage("인증 코드가 이메일로 발송되었습니다. 확인해주세요.", "success");
                // OTT 코드 입력 모달 또는 페이지로 이동
                showOttVerificationModal();
            } else {
                displayMessage(result.message || "OTT 등록에 실패했습니다.", "error");
            }
        } catch (error) {
            console.error("OTT registration error:", error);
            displayMessage("OTT 등록 중 오류가 발생했습니다.", "error");
        }
    }

    async function registerPasskey() {
        displayMessage("Passkey 등록을 시작합니다...", "info");

        // WebAuthn 등록 로직
        // 구현 생략 - 실제 구현 시 WebAuthn API 사용
    }

    // 등록 완료 버튼 클릭
    completeRegistrationBtn.addEventListener('click', async () => {
        if (registeredFactors.length === 0) {
            displayMessage("최소 하나 이상의 인증 수단을 등록해주세요.", "error");
            return;
        }

        try {
            const response = await fetch('/api/mfa/complete-configuration', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-MFA-Session-Id': mfaSessionId,
                    'X-Device-Id': getOrCreateDeviceId(),
                    [csrfHeader]: csrfToken
                },
                body: JSON.stringify({
                    username: username,
                    registeredFactors: registeredFactors.map(f => f.type)
                })
            });

            const result = await response.json();

            // State Machine 상태 업데이트
            if (window.mfaStateTracker && result.stateMachine) {
                window.mfaStateTracker.updateFromServerResponse(result);
            }

            if (response.ok) {
                displayMessage("MFA 설정이 완료되었습니다!", "success");
                setTimeout(() => {
                    window.location.href = result.nextStepUrl || '/mfa/select-factor';
                }, 1500);
            } else {
                displayMessage(result.message || "설정 완료에 실패했습니다.", "error");
            }
        } catch (error) {
            console.error("Configuration completion error:", error);
            displayMessage("설정 완료 중 오류가 발생했습니다.", "error");
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

    // OTT 코드 확인 모달 (간단한 예시)
    function showOttVerificationModal() {
        // 실제 구현 시 모달 또는 별도 페이지로 구현
        const code = prompt("이메일로 받은 6자리 코드를 입력하세요:");
        if (code) {
            verifyOttCode(code);
        }
    }

    async function verifyOttCode(code) {
        try {
            const response = await fetch('/api/mfa/verify/ott-registration', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-MFA-Session-Id': mfaSessionId,
                    'X-Device-Id': getOrCreateDeviceId(),
                    [csrfHeader]: csrfToken
                },
                body: JSON.stringify({
                    username: username,
                    code: code
                })
            });

            const result = await response.json();

            if (response.ok) {
                displayMessage("OTT가 성공적으로 등록되었습니다!", "success");
                await loadRegisteredFactors(); // 목록 새로고침
            } else {
                displayMessage(result.message || "코드 확인에 실패했습니다.", "error");
            }
        } catch (error) {
            console.error("OTT verification error:", error);
            displayMessage("코드 확인 중 오류가 발생했습니다.", "error");
        }
    }

    // 초기 로드
    loadRegisteredFactors();
});