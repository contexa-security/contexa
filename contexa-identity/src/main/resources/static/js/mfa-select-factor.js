// src/main/resources/static/js/mfa-select-factor.js
// State Machine 통합 버전

document.addEventListener("DOMContentLoaded", () => {
    const factorSelectionContainer = document.getElementById("mfaFactorSelectionForm");
    const messageDiv = document.getElementById("factorSelectionMessage");

    if (!factorSelectionContainer) {
        console.warn("MFA Factor Selection container/form not found.");
        return;
    }

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    const mfaSessionId = sessionStorage.getItem("mfaSessionId");
    const username = sessionStorage.getItem("mfaUsername");

    // State Machine 상태 확인
    if (window.mfaStateTracker && !window.mfaStateTracker.isValid()) {
        // 세션에서 복원 시도
        window.mfaStateTracker.restoreFromSession();
    }

    const validStatesForFactorSelection = [
        'PRIMARY_AUTHENTICATION_COMPLETED',  // MFA 정책 평가 직후
        'AWAITING_FACTOR_SELECTION',        // 정상적인 팩터 선택 대기 상태
        'FACTOR_VERIFICATION_COMPLETED'      // 추가 팩터 필요한 경우
    ];

    /*if (window.mfaStateTracker &&
        !validStatesForFactorSelection.includes(window.mfaStateTracker.currentState)) {
        console.warn(`Invalid state for factor selection. Current state: ${window.mfaStateTracker.currentState}`);
        displayMessage("잘못된 인증 상태입니다. 다시 로그인해주세요.", "error");
        setTimeout(() => {
            window.location.href = "/loginForm";
        }, 2000);
        return;
    }*/

    if (!mfaSessionId || !username) {
        displayMessage("MFA 세션 정보가 유효하지 않습니다. 다시 로그인해주세요.", "error");
        if (typeof showToast === 'function') {
            showToast("MFA 세션 정보가 유효하지 않습니다. 다시 로그인해주세요.", "error", 3000);
        }
        return;
    }

    logClientSideMfa(`Select Factor page loaded. SessionId: ${mfaSessionId}, User: ${username}, State: ${window.mfaStateTracker?.currentState}`);

    function displayMessage(message, type = 'error') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="text-sm text-center ${type === 'error' ? 'text-red-500' : (type === 'info' ? 'text-blue-500' : 'text-green-500')}">${message}</p>`;
        }
        if (typeof showToast === 'function') showToast(message, type);
        else alert(message);
    }

    const factorButtons = document.querySelectorAll("#mfaFactorSelectionForm .mfa-factor-button");

    // State Machine 정보를 기반으로 버튼 활성화/비활성화
    if (window.mfaStateTracker && window.mfaStateTracker.stateMetadata?.availableFactors) {
        const availableFactors = window.mfaStateTracker.stateMetadata.availableFactors;

        factorButtons.forEach(button => {
            const factor = button.dataset.factor;
            if (!availableFactors.includes(factor)) {
                button.disabled = true;
                button.classList.add('opacity-50', 'cursor-not-allowed');
                button.title = "이 인증 수단은 현재 사용할 수 없습니다.";
            }
        });
    }

    factorButtons.forEach(button => {
        button.addEventListener("click", async () => {
            factorButtons.forEach(btn => btn.disabled = true);
            const selectedFactor = button.dataset.factor;

            // State Machine 전이 가능 여부 확인
            if (window.mfaStateTracker && !window.mfaStateTracker.canTransitionTo('AWAITING_FACTOR_CHALLENGE_INITIATION')) {
                displayMessage(`선택한 인증 수단(${selectedFactor})을 사용할 수 없습니다.`, "error");
                factorButtons.forEach(btn => btn.disabled = false);
                logClientSideMfa(`Invalid transition attempt: ${window.mfaStateTracker.currentState} -> AWAITING_FACTOR_CHALLENGE_INITIATION`);
                return;
            }

            displayMessage(`선택한 인증 수단(${selectedFactor})으로 진행합니다...`, "info");

            const headers = {
                "Content-Type": "application/json",
                "X-Device-Id": getOrCreateDeviceId(),
                "X-MFA-Session-Id": mfaSessionId
            };

            if (csrfToken && csrfHeader) {
                headers[csrfHeader] = csrfToken;
            }

            try {
                const response = await fetch(`/api/mfa/select-factor`, {
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify({
                        factorType: selectedFactor,
                        username: username
                    })
                });

                const result = await response.json();

                // State Machine 상태 업데이트
                if (window.mfaStateTracker && result.stateMachine) {
                    window.mfaStateTracker.updateFromServerResponse(result);
                    logClientSideMfa(`State updated to: ${result.stateMachine.currentState}`);
                }

                if (response.ok && result.status === "FACTOR_SELECTED_PROCEED_TO_CHALLENGE_UI" && result.nextStepUrl) {
                    showToast(`${selectedFactor} 인증 페이지로 이동합니다.`, "success");
                    sessionStorage.setItem("currentMfaFactor", result.nextFactorType || selectedFactor);

                    if (result.nextStepId) {
                        sessionStorage.setItem("currentMfaStepId", result.nextStepId);
                    }

                    // State Machine 상태 확인
                    if (window.mfaStateTracker) {
                        const expectedState = 'AWAITING_FACTOR_CHALLENGE_INITIATION';
                        if (window.mfaStateTracker.currentState !== expectedState) {
                            console.warn(`State mismatch. Expected: ${expectedState}, Actual: ${window.mfaStateTracker.currentState}`);
                        }
                    }

                    setTimeout(() => {
                        window.location.href = result.nextStepUrl;
                    }, 1000);
                } else {
                    displayMessage(result.message || `인증 수단 처리 중 오류: ${response.statusText}`, "error");
                    factorButtons.forEach(btn => btn.disabled = false);

                    // State Machine 오류 처리
                    if (result.stateMachine && window.mfaStateTracker.isTerminalState()) {
                        const failureReason = result.stateMachine.stateMetadata?.failureReason;
                        if (failureReason) {
                            displayMessage(`오류: ${failureReason}`, "error");
                        }

                        // 터미널 상태면 로그인 페이지로
                        if (window.mfaStateTracker.currentState === 'MFA_FAILED_TERMINAL' ||
                            window.mfaStateTracker.currentState === 'MFA_SESSION_EXPIRED') {
                            setTimeout(() => {
                                window.location.href = "/loginForm";
                            }, 2000);
                        }
                    }
                }
            } catch (error) {
                console.error("MFA Factor Selection error:", error);
                displayMessage("인증 수단 선택 중 오류가 발생했습니다.", "error");
                factorButtons.forEach(btn => btn.disabled = false);
            }
        });
    });

    function getOrCreateDeviceId() {
        let deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            deviceId = crypto.randomUUID();
            localStorage.setItem("deviceId", deviceId);
        }
        return deviceId;
    }

    function logClientSideMfa(message) {
        console.log("[Client MFA SelectFactor] " + message);
    }
});