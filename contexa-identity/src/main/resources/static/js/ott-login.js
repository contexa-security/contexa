document.addEventListener("DOMContentLoaded", () => {
    const ottRequestForm = document.getElementById("singleOttRequestForm");
    const emailInput = document.getElementById("email");
    const sendOtpCodeBtn = document.getElementById("sendOtpCodeBtn");
    const sendMagicLinkBtn = document.getElementById("sendMagicLinkBtn");
    const messageDiv = document.getElementById("ottRequestMessage");

    if (!ottRequestForm || !emailInput || !sendOtpCodeBtn || !sendMagicLinkBtn) {
        console.warn("Single OTT request form elements not found.");
        return;
    }

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    function displayMessage(message, type = 'error') {
        if (messageDiv) {
            messageDiv.innerHTML = `<p class="text-sm text-center ${type === 'error' ? 'text-red-500' : (type === 'info' ? 'text-blue-500' : 'text-green-500')}">${message}</p>`;
        }
        if (typeof showToast === 'function') showToast(message, type);
    }

    async function requestOtt(apiUrl, email, buttonElement) {
        buttonElement.disabled = true;
        if (sendOtpCodeBtn === buttonElement) sendMagicLinkBtn.disabled = true;
        if (sendMagicLinkBtn === buttonElement) sendOtpCodeBtn.disabled = true;

        displayMessage("요청 처리 중...", "info");

        const headers = { "Content-Type": "application/json" };
        if (csrfToken && csrfHeader) { // POST 요청이므로 CSRF 토큰 필요
            headers[csrfHeader] = csrfToken;
        }

        try {
            const response = await fetch(apiUrl, {
                method: "POST",
                headers: headers,
                body: JSON.stringify({ email: email }),
                credentials: "same-origin"
            });

            const result = await response.json();

            if (response.ok && result.nextUrl) {
                showToast(result.message || "정상적으로 처리되었습니다. 다음 페이지로 이동합니다.", "success", 2000);
                setTimeout(() => {
                    window.location.href = result.nextUrl;
                }, 1500);
            } else {
                displayMessage(result.message || "요청에 실패했습니다.", "error");
                buttonElement.disabled = false;
                if (sendOtpCodeBtn === buttonElement) sendMagicLinkBtn.disabled = false;
                if (sendMagicLinkBtn === buttonElement) sendOtpCodeBtn.disabled = false;
            }
        } catch (error) {
            console.error("Error requesting OTT:", error);
            displayMessage("요청 중 오류가 발생했습니다. 네트워크 연결을 확인해주세요.", "error");
            buttonElement.disabled = false;
            if (sendOtpCodeBtn === buttonElement) sendMagicLinkBtn.disabled = false;
            if (sendMagicLinkBtn === buttonElement) sendOtpCodeBtn.disabled = false;
        }
    }

    sendOtpCodeBtn.addEventListener("click", () => {
        const email = emailInput.value;
        if (!email) {
            displayMessage("이메일 주소를 입력해주세요.", "error");
            return;
        }
        // API 경로 확인 필요: LoginController에 /api/ott/generate 로 생성함
        requestOtt("/api/ott/generate", email, sendOtpCodeBtn);
    });

    sendMagicLinkBtn.addEventListener("click", () => {
        const email = emailInput.value;
        if (!email) {
            displayMessage("이메일 주소를 입력해주세요.", "error");
            return;
        }
        // API 경로 확인 필요: LoginController에 /api/ott/generate-magiclink 로 생성함.
        // 또는 기존 /ott/generate (GenerateOneTimeTokenFilter)를 계속 사용하고 싶다면
        // 해당 필터가 성공 후 /ott/sent?type=magic_link_sent 로 보내도록 MagicLinkHandler 수정 필요.
        // 여기서는 새로운 API를 호출한다고 가정.
        requestOtt("/api/ott/generate-magiclink", email, sendMagicLinkBtn);
    });
});