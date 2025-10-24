document.addEventListener("DOMContentLoaded", () => {
    const logoutLink = document.getElementById("logoutLink");
    if (!logoutLink) return;

    logoutLink.addEventListener("click", async (event) => {
        event.preventDefault();

        const authMode = localStorage.getItem("authMode") || "header";
        const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
        const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
        const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
        const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

        const headers = { "Content-Type": "application/json" };

        if (authMode !== "header" && csrfToken && csrfHeader) { // 'cookie' 또는 'header_cookie' 모드 시 CSRF 토큰 추가
            headers[csrfHeader] = csrfToken;
        }

        // 'header' 또는 'header_cookie' 모드일 때 Authorization 헤더 추가
        if (authMode === "header" || authMode === "header_cookie") {
            const accessToken = TokenMemory.accessToken;
            if (accessToken) {
                headers["Authorization"] = `Bearer ${accessToken}`;
            }
            // 'header' 모드에서는 서버에 Refresh Token도 전달하여 만료시킬 수 있도록 확장 가능
            // 예: body: JSON.stringify({ refreshToken: TokenMemory.refreshToken })
        }


        try {
            const response = await fetch("/api/auth/logout", {
                method: "POST",
                credentials: "same-origin", // 쿠키 방식 로그아웃을 위해
                headers: headers
                // 'header' 모드에서 서버가 refreshToken을 필요로 한다면 body에 추가
            });

            if (!response.ok && response.status !== 204) { // 204 No Content도 성공으로 간주
                console.warn(`Logout: Server logout failed. Status: ${response.status}`);
                // 실패하더라도 클라이언트 측 토큰은 제거
            } else {
                console.log("Logout: Successfully logged out from server or no active session.");
            }

        } catch (error) {
            console.error("Logout: Error during server logout:", error);
            // 네트워크 오류 등의 경우에도 클라이언트 측 토큰 제거 시도
        } finally {
            // 클라이언트 측 토큰 및 상태 정리
            TokenMemory.accessToken = null;
            TokenMemory.refreshToken = null;
            // localStorage.removeItem("accessToken"); // TokenMemory가 storage를 관리하므로 중복 제거 불필요
            // localStorage.removeItem("refreshToken");

            // UI 업데이트 (init-auth.js의 updateLoginUi와 유사한 로직 또는 호출)
            const loginLinkElem = document.getElementById("loginLink");
            const registerLinkElem = document.getElementById("registerLink");
            const logoutLinkElem = document.getElementById("logoutLink");

            if (authMode === "header" || authMode === "header_cookie") {
                if (loginLinkElem) loginLinkElem.style.display = "inline-block";
                if (registerLinkElem) registerLinkElem.style.display = "inline-block";
                if (logoutLinkElem) logoutLinkElem.style.display = "none";
            } else { // cookie 모드에서는 서버 리다이렉트에 의존하거나 페이지 새로고침
                // UI가 즉시 갱신되지 않을 수 있으므로, 페이지 리다이렉션이 더 확실할 수 있음
            }
            // 로그아웃 후 로그인 페이지로 이동
            window.location.href = "/loginForm";
        }
    });
});