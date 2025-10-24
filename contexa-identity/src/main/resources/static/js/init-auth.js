/*
// init-auth.js
(async function initAuthFlow() {
    const authMode = localStorage.getItem("authMode") || "header";

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    function updateLoginUi() { /!* ...이전과 동일... *!/ }

    if (authMode === "header" || authMode === "header_cookie") {
        const headers = { "Content-Type": "application/json" }; // POST 요청 본문이 없어도 Content-Type 명시 가능
        let requestBody = null; // 'header' 모드 시 리프레시 토큰을 본문에 담을 경우 사용

        if (authMode === "header_cookie" && csrfToken && csrfHeader) {
            headers[csrfHeader] = csrfToken;
        } else if (authMode === "header") {
            const storedRefreshToken = TokenMemory.refreshToken;
            if (storedRefreshToken) {
                headers["X-Refresh-Token"] = storedRefreshToken; // 헤더에 리프레시 토큰 추가
                // 또는 서버가 본문에서 읽는다면:
                // requestBody = JSON.stringify({ refreshToken: storedRefreshToken });
            } else {
                console.log("Refresh: No refresh token in TokenMemory for 'header' mode. Skipping refresh call.");
                updateLoginUi();
                return;
            }
        }

        try {
            const fetchOptions = {
                method: "POST",
                credentials: authMode === "header_cookie" ? "same-origin" : "include",
                headers: headers,
            };
            if (requestBody) { // 'header' 모드에서 본문에 토큰을 담는 경우
                fetchOptions.body = requestBody;
            }

            const response = await fetch("/api/auth/refresh", fetchOptions);
            const responseStatus = response.status;
            const contentType = response.headers.get("content-type");
            let responseData = null;

            if (responseStatus !== 204) {
                const textResponse = await response.text().catch(() => "Could not read response text.");
                console.warn(`Refresh: Response from /api/auth/refresh was not JSON. Status: ${responseStatus}, Content-Type: ${contentType}`);
                console.warn("Refresh: Non-JSON response body:", textResponse.substring(0, 500));
                responseData = { error: "unexpected_response_type", message: `Server returned non-JSON response (Status: ${responseStatus})` };
            }

            if (responseStatus === 200 && responseData && responseData.accessToken) {
                TokenMemory.accessToken = responseData.accessToken;
                if (authMode === "header" && responseData.refreshToken) {
                    TokenMemory.refreshToken = responseData.refreshToken;
                }
                console.log("Access token refreshed successfully.");
            } else if (responseStatus === 204) { // 204 No Content: 리프레시 토큰이 없거나 유효하지 않아 아무 작업 안 함
                console.log("Refresh: Received 204 No Content. Assuming no active session or refresh token. Clearing tokens.");
                TokenMemory.accessToken = null;
                TokenMemory.refreshToken = null;
            } else { // 400, 401, 403, 500 등 또는 200이지만 accessToken이 없는 경우
                const errorMessage = responseData?.message || `Token refresh failed with status ${responseStatus}`;
                console.warn(`Refresh: Failed to refresh token. Status: ${responseStatus}. Message: ${errorMessage}`, responseData);
                TokenMemory.accessToken = null;
                TokenMemory.refreshToken = null;
            }

        } catch (error) { // 네트워크 오류 등 fetch 자체의 예외
            console.error("Refresh: Network or other error during token refresh:", error);
            TokenMemory.accessToken = null;
            TokenMemory.refreshToken = null;
        }
    }
    updateLoginUi();
})();*/
