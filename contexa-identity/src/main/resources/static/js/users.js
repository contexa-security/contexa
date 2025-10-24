document.addEventListener("DOMContentLoaded", async () => {
    const usersTableBody = document.querySelector("#usersTable tbody");
    if (!usersTableBody) return;

    const authMode = localStorage.getItem("authMode") || "header";
    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');

    async function fetchWithAuth(url, options = {}) {
        const headers = { ...options.headers, "Content-Type": "application/json" };

        if (authMode === "header" || authMode === "header_cookie") {
            const accessToken = TokenMemory.accessToken;
            if (accessToken) {
                headers["Authorization"] = `Bearer ${accessToken}`;
            }
        }

        // CSRF 토큰은 GET 요청에는 보통 필요 없지만, POST/PUT 등에는 필요할 수 있음
        // 여기서는 GET 요청이므로 CSRF는 생략하나, 필요시 추가

        return fetch(url, { ...options, headers, credentials: "same-origin" });
    }

    async function refreshTokensIfNeeded() {
        const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
        const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;
        const refreshHeaders = { "Content-Type": "application/json" };

        if (authMode !== "header" && csrfToken && csrfHeader) {
            refreshHeaders[csrfHeader] = csrfToken;
        }
        // 'header' 모드 시 서버에서 refreshToken을 body로 요구하면 추가

        try {
            const refreshResponse = await fetch("/api/auth/refresh", {
                method: "POST",
                credentials: "same-origin",
                headers: refreshHeaders
            });

            if (refreshResponse.ok) {
                const data = await refreshResponse.json();
                TokenMemory.accessToken = data.accessToken;
                if (authMode === "header") {
                    TokenMemory.refreshToken = data.refreshToken;
                }
                console.log("Token refreshed successfully while fetching users.");
                return true;
            } else {
                console.warn("Failed to refresh token while fetching users.");
                return false;
            }
        } catch (error) {
            console.error("Error refreshing token while fetching users:", error);
            return false;
        }
    }

    async function loadUsers() {
        try {
            let response = await fetchWithAuth("/api/users");

            if (response.status === 401) { // Access Token 만료 가능성
                console.warn("Access token might be expired. Attempting refresh...");
                const refreshed = await refreshTokensIfNeeded();
                if (refreshed) {
                    response = await fetchWithAuth("/api/users"); // 재시도
                } else {
                    if (typeof showToast === 'function') {
                        showToast("세션이 만료되었습니다. 다시 로그인해주세요.", "error");
                    } else {
                        alert("세션이 만료되었습니다. 다시 로그인해주세요.");
                    }
                    TokenMemory.accessToken = null; // 클라이언트 토큰 확실히 제거
                    TokenMemory.refreshToken = null;
                    window.location.href = "/loginForm";
                    return;
                }
            }

            if (response.ok) {
                const users = await response.json();
                renderUsers(users);
            } else {
                const errorData = await response.json().catch(() => ({ message: "사용자 목록 로드 실패" }));
                if (typeof showToast === 'function') {
                    showToast(`오류: ${errorData.message || response.statusText}`, "error");
                } else {
                    alert(`오류: ${errorData.message || response.statusText}`);
                }
            }
        } catch (error) {
            console.error("Error loading users:", error);
            if (typeof showToast === 'function') {
                showToast("사용자 목록을 불러오는 중 오류가 발생했습니다.", "error");
            } else {
                alert("사용자 목록을 불러오는 중 오류가 발생했습니다.");
            }
        }
    }

    function renderUsers(users) {
        usersTableBody.innerHTML = ""; // 기존 내용 초기화
        if (users && users.length > 0) {
            users.forEach(user => {
                const tr = usersTableBody.insertRow();
                tr.insertCell().textContent = user.username || 'N/A';
                tr.insertCell().textContent = user.email || 'N/A';
                tr.insertCell().textContent = user.roles || 'N/A';
                // TailwindCSS 클래스 적용을 위해 각 td에 클래스 추가 가능
                // 예: tr.querySelectorAll('td').forEach(td => td.className = 'py-2 px-4 border-b border-gray-200');
            });
        } else {
            const tr = usersTableBody.insertRow();
            const td = tr.insertCell();
            td.colSpan = 3;
            td.textContent = "표시할 사용자가 없습니다.";
            td.className = "py-4 px-4 text-center text-gray-500";
        }
    }

    loadUsers();
});