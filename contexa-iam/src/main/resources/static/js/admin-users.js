document.addEventListener("DOMContentLoaded", async () => {
    const usersTableBody = document.querySelector("#usersTable tbody");
    if (!usersTableBody) return;

    // fetchWithAuth 함수 (이 파일 내부에 정의)
    async function fetchWithAuth(url, options = {}) {
        const headers = { ...options.headers };
        if (options.body && !headers['Content-Type']) {
            headers['Content-Type'] = 'application/json';
        }

        const authMode = localStorage.getItem("authMode") || "header";

        if (authMode === "header" || authMode === "header_cookie") {
            const accessToken = (typeof window.TokenMemory !== 'undefined' && window.TokenMemory.accessToken) ? window.TokenMemory.accessToken : null;
            if (accessToken) {
                headers["Authorization"] = `Bearer ${accessToken}`;
            }
        }

        const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
        const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
        if (csrfTokenMeta && csrfHeaderMeta && options.method && !['GET', 'HEAD'].includes(options.method.toUpperCase())) {
            headers[csrfHeaderMeta.getAttribute("content")] = csrfTokenMeta.getAttribute("content");
        }

        return fetch(url, { ...options, headers, credentials: "same-origin" });
    }

    // refreshTokensIfNeeded 함수 (이 파일 내부에 정의)
    async function refreshTokensIfNeeded() {
        if (typeof window.TokenMemory === 'undefined' || !window.TokenMemory.refreshToken) {
            console.warn("No refresh token available or TokenMemory not initialized for refresh attempt in admin-users.js.");
            return false;
        }

        const refreshToken = window.TokenMemory.refreshToken;
        const refreshUrl = "/api/auth/refresh";
        const refreshOptions = {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ refreshToken: refreshToken })
        };

        const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
        const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
        if (csrfTokenMeta && csrfHeaderMeta) {
            refreshOptions.headers[csrfHeaderMeta.getAttribute("content")] = csrfTokenMeta.getAttribute("content");
        }

        try {
            const response = await fetch(refreshUrl, refreshOptions);
            if (response.ok) {
                const data = await response.json();
                window.TokenMemory.accessToken = data.accessToken;
                window.TokenMemory.refreshToken = data.refreshToken;
                if (typeof window.showToast === 'function') { window.showToast("토큰이 갱신되었습니다.", "info"); }
                return true;
            } else {
                const errorData = await response.json().catch(() => ({ message: "토큰 갱신 실패" }));
                console.error("Failed to refresh tokens in admin-users.js:", errorData);
                if (typeof window.showToast === 'function') { window.showToast(`토큰 갱신 실패: ${errorData.message || response.statusText}. 다시 로그인해주세요.`, "error"); }
                window.TokenMemory.accessToken = null;
                window.TokenMemory.refreshToken = null;
                window.location.href = "/loginForm";
                return false;
            }
        } catch (error) {
            console.error("Error during token refresh in admin-users.js:", error);
            if (typeof window.showToast === 'function') { window.showToast("토큰 갱신 중 네트워크 오류가 발생했습니다.", "error"); }
            window.TokenMemory.accessToken = null;
            window.TokenMemory.refreshToken = null;
            window.location.href = "/loginForm";
            return false;
        }
    }


    async function loadAdminUsers() {
        const loadingRow = document.getElementById("usersTableLoadingRow");
        const emptyRow = document.getElementById("usersTableEmptyRow");

        if (loadingRow) loadingRow.style.display = '';
        if (emptyRow) emptyRow.style.display = 'none';
        usersTableBody.innerHTML = loadingRow ? loadingRow.outerHTML : '<tr><td colspan="8" class="py-4 px-6 text-center text-slate-400 italic">사용자 정보를 불러오는 중입니다...</td></tr>';

        try {
            let response = await fetchWithAuth("/api/users");

            if (response.status === 401 || response.status === 403) {
                const refreshed = await refreshTokensIfNeeded();
                if (refreshed) {
                    response = await fetchWithAuth("/api/users");
                } else {
                    window.showToast("세션이 만료되었거나 권한이 없습니다. 다시 로그인해주세요.", "error");
                    window.TokenMemory.accessToken = null;
                    window.TokenMemory.refreshToken = null;
                    window.location.href = "/loginForm";
                    return;
                }
            }

            if (response.ok) {
                const users = await response.json();
                renderAdminUsers(users);
            } else {
                const errorData = await response.json().catch(() => ({ message: "사용자 목록 로드 실패" }));
                window.showToast(`오류: ${errorData.message || response.statusText}`, "error");
                usersTableBody.innerHTML = '<tr><td colspan="8" class="py-4 px-6 text-center text-slate-500">사용자 목록을 불러오는 데 실패했습니다.</td></tr>';
            }
        } catch (error) {
            console.error("Error loading admin users:", error);
            window.showToast("사용자 목록을 불러오는 중 오류가 발생했습니다.", "error");
            usersTableBody.innerHTML = '<tr><td colspan="8" class="py-4 px-6 text-center text-slate-500">사용자 목록을 불러오는 데 실패했습니다.</td></tr>';
        } finally {
            if (loadingRow) loadingRow.style.display = 'none';
            if (usersTableBody.rows.length === 0 || (usersTableBody.rows.length === 1 && usersTableBody.rows[0].id === 'usersTableEmptyRow')) {
                if (emptyRow) emptyRow.style.display = '';
            }
        }
    }

    function renderAdminUsers(users) {
        usersTableBody.innerHTML = "";
        if (users && users.length > 0) {
            users.forEach(user => {
                const tr = usersTableBody.insertRow();
                tr.insertCell().textContent = user.id || 'N/A';
                tr.insertCell().textContent = user.name || 'N/A';
                tr.insertCell().textContent = user.username || 'N/A';

                const groupNames = user.selectedGroupNames && user.selectedGroupNames.length > 0
                    ? user.selectedGroupNames.join(', ')
                    : 'N/A';
                tr.insertCell().textContent = groupNames;

                const roleNames = user.roles && user.roles.length > 0 ? user.roles.join(', ') : 'N/A';
                tr.insertCell().textContent = roleNames;

                const permissionNames = user.permissions && user.permissions.length > 0 ? user.permissions.join(', ') : 'N/A';
                tr.insertCell().textContent = permissionNames;

                tr.insertCell().textContent = user.mfaEnabled ? '활성화' : '비활성화';

                const actionsCell = tr.insertCell();
                actionsCell.innerHTML = `
                    <a href="/admin/users/${user.id}" class="text-app-accent hover:underline mr-3">수정</a>
                    <a href="/admin/users/delete/${user.id}" class="text-error hover:underline" onclick="return confirm('정말로 이 사용자를 삭제하시겠습니까?');">삭제</a>
                `;
            });
            const emptyRowEl = document.getElementById("usersTableEmptyRow");
            if (emptyRowEl) emptyRowEl.style.display = 'none';
        } else {
            const emptyRowEl = document.getElementById("usersTableEmptyRow");
            if (emptyRowEl) emptyRowEl.style.display = '';
            usersTableBody.innerHTML = emptyRowEl.outerHTML;
        }
    }

    // 초기 로드
    loadAdminUsers();

    // 새로고침 버튼 이벤트 리스너
    const loadUsersBtn = document.getElementById("loadUsersBtn");
    if (loadUsersBtn) {
        loadUsersBtn.addEventListener("click", loadAdminUsers);
    }
});