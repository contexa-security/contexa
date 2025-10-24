document.addEventListener("DOMContentLoaded", () => {
    const registerForm = document.getElementById("registerForm");
    if (!registerForm) return;

    const csrfTokenMeta = document.querySelector('meta[name="_csrf"]');
    const csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
    const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute("content") : null;
    const csrfHeader = csrfHeaderMeta ? csrfHeaderMeta.getAttribute("content") : null;

    registerForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        const username = registerForm.username.value;
        const name = registerForm.name.value;
        const password = registerForm.password.value;
        const roles = registerForm.roles.value; // "USER", "USER,ADMIN" 형태
        const authMode = localStorage.getItem("authMode") || "header";

        const headers = { "Content-Type": "application/json" };
        if (authMode !== "header" && csrfToken && csrfHeader) {
            headers[csrfHeader] = csrfToken;
        }

        try {
            const response = await fetch("/api/register", {
                method: "POST",
                credentials: "same-origin",
                headers: headers,
                body: JSON.stringify({ username, name, password, roles })
            });

            if (response.ok) {
                // const result = await response.json(); // 서버에서 JSON 응답 시
                if (typeof showToast === 'function') {
                    showToast("회원가입 성공! 로그인 페이지로 이동합니다.", "success");
                } else {
                    alert("회원가입 성공! 로그인 페이지로 이동합니다.");
                }
                setTimeout(() => {
                    window.location.href = "/loginForm";
                }, 1500); // 잠시 메시지 확인 후 이동
            } else {
                const errorData = await response.json().catch(() => ({ message: "알 수 없는 오류." }));
                console.error("Registration failed:", errorData);
                if (typeof showToast === 'function') {
                    showToast(`회원가입 실패: ${errorData.message || response.statusText}`, "error");
                } else {
                    alert(`회원가입 실패: ${errorData.message || response.statusText}`);
                }
            }
        } catch (error) {
            console.error("Registration request error:", error);
            if (typeof showToast === 'function') {
                showToast("회원가입 요청 중 오류가 발생했습니다.", "error");
            } else {
                alert("회원가입 요청 중 오류가 발생했습니다.");
            }
        }
    });
});