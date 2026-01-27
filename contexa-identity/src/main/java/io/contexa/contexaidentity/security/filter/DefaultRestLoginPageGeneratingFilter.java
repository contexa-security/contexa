package io.contexa.contexaidentity.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class DefaultRestLoginPageGeneratingFilter extends OncePerRequestFilter {

    private String loginPageUrl = "/login";

    public DefaultRestLoginPageGeneratingFilter() {
    }

    public DefaultRestLoginPageGeneratingFilter(String loginPageUrl) {
        this.loginPageUrl = loginPageUrl;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        boolean isLoginRequest = isLoginPageRequest(request);
        boolean isErrorRequest = isErrorRequest(request);

        if (isLoginRequest || isErrorRequest) {
            generateLoginPage(request, response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isLoginPageRequest(HttpServletRequest request) {
        return matches(request, loginPageUrl);
    }

    private boolean isErrorRequest(HttpServletRequest request) {
        return matches(request, loginPageUrl) && request.getParameter("error") != null;
    }

    private boolean matches(HttpServletRequest request, String url) {
        String uri = request.getRequestURI();
        int pathParamIndex = uri.indexOf(';');
        if (pathParamIndex > 0) {
            uri = uri.substring(0, pathParamIndex);
        }
        return uri.equals(request.getContextPath() + url);
    }

    private void generateLoginPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String errorMessage = request.getParameter("error");
        String logoutMessage = request.getParameter("logout");

        String csrfToken = getCsrfToken(request);
        String csrfHeaderName = getCsrfHeaderName(request);
        String csrfParameterName = getCsrfParameterName(request);

        String html = """
                <!DOCTYPE html>
                <html lang="ko">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta name="_csrf" content="%s">
                    <meta name="_csrf_header" content="%s">
                    <meta name="_csrf_parameter" content="%s">
                    <title>로그인</title>
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                        .container { max-width: 400px; margin: 50px auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
                        h1 { margin: 0 0 24px; font-size: 24px; color: #333; text-align: center; }
                        .message { padding: 12px; margin-bottom: 16px; border-radius: 6px; }
                        .message.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
                        .message.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
                        .message.info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
                        input { width: 100%%; padding: 12px; margin-bottom: 16px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 14px; }
                        input:focus { outline: none; border-color: #007bff; }
                        button { width: 100%%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
                        button:hover { background: #0056b3; }
                        button:disabled { background: #6c757d; cursor: not-allowed; }
                        .form-footer { margin-top: 16px; text-align: center; font-size: 14px; color: #666; }
                        .spinner { display: none; text-align: center; margin-top: 8px; }
                        .spinner.active { display: block; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>로그인</h1>
                        <div id="message-area">
                            %s
                            %s
                        </div>
                        <div id="loginContainer" class="form">
                            <input type="text" id="username" placeholder="사용자명 또는 이메일" required autofocus>
                            <input type="password" id="password" placeholder="비밀번호" required>
                            <button type="button" id="loginButton">로그인</button>
                            <div class="spinner" id="spinner">인증 중...</div>
                        </div>
                        <div class="form-footer" id="form-footer">
                            REST API 기반 인증 시스템
                        </div>
                    </div>
                
                    <script>
                        document.addEventListener('DOMContentLoaded', function() {
                            const messageArea = document.getElementById('message-area');
                            const loginButton = document.getElementById('loginButton');
                            const spinner = document.getElementById('spinner');
                            const formFooter = document.getElementById('form-footer');
                
                            // CSRF 토큰 가져오기
                            function getCsrfToken() {
                                const meta = document.querySelector('meta[name="_csrf"]');
                                return meta ? meta.getAttribute('content') : null;
                            }
                
                            function getCsrfHeader() {
                                const meta = document.querySelector('meta[name="_csrf_header"]');
                                return meta ? meta.getAttribute('content') : 'X-CSRF-TOKEN';
                            }
                
                            loginButton.addEventListener('click', async () => {
                                const username = document.getElementById('username').value;
                                const password = document.getElementById('password').value;
                
                                if (!username || !password) {
                                    messageArea.innerHTML = '<div class="message error">사용자명과 비밀번호를 입력하세요.</div>';
                                    return;
                                }
                
                                // UI 상태 변경
                                loginButton.disabled = true;
                                spinner.classList.add('active');
                                messageArea.innerHTML = '';
                
                                try {
                                    // REST 로그인 요청 (단일 인증)
                                    const csrfToken = getCsrfToken();
                                    const csrfHeaderName = getCsrfHeader();
                
                                    const headers = {
                                        'Content-Type': 'application/json'
                                    };
                
                                    if (csrfToken && csrfHeaderName) {
                                        headers[csrfHeaderName] = csrfToken;
                                    }
                
                                    const response = await fetch('/api/auth/login', {
                                        method: 'POST',
                                        headers: headers,
                                        body: JSON.stringify({
                                            username: username,
                                            password: password
                                        })
                                    });
                
                                    if (!response.ok) {
                                        const errorData = await response.json().catch(() => ({ message: '로그인 실패: 사용자명 또는 비밀번호를 확인하세요.' }));
                                        throw new Error(errorData.message || '로그인에 실패했습니다.');
                                    }
                
                                    const result = await response.json();
                
                                    console.log('[DEBUG] Login success:', result);
                
                                    // 단일 인증 성공 - 홈으로 리다이렉트
                                    messageArea.innerHTML = '<div class="message success">로그인 성공!</div>';
                                    const redirectUrl = result.redirectUrl || '/home';
                                    setTimeout(() => {
                                        window.location.href = redirectUrl;
                                    }, 500);
                
                                } catch (error) {
                                    console.error('Login error:', error);
                
                                    // 일반 로그인 실패 - 재시도 가능
                                    messageArea.innerHTML = '<div class="message error">' + error.message + '</div>';
                                    loginButton.disabled = false;
                                    spinner.classList.remove('active');
                                }
                            });
                
                            // Enter 키 처리
                            document.getElementById('password').addEventListener('keypress', (e) => {
                                if (e.key === 'Enter') {
                                    loginButton.click();
                                }
                            });
                        });
                    </script>
                </body>
                </html>
                """.formatted(
                csrfToken,
                csrfHeaderName,
                csrfParameterName,
                errorMessage != null ? "<div class=\"message error\">로그인 실패: 사용자명 또는 비밀번호를 확인하세요.</div>" : "",
                logoutMessage != null ? "<div class=\"message success\">로그아웃되었습니다.</div>" : ""
        );

        writer.write(html);
        writer.flush();

    }

    private String getCsrfToken(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token == null) {
            token = (CsrfToken) request.getAttribute("_csrf");
        }
        return (token != null) ? token.getToken() : "";
    }

    private String getCsrfHeaderName(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token == null) {
            token = (CsrfToken) request.getAttribute("_csrf");
        }
        return (token != null) ? token.getHeaderName() : "X-CSRF-TOKEN";
    }

    private String getCsrfParameterName(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token == null) {
            token = (CsrfToken) request.getAttribute("_csrf");
        }
        return (token != null) ? token.getParameterName() : "_csrf";
    }

    public void setLoginPageUrl(String loginPageUrl) {
        this.loginPageUrl = loginPageUrl;
    }
}
