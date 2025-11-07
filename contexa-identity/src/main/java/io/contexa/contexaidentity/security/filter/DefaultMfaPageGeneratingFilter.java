package io.contexa.contexaidentity.security.filter;

import io.contexa.contexaidentity.domain.dto.UserDto;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.MfaPageConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Default MFA Page Generating Filter
 *
 * Spring Security 7.0의 DefaultLoginPageGeneratingFilter 패턴을 적용한 MFA 페이지 생성 필터.
 * DSL 설정(AuthenticationFlowConfig)을 기반으로 MFA 플로우의 모든 페이지를 생성합니다.
 *
 * 주요 기능:
 * 1. Primary Authentication (1차 인증) 페이지 생성 - Form Login 또는 REST
 * 2. MFA Select Factor (2차 인증 선택) 페이지 생성
 * 3. Factor Challenge (개별 Factor 챌린지) 페이지 생성 - OTT, Passkey 등
 * 4. 커스텀 페이지가 설정된 경우 해당 URL로 forward
 * 5. FactorContext를 request attribute로 자동 주입
 * 6. contexa-mfa-sdk.js 스크립트 자동 주입
 *
 * 페이지 표시 순서:
 * 1. Primary Auth Page (loginPage) - 사용자 ID/PW 입력
 * 2. Select Factor Page - 등록된 2차 인증 방법 선택
 * 3. Factor Challenge Page - 선택된 Factor의 챌린지 페이지
 *
 * 사용 예시:
 * <pre>
 * .mfa(mfa -> mfa
 *     .primaryAuthentication(primary -> primary
 *         .formLogin(form -> form.loginPage("/custom/login"))  // 커스텀 1차 인증 페이지
 *     )
 *     .mfaPage(page -> page
 *         .selectFactorPage("/custom/mfa/select")  // 커스텀 2차 인증 선택 페이지
 *         .ottPages("/custom/mfa/ott-request", "/custom/mfa/ott-verify")
 *     )
 * )
 * </pre>
 *
 * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
 */
@Slf4j
public class DefaultMfaPageGeneratingFilter extends OncePerRequestFilter {

    private final AuthenticationFlowConfig mfaFlowConfig;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    // ========== HTML 템플릿 상수 (Spring Security 패턴) ==========

    /**
     * Username 입력 필드 - Readonly (인증된 사용자용)
     *
     * <p>
     * 1차 인증이 완료된 사용자의 경우, username을 readonly로 표시합니다.
     * </p>
     *
     * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter#ONE_TIME_READONLY_USERNAME_INPUT
     */
    private static final String OTT_READONLY_USERNAME_INPUT = """
        <div class="form-group">
            <label for="username">사용자명</label>
            <input type="text" id="username" name="username"
                   value="{{username}}"
                   class="form-control"
                   placeholder="사용자명"
                   required
                   >
        </div>
        """;

    /**
     * Username 입력 필드 - Editable (미인증 사용자용)
     *
     * <p>
     * 1차 인증이 완료되지 않은 사용자의 경우, username을 입력받습니다.
     * </p>
     *
     * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter#ONE_TIME_USERNAME_INPUT
     */
    private static final String OTT_EDITABLE_USERNAME_INPUT = """
        <div class="form-group">
            <label for="username">사용자명</label>
            <input type="text" id="username" name="username"
                   class="form-control"
                   placeholder="사용자명을 입력하세요"
                   required
                   autofocus>
        </div>
        """;

    /**
     * OTT 요청 페이지 템플릿
     *
     * <p>
     * Spring Security의 ONE_TIME_TEMPLATE 패턴을 따릅니다.
     * HTML Form 제출 방식으로 JavaScript 비활성화 환경에서도 작동합니다.
     * </p>
     *
     * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter#ONE_TIME_TEMPLATE
     */
    private static final String OTT_REQUEST_TEMPLATE = """
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="_csrf" content="{{csrfToken}}">
            <meta name="_csrf_header" content="{{csrfHeaderName}}">
            <meta name="_csrf_parameter" content="{{csrfParameterName}}">
            <title>인증 코드 요청</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
                    padding: 40px;
                    max-width: 480px;
                    width: 100%;
                }
                h1 {
                    color: #333;
                    font-size: 24px;
                    margin-bottom: 8px;
                    text-align: center;
                }
                .description {
                    color: #666;
                    font-size: 14px;
                    text-align: center;
                    margin-bottom: 30px;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                label {
                    display: block;
                    color: #555;
                    font-size: 14px;
                    font-weight: 500;
                    margin-bottom: 8px;
                }
                .form-control {
                    width: 100%;
                    padding: 12px 16px;
                    font-size: 15px;
                    border: 1.5px solid #e0e0e0;
                    border-radius: 8px;
                    transition: all 0.2s;
                }
                .form-control:focus {
                    outline: none;
                    border-color: #667eea;
                    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
                }
                .form-control:read-only {
                    background-color: #f5f5f5;
                    color: #666;
                    cursor: not-allowed;
                }
                .primary-button {
                    width: 100%;
                    padding: 14px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.2s, box-shadow 0.2s;
                }
                .primary-button:hover:not(:disabled) {
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
                }
                .primary-button:active:not(:disabled) {
                    transform: translateY(0);
                }
                .primary-button:disabled {
                    opacity: 0.6;
                    cursor: not-allowed;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>인증 코드 요청</h1>
                <p class="description">등록된 이메일 주소로 인증 코드를 전송합니다.</p>

                <form id="ott-request-form" method="post" action="{{ottRequestUrl}}">
                    {{usernameInput}}
                    {{hiddenInputs}}

                    <button type="submit" class="primary-button">
                        인증 코드 전송
                    </button>
                </form>

                <!-- Form submit만 사용 (SDK Progressive Enhancement 불필요) -->
            </div>
        </body>
        </html>
        """;

    /**
     * OTT Verify Page 전체 템플릿 (HTML Form 기반 + JavaScript SDK Progressive Enhancement)
     */
    private static final String OTT_VERIFY_TEMPLATE = """
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="_csrf" content="{{csrfToken}}">
            <meta name="_csrf_header" content="{{csrfHeaderName}}">
            <meta name="_csrf_parameter" content="{{csrfParameterName}}">
            <title>MFA - 인증 코드 입력</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
                    padding: 40px;
                    max-width: 480px;
                    width: 100%;
                }
                h1 {
                    color: #333;
                    font-size: 24px;
                    margin-bottom: 8px;
                    text-align: center;
                }
                .description {
                    color: #666;
                    font-size: 14px;
                    text-align: center;
                    margin-bottom: 24px;
                }
                .user-info {
                    background: #f6f8fa;
                    padding: 12px 16px;
                    border-radius: 8px;
                    margin-bottom: 24px;
                    text-align: center;
                }
                .user-info .label {
                    font-size: 12px;
                    color: #666;
                    margin-bottom: 4px;
                }
                .user-info .username {
                    font-size: 16px;
                    font-weight: 600;
                    color: #333;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                label {
                    display: block;
                    color: #555;
                    font-size: 14px;
                    font-weight: 500;
                    margin-bottom: 8px;
                }
                .form-control {
                    width: 100%;
                    padding: 16px;
                    font-size: 24px;
                    text-align: center;
                    letter-spacing: 0.5em;
                    border: 1.5px solid #e0e0e0;
                    border-radius: 8px;
                    transition: all 0.2s;
                }
                .form-control:focus {
                    outline: none;
                    border-color: #667eea;
                    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
                }
                .primary-button {
                    width: 100%;
                    padding: 14px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.2s, box-shadow 0.2s;
                    margin-bottom: 12px;
                }
                .primary-button:hover:not(:disabled) {
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
                }
                .primary-button:active:not(:disabled) {
                    transform: translateY(0);
                }
                .primary-button:disabled {
                    opacity: 0.6;
                    cursor: not-allowed;
                }
                .secondary-button {
                    width: 100%;
                    padding: 14px;
                    background: #6c757d;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: background 0.2s;
                }
                .secondary-button:hover:not(:disabled) {
                    background: #5a6268;
                }
                .secondary-button:disabled {
                    opacity: 0.6;
                    cursor: not-allowed;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>인증 코드 입력</h1>
                <p class="description">이메일로 전송된 6자리 코드를 입력하세요.</p>

                <div class="user-info">
                    <div class="label">인증 중인 계정</div>
                    <div class="username">{{username}}</div>
                </div>

                <form id="ott-verify-form" method="post" action="{{ottVerifyUrl}}">
                    <div class="form-group">
                        <label for="token">인증 코드</label>
                        <input type="text" id="token" name="token"
                               class="form-control"
                               required
                               autofocus>
                    </div>

                    {{hiddenInputs}}

                    <button type="submit" class="primary-button">
                        확인
                    </button>
                </form>

                <form id="resend-form" method="post" action="{{ottResendUrl}}">
                    {{resendHiddenInputs}}
                    <button type="submit" class="secondary-button">
                        코드 재전송
                    </button>
                </form>

                <!-- Progressive Enhancement: JavaScript SDK 지원 -->
                <script src="{{contextPath}}/js/contexa-mfa-sdk.js"></script>
                <script>
                    // JavaScript 활성화 시 SDK를 통한 향상된 UX 제공
                    if (typeof ContexaMFA !== 'undefined') {
                        const verifyForm = document.getElementById('ott-verify-form');
                        const resendForm = document.getElementById('resend-form');
                        const verifyButton = verifyForm.querySelector('button[type="submit"]');
                        const resendButton = resendForm.querySelector('button[type="submit"]');
                        const codeInput = document.getElementById('token');

                        // SDK 초기화
                        const mfa = new ContexaMFA.Client({ autoRedirect: false });
                        mfa.init().catch(console.error);

                        // 검증 Form Progressive Enhancement
                        verifyForm.addEventListener('submit', async (e) => {
                            e.preventDefault();

                            const code = codeInput.value;
                            verifyButton.disabled = true;
                            verifyButton.textContent = '확인 중...';

                            try {
                                const result = await mfa.verifyOtt(code);

                                // 명시적 리다이렉트 처리
                                if (result.status === 'MFA_COMPLETED' && result.redirectUrl) {
                                    window.location.href = result.redirectUrl;
                                } else if (result.status === 'MFA_CONTINUE' && result.nextStepUrl) {
                                    window.location.href = result.nextStepUrl;
                                } else if (result.nextStepUrl) {
                                    window.location.href = result.nextStepUrl;
                                } else if (result.redirectUrl) {
                                    window.location.href = result.redirectUrl;
                                }
                            } catch (error) {
                                console.error('OTT 검증 실패:', error);
                                alert('인증 코드 확인 실패: ' + (error.message || '알 수 없는 오류'));
                                verifyButton.disabled = false;
                                verifyButton.textContent = '확인';
                            }
                        });

                        // 재전송 버튼은 form submit 그대로 사용 (SDK 불필요)
                    }
                </script>
            </div>
        </body>
        </html>
        """;

    /**
     * Passkey Challenge Page 전체 템플릿 (JavaScript WebAuthn API 사용)
     *
     * <p>
     * 참고: Passkey는 WebAuthn API를 사용하므로 JavaScript가 필수입니다.
     * Progressive Enhancement를 적용할 수 없지만, Spring Security 패턴을 최대한 준수합니다.
     * </p>
     */
    private static final String PASSKEY_CHALLENGE_TEMPLATE = """
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="_csrf" content="{{csrfToken}}">
            <meta name="_csrf_header" content="{{csrfHeaderName}}">
            <meta name="_csrf_parameter" content="{{csrfParameterName}}">
            <title>MFA - Passkey 인증</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
                    padding: 40px;
                    max-width: 480px;
                    width: 100%;
                    text-align: center;
                }
                h1 {
                    color: #333;
                    font-size: 24px;
                    margin-bottom: 8px;
                }
                .description {
                    color: #666;
                    font-size: 14px;
                    margin-bottom: 24px;
                }
                .user-info {
                    background: #f6f8fa;
                    padding: 12px 16px;
                    border-radius: 8px;
                    margin-bottom: 24px;
                }
                .user-info .label {
                    font-size: 12px;
                    color: #666;
                    margin-bottom: 4px;
                }
                .user-info .username {
                    font-size: 16px;
                    font-weight: 600;
                    color: #333;
                }
                .icon {
                    font-size: 64px;
                    margin-bottom: 24px;
                }
                .primary-button {
                    width: 100%;
                    padding: 14px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.2s, box-shadow 0.2s;
                }
                .primary-button:hover:not(:disabled) {
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
                }
                .primary-button:active:not(:disabled) {
                    transform: translateY(0);
                }
                .primary-button:disabled {
                    opacity: 0.6;
                    cursor: not-allowed;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">🔐</div>
                <h1>Passkey 인증</h1>
                <p class="description">생체 인증 또는 보안 키를 사용하여 인증하세요.</p>

                <div class="user-info">
                    <div class="label">인증 중인 계정</div>
                    <div class="username">{{username}}</div>
                </div>

                <button id="auth-button" class="primary-button">
                    Passkey 인증 시작
                </button>

                <!-- JavaScript SDK (WebAuthn API 사용) -->
                <script src="{{contextPath}}/js/contexa-mfa-sdk.js"></script>
                <script>
                    const authButton = document.getElementById('auth-button');
                    const mfa = new ContexaMFA.Client({ autoRedirect: false });

                    // SDK 초기화
                    mfa.init().catch(console.error);

                    // 사용자 명시적 클릭으로만 시작
                    authButton.addEventListener('click', async () => {
                        authButton.disabled = true;
                        authButton.textContent = '인증 진행 중...';

                        try {
                            const result = await mfa.verifyPasskey();

                            // 명시적 리다이렉트 처리
                            if (result.status === 'MFA_COMPLETED' && result.redirectUrl) {
                                window.location.href = result.redirectUrl;
                            } else if (result.status === 'MFA_CONTINUE' && result.nextStepUrl) {
                                window.location.href = result.nextStepUrl;
                            } else if (result.redirectUrl) {
                                window.location.href = result.redirectUrl;
                            } else if (result.nextStepUrl) {
                                window.location.href = result.nextStepUrl;
                            }
                        } catch (error) {
                            console.error('Passkey 인증 실패:', error);
                            alert('인증 실패: ' + (error.message || '알 수 없는 오류'));
                            authButton.disabled = false;
                            authButton.textContent = 'Passkey 인증 시작';
                        }
                    });
                </script>
            </div>
        </body>
        </html>
        """;

    /**
     * Select Factor Page 전체 템플릿 (HTML Form 기반 + JavaScript SDK Progressive Enhancement)
     */
    private static final String SELECT_FACTOR_TEMPLATE = """
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="_csrf" content="{{csrfToken}}">
            <meta name="_csrf_header" content="{{csrfHeaderName}}">
            <meta name="_csrf_parameter" content="{{csrfParameterName}}">
            <title>MFA - 인증 방법 선택</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
                    padding: 40px;
                    max-width: 480px;
                    width: 100%;
                }
                h1 {
                    color: #333;
                    font-size: 24px;
                    margin-bottom: 8px;
                    text-align: center;
                }
                .description {
                    color: #666;
                    font-size: 14px;
                    text-align: center;
                    margin-bottom: 24px;
                }
                .user-info {
                    background: #f6f8fa;
                    padding: 12px 16px;
                    border-radius: 8px;
                    margin-bottom: 24px;
                    text-align: center;
                }
                .user-info .label {
                    font-size: 12px;
                    color: #666;
                    margin-bottom: 4px;
                }
                .user-info .username {
                    font-size: 16px;
                    font-weight: 600;
                    color: #333;
                }
                .factor-list {
                    list-style: none;
                }
                .factor-item {
                    margin-bottom: 12px;
                }
                .factor-form button {
                    width: 100%;
                    padding: 16px;
                    background: white;
                    border: 1.5px solid #e0e0e0;
                    border-radius: 8px;
                    font-size: 16px;
                    cursor: pointer;
                    transition: all 0.2s;
                    text-align: left;
                }
                .factor-form button:hover:not(:disabled) {
                    border-color: #667eea;
                    background: #f8f9fa;
                }
                .factor-form button:disabled {
                    opacity: 0.6;
                    cursor: not-allowed;
                }
                .message {
                    padding: 12px;
                    margin-bottom: 16px;
                    border-radius: 8px;
                }
                .message.error {
                    background: #f8d7da;
                    color: #721c24;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>인증 방법 선택</h1>
                <p class="description">2단계 인증 방법을 선택하세요.</p>

                <div class="user-info">
                    <div class="label">인증 중인 계정</div>
                    <div class="username">{{username}}</div>
                </div>

                {{factorButtons}}

                <!-- Progressive Enhancement: JavaScript SDK 지원 -->
                <script src="{{contextPath}}/js/contexa-mfa-sdk.js"></script>
                <script>
                    // JavaScript 활성화 시 SDK를 통한 향상된 UX 제공
                    if (typeof ContexaMFA !== 'undefined') {
                        const forms = document.querySelectorAll('.factor-form');
                        const mfa = new ContexaMFA.Client({ autoRedirect: false });

                        // SDK 초기화
                        mfa.init().catch(console.error);

                        forms.forEach(form => {
                            form.addEventListener('submit', async (e) => {
                                e.preventDefault();

                                const factorType = form.dataset.factorType;
                                const button = form.querySelector('button[type="submit"]');
                                const originalText = button.textContent;

                                button.disabled = true;
                                button.textContent = '처리 중...';

                                try {
                                    const result = await mfa.selectFactor(factorType);

                                    // 명시적 리다이렉트 처리
                                    if (result.nextStepUrl) {
                                        window.location.href = result.nextStepUrl;
                                    } else if (result.redirectUrl) {
                                        window.location.href = result.redirectUrl;
                                    }
                                } catch (error) {
                                    console.error('Factor 선택 실패:', error);
                                    alert('인증 방법 선택 실패: ' + (error.message || '알 수 없는 오류'));
                                    button.disabled = false;
                                    button.textContent = originalText;
                                }
                            });
                        });
                    }
                </script>
            </div>
        </body>
        </html>
        """;

    /**
     * Select Factor Page - Factor 버튼 템플릿 (개별 Form)
     */
    private static final String FACTOR_BUTTON_TEMPLATE = """
        <li class="factor-item">
            <form class="factor-form" method="post" action="{{selectFactorUrl}}" data-factor-type="{{factorType}}">
                {{hiddenInputs}}
                <input type="hidden" name="factorType" value="{{factorType}}">
                <button type="submit">{{factorDisplayName}}</button>
            </form>
        </li>
        """;

    /**
     * Failure Page 전체 템플릿 (HTML Form 기반)
     */
    private static final String FAILURE_PAGE_TEMPLATE = """
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MFA - 인증 실패</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
                    padding: 40px;
                    max-width: 480px;
                    width: 100%;
                    text-align: center;
                }
                .icon {
                    font-size: 64px;
                    margin-bottom: 16px;
                }
                h1 {
                    color: #dc3545;
                    font-size: 24px;
                    margin-bottom: 16px;
                }
                .error-message {
                    color: #666;
                    font-size: 16px;
                    margin-bottom: 32px;
                    line-height: 1.5;
                }
                .primary-button {
                    width: 100%;
                    padding: 14px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.2s, box-shadow 0.2s;
                }
                .primary-button:hover:not(:disabled) {
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
                }
                .primary-button:active:not(:disabled) {
                    transform: translateY(0);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">❌</div>
                <h1>인증 실패</h1>
                <p class="error-message">{{errorMessage}}</p>

                <form method="get" action="{{retryUrl}}">
                    <button type="submit" class="primary-button">
                        다시 시도
                    </button>
                </form>
            </div>
        </body>
        </html>
        """;

    /**
     * Constructor
     *
     * @param mfaFlowConfig DSL로 구성된 MFA 플로우 설정 (AuthenticationFlowConfig)
     * @param stateMachineIntegrator MFA State Machine 통합 객체
     * @throws IllegalArgumentException MFA 플로우가 아닌 경우
     */
    public DefaultMfaPageGeneratingFilter(
            AuthenticationFlowConfig mfaFlowConfig,
            MfaStateMachineIntegrator stateMachineIntegrator) {
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null");
        Assert.isTrue(AuthType.MFA.name().equalsIgnoreCase(mfaFlowConfig.getTypeName()),
                "This filter only works with MFA flow config. Provided flow type: " + mfaFlowConfig.getTypeName());
        Assert.notNull(stateMachineIntegrator, "MfaStateMachineIntegrator cannot be null");

        this.mfaFlowConfig = mfaFlowConfig;
        this.stateMachineIntegrator = stateMachineIntegrator;

        log.info("DefaultMfaPageGeneratingFilter initialized for MFA flow. Primary auth page: {}, Select factor page: {}",
                extractPrimaryLoginPage(),
                extractSelectFactorUrl());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain chain) throws ServletException, IOException {

        String requestUri = normalizeUri(request);

        // Step 1: Primary Authentication Page (1차 인증) - 최우선 처리
        if (isPrimaryAuthPage(requestUri)) {
            handlePrimaryAuthPage(request, response);
            return;
        }

        // Step 2: MFA Select Factor Page (2차 인증 선택)
        if (isSelectFactorPage(requestUri)) {
            handleSelectFactorPage(request, response);
            return;
        }

        // Step 3: Factor Challenge Pages (개별 Factor 챌린지)

        // OTT Request Code Page
        if (isOttRequestPage(requestUri)) {
            handleOttRequestPage(request, response);
            return;
        }

        // OTT Verify Page
        if (isOttChallengePage(requestUri)) {
            handleOttChallengePage(request, response);
            return;
        }

        // Passkey Challenge Page
        if (isPasskeyChallengePage(requestUri)) {
            handlePasskeyChallengePage(request, response);
            return;
        }

        // Step 4: MFA Utility Pages

        // MFA Configure Page
        if (isConfigurePage(requestUri)) {
            handleConfigurePage(request, response);
            return;
        }

        // MFA Failure Page
        if (isFailurePage(requestUri)) {
            handleFailurePage(request, response);
            return;
        }

        chain.doFilter(request, response);
    }

    // ===== Primary Authentication (1차 인증) =====

    /**
     * Primary Authentication 페이지 요청 여부 확인
     */
    private boolean isPrimaryAuthPage(String requestUri) {
        String primaryLoginPage = extractPrimaryLoginPage();
        return requestUri.equals(primaryLoginPage);
    }

    /**
     * Primary Authentication 페이지 처리
     */
    private void handlePrimaryAuthPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        PrimaryAuthenticationOptions primaryOpts = mfaFlowConfig.getPrimaryAuthenticationOptions();
        if (primaryOpts == null) {
            log.warn("Primary authentication options not configured for MFA flow. Skipping primary auth page generation.");
            return;
        }

        if (primaryOpts.isFormLogin()) {
            FormOptions formOpts = primaryOpts.getFormOptions();

            // ⭐ Spring Security 패턴: 커스텀 페이지는 필터가 처리하지 않음 (EntryPoint가 redirect로 처리)
            if (isCustomLoginPage(formOpts.getLoginPage())) {
                log.debug("Custom primary login page configured: {}. Skipping default page generation.",
                         formOpts.getLoginPage());
                return; // 커스텀 페이지는 EntryPoint가 처리
            }

            // 기본 로그인 페이지 생성
            log.debug("Generating default primary form login page");
            generatePrimaryFormLoginPage(request, response, formOpts);

        } else if (primaryOpts.isRestLogin()) {
            // ⭐ REST 인증도 HTML 페이지 필요 (JavaScript가 비동기 인증 처리)
            RestOptions restOpts = primaryOpts.getRestOptions();
            String loginPage = primaryOpts.getLoginPage(); // PrimaryAuthenticationOptions에서 가져옴

            // ⭐ Spring Security 패턴: 커스텀 페이지는 필터가 처리하지 않음
            if (isCustomLoginPage(loginPage)) {
                log.debug("Custom REST login page configured: {}. Skipping default page generation.", loginPage);
                return; // 커스텀 페이지는 EntryPoint가 처리
            }

            // 기본 REST 로그인 페이지 생성 (JavaScript 기반)
            log.debug("Generating default primary REST login page");
            generatePrimaryRestLoginPage(request, response, restOpts);
        }
    }

    /**
     * Primary Login Page URL 추출 (DSL 설정 기반)
     */
    private String extractPrimaryLoginPage() {
        PrimaryAuthenticationOptions primaryOpts = mfaFlowConfig.getPrimaryAuthenticationOptions();
        if (primaryOpts != null) {
            // ⭐ Form 인증인 경우
            if (primaryOpts.isFormLogin()) {
                FormOptions formOpts = primaryOpts.getFormOptions();
                return StringUtils.hasText(formOpts.getLoginPage()) ?
                        formOpts.getLoginPage() : "/loginForm"; // 기본값
            }

            // ⭐ REST 인증인 경우 - PrimaryAuthenticationOptions의 loginPage 사용
            if (primaryOpts.isRestLogin()) {
                String loginPage = primaryOpts.getLoginPage();
                return StringUtils.hasText(loginPage) ? loginPage : "/loginForm"; // 기본값
            }
        }
        return "/loginForm"; // 폴백 기본값
    }

    /**
     * 커스텀 로그인 페이지 여부 확인
     *
     * Spring Security 패턴: 기본값과 다른 값이 설정되었는지 확인
     *
     * @param loginPage 검증할 로그인 페이지 URL
     * @return 커스텀 페이지인 경우 true, 기본 페이지인 경우 false
     */
    private boolean isCustomLoginPage(String loginPage) {
        // loginPage가 명시적으로 설정되고 기본값("/loginForm")과 다른 경우 커스텀으로 판단
        return StringUtils.hasText(loginPage) && !"/loginForm".equals(loginPage);
    }

    // ===== MFA Select Factor Page (2차 인증 선택) =====

    /**
     * Select Factor 페이지 요청 여부 확인
     */
    private boolean isSelectFactorPage(String requestUri) {
        String selectFactorUrl = extractSelectFactorUrl();
        return requestUri.equals(selectFactorUrl);
    }

    /**
     * Select Factor 페이지 처리
     */
    private void handleSelectFactorPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        // ⭐ Spring Security 패턴: 커스텀 페이지는 필터가 처리하지 않음
        if (pageConfig != null && pageConfig.hasCustomSelectFactorPage()) {
            log.debug("Custom select factor page configured: {}. Skipping default page generation.",
                     pageConfig.getSelectFactorPageUrl());
            return; // 커스텀 페이지는 사용자가 직접 제공
        }

        log.debug("Generating default select factor page");
        generateSelectFactorPage(request, response);
    }

    /**
     * Select Factor URL 추출 (DSL 설정 + 기본값 폴백)
     */
    private String extractSelectFactorUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getSelectFactorPageUrl())) {
            return pageConfig.getSelectFactorPageUrl();
        }
        return "/mfa/select-factor"; // 기본값
    }

    // ===== OTT Challenge Pages =====

    /**
     * OTT Request 페이지 요청 여부 확인
     */
    private boolean isOttRequestPage(String requestUri) {
        String ottRequestUrl = extractOttRequestUrl();
        return requestUri.equals(ottRequestUrl);
    }

    /**
     * OTT Request 페이지 처리
     */
    private void handleOttRequestPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        // ⭐ Spring Security 패턴: 커스텀 페이지는 필터가 처리하지 않음
        if (pageConfig != null && pageConfig.hasCustomOttRequestPage()) {
            log.debug("Custom OTT request page configured: {}. Skipping default page generation.",
                     pageConfig.getOttRequestPageUrl());
            return; // 커스텀 페이지는 사용자가 직접 제공
        }

        log.debug("Generating default OTT request page");
        generateOttRequestCodePage(request, response);
    }

    /**
     * OTT Challenge 페이지 요청 여부 확인
     */
    private boolean isOttChallengePage(String requestUri) {
        String ottChallengeUrl = extractOttChallengeUrl();
        return requestUri.equals(ottChallengeUrl);
    }

    /**
     * OTT Challenge 페이지 처리
     */
    private void handleOttChallengePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        // ⭐ Spring Security 패턴: 커스텀 페이지는 필터가 처리하지 않음
        if (pageConfig != null && pageConfig.hasCustomOttVerifyPage()) {
            log.debug("Custom OTT verify page configured: {}. Skipping default page generation.",
                     pageConfig.getOttVerifyPageUrl());
            return; // 커스텀 페이지는 사용자가 직접 제공
        }

        log.debug("Generating default OTT verify page");
        generateOttVerifyPage(request, response);
    }

    /**
     * OTT Request URL 추출 (DSL 설정 + 기본값 폴백)
     */
    private String extractOttRequestUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getOttRequestPageUrl())) {
            return pageConfig.getOttRequestPageUrl();
        }
        return "/mfa/ott/request-code-ui"; // 기본값
    }

    /**
     * OTT Challenge URL 추출 (DSL 설정 + 기본값 폴백)
     */
    private String extractOttChallengeUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getOttVerifyPageUrl())) {
            return pageConfig.getOttVerifyPageUrl();
        }
        return "/mfa/challenge/ott"; // 기본값
    }

    /**
     * OTT 코드 생성 API URL 추출
     *
     * <p>
     * OTT 요청 페이지의 Form action URL로 사용됩니다.
     * JavaScript 비활성화 시 이 URL로 POST 요청이 전송됩니다.
     * </p>
     *
     * @return OTT 코드 생성 API URL (기본: /mfa/ott/generate-code)
     */
    private String extractOttCodeGenerationUrl() {
        // TODO: AuthUrlConfig에서 가져오도록 개선 필요
        return "/mfa/ott/generate-code"; // OttUrls.codeGeneration
    }

    /**
     * OTT 검증 처리 Filter URL 추출
     *
     * <p>
     * OTT 검증 페이지의 Form action URL로 사용됩니다.
     * Spring Security OTT Filter가 이 경로에서 POST 요청을 처리합니다.
     * </p>
     *
     * @return OTT 검증 처리 URL (기본: /login/mfa-ott)
     */
    private String extractOttLoginProcessingUrl() {
        // TODO: AuthUrlConfig에서 가져오도록 개선 필요
        return "/login/mfa-ott"; // OttUrls.loginProcessing
    }

    // ===== Passkey Challenge Page =====

    /**
     * Passkey Challenge 페이지 요청 여부 확인
     */
    private boolean isPasskeyChallengePage(String requestUri) {
        String passkeyUrl = extractPasskeyChallengeUrl();
        return requestUri.equals(passkeyUrl);
    }

    /**
     * Passkey Challenge 페이지 처리
     */
    private void handlePasskeyChallengePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        // ⭐ Spring Security 패턴: 커스텀 페이지는 필터가 처리하지 않음
        if (pageConfig != null && pageConfig.hasCustomPasskeyPage()) {
            log.debug("Custom Passkey challenge page configured: {}. Skipping default page generation.",
                     pageConfig.getPasskeyChallengePageUrl());
            return; // 커스텀 페이지는 사용자가 직접 제공
        }

        log.debug("Generating default Passkey challenge page");
        generatePasskeyChallengePage(request, response);
    }

    /**
     * Passkey Challenge URL 추출 (DSL 설정 + 기본값 폴백)
     */
    private String extractPasskeyChallengeUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getPasskeyChallengePageUrl())) {
            return pageConfig.getPasskeyChallengePageUrl();
        }
        return "/mfa/challenge/passkey"; // 기본값
    }

    // ===== Utility Pages =====

    /**
     * Configure 페이지 요청 여부 확인
     */
    private boolean isConfigurePage(String requestUri) {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getConfigurePageUrl())) {
            return requestUri.equals(pageConfig.getConfigurePageUrl());
        }
        return requestUri.equals("/mfa/configure"); // 기본값
    }

    /**
     * Configure 페이지 처리
     * 사용자 팩터 등록 기능 제거로 인해 Configure 페이지는 더 이상 지원하지 않음
     */
    private void handleConfigurePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        log.warn("MFA Configure page is no longer supported. User factor registration has been removed.");
        response.sendError(HttpServletResponse.SC_NOT_FOUND, "MFA Configure page is not available");
    }

    /**
     * Failure 페이지 요청 여부 확인
     */
    private boolean isFailurePage(String requestUri) {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getFailurePageUrl())) {
            return requestUri.equals(pageConfig.getFailurePageUrl());
        }
        return requestUri.equals("/mfa/failure"); // 기본값
    }

    /**
     * Failure 페이지 처리
     */
    private void handleFailurePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        // ⭐ Spring Security 패턴: 커스텀 페이지는 필터가 처리하지 않음
        if (pageConfig != null && pageConfig.hasCustomFailurePage()) {
            log.debug("Custom failure page configured: {}. Skipping default page generation.",
                     pageConfig.getFailurePageUrl());
            return; // 커스텀 페이지는 사용자가 직접 제공
        }

        log.debug("Generating default failure page");
        generateFailurePage(request, response);
    }

    // ===== Utility Methods =====

    /**
     * Request URI 정규화 (Context Path 제거)
     */
    private String normalizeUri(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();

        if (StringUtils.hasText(contextPath)) {
            requestUri = requestUri.substring(contextPath.length());
        }

        return requestUri;
    }


    /**
     * Select Factor Page 생성
     */
    private void generateSelectFactorPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        // Step 1: FactorContext 조회
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        // Step 2: Context Path 추출
        String contextPath = request.getContextPath();

        // Step 3: Username 조회
        String username = getUsername();
        if (username == null) {
            log.warn("Select Factor Page: 인증되지 않은 사용자 접근 시도");
            username = "(알 수 없음)";
        }

        // Step 4: Available Factors 추출
        List<AuthType> availableFactors = ctx != null && ctx.getAvailableFactors() != null ?
                new java.util.ArrayList<>(ctx.getAvailableFactors()) : List.of();

        if (availableFactors.isEmpty()) {
            log.warn("Select Factor Page: 사용 가능한 Factor가 없음. Session: {}",
                    ctx != null ? ctx.getMfaSessionId() : "unknown");
        }

        // Step 5: Select Factor URL 추출 (mfaFlowConfig 기반)
        String selectFactorUrl = extractSelectFactorUrl();
        String fullSelectFactorUrl = contextPath + selectFactorUrl;

        // Step 6: Factor 버튼 HTML 생성
        StringBuilder factorButtonsHtml = new StringBuilder("<ul class=\"factor-list\">\n");

        for (AuthType factorType : availableFactors) {
            String hiddenInputs = resolveHiddenInputs(request);
            String factorDisplayName = getFactorDisplayName(factorType);

            String buttonHtml = MfaHtmlTemplates.fromTemplate(FACTOR_BUTTON_TEMPLATE)
                .withValue("selectFactorUrl", fullSelectFactorUrl)
                .withValue("factorType", factorType.name())
                .withValue("factorDisplayName", factorDisplayName)
                .withRawHtml("hiddenInputs", hiddenInputs)
                .render();

            factorButtonsHtml.append(buttonHtml);
        }

        factorButtonsHtml.append("</ul>");

        // Step 7: 전체 페이지 렌더링
        String html = MfaHtmlTemplates.fromTemplate(SELECT_FACTOR_TEMPLATE)
            .withValue("contextPath", contextPath)
            .withValue("username", username)
            .withValue("csrfToken", getCsrfToken(request))
            .withValue("csrfHeaderName", getCsrfHeaderName(request))
            .withValue("csrfParameterName", getCsrfParameterName(request))
            .withRawHtml("factorButtons", factorButtonsHtml.toString())
            .render();

        // Step 8: 응답 전송
        PrintWriter writer = response.getWriter();
        writer.write(html);
        writer.flush();

        log.debug("Select Factor Page 생성 완료. Username: {}, Available Factors: {}, Session: {}",
                username, availableFactors.stream().map(AuthType::name).collect(Collectors.joining(", ")),
                ctx != null ? ctx.getMfaSessionId() : "unknown");
    }

    /**
     * Primary Form Login Page 생성 (기본 1차 인증 페이지)
     */
    private void generatePrimaryFormLoginPage(HttpServletRequest request, HttpServletResponse response, FormOptions formOpts)
            throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String loginProcessingUrl = formOpts.getLoginProcessingUrl();
        String usernameParam = formOpts.getUsernameParameter();
        String passwordParam = formOpts.getPasswordParameter();

        String errorMessage = request.getParameter("error");
        String logoutMessage = request.getParameter("logout");

        // CSRF 토큰 추출
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
    <title>로그인 - MFA 인증</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { margin: 0 0 24px; font-size: 24px; color: #333; text-align: center; }
        .message { padding: 12px; margin-bottom: 16px; border-radius: 6px; }
        .message.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .message.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        input { width: 100%%; padding: 12px; margin-bottom: 16px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 14px; }
        input:focus { outline: none; border-color: #007bff; }
        button { width: 100%%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        button:hover { background: #0056b3; }
        button:disabled { background: #6c757d; cursor: not-allowed; }
        .form-footer { margin-top: 16px; text-align: center; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>로그인</h1>
        %s
        %s
        <form method="post" action="%s">
            <input type="hidden" name="%s" value="%s">
            <input type="text" name="%s" placeholder="사용자명 또는 이메일" required autofocus>
            <input type="password" name="%s" placeholder="비밀번호" required>
            <button type="submit">로그인</button>
        </form>
        <div class="form-footer">
            로그인 후 다단계 인증(MFA)이 진행됩니다.
        </div>
    </div>
</body>
</html>
                """.formatted(
                csrfToken,
                csrfHeaderName,
                csrfParameterName,
                errorMessage != null ? "<div class=\"message error\">로그인 실패: 사용자명 또는 비밀번호를 확인하세요.</div>" : "",
                logoutMessage != null ? "<div class=\"message success\">로그아웃되었습니다.</div>" : "",
                loginProcessingUrl,
                csrfParameterName,
                csrfToken,
                usernameParam,
                passwordParam
        );

        writer.write(html);
        writer.flush();

        log.debug("Generated default primary form login page for MFA flow. Processing URL: {}", loginProcessingUrl);
    }

    /**
     * Primary REST Login Page 생성
     *
     * REST 인증용 HTML 페이지를 생성합니다.
     * JavaScript를 사용하여 비동기로 인증 요청을 처리합니다.
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param restOpts REST 인증 옵션
     * @throws IOException 페이지 생성 실패 시
     */
    private void generatePrimaryRestLoginPage(HttpServletRequest request, HttpServletResponse response, RestOptions restOpts)
            throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String loginProcessingUrl = restOpts.getLoginProcessingUrl();

        String errorMessage = request.getParameter("error");
        String logoutMessage = request.getParameter("logout");

        // CSRF 토큰 추출
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
    <title>로그인 - MFA 인증 (REST)</title>
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
        <h1>로그인 (REST API)</h1>
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
            로그인 후 다단계 인증(MFA)이 진행됩니다.
        </div>
    </div>

    <script src="/js/contexa-mfa-sdk.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const messageArea = document.getElementById('message-area');
            const loginButton = document.getElementById('loginButton');
            const spinner = document.getElementById('spinner');
            const formFooter = document.getElementById('form-footer');

            // SDK 초기화 (autoRedirect: true - 자동 리다이렉트)
            const mfa = new ContexaMFA.Client({ autoRedirect: true });

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
                    // SDK의 login 메서드 호출
                    const result = await mfa.apiClient.login(username, password);

                    // 디버그: 서버 응답 확인
                    console.log('[DEBUG] Server response:', JSON.stringify(result, null, 2));
                    console.log('[DEBUG] result.status:', result.status);
                    console.log('[DEBUG] result.redirectUrl:', result.redirectUrl);

                    // MFA 필요 여부에 따른 분기 처리
                    if (result.status === 'MFA_COMPLETED') {
                        // MFA 불필요 - 즉시 홈으로 리다이렉트 (서버가 토큰 발급 완료)
                        messageArea.innerHTML = '<div class="message success">로그인 성공! 홈으로 이동합니다...</div>';
                        const redirectUrl = result.redirectUrl || '/home';
                        setTimeout(() => {
                            window.location.href = redirectUrl;
                        }, 500);
                    } else if (result.status === 'MFA_REQUIRED_SELECT_FACTOR' ||
                               result.status === 'MFA_REQUIRED') {
                        // MFA 필요 - Factor 선택 페이지로 리다이렉트
                        messageArea.innerHTML = '<div class="message success">로그인 성공! 다단계 인증을 진행합니다...</div>';
                        const nextStepUrl = result.nextStepUrl || '/mfa/select-factor';
                        setTimeout(() => {
                            window.location.href = nextStepUrl;
                        }, 500);
                    } else {
                        // 기타 응답 - 메시지만 표시
                        const message = result.message || '로그인 성공!';
                        messageArea.innerHTML = '<div class="message success">' + message + '</div>';
                    }
                } catch (error) {
                    // 차단 상태 감지
                    if (error.response && error.response.blocked === true) {
                        // 계정 차단 상태 - footer 숨기고 버튼 비활성화 유지
                        const supportContact = error.response.supportContact || '관리자';
                        messageArea.innerHTML = '<div class="message error">' +
                            error.message + '<br>문의: ' + supportContact + '</div>';
                        formFooter.style.display = 'none';
                        loginButton.disabled = true;
                    } else {
                        // 일반 로그인 실패 - 재시도 가능
                        messageArea.innerHTML = '<div class="message error">' + error.message + '</div>';
                        loginButton.disabled = false;
                        spinner.classList.remove('active');
                    }
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

        log.debug("Generated default primary REST login page for MFA flow. Processing URL: {}", loginProcessingUrl);
    }

    /**
     * OTT Request Code Page 생성
     *
     * <p>
     * Spring Security의 DefaultLoginPageGeneratingFilter.renderOneTimeTokenLogin() 패턴을 따릅니다.
     * </p>
     *
     * <p>
     * 주요 개선 사항:
     * <ul>
     *   <li>Username 입력 필드 추가 (인증 상태에 따라 readonly/editable)</li>
     *   <li>HTML Form 제출 방식 지원 (JavaScript 비활성화 환경 대응)</li>
     *   <li>CSRF 토큰을 hidden input으로 자동 제출</li>
     *   <li>Context Path 처리</li>
     *   <li>MfaHtmlTemplates를 통한 XSS 방어</li>
     *   <li>Progressive Enhancement (JavaScript SDK는 선택적)</li>
     * </ul>
     * </p>
     *
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @throws IOException 입출력 오류 발생 시
     * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter#renderOneTimeTokenLogin
     */
    private void generateOttRequestCodePage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        // Step 1: Context Path 추출
        String contextPath = request.getContextPath();

        // Step 2: 현재 인증된 사용자의 username 조회 (Spring Security 패턴)
        String username = getUsername();

        // Step 3: Username 입력 필드 생성 (조건부 렌더링)
        String usernameInput;
        if (username != null) {
            // 인증된 사용자: readonly 필드
            usernameInput = MfaHtmlTemplates.fromTemplate(OTT_READONLY_USERNAME_INPUT)
                .withValue("username", username)
                .render();
            log.debug("OTT Request Page: 인증된 사용자 '{}' - readonly username 필드 생성", username);
        } else {
            // 미인증 사용자: editable 필드
            usernameInput = OTT_EDITABLE_USERNAME_INPUT;
            log.debug("OTT Request Page: 미인증 사용자 - editable username 필드 생성");
        }

        // Step 4: CSRF 토큰 및 기타 hidden 필드 생성 (Spring Security 패턴)
        String hiddenInputs = resolveHiddenInputs(request);

        // Step 5: OTT 코드 생성 API URL 추출 (Form action용)
        String ottRequestUrl = extractOttCodeGenerationUrl(); // "/mfa/ott/generate-code"
        String fullOttRequestUrl = contextPath + ottRequestUrl;

        // Step 6: 템플릿 렌더링 (MfaHtmlTemplates 사용)
        String html = MfaHtmlTemplates.fromTemplate(OTT_REQUEST_TEMPLATE)
            .withValue("contextPath", contextPath)
            .withValue("ottRequestUrl", fullOttRequestUrl)
            .withValue("csrfToken", getCsrfToken(request))
            .withValue("csrfHeaderName", getCsrfHeaderName(request))
            .withValue("csrfParameterName", getCsrfParameterName(request))
            .withRawHtml("usernameInput", usernameInput)
            .withRawHtml("hiddenInputs", hiddenInputs)
            .render();

        // Step 7: 응답 전송
        PrintWriter writer = response.getWriter();
        writer.write(html);
        writer.flush();

        log.debug("OTT Request Page 생성 완료. Form action URL: {}, Username: {}",
            fullOttRequestUrl, username != null ? username : "(입력 필요)");
    }

    /**
     * OTT Verify Page 생성
     */
    private void generateOttVerifyPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        // Step 1: Context Path 추출
        String contextPath = request.getContextPath();

        // Step 2: 현재 인증된 사용자의 username 조회 (Spring Security 패턴)
        String username = getUsername();
        if (username == null) {
            // OTT 검증 페이지는 인증된 사용자만 접근 가능
            log.warn("OTT Verify Page: 인증되지 않은 사용자 접근 시도");
            username = "(알 수 없음)";
        }

        // Step 3: CSRF 토큰 및 기타 hidden 필드 생성 (Spring Security 패턴)
        String hiddenInputs = resolveHiddenInputs(request);

        // Step 4: OTT 검증 처리 Filter URL 추출 (Form action용)
        String ottVerifyUrl = extractOttLoginProcessingUrl(); // "/login/mfa-ott"
        String fullOttVerifyUrl = contextPath + ottVerifyUrl;

        // Step 5: OTT 코드 재전송 API URL 추출 (재전송 Form action용)
        String ottResendUrl = extractOttCodeGenerationUrl(); // "/mfa/ott/generate-code"
        String fullOttResendUrl = contextPath + ottResendUrl;

        // Step 6: 재전송용 hidden inputs (동일한 CSRF 토큰 재사용)
        String resendHiddenInputs = resolveHiddenInputs(request);

        // Step 7: 템플릿 렌더링 (MfaHtmlTemplates 사용)
        String html = MfaHtmlTemplates.fromTemplate(OTT_VERIFY_TEMPLATE)
            .withValue("contextPath", contextPath)
            .withValue("username", username)
            .withValue("ottVerifyUrl", fullOttVerifyUrl)
            .withValue("ottResendUrl", fullOttResendUrl)
            .withValue("csrfToken", getCsrfToken(request))
            .withValue("csrfHeaderName", getCsrfHeaderName(request))
            .withValue("csrfParameterName", getCsrfParameterName(request))
            .withRawHtml("hiddenInputs", hiddenInputs)
            .withRawHtml("resendHiddenInputs", resendHiddenInputs)
            .render();

        // Step 8: 응답 전송
        PrintWriter writer = response.getWriter();
        writer.write(html);
        writer.flush();

        log.debug("OTT Verify Page 생성 완료. Verify URL: {}, Resend URL: {}, Username: {}",
            fullOttVerifyUrl, fullOttResendUrl, username);
    }

    /**
     * Passkey Challenge Page 생성
     */
    private void generatePasskeyChallengePage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        // Step 1: Context Path 추출
        String contextPath = request.getContextPath();

        // Step 2: 현재 인증된 사용자의 username 조회 (Spring Security 패턴)
        String username = getUsername();
        if (username == null) {
            // Passkey 챌린지 페이지는 인증된 사용자만 접근 가능
            log.warn("Passkey Challenge Page: 인증되지 않은 사용자 접근 시도");
            username = "(알 수 없음)";
        }

        // Step 3: 템플릿 렌더링 (MfaHtmlTemplates 사용)
        String html = MfaHtmlTemplates.fromTemplate(PASSKEY_CHALLENGE_TEMPLATE)
            .withValue("contextPath", contextPath)
            .withValue("username", username)
            .withValue("csrfToken", getCsrfToken(request))
            .withValue("csrfHeaderName", getCsrfHeaderName(request))
            .withValue("csrfParameterName", getCsrfParameterName(request))
            .render();

        // Step 4: 응답 전송
        PrintWriter writer = response.getWriter();
        writer.write(html);
        writer.flush();

        log.debug("Passkey Challenge Page 생성 완료. Username: {}", username);
    }

    // 제거됨: generateConfigurePage() - 사용자 팩터 등록 기능 제거

    /**
     * Failure Page 생성
     */
    private void generateFailurePage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        // Step 1: Context Path 추출
        String contextPath = request.getContextPath();

        // Step 2: 에러 메시지 추출
        String errorMessage = request.getParameter("error");
        String displayMessage = StringUtils.hasText(errorMessage) ? errorMessage : "인증에 실패했습니다.";

        // Step 3: Retry URL 추출 (Select Factor 페이지로 이동)
        String selectFactorUrl = extractSelectFactorUrl();
        String fullRetryUrl = contextPath + selectFactorUrl;

        // Step 4: 템플릿 렌더링 (MfaHtmlTemplates 사용)
        String html = MfaHtmlTemplates.fromTemplate(FAILURE_PAGE_TEMPLATE)
            .withValue("errorMessage", displayMessage)
            .withValue("retryUrl", fullRetryUrl)
            .render();

        // Step 5: 응답 전송
        PrintWriter writer = response.getWriter();
        writer.write(html);
        writer.flush();

        log.debug("Failure Page 생성 완료. Error: {}, Retry URL: {}", displayMessage, fullRetryUrl);
    }

    /**
     * CSRF 토큰 값 추출
     *
     * Spring Security의 CsrfToken을 request attribute에서 가져옵니다.
     *
     * @param request HTTP 요청
     * @return CSRF 토큰 값 (없으면 빈 문자열)
     */
    private String getCsrfToken(HttpServletRequest request) {
        CsrfToken csrfToken =
                (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return csrfToken != null ? csrfToken.getToken() : "";
    }

    /**
     * CSRF 헤더명 추출
     *
     * @param request HTTP 요청
     * @return CSRF 헤더명 (기본값: X-CSRF-TOKEN)
     */
    private String getCsrfHeaderName(HttpServletRequest request) {
        CsrfToken csrfToken =
                (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return csrfToken != null ? csrfToken.getHeaderName() : "X-CSRF-TOKEN";
    }

    /**
     * CSRF 파라미터명 추출
     *
     * @param request HTTP 요청
     * @return CSRF 파라미터명 (기본값: _csrf)
     */
    private String getCsrfParameterName(HttpServletRequest request) {
        CsrfToken csrfToken =
                (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return csrfToken != null ? csrfToken.getParameterName() : "_csrf";
    }

    // ========== Spring Security 패턴 기반 헬퍼 메서드 ==========

    /**
     * 현재 인증된 사용자의 username 조회
     *
     * <p>
     * Spring Security의 SecurityContext에서 인증된 사용자 정보를 가져옵니다.
     * Spring Security의 DefaultLoginPageGeneratingFilter.getUsername() 패턴을 따릅니다.
     * </p>
     *
     * @return 인증된 경우 username, 미인증 시 null
     * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter#getUsername()
     */
    @Nullable
    private String getUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null
            && authentication.isAuthenticated()
            && !(authentication instanceof AnonymousAuthenticationToken)) {
            return ((UserDto)authentication.getPrincipal()).getUsername();
        }

        return null;
    }

    /**
     * CSRF 토큰 및 기타 hidden 필드를 HTML로 렌더링
     *
     * <p>
     * Spring Security의 DefaultLoginPageGeneratingFilter.resolveHiddenInputs 패턴을 따릅니다.
     * CSRF 토큰을 Form hidden input으로 렌더링하여 자동 제출되도록 합니다.
     * </p>
     *
     * @param request HTTP 요청
     * @return HTML hidden input 문자열 (예: &lt;input type="hidden" name="_csrf" value="..." /&gt;)
     * @see org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter#resolveHiddenInputs
     */
    private String resolveHiddenInputs(HttpServletRequest request) {
        Map<String, String> hiddenInputs = new LinkedHashMap<>();

        // CSRF 토큰 추가
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            hiddenInputs.put(csrfToken.getParameterName(), csrfToken.getToken());
        }

        // MFA Session ID 추가 (있는 경우)
        String mfaSessionId = (String) request.getAttribute("mfaSessionId");
        if (StringUtils.hasText(mfaSessionId)) {
            hiddenInputs.put("mfaSessionId", mfaSessionId);
        }

        return hiddenInputs.entrySet()
            .stream()
            .map(entry -> renderHiddenInput(entry.getKey(), entry.getValue()))
            .collect(Collectors.joining("\n"));
    }

    /**
     * HTML hidden input 필드 렌더링
     *
     * @param name 필드명
     * @param value 필드값
     * @return HTML hidden input 문자열
     */
    private String renderHiddenInput(String name, String value) {
        return String.format(
            "<input type=\"hidden\" name=\"%s\" value=\"%s\" />",
            escapeHtml(name),
            escapeHtml(value)
        );
    }

    /**
     * HTML 특수 문자 이스케이프 (XSS 방어)
     *
     * @param input 이스케이프할 문자열
     * @return 이스케이프된 문자열
     */
    private String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;")
                   .replace("/", "&#x2F;");
    }

    /**
     * Factor Type의 Display Name 반환
     *
     * @param factorType Factor 타입 (예: OTT, PASSKEY)
     * @return 사용자 친화적 표시 이름
     */
    private String getFactorDisplayName(AuthType factorType) {
        return switch (factorType) {
            case OTT -> "이메일 인증 코드 (OTT)";
            case PASSKEY -> "Passkey 생체 인증";
            default -> factorType.name();
        };
    }
}
