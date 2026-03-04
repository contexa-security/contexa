package io.contexa.contexaidentity.security.filter;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.properties.MfaPageConfig;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
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

@Slf4j
public class DefaultMfaPageGeneratingFilter extends OncePerRequestFilter {

    private final AuthenticationFlowConfig mfaFlowConfig;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final AuthUrlProvider authUrlProvider;
    private final MfaSettings mfaSettings;
    private final String tokenPersistence;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String requestUri = normalizeUri(request);

        if (isPrimaryAuthPage(requestUri)) {
            if ("GET".equalsIgnoreCase(request.getMethod())) {
                if (hasCustomPrimaryLoginPage()) {
                    chain.doFilter(request, response);
                    return;
                }
                handlePrimaryAuthPage(request, response);
                return;
            }
        }

        if (isSelectFactorPage(requestUri)) {
            if (hasCustomSelectFactorPage()) {
                chain.doFilter(request, response);
                return;
            }
            handleSelectFactorPage(request, response);
            return;
        }

        if (isOttRequestPage(requestUri)) {
            if (hasCustomOttRequestPage()) {
                chain.doFilter(request, response);
                return;
            }
            handleOttRequestPage(request, response);
            return;
        }

        if (isOttChallengePage(requestUri)) {
            if (hasCustomOttVerifyPage()) {
                chain.doFilter(request, response);
                return;
            }
            handleOttChallengePage(request, response);
            return;
        }

        if (isPasskeyChallengePage(requestUri)) {

            if ("GET".equalsIgnoreCase(request.getMethod())) {
                if (hasCustomPasskeyPage()) {
                    chain.doFilter(request, response);
                    return;
                }
                handlePasskeyChallengePage(request, response);
                return;
            }
        }

        if (isConfigurePage(requestUri)) {
            if (hasCustomConfigurePage()) {
                chain.doFilter(request, response);
                return;
            }
            handleConfigurePage(request, response);
            return;
        }

        if (isFailurePage(requestUri)) {
            if (hasCustomFailurePage()) {
                chain.doFilter(request, response);
                return;
            }
            handleFailurePage(request, response);
            return;
        }

        chain.doFilter(request, response);
    }

    private static final String OTT_READONLY_USERNAME_INPUT = """
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username"
                       value="{{username}}"
                       class="form-control"
                       placeholder="Username"
                       required
                       >
            </div>
            """;

    private static final String OTT_EDITABLE_USERNAME_INPUT = """
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username"
                       class="form-control"
                       placeholder="Enter your username"
                       required
                       autofocus>
            </div>
            """;

    private static final String CSRF_HEADERS = """
            {"{{headerName}}" : "{{headerValue}}"}""";

    private static final String OTT_REQUEST_TEMPLATE = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="_csrf" content="{{csrfToken}}">
                <meta name="_csrf_header" content="{{csrfHeaderName}}">
                <meta name="_csrf_parameter" content="{{csrfParameterName}}">
                <title>Request Authentication Code</title>
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
                    .error-message {
                        background: #fff0f0;
                        color: #d32f2f;
                        padding: 12px 16px;
                        border-radius: 8px;
                        border: 1px solid #ffcdd2;
                        font-size: 14px;
                        margin-bottom: 20px;
                        text-align: center;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Request Authentication Code</h1>
                    <p class="description">An authentication code will be sent to your registered email address.</p>
                    {{errorMessage}}
                    <form id="ott-request-form" method="post" action="{{ottRequestUrl}}">
                        {{usernameInput}}
                        {{hiddenInputs}}

                        <button type="submit" class="primary-button">
                            Send Authentication Code
                        </button>
                    </form>
            
                    <!-- Form submit only (SDK Progressive Enhancement not required) -->
                </div>
            </body>
            </html>
            """;

    private static final String OTT_VERIFY_TEMPLATE = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="_csrf" content="{{csrfToken}}">
                <meta name="_csrf_header" content="{{csrfHeaderName}}">
                <meta name="_csrf_parameter" content="{{csrfParameterName}}">
                <title>MFA - Enter Authentication Code</title>
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
                    .error-message {
                        display: none;
                        background: #f8d7da;
                        color: #721c24;
                        padding: 12px 16px;
                        border-radius: 8px;
                        margin-bottom: 16px;
                        font-size: 14px;
                        text-align: center;
                        line-height: 1.5;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Enter Authentication Code</h1>
                    <p class="description">Enter the 6-digit code sent to your email.</p>

                    <div class="user-info">
                        <div class="label">Account being authenticated</div>
                        <div class="username">{{username}}</div>
                    </div>

                    <div id="error-message" class="error-message"></div>

                    <form id="ott-verify-form" method="post" action="{{ottVerifyUrl}}">
                        <div class="form-group">
                            <label for="token">Authentication Code</label>
                            <input type="text" id="token" name="token"
                                   class="form-control"
                                   required
                                   autofocus>
                        </div>

                        {{hiddenInputs}}

                        <button type="submit" class="primary-button">
                            Verify
                        </button>
                    </form>

                    <form id="resend-form" method="post" action="{{ottResendUrl}}">
                        {{resendHiddenInputs}}
                        <button type="submit" class="secondary-button">
                            Resend Code
                        </button>
                    </form>
            
                    <!-- Progressive Enhancement: JavaScript SDK support -->
                    <script src="{{contextPath}}/js/contexa-mfa-sdk.js"></script>
                    <script>
                        // Enhanced UX through SDK when JavaScript is enabled
                        if (typeof ContexaMFA !== 'undefined') {
                            var currentAttempts = parseInt('{{attemptsMade}}', 10) || 0;
                            var maxAttempts = parseInt('{{maxAttempts}}', 10) || 5;

                            const verifyForm = document.getElementById('ott-verify-form');
                            const resendForm = document.getElementById('resend-form');
                            const verifyButton = verifyForm.querySelector('button[type="submit"]');
                            const resendButton = resendForm.querySelector('button[type="submit"]');
                            const codeInput = document.getElementById('token');
                            const errorMsgEl = document.getElementById('error-message');

                            function disableVerificationForm() {
                                codeInput.disabled = true;
                                verifyButton.disabled = true;
                                verifyButton.textContent = 'Verify';
                                resendButton.disabled = true;
                                errorMsgEl.textContent = 'Maximum verification attempts exceeded. Please contact your administrator.';
                                errorMsgEl.style.display = 'block';
                            }

                            // Show existing attempt info on page load
                            if (currentAttempts > 0) {
                                var remaining = maxAttempts - currentAttempts;
                                if (remaining <= 0) {
                                    disableVerificationForm();
                                } else {
                                    errorMsgEl.textContent = remaining + ' attempt(s) remaining out of ' + maxAttempts + '.';
                                    errorMsgEl.style.display = 'block';
                                }
                            }

                            // SDK initialization
                            const mfa = new ContexaMFA.Client({ autoRedirect: false, tokenPersistence: '{{tokenPersistence}}' });
                            mfa.init().catch(console.error);

                            // Verification Form Progressive Enhancement
                            verifyForm.addEventListener('submit', async (e) => {
                                e.preventDefault();

                                const code = codeInput.value;
                                verifyButton.disabled = true;
                                verifyButton.textContent = 'Verifying...';

                                try {
                                    const result = await mfa.verifyOtt(code);

                                    // Explicit redirect handling
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
                                    console.error('OTT verification failed:', error);

                                    // BLOCK MFA: redirect to blocked page on retry limit exceeded
                                    if (error.response && error.response.blockMfaFailed) {
                                        window.location.href = error.response.redirectUrl || '/zero-trust/blocked';
                                        return;
                                    }

                                    if (error.response && error.response.attemptsMade != null) {
                                        currentAttempts = error.response.attemptsMade;
                                    } else {
                                        currentAttempts++;
                                    }
                                    var remaining = maxAttempts - currentAttempts;
                                    if (remaining <= 0) {
                                        disableVerificationForm();
                                    } else {
                                        var msg = 'Authentication code verification failed. '
                                            + remaining + ' attempt(s) remaining out of ' + maxAttempts + '.';
                                        errorMsgEl.textContent = msg;
                                        errorMsgEl.style.display = 'block';
                                        verifyButton.disabled = false;
                                        verifyButton.textContent = 'Verify';
                                        codeInput.value = '';
                                        codeInput.focus();
                                    }
                                }
                            });

                            // Resend button uses form submit as-is (SDK not required)
                        }
                    </script>
                </div>
            </body>
            </html>
            """;

    private static final String PASSKEY_CHALLENGE_TEMPLATE = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="_csrf" content="{{csrfToken}}">
                <meta name="_csrf_header" content="{{csrfHeaderName}}">
                <meta name="_csrf_parameter" content="{{csrfParameterName}}">
                <title>MFA - Passkey Authentication</title>
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
                    <h1>Passkey Authentication</h1>
                    <p class="description">Authenticate using biometrics or a security key.</p>

                    <div class="user-info">
                        <div class="label">Account being authenticated</div>
                        <div class="username">{{username}}</div>
                    </div>

                    <button id="auth-button" class="primary-button">
                        Start Passkey Authentication
                    </button>

                    <!-- Passkey registration link -->
                    <div style="text-align: center; margin-top: 24px; padding-top: 24px; border-top: 1px solid #e0e0e0;">
                        <p style="color: #666; font-size: 14px; margin-bottom: 8px;">
                            Don't have a registered Passkey?
                        </p>
                        <a href="{{contextPath}}/webauthn/register"
                           style="color: #667eea; text-decoration: none; font-weight: 600; font-size: 14px;">
                            Register Passkey →
                        </a>
                    </div>
            
                    <!-- Spring Security WebAuthn JavaScript (base library) -->
                    <script src="{{contextPath}}/login/webauthn.js"></script>
            
                    <!-- Contexa MFA SDK (MFA flow management wrapper) -->
                    <script src="{{contextPath}}/js/contexa-mfa-sdk.js"></script>
                    <script>
                        if (typeof ContexaMFA !== 'undefined') {
                            const authButton = document.getElementById('auth-button');
                            const mfa = new ContexaMFA.Client({ autoRedirect: false, tokenPersistence: '{{tokenPersistence}}' });
            
                            // Disable button initially (until challenge is ready)
                            authButton.disabled = true;
                            authButton.textContent = 'Initializing...';

                            // SDK initialization (challenge already started by backend)
                            (async () => {
                                try {
                                    await mfa.init();

                                    // Phase 2.3: Challenge started by backend with INITIATE_CHALLENGE_AUTO
                                    // JavaScript no longer needs to send INITIATE_CHALLENGE
                                    authButton.disabled = false;
                                    authButton.textContent = 'Authenticate with Passkey';
                                    console.log('Passkey challenge ready (auto-initiated by backend)');
                                } catch (error) {
                                    console.error('Failed to initialize SDK:', error);
                                    authButton.disabled = false;
                                    authButton.textContent = 'Authenticate with Passkey';
                                }
                            })();

                            // Passkey authentication
                            authButton.addEventListener('click', async () => {
                                authButton.disabled = true;
                                authButton.textContent = 'Authenticating...';

                                try {
                                    const result = await mfa.verifyPasskey();

                                    // Explicit redirect handling
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
                                    console.error('Passkey authentication failed:', error);
                                    window.location.href = '{{contextPath}}{{failureUrl}}?error=' + encodeURIComponent(error.message || 'Unknown error');
                                }
                            });
                        }
                    </script>
                </div>
            </body>
            </html>
            """;

    private static final String SELECT_FACTOR_TEMPLATE = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="_csrf" content="{{csrfToken}}">
                <meta name="_csrf_header" content="{{csrfHeaderName}}">
                <meta name="_csrf_parameter" content="{{csrfParameterName}}">
                <title>MFA - Select Authentication Method</title>
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
                    <h1>Select Authentication Method</h1>
                    <p class="description">Choose a two-factor authentication method.</p>

                    <div class="user-info">
                        <div class="label">Account being authenticated</div>
                        <div class="username">{{username}}</div>
                    </div>

                    {{factorButtons}}
            
                    <!-- Progressive Enhancement: JavaScript SDK support -->
                    <script src="{{contextPath}}/js/contexa-mfa-sdk.js"></script>
                    <script>
                        // Enhanced UX through SDK when JavaScript is enabled
                        if (typeof ContexaMFA !== 'undefined') {
                            const forms = document.querySelectorAll('.factor-form');
                            const mfa = new ContexaMFA.Client({ autoRedirect: false, tokenPersistence: '{{tokenPersistence}}' });
            
                            // SDK initialization
                            mfa.init().catch(console.error);
            
                            forms.forEach(form => {
                                form.addEventListener('submit', async (e) => {
                                    e.preventDefault();
            
                                    const factorType = form.dataset.factorType;
                                    const button = form.querySelector('button[type="submit"]');
                                    const originalText = button.textContent;
            
                                    button.disabled = true;
                                    button.textContent = 'Processing...';

                                    try {
                                        const result = await mfa.selectFactor(factorType);

                                        // Explicit redirect handling
                                        if (result.nextStepUrl) {
                                            window.location.href = result.nextStepUrl;
                                        } else if (result.redirectUrl) {
                                            window.location.href = result.redirectUrl;
                                        }
                                    } catch (error) {
                                        console.error('Factor selection failed:', error);
                                        alert('Authentication method selection failed: ' + (error.message || 'Unknown error'));
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

    private static final String FACTOR_BUTTON_TEMPLATE = """
            <li class="factor-item">
                <form class="factor-form" method="post" action="{{selectFactorUrl}}" data-factor-type="{{factorType}}">
                    {{hiddenInputs}}
                    <input type="hidden" name="factorType" value="{{factorType}}">
                    <button type="submit">{{factorDisplayName}}</button>
                </form>
            </li>
            """;

    private static final String FAILURE_PAGE_TEMPLATE = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>MFA - Authentication Failed</title>
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
                    <h1>Authentication Failed</h1>
                    <p class="error-message">{{errorMessage}}</p>

                    <form method="get" action="{{retryUrl}}">
                        <button type="submit" class="primary-button">
                            Try Again
                        </button>
                    </form>
                </div>
            </body>
            </html>
            """;

    public DefaultMfaPageGeneratingFilter(
            AuthenticationFlowConfig mfaFlowConfig,
            MfaStateMachineIntegrator stateMachineIntegrator,
            AuthUrlProvider authUrlProvider,
            MfaSettings mfaSettings,
            String tokenPersistence) {
        Assert.notNull(mfaFlowConfig, "AuthenticationFlowConfig cannot be null");
        Assert.isTrue(AuthType.MFA.name().equalsIgnoreCase(mfaFlowConfig.getTypeName()),
                "This filter only works with MFA flow config. Provided flow type: " + mfaFlowConfig.getTypeName());
        Assert.notNull(stateMachineIntegrator, "MfaStateMachineIntegrator cannot be null");
        Assert.notNull(authUrlProvider, "AuthUrlProvider cannot be null");
        Assert.notNull(mfaSettings, "MfaSettings cannot be null");

        this.mfaFlowConfig = mfaFlowConfig;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.authUrlProvider = authUrlProvider;
        this.mfaSettings = mfaSettings;
        this.tokenPersistence = tokenPersistence != null ? tokenPersistence : "memory";

    }

    private boolean isPrimaryAuthPage(String requestUri) {
        String primaryLoginPage = extractPrimaryLoginPage();
        return requestUri.equals(primaryLoginPage);
    }

    private void handlePrimaryAuthPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        PrimaryAuthenticationOptions primaryOpts = mfaFlowConfig.getPrimaryAuthenticationOptions();
        if (primaryOpts == null) {
            log.warn("Primary authentication options not configured for MFA flow. Skipping primary auth page generation.");
            return;
        }

        if (primaryOpts.isFormLogin()) {
            FormOptions formOpts = primaryOpts.getFormOptions();

            if (isCustomLoginPage(formOpts.getLoginPage())) {
                return;
            }

            generatePrimaryFormLoginPage(request, response, formOpts);

        } else if (primaryOpts.isRestLogin()) {

            RestOptions restOpts = primaryOpts.getRestOptions();
            String loginPage = primaryOpts.getLoginPage();

            if (isCustomLoginPage(loginPage)) {
                return;
            }

            generatePrimaryRestLoginPage(request, response, restOpts);
        }
    }

    private String extractPrimaryLoginPage() {
        PrimaryAuthenticationOptions primaryOpts = mfaFlowConfig.getPrimaryAuthenticationOptions();
        if (primaryOpts != null) {

            if (primaryOpts.isFormLogin()) {
                FormOptions formOpts = primaryOpts.getFormOptions();
                return StringUtils.hasText(formOpts.getLoginPage()) ?
                        formOpts.getLoginPage() : authUrlProvider.getPrimaryLoginPage();
            }

            if (primaryOpts.isRestLogin()) {
                String loginPage = primaryOpts.getLoginPage();
                return StringUtils.hasText(loginPage) ? loginPage : authUrlProvider.getPrimaryLoginPage();
            }
        }
        return authUrlProvider.getPrimaryLoginPage();
    }

    private boolean isCustomLoginPage(String loginPage) {

        String defaultLoginPage = authUrlProvider.getPrimaryLoginPage();
        return StringUtils.hasText(loginPage) && !loginPage.equals(defaultLoginPage);
    }

    private boolean hasCustomPrimaryLoginPage() {
        PrimaryAuthenticationOptions primaryOpts = mfaFlowConfig.getPrimaryAuthenticationOptions();
        if (primaryOpts == null) {
            return false;
        }

        if (primaryOpts.isFormLogin()) {
            FormOptions formOpts = primaryOpts.getFormOptions();
            return formOpts != null && isCustomLoginPage(formOpts.getLoginPage());
        }

        if (primaryOpts.isRestLogin()) {
            return isCustomLoginPage(primaryOpts.getLoginPage());
        }

        return false;
    }

    private boolean hasCustomSelectFactorPage() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        return pageConfig != null && pageConfig.hasCustomSelectFactorPage();
    }

    private boolean hasCustomOttRequestPage() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        return pageConfig != null && pageConfig.hasCustomOttRequestPage();
    }

    private boolean hasCustomOttVerifyPage() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        return pageConfig != null && pageConfig.hasCustomOttVerifyPage();
    }

    private boolean hasCustomPasskeyPage() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        return pageConfig != null && pageConfig.hasCustomPasskeyPage();
    }

    private boolean hasCustomConfigurePage() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        return pageConfig != null && pageConfig.hasCustomConfigurePage();
    }

    private boolean hasCustomFailurePage() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        return pageConfig != null && pageConfig.hasCustomFailurePage();
    }

    private boolean isSelectFactorPage(String requestUri) {
        String selectFactorUrl = extractSelectFactorUrl();
        return requestUri.equals(selectFactorUrl);
    }

    private void handleSelectFactorPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomSelectFactorPage()) {
            return;
        }

        generateSelectFactorPage(request, response);
    }

    private String extractSelectFactorUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getSelectFactorPageUrl())) {
            return pageConfig.getSelectFactorPageUrl();
        }
        return authUrlProvider.getMfaSelectFactor();
    }

    private boolean isOttRequestPage(String requestUri) {
        String ottRequestUrl = extractOttRequestUrl();
        return requestUri.equals(ottRequestUrl);
    }

    private void handleOttRequestPage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomOttRequestPage()) {
            return;
        }

        generateOttRequestCodePage(request, response);
    }

    private boolean isOttChallengePage(String requestUri) {
        String ottChallengeUrl = extractOttChallengeUrl();
        return requestUri.equals(ottChallengeUrl);
    }

    private void handleOttChallengePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomOttVerifyPage()) {
            return;
        }

        generateOttVerifyPage(request, response);
    }

    private String extractOttRequestUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getOttRequestPageUrl())) {
            return pageConfig.getOttRequestPageUrl();
        }
        return authUrlProvider.getOttRequestCodeUi();
    }

    private String extractOttChallengeUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getOttVerifyPageUrl())) {
            return pageConfig.getOttVerifyPageUrl();
        }
        return authUrlProvider.getOttChallengeUi();
    }

    private String extractOttCodeGenerationUrl() {
        return authUrlProvider.getOttCodeGeneration();
    }

    private String extractOttLoginProcessingUrl() {
        return authUrlProvider.getOttLoginProcessing();
    }

    private boolean isPasskeyChallengePage(String requestUri) {
        String passkeyUrl = extractPasskeyChallengeUrl();
        return requestUri.equals(passkeyUrl);
    }

    private void handlePasskeyChallengePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomPasskeyPage()) {
            return;
        }

        generatePasskeyChallengePage(request, response);
    }

    private String extractPasskeyChallengeUrl() {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getPasskeyChallengePageUrl())) {
            return pageConfig.getPasskeyChallengePageUrl();
        }
        return authUrlProvider.getPasskeyChallengeUi();
    }

    private boolean isConfigurePage(String requestUri) {
        // Configure page is no longer supported
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getConfigurePageUrl())) {
            return requestUri.equals(pageConfig.getConfigurePageUrl());
        }
        return false;
    }

    private void handleConfigurePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        log.warn("MFA Configure page is no longer supported. User factor registration has been removed.");
        response.sendError(HttpServletResponse.SC_NOT_FOUND, "MFA Configure page is not available");
    }

    private boolean isFailurePage(String requestUri) {
        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();
        if (pageConfig != null && StringUtils.hasText(pageConfig.getFailurePageUrl())) {
            return requestUri.equals(pageConfig.getFailurePageUrl());
        }
        return requestUri.equals(authUrlProvider.getMfaFailure());
    }

    private void handleFailurePage(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        MfaPageConfig pageConfig = mfaFlowConfig.getMfaPageConfig();

        if (pageConfig != null && pageConfig.hasCustomFailurePage()) {
            return;
        }

        generateFailurePage(request, response);
    }

    private String normalizeUri(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();

        if (StringUtils.hasText(contextPath)) {
            requestUri = requestUri.substring(contextPath.length());
        }

        return requestUri;
    }

    private void generateSelectFactorPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        String contextPath = request.getContextPath();

        String username = getUsername();
        if (username == null) {
            log.warn("Select Factor Page: Unauthenticated user access attempt");
            username = "(Unknown)";
        }

        List<AuthType> availableFactors = ctx != null && ctx.getAvailableFactors() != null ?
                new java.util.ArrayList<>(ctx.getAvailableFactors()) : List.of();

        if (availableFactors.isEmpty()) {
            log.warn("Select Factor Page: No available factors. Session: {}",
                    ctx != null ? ctx.getMfaSessionId() : "unknown");
        }

        String selectFactorUrl = extractSelectFactorUrl();
        String fullSelectFactorUrl = contextPath + selectFactorUrl;

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

        String html = MfaHtmlTemplates.fromTemplate(SELECT_FACTOR_TEMPLATE)
                .withValue("contextPath", contextPath)
                .withValue("username", username)
                .withValue("csrfToken", getCsrfToken(request))
                .withValue("csrfHeaderName", getCsrfHeaderName(request))
                .withValue("csrfParameterName", getCsrfParameterName(request))
                .withValue("tokenPersistence", tokenPersistence)
                .withRawHtml("factorButtons", factorButtonsHtml.toString())
                .render();

        PrintWriter writer = response.getWriter();
        writer.write(html);
        writer.flush();

    }

    private void generatePrimaryFormLoginPage(HttpServletRequest request, HttpServletResponse response, FormOptions formOpts)
            throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String loginProcessingUrl = formOpts.getLoginProcessingUrl();

        String errorMessage = request.getParameter("error");
        String logoutMessage = request.getParameter("logout");

        String csrfToken = getCsrfToken(request);
        String csrfHeaderName = getCsrfHeaderName(request);
        String csrfParameterName = getCsrfParameterName(request);

        String html = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta name="_csrf" content="%s">
                    <meta name="_csrf_header" content="%s">
                    <meta name="_csrf_parameter" content="%s">
                    <title>Login - MFA Authentication</title>
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
                        <h1>Login</h1>
                        <div id="message-area">
                            %s
                            %s
                        </div>
                        <div id="loginContainer" class="form">
                            <input type="text" id="username" placeholder="Username or Email" required autofocus>
                            <input type="password" id="password" placeholder="Password" required>
                            <button type="button" id="loginButton">Login</button>
                            <div class="spinner" id="spinner">Authenticating...</div>
                        </div>
                        <div class="form-footer" id="form-footer">
                            Multi-factor authentication (MFA) will proceed after login.
                        </div>
                    </div>
                
                    <script src="/js/contexa-mfa-sdk.js"></script>
                    <script>
                        document.addEventListener('DOMContentLoaded', function() {
                            const messageArea = document.getElementById('message-area');
                            const loginButton = document.getElementById('loginButton');
                            const spinner = document.getElementById('spinner');
                            const formFooter = document.getElementById('form-footer');
                
                            // SDK initialization (autoRedirect: true - auto redirect)
                            const mfa = new ContexaMFA.Client({ autoRedirect: true, tokenPersistence: '%s' });

                            loginButton.addEventListener('click', async () => {
                                const username = document.getElementById('username').value;
                                const password = document.getElementById('password').value;

                                if (!username || !password) {
                                    messageArea.innerHTML = '<div class="message error">Please enter username and password.</div>';
                                    return;
                                }

                                // Change UI state
                                loginButton.disabled = true;
                                spinner.classList.add('active');
                                messageArea.innerHTML = '';

                                try {
                                    // Call SDK loginForm method
                                    const result = await mfa.apiClient.loginForm(username, password);

                                    // Debug: check server response
                                    console.log('[DEBUG] Server response:', JSON.stringify(result, null, 2));
                                    console.log('[DEBUG] result.status:', result.status);
                                    console.log('[DEBUG] result.redirectUrl:', result.redirectUrl);

                                    // Branch processing based on MFA requirement
                                    if (result.status === 'MFA_COMPLETED') {
                                        // MFA not required - redirect to home immediately (server issued tokens)
                                        messageArea.innerHTML = '<div class="message success">Login successful! Redirecting to home...</div>';
                                        const redirectUrl = result.redirectUrl || '/';
                                        setTimeout(() => {
                                            window.location.href = redirectUrl;
                                        }, 500);
                                    } else if (result.status === 'MFA_REQUIRED_SELECT_FACTOR' ||
                                               result.status === 'MFA_REQUIRED') {
                                        // MFA required - redirect to factor selection page
                                        messageArea.innerHTML = '<div class="message success">Login successful! Proceeding with multi-factor authentication...</div>';
                                        const nextStepUrl = result.nextStepUrl || '/mfa/select-factor';
                                        setTimeout(() => {
                                            window.location.href = nextStepUrl;
                                        }, 500);
                                    } else {
                                        // Other response - show message only
                                        const message = result.message || 'Login successful!';
                                        messageArea.innerHTML = '<div class="message success">' + message + '</div>';
                                    }
                                } catch (error) {
                                    // Detect blocked status
                                    if (error.response && error.response.blocked === true) {
                                        // Account blocked - hide footer and keep button disabled
                                        const supportContact = error.response.supportContact || 'Administrator';
                                        messageArea.innerHTML = '<div class="message error">' +
                                            error.message + '<br>Contact: ' + supportContact + '</div>';
                                        formFooter.style.display = 'none';
                                        loginButton.disabled = true;
                                    } else {
                                        // Normal login failure - retry possible
                                        messageArea.innerHTML = '<div class="message error">' + error.message + '</div>';
                                        loginButton.disabled = false;
                                        spinner.classList.remove('active');
                                    }
                                }
                            });

                            // Handle Enter key
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
                errorMessage != null ? "<div class=\"message error\">Login failed: Please check your username or password.</div>" : "",
                logoutMessage != null ? "<div class=\"message success\">You have been logged out.</div>" : "",
                tokenPersistence
        );

        writer.write(html);
        writer.flush();

    }

    private void generatePrimaryRestLoginPage(HttpServletRequest request, HttpServletResponse response, RestOptions restOpts)
            throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter writer = response.getWriter();

        String loginProcessingUrl = restOpts.getLoginProcessingUrl();

        String errorMessage = request.getParameter("error");
        String logoutMessage = request.getParameter("logout");

        String csrfToken = getCsrfToken(request);
        String csrfHeaderName = getCsrfHeaderName(request);
        String csrfParameterName = getCsrfParameterName(request);

        String html = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta name="_csrf" content="%s">
                    <meta name="_csrf_header" content="%s">
                    <meta name="_csrf_parameter" content="%s">
                    <title>Login - MFA Authentication (REST)</title>
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
                        <h1>Login (REST API)</h1>
                        <div id="message-area">
                            %s
                            %s
                        </div>
                        <div id="loginContainer" class="form">
                            <input type="text" id="username" placeholder="Username or Email" required autofocus>
                            <input type="password" id="password" placeholder="Password" required>
                            <button type="button" id="loginButton">Login</button>
                            <div class="spinner" id="spinner">Authenticating...</div>
                        </div>
                        <div class="form-footer" id="form-footer">
                            Multi-factor authentication (MFA) will proceed after login.
                        </div>
                    </div>
                
                    <script src="/js/contexa-mfa-sdk.js"></script>
                    <script>
                        document.addEventListener('DOMContentLoaded', function() {
                            const messageArea = document.getElementById('message-area');
                            const loginButton = document.getElementById('loginButton');
                            const spinner = document.getElementById('spinner');
                            const formFooter = document.getElementById('form-footer');

                            // SDK initialization (autoRedirect: true - auto redirect)
                            const mfa = new ContexaMFA.Client({ autoRedirect: true, tokenPersistence: '%s' });

                            loginButton.addEventListener('click', async () => {
                                const username = document.getElementById('username').value;
                                const password = document.getElementById('password').value;

                                if (!username || !password) {
                                    messageArea.innerHTML = '<div class="message error">Please enter username and password.</div>';
                                    return;
                                }

                                // Change UI state
                                loginButton.disabled = true;
                                spinner.classList.add('active');
                                messageArea.innerHTML = '';

                                try {
                                    // Call SDK login method
                                    const result = await mfa.apiClient.login(username, password);

                                    // Debug: check server response
                                    console.log('[DEBUG] Server response:', JSON.stringify(result, null, 2));
                                    console.log('[DEBUG] result.status:', result.status);
                                    console.log('[DEBUG] result.redirectUrl:', result.redirectUrl);

                                    // Branch processing based on MFA requirement
                                    if (result.status === 'MFA_COMPLETED') {
                                        // MFA not required - redirect to home immediately (server issued tokens)
                                        messageArea.innerHTML = '<div class="message success">Login successful! Redirecting to home...</div>';
                                        const redirectUrl = result.redirectUrl || '/';
                                        setTimeout(() => {
                                            window.location.href = redirectUrl;
                                        }, 500);
                                    } else if (result.status === 'MFA_REQUIRED_SELECT_FACTOR' ||
                                               result.status === 'MFA_REQUIRED') {
                                        // MFA required - redirect to factor selection page
                                        messageArea.innerHTML = '<div class="message success">Login successful! Proceeding with multi-factor authentication...</div>';
                                        const nextStepUrl = result.nextStepUrl || '/mfa/select-factor';
                                        setTimeout(() => {
                                            window.location.href = nextStepUrl;
                                        }, 500);
                                    } else {
                                        // Other response - show message only
                                        const message = result.message || 'Login successful!';
                                        messageArea.innerHTML = '<div class="message success">' + message + '</div>';
                                    }
                                } catch (error) {
                                    // Detect blocked status
                                    if (error.response && error.response.blocked === true) {
                                        // Account blocked - hide footer and keep button disabled
                                        const supportContact = error.response.supportContact || 'Administrator';
                                        messageArea.innerHTML = '<div class="message error">' +
                                            error.message + '<br>Contact: ' + supportContact + '</div>';
                                        formFooter.style.display = 'none';
                                        loginButton.disabled = true;
                                    } else {
                                        // Normal login failure - retry possible
                                        messageArea.innerHTML = '<div class="message error">' + error.message + '</div>';
                                        loginButton.disabled = false;
                                        spinner.classList.remove('active');
                                    }
                                }
                            });

                            // Handle Enter key
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
                errorMessage != null ? "<div class=\"message error\">Login failed: Please check your username or password.</div>" : "",
                logoutMessage != null ? "<div class=\"message success\">You have been logged out.</div>" : "",
                tokenPersistence
        );

        writer.write(html);
        writer.flush();

    }

    private void generateOttRequestCodePage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        String contextPath = request.getContextPath();

        String username = getUsername();

        String usernameInput;
        if (username != null) {

            usernameInput = MfaHtmlTemplates.fromTemplate(OTT_READONLY_USERNAME_INPUT)
                    .withValue("username", username)
                    .render();
        } else {

            usernameInput = OTT_EDITABLE_USERNAME_INPUT;
        }

        String hiddenInputs = resolveHiddenInputs(request);

        String ottRequestUrl = extractOttCodeGenerationUrl();
        String fullOttRequestUrl = contextPath + ottRequestUrl;

        String errorParam = request.getParameter("error");
        String errorMessage = "";
        if ("user_not_found".equals(errorParam)) {
            errorMessage = "<div class=\"error-message\">User not found. Please enter a valid username.</div>";
        }

        String html = MfaHtmlTemplates.fromTemplate(OTT_REQUEST_TEMPLATE)
                .withValue("contextPath", contextPath)
                .withValue("ottRequestUrl", fullOttRequestUrl)
                .withValue("csrfToken", getCsrfToken(request))
                .withValue("csrfHeaderName", getCsrfHeaderName(request))
                .withValue("csrfParameterName", getCsrfParameterName(request))
                .withRawHtml("usernameInput", usernameInput)
                .withRawHtml("hiddenInputs", hiddenInputs)
                .withRawHtml("errorMessage", errorMessage)
                .render();

        PrintWriter writer = response.getWriter();
        writer.write(html);
        writer.flush();

    }

    private void generateOttVerifyPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        String contextPath = request.getContextPath();

        String username = getUsername();
        if (username == null) {

            log.warn("OTT Verify Page: Unauthenticated user access attempt");
            username = "(Unknown)";
        }

        String hiddenInputs = resolveHiddenInputs(request);

        String ottVerifyUrl = extractOttLoginProcessingUrl();
        String fullOttVerifyUrl = contextPath + ottVerifyUrl;

        String ottResendUrl = extractOttCodeGenerationUrl();
        String fullOttResendUrl = contextPath + ottResendUrl;

        String resendHiddenInputs = resolveResendHiddenInputs(request, username);

        int attemptsMade = 0;
        int maxAttempts = mfaSettings.getMaxRetryAttempts();
        FactorContext factorContext = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (factorContext != null) {
            attemptsMade = factorContext.getRetryCount();
        }

        String html = MfaHtmlTemplates.fromTemplate(OTT_VERIFY_TEMPLATE)
                .withValue("contextPath", contextPath)
                .withValue("username", username)
                .withValue("ottVerifyUrl", fullOttVerifyUrl)
                .withValue("ottResendUrl", fullOttResendUrl)
                .withValue("csrfToken", getCsrfToken(request))
                .withValue("csrfHeaderName", getCsrfHeaderName(request))
                .withValue("csrfParameterName", getCsrfParameterName(request))
                .withValue("attemptsMade", String.valueOf(attemptsMade))
                .withValue("maxAttempts", String.valueOf(maxAttempts))
                .withValue("tokenPersistence", tokenPersistence)
                .withRawHtml("hiddenInputs", hiddenInputs)
                .withRawHtml("resendHiddenInputs", resendHiddenInputs)
                .render();

        PrintWriter writer = response.getWriter();
        writer.write(html);
        writer.flush();

    }

    private void generatePasskeyChallengePage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        String contextPath = request.getContextPath();

        String username = getUsername();
        if (username == null) {

            log.warn("Passkey Challenge Page: Unauthenticated user access attempt");
            username = "(Unknown)";
        }

        String csrfHeaderName = getCsrfHeaderName(request);
        String csrfToken = getCsrfToken(request);
        String csrfHeaders = CSRF_HEADERS
                .replace("{{headerName}}", csrfHeaderName)
                .replace("{{headerValue}}", csrfToken);

        String failureUrl = authUrlProvider.getMfaFailure();

        String html = MfaHtmlTemplates.fromTemplate(PASSKEY_CHALLENGE_TEMPLATE)
                .withValue("contextPath", contextPath)
                .withValue("username", username)
                .withValue("csrfToken", csrfToken)
                .withValue("csrfHeaderName", csrfHeaderName)
                .withValue("csrfParameterName", getCsrfParameterName(request))
                .withValue("csrfHeaders", csrfHeaders)
                .withValue("failureUrl", failureUrl)
                .withValue("tokenPersistence", tokenPersistence)
                .render();

        PrintWriter writer = response.getWriter();
        writer.write(html);
        writer.flush();

    }

    private void generateFailurePage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        String contextPath = request.getContextPath();

        String errorMessage = request.getParameter("error");
        String displayMessage = StringUtils.hasText(errorMessage) ? errorMessage : "Authentication failed.";

        String selectFactorUrl = extractSelectFactorUrl();
        String fullRetryUrl = contextPath + selectFactorUrl;

        String html = MfaHtmlTemplates.fromTemplate(FAILURE_PAGE_TEMPLATE)
                .withValue("errorMessage", displayMessage)
                .withValue("retryUrl", fullRetryUrl)
                .render();

        PrintWriter writer = response.getWriter();
        writer.write(html);
        writer.flush();

    }

    private String getCsrfToken(HttpServletRequest request) {
        CsrfToken csrfToken =
                (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return csrfToken != null ? csrfToken.getToken() : "";
    }

    private String getCsrfHeaderName(HttpServletRequest request) {
        CsrfToken csrfToken =
                (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return csrfToken != null ? csrfToken.getHeaderName() : "X-CSRF-TOKEN";
    }

    private String getCsrfParameterName(HttpServletRequest request) {
        CsrfToken csrfToken =
                (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return csrfToken != null ? csrfToken.getParameterName() : "_csrf";
    }

    @Nullable
    private String getUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null
                && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            return authentication.getName();
        }

        return null;
    }

    private String resolveResendHiddenInputs(HttpServletRequest request, String username) {
        Map<String, String> hiddenInputs = new LinkedHashMap<>();

        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            hiddenInputs.put(csrfToken.getParameterName(), csrfToken.getToken());
        }

        String mfaSessionId = (String) request.getAttribute("mfaSessionId");
        if (StringUtils.hasText(mfaSessionId)) {
            hiddenInputs.put("mfaSessionId", mfaSessionId);
        }

        if (StringUtils.hasText(username)) {
            hiddenInputs.put("username", username);
        }

        return hiddenInputs.entrySet()
                .stream()
                .map(entry -> renderHiddenInput(entry.getKey(), entry.getValue()))
                .collect(Collectors.joining("\n"));
    }

    private String resolveHiddenInputs(HttpServletRequest request) {
        Map<String, String> hiddenInputs = new LinkedHashMap<>();

        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            hiddenInputs.put(csrfToken.getParameterName(), csrfToken.getToken());
        }

        String mfaSessionId = (String) request.getAttribute("mfaSessionId");
        if (StringUtils.hasText(mfaSessionId)) {
            hiddenInputs.put("mfaSessionId", mfaSessionId);
        }

        return hiddenInputs.entrySet()
                .stream()
                .map(entry -> renderHiddenInput(entry.getKey(), entry.getValue()))
                .collect(Collectors.joining("\n"));
    }

    private String renderHiddenInput(String name, String value) {
        return String.format(
                "<input type=\"hidden\" name=\"%s\" value=\"%s\" />",
                escapeHtml(name),
                escapeHtml(value)
        );
    }

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

    private String getFactorDisplayName(AuthType factorType) {
        return switch (factorType) {
            case MFA_OTT -> "Email Authentication Code (OTT)";
            case MFA_PASSKEY -> "Passkey Biometric Authentication";
            default -> factorType.name();
        };
    }
}
