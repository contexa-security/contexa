/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexaidentity.security.handler.login.LoginFactsDetails;
import io.contexa.contexaidentity.security.handler.login.LoginFactsRecorder;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.SignInDecision;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPendingSessionMarker;

@Slf4j
public class OAuth2SingleAuthSuccessHandler extends AbstractTokenBasedSuccessHandler {

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final LoginPolicyHandler loginPolicyHandler;
    private ZeroTrustEventPublisher zeroTrustEventPublisher;

    public OAuth2SingleAuthSuccessHandler(TokenService tokenService,
                                          AuthResponseWriter responseWriter,
                                          AuthContextProperties authContextProperties,
                                          @Nullable LoginPolicyHandler loginPolicyHandler) {
        super(tokenService, responseWriter, authContextProperties);
        this.loginPolicyHandler = loginPolicyHandler;
    }

    /** The engine the completed sign-in goes to; without it no sign-in is decided. */
    public void setZeroTrustEventPublisher(@Nullable ZeroTrustEventPublisher zeroTrustEventPublisher) {
        this.zeroTrustEventPublisher = zeroTrustEventPublisher;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        onAuthenticationSuccess(request, response, authentication, null);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication,
                                        @Nullable TokenTransportResult providedResult) throws IOException {

        if (response.isCommitted()) {
            log.error("Response already committed for user: {}", authentication.getName());
            return;
        }

        if (loginPolicyHandler != null) {
            try {
                loginPolicyHandler.onLoginSuccess(authentication.getName(), request.getRemoteAddr());
            } catch (Exception e) {
                log.error("Failed to record login success for user: {}", authentication.getName(), e);
            }
        }

        // A completed single-factor login ends any MFA left pending in this session; a token state cannot tell
        // the new login apart from the pending one through the session.
        MfaPendingSessionMarker.clear(request);

        LoginFactsRecorder.recordSingleFactor(authentication, request);
        TokenPair tokenPair = createTokenPair(authentication, null, request, response);
        // Before the response leaves, so the next request meets what the sign-in brings.
        // The client's next request is a bearer call, which is one session with the login its token carries.
        Map<String, Object> signIn = new HashMap<>();
        signIn.put("authenticationType", SignInDecision.SINGLE);
        if (authentication.getDetails() instanceof LoginFactsDetails facts) {
            signIn.put(ZeroTrustEventPublisher.TOKEN_SESSION_ID, facts.getSignInId());
        }
        SignInDecision.send(zeroTrustEventPublisher, authentication, request, signIn);
        TokenTransportResult transportResult = prepareTokenTransport(tokenPair.getAccessToken(), tokenPair.getRefreshToken());
        Map<String, Object> responseData = buildResponseData(transportResult, authentication, request, response);

        // The application's success handler (the flow's successHandler option) gets the tokens first and may write the
        // response itself, as in the MFA flows; Contexa writes its own only when it did not.
        executeDelegateHandler(request, response, authentication, TokenTransportResult.builder()
                .body(responseData)
                .cookiesToSet(transportResult != null ? transportResult.getCookiesToSet() : null)
                .cookiesToRemove(transportResult != null ? transportResult.getCookiesToRemove() : null)
                .headers(transportResult != null ? transportResult.getHeaders() : null)
                .build());
        if (response.isCommitted()) {
            return;
        }
        setCookies(response, transportResult);

        if (!isApiRequest(request)) {
            String targetUrl = determineTargetUrl(request, response);
            if (response.isCommitted()) {
                log.error("Did not redirect to {} since response already committed.", targetUrl);
                return;
            }
            this.redirectStrategy.sendRedirect(request, response, targetUrl);
        } else {
            writeJsonResponse(response, responseData);
        }
    }

    @Override
    protected Map<String, Object> buildResponseData(TokenTransportResult transportResult,
                                                    Authentication authentication,
                                                    HttpServletRequest request,
                                                    HttpServletResponse response) {

        Map<String, Object> responseData = new HashMap<>();

        if (transportResult != null && transportResult.getBody() != null) {
            responseData.putAll(transportResult.getBody());
        }

        responseData.put("authenticated", true);
        responseData.put("redirectUrl", determineTargetUrl(request, response));
        responseData.put("message", "Login successful!");
        responseData.put("username", authentication.getName());

        return responseData;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {

        if (alwaysUse && defaultTargetUrl != null) {
            return request.getContextPath() + defaultTargetUrl;
        }

        if (defaultTargetUrl != null) return request.getContextPath() + defaultTargetUrl;

        String successUrl = authContextProperties.getUrls().getSingle().getLoginSuccess();
        return request.getContextPath() + successUrl;
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        if (acceptHeader != null && acceptHeader.contains("application/json")) {
            return true;
        }
        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("application/json")) {
            return true;
        }
        String requestURI = request.getRequestURI();
        return requestURI != null && requestURI.contains("/api/");
    }
}
