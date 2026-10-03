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
package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPendingSessionMarker;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Restricts HTTP sessions whose primary authentication succeeded but whose MFA has not completed.
 *
 * <p>The primary MFA authentication filters persist the authenticated SecurityContext into the HTTP
 * session so that it survives the redirects of the MFA flow, and mark the session with
 * {@link MfaPendingSessionMarker}. Without this filter such a session could reach any protected
 * resource with the first factor only: the MFA continuation filter handles MFA URLs only, and
 * authorization rules such as {@code isAuthenticated()} cannot tell it apart from a completed login.</p>
 *
 * <p>For a marked session carrying an authenticated principal, only the requests needed to progress or
 * leave the MFA flow pass: login, logout, MFA pages and factor endpoints of every registered flow, the
 * MFA configuration endpoint, Contexa static resources, Zero Trust notice pages and the error path.
 * Every other request is denied: browser requests are redirected to the MFA page of the pending flow
 * (or to its login page when the MFA session no longer exists), API requests receive a 401 JSON error.</p>
 *
 * <p>Passkey registration requests are denied as well, because registering a passkey with the first
 * factor alone would let the second factor be bypassed. They are answered with guidance instead of the
 * generic error: browser requests are redirected to the MFA passkey page of the pending flow, which
 * explains how to verify the identity first, and API requests receive a 401 JSON error with the code
 * {@value #PASSKEY_REGISTRATION_ERROR_CODE} and the URL of the next step.</p>
 *
 * <p>The filter is registered in every flow chain, because a protected resource may be served by a
 * chain other than the MFA flow chain while sharing the same HTTP session.</p>
 */
@Slf4j
public class MfaPendingAccessControlFilter extends OncePerRequestFilter {

    public static final String ERROR_CODE = "MFA_REQUIRED";

    public static final String PASSKEY_REGISTRATION_ERROR_CODE = "PASSKEY_REGISTRATION_REQUIRES_MFA";

    private static final String ERROR_MESSAGE = "Multi-factor authentication must be completed to access this resource";
    private static final String PASSKEY_REGISTRATION_ERROR_MESSAGE =
            "A passkey can be registered only after multi-factor authentication is completed. "
                    + "Verify your identity in the MFA flow first, for example with an email verification code; "
                    + "passkey registration becomes available once sign-in is complete.";
    private static final String CONTEXA_SCRIPT_PREFIX = "/js/contexa-";
    private static final String SCRIPT_SUFFIX = ".js";
    private static final String FAVICON_PATH = "/favicon.ico";
    private static final List<String> PERMITTED_PATH_PREFIXES = List.of(
            "/contexa/zero-trust/",
            "/contexa/css/",
            "/contexa/js/",
            "/contexa/img/",
            "/.well-known/");

    private final AuthUrlProvider authUrlProvider;
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;
    private final MfaSessionRepository sessionRepository;
    private final AuthResponseWriter responseWriter;
    private final String errorPath;
    private final SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    public MfaPendingAccessControlFilter(AuthUrlProvider authUrlProvider,
                                         MfaFlowUrlRegistry mfaFlowUrlRegistry,
                                         MfaSessionRepository sessionRepository,
                                         AuthResponseWriter responseWriter,
                                         String errorPath) {
        Assert.notNull(authUrlProvider, "authUrlProvider cannot be null");
        Assert.notNull(mfaFlowUrlRegistry, "mfaFlowUrlRegistry cannot be null");
        Assert.notNull(sessionRepository, "sessionRepository cannot be null");
        Assert.notNull(responseWriter, "responseWriter cannot be null");
        this.authUrlProvider = authUrlProvider;
        this.mfaFlowUrlRegistry = mfaFlowUrlRegistry;
        this.sessionRepository = sessionRepository;
        this.responseWriter = responseWriter;
        this.errorPath = errorPath;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String pendingFlowTypeName = MfaPendingSessionMarker.getPendingFlowTypeName(request);
        if (pendingFlowTypeName == null || isMfaProgressRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // A token state keeps no login in the session, so a pending MFA restricts the session whatever
        // authentication the request carries; the session state keeps its rule unchanged.
        Authentication authentication = securityContextHolderStrategy.getContext().getAuthentication();
        if (!MfaPendingSessionMarker.isTokenStatePending(request)
                && (authentication == null
                || !authentication.isAuthenticated()
                || trustResolver.isAnonymous(authentication))) {
            filterChain.doFilter(request, response);
            return;
        }

        denyAccess(request, response, pendingFlowTypeName);
    }

    /**
     * Returns whether the request is required to progress or leave the MFA flow and may therefore
     * pass while MFA is pending. Subclasses may extend the permitted requests, for example with
     * static resources of custom MFA pages.
     */
    protected boolean isMfaProgressRequest(HttpServletRequest request) {
        String path = resolvePath(request);
        if (path.equals(FAVICON_PATH) || (StringUtils.hasText(errorPath) && path.equals(errorPath))) {
            return true;
        }
        if (path.startsWith(CONTEXA_SCRIPT_PREFIX) && path.endsWith(SCRIPT_SUFFIX)) {
            return true;
        }
        for (String prefix : PERMITTED_PATH_PREFIXES) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        return authUrlProvider.getMfaInProgressUrls().contains(path)
                || mfaFlowUrlRegistry.getAllMfaInProgressUrls().contains(path);
    }

    private void denyAccess(HttpServletRequest request,
                            HttpServletResponse response,
                            String pendingFlowTypeName) throws IOException {

        AuthUrlProvider provider = resolveProvider(pendingFlowTypeName);
        boolean mfaSessionActive = isMfaSessionActive(request);

        if (isPasskeyRegistrationRequest(request)) {
            denyPasskeyRegistration(request, response, provider, mfaSessionActive);
            return;
        }

        String redirectUrl = request.getContextPath()
                + (mfaSessionActive ? provider.getMfaSelectFactor() : provider.getPrimaryLoginPage());

        if (WebUtil.isApiOrAjaxRequest(request)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", ERROR_CODE);
            body.put("message", ERROR_MESSAGE);
            body.put("mfaSessionActive", mfaSessionActive);
            body.put("redirectUrl", redirectUrl);
            if (mfaSessionActive) {
                body.put("mfaUrl", redirectUrl);
            }
            responseWriter.writeErrorResponse(
                    response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    ERROR_CODE,
                    ERROR_MESSAGE,
                    request.getRequestURI(),
                    body);
            return;
        }

        response.sendRedirect(redirectUrl);
    }

    /**
     * Denies a passkey registration request of a session with an incomplete MFA. The next step is the
     * MFA passkey page of the pending flow, which explains how to verify the identity before a passkey
     * can be registered, or the login page when the MFA session no longer exists.
     */
    private void denyPasskeyRegistration(HttpServletRequest request,
                                         HttpServletResponse response,
                                         AuthUrlProvider provider,
                                         boolean mfaSessionActive) throws IOException {

        String nextStepUrl = request.getContextPath()
                + (mfaSessionActive ? provider.getPasskeyChallengeUi() : provider.getPrimaryLoginPage());

        if (WebUtil.isApiOrAjaxRequest(request)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", PASSKEY_REGISTRATION_ERROR_CODE);
            body.put("message", PASSKEY_REGISTRATION_ERROR_MESSAGE);
            body.put("mfaSessionActive", mfaSessionActive);
            body.put("nextStepUrl", nextStepUrl);
            body.put("redirectUrl", nextStepUrl);
            if (mfaSessionActive) {
                body.put("mfaUrl", nextStepUrl);
            }
            responseWriter.writeErrorResponse(
                    response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    PASSKEY_REGISTRATION_ERROR_CODE,
                    PASSKEY_REGISTRATION_ERROR_MESSAGE,
                    request.getRequestURI(),
                    body);
            return;
        }

        response.sendRedirect(nextStepUrl);
    }

    private boolean isPasskeyRegistrationRequest(HttpServletRequest request) {
        String path = resolvePath(request);
        return authUrlProvider.getPasskeyRegistrationUrls().contains(path)
                || mfaFlowUrlRegistry.getAllPasskeyRegistrationUrls().contains(path);
    }

    private boolean isMfaSessionActive(HttpServletRequest request) {
        try {
            String mfaSessionId = sessionRepository.getSessionId(request);
            return mfaSessionId != null && sessionRepository.existsSession(mfaSessionId);
        } catch (Exception e) {
            log.error("Failed to resolve MFA session state while MFA is pending", e);
            return false;
        }
    }

    private AuthUrlProvider resolveProvider(String flowTypeName) {
        AuthUrlProvider flowProvider = mfaFlowUrlRegistry.getProvider(flowTypeName);
        return flowProvider != null ? flowProvider : authUrlProvider;
    }

    private String resolvePath(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (StringUtils.hasText(contextPath) && requestUri.startsWith(contextPath)) {
            return requestUri.substring(contextPath.length());
        }
        return requestUri;
    }
}
