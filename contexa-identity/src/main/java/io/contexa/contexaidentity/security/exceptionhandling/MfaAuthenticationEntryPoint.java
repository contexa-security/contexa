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
package io.contexa.contexaidentity.security.exceptionhandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.domain.ErrorResponse;
import io.contexa.contexacommon.enums.ErrorCode;
import io.contexa.contexacommon.properties.MfaPageConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.function.Function;

@Slf4j
public class MfaAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final MfaPageConfig mfaPageConfig;
    private final AuthUrlProvider authUrlProvider;
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    public MfaAuthenticationEntryPoint(ObjectMapper objectMapper, String loginPageUrl,
                                       MfaPageConfig mfaPageConfig, AuthUrlProvider authUrlProvider,
                                       MfaFlowUrlRegistry mfaFlowUrlRegistry,
                                       MfaStateMachineIntegrator stateMachineIntegrator) {
        super(loginPageUrl);
        Assert.notNull(objectMapper, "ObjectMapper cannot be null");
        this.objectMapper = objectMapper;
        this.mfaPageConfig = mfaPageConfig;
        this.authUrlProvider = authUrlProvider;
        this.mfaFlowUrlRegistry = mfaFlowUrlRegistry;
        this.stateMachineIntegrator = stateMachineIntegrator;
    }

    public MfaAuthenticationEntryPoint(ObjectMapper objectMapper, String loginPageUrl, MfaPageConfig mfaPageConfig) {
        this(objectMapper, loginPageUrl, mfaPageConfig, null, null, null);
    }

    public MfaAuthenticationEntryPoint withRuntimeDependencies(
            AuthUrlProvider authUrlProvider,
            MfaFlowUrlRegistry mfaFlowUrlRegistry,
            MfaStateMachineIntegrator stateMachineIntegrator) {
        Assert.notNull(authUrlProvider, "AuthUrlProvider cannot be null");
        Assert.notNull(mfaFlowUrlRegistry, "MfaFlowUrlRegistry cannot be null");
        Assert.notNull(stateMachineIntegrator, "MfaStateMachineIntegrator cannot be null");
        return new MfaAuthenticationEntryPoint(
                objectMapper,
                getLoginFormUrl(),
                mfaPageConfig,
                authUrlProvider,
                mfaFlowUrlRegistry,
                stateMachineIntegrator);
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        if (WebUtil.isApiOrAjaxRequest(request)) {
            response.setContentType("application/json; charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            ErrorResponse body = new ErrorResponse(
                    Instant.now().toString(),
                    HttpServletResponse.SC_UNAUTHORIZED,
                    ErrorCode.AUTH_FAILED.code(),
                    ErrorCode.AUTH_FAILED.message(),
                    request.getRequestURI()
            );

            objectMapper.writeValue(response.getOutputStream(), body);
            return;
        }

        super.commence(request, response, authException);
    }

    @Override
    protected String determineUrlToUseForThisRequest(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) {

        if (isPasskeyRegistrationRequest(request)) {
            // Passkey registration needs a completed login, not the passkey step of an MFA flow.
            return getLoginFormUrl();
        }

        String factorType = request.getParameter("factor.type");
        // Read once: with an MFA session open it is the flow's own provider, read from the session store.
        AuthUrlProvider provider = providerOrNull(request);

        if ("select".equalsIgnoreCase(factorType) || isSelectFactorRequest(request, provider)) {
            return getSelectFactorPageUrl(request);
        }

        if ("ott".equalsIgnoreCase(factorType) || isOttRequestPageRequest(request, provider)) {
            return getOttRequestPageUrl(request);
        }

        if ("ott-verify".equalsIgnoreCase(factorType) || isOttVerifyPageRequest(request, provider)) {
            return getOttVerifyPageUrl(request);
        }

        if ("passkey".equalsIgnoreCase(factorType) || "webauthn".equalsIgnoreCase(factorType) ||
                isPasskeyChallengeRequest(request, provider)) {
            return getPasskeyChallengePageUrl(request);
        }

        if ("configure".equalsIgnoreCase(factorType) || isConfigurePageRequest(request, provider)) {
            return getConfigurePageUrl(request);
        }

        if ("failure".equalsIgnoreCase(factorType) || isFailurePageRequest(request, provider)) {
            return getFailurePageUrl(request);
        }

        return getLoginFormUrl();  
    }

    private String getSelectFactorPageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomSelectFactorPage()) {
            return mfaPageConfig.getSelectFactorPageUrl();
        }
        return resolveProvider(request).getMfaSelectFactor();
    }

    private String getOttRequestPageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttRequestPage()) {
            return mfaPageConfig.getOttRequestPageUrl();
        }
        return resolveProvider(request).getOttRequestCodeUi();
    }

    private String getOttVerifyPageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomOttVerifyPage()) {
            return mfaPageConfig.getOttVerifyPageUrl();
        }
        return resolveProvider(request).getOttChallengeUi();
    }

    private String getPasskeyChallengePageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomPasskeyPage()) {
            return mfaPageConfig.getPasskeyChallengePageUrl();
        }
        return resolveProvider(request).getPasskeyChallengeUi();
    }

    private String getConfigurePageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomConfigurePage()) {
            return mfaPageConfig.getConfigurePageUrl();
        }
        return resolveProvider(request).getMfaConfig();
    }

    private String getFailurePageUrl(HttpServletRequest request) {
        if (mfaPageConfig != null && mfaPageConfig.hasCustomFailurePage()) {
            return mfaPageConfig.getFailurePageUrl();
        }
        return resolveProvider(request).getMfaFailure();
    }

    private AuthUrlProvider resolveProvider(HttpServletRequest request) {
        if (stateMachineIntegrator != null) {
            FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
            if (ctx != null && ctx.getFlowTypeName() != null && mfaFlowUrlRegistry != null) {
                AuthUrlProvider flowProvider = mfaFlowUrlRegistry.getProvider(ctx.getFlowTypeName());
                if (flowProvider != null) {
                    return flowProvider;
                }
            }
        }
        if (authUrlProvider != null) {
            return authUrlProvider;
        }
        throw new IllegalStateException("AuthUrlProvider is not available in MfaAuthenticationEntryPoint");
    }

    /*
     * A step page is the page itself: the address the step is served at, or the step's own name at the end of the path
     * (a flow under a prefix serves it there). A part of a name anywhere in the address is not one: the console's
     * "/ai-monitor/failures" is not the MFA failure page, and a person whose session ended there is sent to sign in.
     */

    private boolean isSelectFactorRequest(HttpServletRequest request, AuthUrlProvider provider) {
        return isStepPage(request, provider, AuthUrlProvider::getMfaSelectFactor, "/mfa/select-factor");
    }

    private boolean isOttRequestPageRequest(HttpServletRequest request, AuthUrlProvider provider) {
        return isStepPage(request, provider, AuthUrlProvider::getOttRequestCodeUi, "/loginOtt", "/ott/request");
    }

    private boolean isOttVerifyPageRequest(HttpServletRequest request, AuthUrlProvider provider) {
        return isStepPage(request, provider, AuthUrlProvider::getOttChallengeUi, "/ott/verify", "/mfa/challenge/ott");
    }

    private boolean isPasskeyRegistrationRequest(HttpServletRequest request) {
        if (authUrlProvider == null) {
            return false;
        }
        String registrationPage = request.getContextPath() + authUrlProvider.getPasskeyRegistrationPage();
        String uri = request.getRequestURI();
        return uri.equals(registrationPage) || uri.startsWith(registrationPage + "/");
    }

    private boolean isPasskeyChallengeRequest(HttpServletRequest request, AuthUrlProvider provider) {
        // The WebAuthn ceremony is served under its own path segment.
        return pathOf(request).contains("/webauthn/")
                || isStepPage(request, provider, AuthUrlProvider::getPasskeyChallengeUi,
                "/loginPasskey", "/mfa/challenge/passkey");
    }

    private boolean isConfigurePageRequest(HttpServletRequest request, AuthUrlProvider provider) {
        return isStepPage(request, provider, AuthUrlProvider::getMfaConfig, "/mfa/configure");
    }

    private boolean isFailurePageRequest(HttpServletRequest request, AuthUrlProvider provider) {
        return isStepPage(request, provider, AuthUrlProvider::getMfaFailure, "/mfa/failure");
    }

    private static boolean isStepPage(HttpServletRequest request, AuthUrlProvider provider,
                                      Function<AuthUrlProvider, String> servedAt, String... names) {
        String path = pathOf(request);
        for (String name : names) {
            if (path.endsWith(name)) {
                return true;
            }
        }
        String page = provider != null ? servedAt.apply(provider) : null;
        if (!StringUtils.hasText(page)) {
            return false;
        }
        int query = page.indexOf('?');
        return path.equals(query >= 0 ? page.substring(0, query) : page);
    }

    private AuthUrlProvider providerOrNull(HttpServletRequest request) {
        try {
            return resolveProvider(request);
        } catch (IllegalStateException notBound) {
            return null;
        }
    }

    /** The path within the application, as the step pages are named. */
    private static String pathOf(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        return StringUtils.hasText(context) && uri.startsWith(context) ? uri.substring(context.length()) : uri;
    }
}
