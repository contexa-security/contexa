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

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.OttUrls;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Slf4j
public final class OneTimeTokenCreationSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

    /** Where a flow by code alone names, with the request, the page that takes its code. */
    public static final String SUBMIT_PAGE_ATTRIBUTE = "io.contexa.ott.submitPageUrl";

    /** The "code sent" address of the settings while the application has named none of its own. */
    private static final String DEFAULT_CODE_SENT_URL = new OttUrls().getCodeSent();

    private final MfaStateMachineIntegrator mfaStateMachineIntegrator;
    private final AuthUrlProvider authUrlProvider;
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;
    private final MfaSessionRepository sessionRepository;

    public OneTimeTokenCreationSuccessHandler(
            MfaStateMachineIntegrator mfaStateMachineIntegrator,
            AuthUrlProvider authUrlProvider,
            MfaFlowUrlRegistry mfaFlowUrlRegistry,
            MfaSessionRepository sessionRepository) {
        this.mfaStateMachineIntegrator = mfaStateMachineIntegrator;
        this.authUrlProvider = authUrlProvider;
        this.mfaFlowUrlRegistry = mfaFlowUrlRegistry;
        this.sessionRepository = sessionRepository;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException {

        FactorContext factorContext = mfaStateMachineIntegrator.loadFactorContextFromRequest(request);
        String usernameFromToken = token.getUsername();

        if (factorContext != null &&
                MfaFlowTypeUtils.isMfaFlow(factorContext.getFlowTypeName()) &&
                Objects.equals(factorContext.getUsername(), usernameFromToken) &&
                factorContext.getCurrentProcessingFactor() == AuthType.MFA_OTT) {

            if (!sessionRepository.existsSession(factorContext.getMfaSessionId())) {
                log.error("MFA session {} not found in {} repository during OTT generation",
                        factorContext.getMfaSessionId(), sessionRepository.getRepositoryType());
                handleSessionNotFound(request, response, usernameFromToken);
                return;
            }

            sessionRepository.refreshSession(factorContext.getMfaSessionId());

            mfaStateMachineIntegrator.sendEvent(MfaEvent.INITIATE_CHALLENGE, factorContext, request);

            String challengeUiUrl = resolveProvider(request).getOttChallengeUi();
            String redirectUrl = request.getContextPath() + challengeUiUrl;
            response.sendRedirect(redirectUrl);
            return;
        }

        if ((factorContext == null || !MfaFlowTypeUtils.isMfaFlow(factorContext.getFlowTypeName()))) {
            // An application that named a "code sent" address of its own (contexa.auth.urls.factors.ott.code-sent) has a
            // page there, and a sign-in by mail code alone goes to it as it always did, with the same parameters.
            String namedCodeSentUrl = resolveProvider(request).getOttCodeSent();
            if (StringUtils.hasText(namedCodeSentUrl) && !DEFAULT_CODE_SENT_URL.equals(namedCodeSentUrl)) {
                response.sendRedirect(request.getContextPath() + namedCodeSentUrl
                        + "?email=" + URLEncoder.encode(usernameFromToken, StandardCharsets.UTF_8)
                        + "&type=code_sent"
                        + "&flow=ott_single"
                        + "&repository=" + sessionRepository.getRepositoryType());
                return;
            }
            // Unnamed, that address is the "code sent" page of the MFA pages, which a sign-in by mail code alone does
            // not have: it answers "not found" in such a flow. The browser goes on to the page that takes the code,
            // which the flow does have. The name the code was asked for stays out of the address.
            // The flow names the page with the request (its DSL's defaultSubmitPageUrl); without that the page of the
            // settings is the one a flow by code alone has by default.
            String submitPageUrl = request.getAttribute(SUBMIT_PAGE_ATTRIBUTE) instanceof String named ? named : null;
            if (!StringUtils.hasText(submitPageUrl)) {
                submitPageUrl = resolveProvider(request).getSingleOttChallenge();
            }
            if (!StringUtils.hasText(submitPageUrl)) {
                submitPageUrl = "/login/ott/verify";
            }

            response.sendRedirect(request.getContextPath() + submitPageUrl);
            return;
        }

        if (factorContext != null && Objects.equals(factorContext.getUsername(), usernameFromToken)
                && factorContext.getCurrentProcessingFactor() != AuthType.MFA_OTT) {
            // The person chose another factor (a passkey) and then asked for a code: back to the choice of factors,
            // where the mail code can be chosen. The reason given was "user not found".
            log.warn("OTT code requested while factor {} is selected: repository={}, flow={}",
                    factorContext.getCurrentProcessingFactor(), sessionRepository.getRepositoryType(),
                    factorContext.getFlowTypeName());
            response.sendRedirect(request.getContextPath() + resolveProvider(request).getMfaSelectFactor());
            return;
        }

        log.warn("OTT context mismatch: repository={}, flow={}, contextUser={}, tokenUser={}",
                sessionRepository.getRepositoryType(),
                factorContext != null ? factorContext.getFlowTypeName() : null,
                factorContext != null ? factorContext.getUsername() : null,
                usernameFromToken);

        String ottRequestUrl = resolveProvider(request).getOttRequestCodeUi();
        if (!StringUtils.hasText(ottRequestUrl)) {
            ottRequestUrl = "/mfa/ott/request-code-ui";
        }
        response.sendRedirect(request.getContextPath() + ottRequestUrl + "?error=user_not_found");
    }

    private AuthUrlProvider resolveProvider(HttpServletRequest request) {
        FactorContext ctx = mfaStateMachineIntegrator.loadFactorContextFromRequest(request);
        if (ctx != null && ctx.getFlowTypeName() != null && mfaFlowUrlRegistry != null) {
            AuthUrlProvider flowProvider = mfaFlowUrlRegistry.getProvider(ctx.getFlowTypeName());
            if (flowProvider != null) {
                return flowProvider;
            }
        }
        return authUrlProvider;
    }

    private void handleSessionNotFound(HttpServletRequest request, HttpServletResponse response,
                                       String username) throws IOException {
        log.error("Session not found in {} repository during OTT generation for user: {}",
                sessionRepository.getRepositoryType(), username);

        String redirectUrl = request.getContextPath() + "/login?error=session_not_found&repository=" +
                sessionRepository.getRepositoryType();
        response.sendRedirect(redirectUrl);
    }
}
