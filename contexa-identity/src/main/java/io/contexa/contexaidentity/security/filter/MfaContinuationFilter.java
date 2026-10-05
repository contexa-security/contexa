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
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.validator.MfaContextValidator;
import io.contexa.contexaidentity.security.core.validator.ValidationResult;
import io.contexa.contexaidentity.security.filter.handler.MfaRequestHandler;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.filter.handler.StateMachineAwareMfaRequestHandler;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import io.contexa.contexaidentity.security.filter.matcher.MfaUrlMatcher;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Slf4j
public class MfaContinuationFilter extends OncePerRequestFilter {

    public static final String FACTOR_CONTEXT_ATTR = "io.contexa.mfa.FactorContext";
    public static final String VALIDATION_RESULT_ATTR = "io.contexa.mfa.ValidationResult";

    private volatile boolean initialized = false;

    private final AuthResponseWriter responseWriter;
    private final MfaRequestHandler requestHandler;
    private final MfaUrlMatcher urlMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final AuthUrlProvider authUrlProvider;
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;
    private volatile String flowTypeName;
    private volatile AuthUrlProvider flowUrlProvider;
    private volatile boolean restorePrimaryProof;
    private static final RequestAttributeSecurityContextRepository REQUEST_CONTEXT_REPOSITORY =
            new RequestAttributeSecurityContextRepository();
    private volatile Set<String> primaryProofPaths = Set.of();

    public MfaContinuationFilter(AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 ApplicationContext applicationContext) {
        this.responseWriter = Objects.requireNonNull(responseWriter);

        this.authUrlProvider = applicationContext.getBean(AuthUrlProvider.class);
        this.urlMatcher = new MfaUrlMatcher(authUrlProvider, applicationContext);
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        this.sessionRepository = applicationContext.getBean(MfaSessionRepository.class);
        this.mfaFlowUrlRegistry = applicationContext.getBean(MfaFlowUrlRegistry.class);

        this.requestHandler = new StateMachineAwareMfaRequestHandler(
                authContextProperties,
                responseWriter,
                applicationContext,
                stateMachineIntegrator,
                authUrlProvider,
                sessionRepository,
                mfaFlowUrlRegistry
        );
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (!initialized) {
            log.error("MfaContinuationFilter not initialized. URL matchers must be initialized before processing requests.");
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                    "MFA service is initializing. Please try again in a moment.");
            return;
        }

        if (restorePrimaryProof) {
            restorePrimaryProofForMfaRequest(request, response);
        }

        if (!urlMatcher.isMfaRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (ctx != null) {
            request.setAttribute(FACTOR_CONTEXT_ATTR, ctx);
        }

        if (this.flowTypeName != null && ctx != null
                && ctx.getFlowTypeName() != null
                && !this.flowTypeName.equalsIgnoreCase(ctx.getFlowTypeName())) {
            filterChain.doFilter(request, response);
            return;
        }

        ValidationResult validation = MfaContextValidator.validateFactorSelectionContext(ctx);
        request.setAttribute(VALIDATION_RESULT_ATTR, validation);

        if (validation.hasErrors()) {
            log.error("Invalid MFA context for request: {} - Errors: {}",
                    request.getRequestURI(), validation.getErrors());
            handleInvalidContext(request, response, validation);
            return;
        }

        if (validation.hasWarnings()) {
            log.error("MFA context warnings for request: {} - Warnings: {}",
                    request.getRequestURI(), validation.getWarnings());
        }

        if (ctx.getCurrentState().isTerminal()) {
            requestHandler.handleTerminalContext(request, response, ctx);
            return;
        }

        try {
            MfaRequestType requestType = urlMatcher.getRequestType(request);
            requestHandler.handleRequest(requestType, request, response, ctx, filterChain);
        } catch (Exception e) {
            requestHandler.handleGenericError(request, response, ctx, e);
        }
    }

    private void handleInvalidContext(HttpServletRequest request, HttpServletResponse response,
                                      ValidationResult validation) throws IOException {

        FactorContext ctx = (FactorContext) request.getAttribute(FACTOR_CONTEXT_ATTR);
        String oldSessionId = ctx != null ? ctx.getMfaSessionId() : sessionRepository.getSessionId(request);

        if (oldSessionId != null && sessionRepository.existsSession(oldSessionId)) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, response);
            } catch (Exception e) {
                log.error("Failed to cleanup invalid session: {}", oldSessionId, e);
            }
        } else if (oldSessionId != null) {
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_SESSION_INVALID");
        errorResponse.put("message", "MFA session is invalid.");
        errorResponse.put("errors", validation.getErrors());
        errorResponse.put("warnings", validation.getWarnings());
        errorResponse.put("redirectUrl", request.getContextPath() + resolveProvider(request).getPrimaryLoginPage());
        errorResponse.put("repositoryType", sessionRepository.getRepositoryType());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "MFA_SESSION_INVALID", String.join(", ", validation.getErrors()),
                request.getRequestURI(), errorResponse);
    }

    public void initializeUrlMatchers() {
        this.flowUrlProvider = authUrlProvider;
        this.primaryProofPaths = resolvePrimaryProofPaths(authUrlProvider);
        urlMatcher.initializeMatchers();
        initialized = true;
    }

    public void initializeUrlMatchers(AuthUrlProvider flowUrlProvider) {
        this.flowUrlProvider = flowUrlProvider;
        this.primaryProofPaths = resolvePrimaryProofPaths(flowUrlProvider);
        this.urlMatcher.initializeMatchers(flowUrlProvider);
        initialized = true;
    }

    /**
     * Enables the per-request restoration of the primary proof. Only token states use it, because they
     * keep no login in the HTTP session while the second factor is pending.
     */
    public void setRestorePrimaryProof(boolean restorePrimaryProof) {
        this.restorePrimaryProof = restorePrimaryProof;
    }

    /**
     * The MFA step URLs of the flow. The primary login and logout URLs are excluded because they start or
     * end a login, and the passkey registration URLs are not MFA steps, so a pending MFA never reaches them.
     */
    private static Set<String> resolvePrimaryProofPaths(AuthUrlProvider provider) {
        Set<String> paths = new LinkedHashSet<>(provider.getMfaInProgressUrls());
        paths.remove(provider.getPrimaryLoginPage());
        paths.remove(provider.getPrimaryFormLoginProcessing());
        paths.remove(provider.getPrimaryRestLoginProcessing());
        paths.remove(provider.getPrimaryLoginFailure());
        paths.remove(provider.getLogoutPage());
        paths.remove(provider.getLogoutProcessingUrl());
        return Set.copyOf(paths);
    }


    /**
     * Expose primary proof only for the current, configured MFA request. It is never
     * persisted as a completed login; ordinary application requests remain unauthenticated.
     */
    private void restorePrimaryProofForMfaRequest(HttpServletRequest request, HttpServletResponse response) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if (!primaryProofPaths.contains(path)) {
            return;
        }
        var existing = SecurityContextHolder.getContext().getAuthentication();
        if (existing != null && !(existing instanceof AnonymousAuthenticationToken)) {
            return;
        }
        FactorContext context = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (context == null || MfaContextValidator.validateMfaContext(context).hasErrors()
                || (flowTypeName != null && !flowTypeName.equalsIgnoreCase(context.getFlowTypeName()))) {
            return;
        }
        var primary = context.getPrimaryAuthentication();
        if (primary == null || !primary.isAuthenticated()) {
            return;
        }
        var requestContext = SecurityContextHolder.createEmptyContext();
        requestContext.setAuthentication(primary);
        SecurityContextHolder.setContext(requestContext);
        // Registered for this request only, as the stateless Spring authentication filters do. Without it the
        // session management of the chain takes the proof for a new login and rotates session and CSRF token.
        REQUEST_CONTEXT_REPOSITORY.saveContext(requestContext, request, response);
    }

    private AuthUrlProvider resolveProvider(HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (ctx != null && ctx.getFlowTypeName() != null) {
            AuthUrlProvider flowProvider = mfaFlowUrlRegistry.getProvider(ctx.getFlowTypeName());
            if (flowProvider != null) {
                return flowProvider;
            }
        }
        return authUrlProvider;
    }

    public void setFlowTypeName(String flowTypeName) {
        this.flowTypeName = flowTypeName;
    }
}
