package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorIdentifier;
import io.contexa.contexaidentity.security.core.validator.MfaContextValidator;
import io.contexa.contexaidentity.security.core.validator.ValidationResult;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
public class MfaStepFilterWrapper extends OncePerRequestFilter {

    private final ConfiguredFactorFilterProvider configuredFactorFilterProvider;
    private final RequestMatcher mfaFactorProcessingMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final MfaSettings mfaSettings;
    private final AuthResponseWriter responseWriter;

    public MfaStepFilterWrapper(ConfiguredFactorFilterProvider configuredFactorFilterProvider,
                                RequestMatcher mfaFactorProcessingMatcher,
                                ApplicationContext applicationContext,
                                AuthContextProperties authContextProperties, AuthResponseWriter responseWriter) {
        this.configuredFactorFilterProvider = Objects.requireNonNull(configuredFactorFilterProvider);
        this.mfaFactorProcessingMatcher = Objects.requireNonNull(mfaFactorProcessingMatcher);
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);
        this.sessionRepository = applicationContext.getBean(MfaSessionRepository.class);
        this.mfaSettings = authContextProperties.getMfa();
        this.responseWriter = responseWriter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        if (!this.mfaFactorProcessingMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        long startTime = System.currentTimeMillis();

        FactorContext ctx = (FactorContext) request.getAttribute("io.contexa.mfa.FactorContext");

        if (ctx == null) {
            ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
            if (ctx != null) {
                request.setAttribute("io.contexa.mfa.FactorContext", ctx);
            }
        } else {
        }

        ValidationResult validation = MfaContextValidator.validateFactorProcessingContext(ctx, sessionRepository);
        if (validation.hasErrors()) {
            log.error("Invalid context for MFA factor processing using {} repository. URI: {}, Errors: {}",
                    sessionRepository.getRepositoryType(), request.getRequestURI(), validation.getErrors());

            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("errors", validation.getErrors());
                errorResponse.put("warnings", validation.getWarnings());
                errorResponse.put("repositoryType", sessionRepository.getRepositoryType());

                responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                        "INVALID_MFA_CONTEXT", String.join(", ", validation.getErrors()),
                        request.getRequestURI(), errorResponse);
            }
            return;
        }

        if (validation.hasWarnings()) {
            log.error("MFA factor processing warnings: {}", validation.getWarnings());
        }
        if (isSessionExpired(ctx)) {
            log.error("MFA session expired for session: {}", ctx.getMfaSessionId());
            stateMachineIntegrator.sendEvent(MfaEvent.SESSION_TIMEOUT, ctx, request);
            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "MFA session expired");
            }
            return;
        }

        if (isRetryLimitExceeded(ctx)) {
            log.error("Retry limit exceeded for session: {}", ctx.getMfaSessionId());
            stateMachineIntegrator.sendEvent(MfaEvent.RETRY_LIMIT_EXCEEDED, ctx, request);
            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        "Maximum verification attempts exceeded");
            }
            return;
        }

        boolean accepted = stateMachineIntegrator.sendEvent(MfaEvent.SUBMIT_FACTOR_CREDENTIAL, ctx, request);
        if (!accepted) {
            log.error("State Machine rejected SUBMIT_FACTOR_CREDENTIAL event for session: {} in state: {}",
                    ctx.getMfaSessionId(), ctx.getCurrentState());

            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid state for factor verification");
            }
            return;
        }
        FactorIdentifier factorIdentifier = FactorIdentifier.of(ctx.getFlowTypeName(), ctx.getCurrentStepId());
        Filter delegateFactorFilter = configuredFactorFilterProvider.getFilter(factorIdentifier);
        if (delegateFactorFilter != null) {
            delegateFactorFilter.doFilter(request, response, chain);

        } else {
            log.error("No delegate filter found for factorIdentifier: {}", factorIdentifier);
            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "MFA factor processing misconfiguration");
            }
        }
    }

    private boolean isSessionExpired(FactorContext ctx) {
        Object challengeStartTime = ctx.getAttribute("challengeInitiatedAt");
        if (challengeStartTime instanceof Long challengeStartTimeMs) {
            return mfaSettings.isChallengeExpired(challengeStartTimeMs);
        }
        return false;
    }

    private boolean isRetryLimitExceeded(FactorContext ctx) {
        int attempts = ctx.getAttemptCount(ctx.getCurrentProcessingFactor());
        return !mfaSettings.isRetryAllowed(attempts);
    }

    private void ensureMinimumDelay(long startTime) {
        long elapsed = System.currentTimeMillis() - startTime;
        long minDelayMs = mfaSettings.getMinimumDelayMs();
        if (elapsed < minDelayMs) {
            try {
                Thread.sleep(minDelayMs - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}