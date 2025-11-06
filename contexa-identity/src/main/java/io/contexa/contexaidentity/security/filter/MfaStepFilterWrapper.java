package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.bootstrap.ConfiguredFactorFilterProvider;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorIdentifier;
import io.contexa.contexaidentity.security.core.validator.MfaContextValidator;
import io.contexa.contexaidentity.security.core.validator.ValidationResult;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.properties.MfaSettings;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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

/**
 * 완전 일원화된 MfaStepFilterWrapper
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - FilterChain 래퍼도 State Machine Service 사용
 */
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

        log.info("MfaStepFilterWrapper initialized with {} repository",
                sessionRepository.getRepositoryType());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        if (!this.mfaFactorProcessingMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        log.debug("MfaStepFilterWrapper processing factor submission request: {} using {} repository",
                request.getRequestURI(), sessionRepository.getRepositoryType());

        long startTime = System.currentTimeMillis();

        FactorContext ctx = (FactorContext) request.getAttribute("io.contexa.mfa.FactorContext");

        if (ctx == null) {
            log.debug("FactorContext not found in request attribute, loading from State Machine");
            ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
            if (ctx != null) {
                request.setAttribute("io.contexa.mfa.FactorContext", ctx);
            }
        } else {
            log.debug("FactorContext retrieved from request attribute for session: {}", ctx.getMfaSessionId());
        }

        ValidationResult validation = MfaContextValidator.validateFactorProcessingContext(ctx, sessionRepository);
        if (validation.hasErrors()) {
            log.warn("Invalid context for MFA factor processing using {} repository. URI: {}, Errors: {}",
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
            log.warn("MFA factor processing warnings: {}", validation.getWarnings());
        }
        if (isSessionExpired(ctx)) {
            log.warn("MFA session expired for session: {}", ctx.getMfaSessionId());
            stateMachineIntegrator.sendEvent(MfaEvent.SESSION_TIMEOUT, ctx, request);
            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "MFA session expired");
            }
            return;
        }

        if (isRetryLimitExceeded(ctx)) {
            log.warn("Retry limit exceeded for session: {}", ctx.getMfaSessionId());
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
            log.info("Delegating MFA factor processing for {} to filter: {} using {} repository",
                    factorIdentifier, delegateFactorFilter.getClass().getName(),
                    sessionRepository.getRepositoryType());

            FilterChain wrappedChain = new RepositoryAwareStateMachineFilterChain(
                    chain, ctx, request, stateMachineIntegrator, sessionRepository, startTime,mfaSettings);

            delegateFactorFilter.doFilter(request, response, wrappedChain);
        } else {
            log.error("No delegate filter found for factorIdentifier: {}", factorIdentifier);
            ensureMinimumDelay(startTime);

            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "MFA factor processing misconfiguration");
            }
        }
    }

    /**
     * 개선: MfaSettings를 활용한 세션 만료 확인 (하드코딩 상수 제거)
     */
    private boolean isSessionExpired(FactorContext ctx) {
        Object challengeStartTime = ctx.getAttribute("challengeInitiatedAt");
        if (challengeStartTime instanceof Long challengeStartTimeMs) {
            // 개선: MfaSettings의 메서드 활용
            return mfaSettings.isChallengeExpired(challengeStartTimeMs);
        }
        return false;
    }

    /**
     * 개선: MfaSettings를 활용한 재시도 한계 확인 (하드코딩 상수 제거)
     */
    private boolean isRetryLimitExceeded(FactorContext ctx) {
        int attempts = ctx.getAttemptCount(ctx.getCurrentProcessingFactor());
        // 개선: MfaSettings의 메서드 활용
        return !mfaSettings.isRetryAllowed(attempts);
    }

    /**
     * 개선: MfaSettings를 활용한 최소 지연 보장 (하드코딩 상수 제거)
     */
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

    /**
     * 완전 일원화된 State Machine 인식 FilterChain 래퍼
     * - ContextPersistence 제거하고 MfaStateMachineService만 사용
     */
    private static class RepositoryAwareStateMachineFilterChain implements FilterChain {
        private final FilterChain delegate;
        private final FactorContext context;
        private final HttpServletRequest request;
        private final MfaStateMachineIntegrator stateMachineIntegrator;
        private final MfaSessionRepository sessionRepository;
        private final long startTime;
        private final MfaSettings mfaSettings;

        public RepositoryAwareStateMachineFilterChain(FilterChain delegate, FactorContext context,
                                                      HttpServletRequest request,
                                                      MfaStateMachineIntegrator stateMachineIntegrator,
                                                      MfaSessionRepository sessionRepository,
                                                      long startTime, MfaSettings mfaSettings) {
            this.delegate = delegate;
            this.context = context;
            this.request = request;
            this.stateMachineIntegrator = stateMachineIntegrator;
            this.sessionRepository = sessionRepository;
            this.startTime = startTime;
            this.mfaSettings = mfaSettings;
        }

        @Override
        public void doFilter(jakarta.servlet.ServletRequest servletRequest,
                             jakarta.servlet.ServletResponse servletResponse)
                throws IOException, ServletException {

            HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

            try {
                delegate.doFilter(servletRequest, servletResponse);

                if (httpResponse.isCommitted()) {
                    log.debug("MFA Step Filter Wrapper (session {}): Response committed - final auth success. Skipping saveFactorContext.",
                              context.getMfaSessionId());
                    return;
                }

                if (!sessionRepository.existsSession(context.getMfaSessionId())) {
                    log.debug("MFA Step Filter Wrapper (session {}): Session no longer exists. Skipping saveFactorContext.",
                              context.getMfaSessionId());
                    return;
                }

                long verificationTime = System.currentTimeMillis() - startTime;
                context.updateLastActivityTimestamp();
                sessionRepository.refreshSession(context.getMfaSessionId());

                log.debug("MFA Step Filter Wrapper (session {}): FactorContext already saved by handler. Verification time: {}ms, Current state: {}",
                        context.getMfaSessionId(), verificationTime, context.getCurrentState());

            } catch (Exception e) {
                log.error("MFA Step Filter Wrapper (session {}): Error during delegate filter execution using {} repository.",
                        context.getMfaSessionId(), sessionRepository.getRepositoryType(), e);

                if (e instanceof org.springframework.security.core.AuthenticationException) {
                    log.debug("MFA Step Filter Wrapper (session {}): AuthenticationException - already saved by FailureHandler",
                             context.getMfaSessionId());
                } else {
                    log.debug("MFA Step Filter Wrapper (session {}): Sending SYSTEM_ERROR event due to non-AuthenticationException.",
                             context.getMfaSessionId());
                    stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, context, this.request);
                }
                throw e;
            } finally {
                ensureMinimumDelay(startTime);
            }
        }

        private void ensureMinimumDelay(long processingStartTime) {
            long elapsed = System.currentTimeMillis() - processingStartTime;
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
}