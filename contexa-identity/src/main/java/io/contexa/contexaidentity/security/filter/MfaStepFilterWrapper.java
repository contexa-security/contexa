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

        // 통합된 검증 로직 사용
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
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

        // 경고 로깅
        if (validation.hasWarnings()) {
            log.warn("MFA factor processing warnings: {}", validation.getWarnings());
        }

        // 개선: Repository를 통한 세션 검증
        if (!sessionRepository.existsSession(ctx.getMfaSessionId())) {
            log.warn("MFA session {} not found in {} repository during factor processing",
                    ctx.getMfaSessionId(), sessionRepository.getRepositoryType());
            ensureMinimumDelay(startTime);
            if (!response.isCommitted()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Session not found");
            }
            return;
        }

        // 세션 타임아웃 및 재시도 한계 확인
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

            ctx.setAttribute("verificationStartTime", System.currentTimeMillis());
            stateMachineIntegrator.saveFactorContext(ctx);

            // FilterChain 래퍼에 Repository 정보 전달
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
        // 개선: MfaSettings 에서 최소 지연 시간 가져오기
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
        private final HttpServletRequest request; // HttpServletRequest 저장
        private final MfaStateMachineIntegrator stateMachineIntegrator;
        private final MfaSessionRepository sessionRepository;
        private final long startTime; // 요청 시작 시간 (최소 지연 시간 보장용)
        private final MfaSettings mfaSettings; // MfaSettings 주입

        public RepositoryAwareStateMachineFilterChain(FilterChain delegate, FactorContext context,
                                                      HttpServletRequest request, // request 추가
                                                      MfaStateMachineIntegrator stateMachineIntegrator,
                                                      MfaSessionRepository sessionRepository,
                                                      long startTime, MfaSettings mfaSettings) { // mfaSettings 추가
            this.delegate = delegate;
            this.context = context;
            this.request = request; // 저장
            this.stateMachineIntegrator = stateMachineIntegrator;
            this.sessionRepository = sessionRepository;
            this.startTime = startTime;
            this.mfaSettings = mfaSettings; // 저장
        }

        @Override
        public void doFilter(jakarta.servlet.ServletRequest servletRequest, // 이름 변경 (shadowing 방지)
                             jakarta.servlet.ServletResponse servletResponse)
                throws IOException, ServletException {

            HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
//            MfaState beforeState = stateMachineIntegrator.getCurrentState(sessionRepository.getSessionId(request));

            try {
                delegate.doFilter(servletRequest, servletResponse); // 원래 필터 체인 실행

                // 검증 시간 기록
                long verificationTime = System.currentTimeMillis() - startTime;
                context.setAttribute("lastVerificationTime", verificationTime);
                context.updateLastActivityTimestamp(); // 활동 시간 갱신 추가

                // 세션 갱신 (Repository 사용)
                sessionRepository.refreshSession(context.getMfaSessionId());

                // FactorContext를 StateMachine에 저장
                stateMachineIntegrator.saveFactorContext(context);
                log.debug("MFA Step Filter Wrapper (session {}): FactorContext saved after delegate filter execution. Current state: {}",
                        context.getMfaSessionId(), context.getCurrentState());

                // 상태 변경 및 이벤트 전송은 각 Factor의 Success/Failure Handler가 담당해야 함.
                // 여기서 임의로 이벤트를 보내는 로직은 제거.
                // 핸들러가 이미 응답을 커밋했을 수 있으므로, 응답 커밋 여부 확인은 여전히 유효.
                if (httpResponse.isCommitted()) {
                    log.debug("MFA Step Filter Wrapper (session {}): Response already committed by delegate filter or its handlers.", context.getMfaSessionId());
                }

                /*if (!httpResponse.isCommitted()) {
                    if (beforeState == context.getCurrentState()) {
                        stateMachineIntegrator.sendEvent(
                                MfaEvent.FACTOR_VERIFICATION_FAILED, context, this.request);
                    }
                }*/

            } catch (Exception e) {
                log.error("MFA Step Filter Wrapper (session {}): Error during delegate filter execution using {} repository.",
                        context.getMfaSessionId(), sessionRepository.getRepositoryType(), e);

                // AuthenticationException은 해당 Factor의 FailureHandler에서 처리되어야 함.
                // 그 외 예외는 시스템 에러로 간주하고 상태 머신에 알림.
                if (!(e instanceof org.springframework.security.core.AuthenticationException)) {
                    log.debug("MFA Step Filter Wrapper (session {}): Sending SYSTEM_ERROR event due to non-AuthenticationException.", context.getMfaSessionId());
                    stateMachineIntegrator.sendEvent(MfaEvent.SYSTEM_ERROR, context, this.request);
                }
                // 예외를 다시 던져서 Spring Security의 표준 예외 처리 메커니즘 (예: ExceptionTranslationFilter, ASEPFilter)이 처리하도록 함.
                throw e;
            } finally {
                // 최소 지연 시간 보장
                ensureMinimumDelay(startTime);
            }
        }

        private void ensureMinimumDelay(long processingStartTime) { // 메서드 이름 변경 및 mfaSettings 사용
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