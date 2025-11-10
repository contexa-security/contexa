package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.validator.MfaContextValidator;
import io.contexa.contexaidentity.security.core.validator.ValidationResult;
import io.contexa.contexaidentity.security.filter.handler.MfaRequestHandler;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.filter.handler.StateMachineAwareMfaRequestHandler;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import io.contexa.contexaidentity.security.filter.matcher.MfaUrlMatcher;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 완전 일원화된 MfaContinuationFilter
 * - ContextPersistence 완전 제거
 * - MfaStateMachineService만 사용
 * - State Machine에서 직접 컨텍스트 로드
 */
@Slf4j
public class MfaContinuationFilter extends OncePerRequestFilter {

    // ✅ 최적화: Request Attribute 키 정의 (필터 체인 간 컨텍스트 공유)
    public static final String FACTOR_CONTEXT_ATTR = "io.contexa.mfa.FactorContext";
    public static final String VALIDATION_RESULT_ATTR = "io.contexa.mfa.ValidationResult";

    private final AuthResponseWriter responseWriter;
    private final MfaRequestHandler requestHandler;
    private final MfaUrlMatcher urlMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;
    private final AuthUrlProvider authUrlProvider;

    public MfaContinuationFilter(AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 ApplicationContext applicationContext) {
        this.responseWriter = Objects.requireNonNull(responseWriter);

        this.authUrlProvider = applicationContext.getBean(AuthUrlProvider.class);
        this.urlMatcher = new MfaUrlMatcher(authUrlProvider, applicationContext);
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        this.sessionRepository = applicationContext.getBean(MfaSessionRepository.class);

        this.requestHandler = new StateMachineAwareMfaRequestHandler(
                authContextProperties,
                responseWriter,
                applicationContext,
                stateMachineIntegrator,
                authUrlProvider
        );

        log.info("MfaContinuationFilter initialized with {} repository",
                sessionRepository.getRepositoryType());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (!urlMatcher.isMfaRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("MfaContinuationFilter processing request: {} {} using {} repository",
                request.getMethod(), request.getRequestURI(), sessionRepository.getRepositoryType());

        // ✅ High 수정 2: 세션 조회 중복 제거
        // 디버깅용 세션 조회 로직(Line 87-100)을 제거하고 loadFactorContextFromRequest()에서 한 번만 조회
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);

        // ✅ 최적화: FactorContext를 Request Attribute에 저장 (중복 로드 방지)
        if (ctx != null) {
            request.setAttribute(FACTOR_CONTEXT_ATTR, ctx);
            log.debug("FactorContext saved to request attribute for session: {}", ctx.getMfaSessionId());
        }

        ValidationResult validation = MfaContextValidator.validateFactorSelectionContext(ctx, sessionRepository);

        // ✅ 최적화: ValidationResult를 Request Attribute에 저장 (중복 검증 방지)
        request.setAttribute(VALIDATION_RESULT_ATTR, validation);
        log.debug("ValidationResult saved to request attribute - hasErrors: {}", validation.hasErrors());

        if (validation.hasErrors()) {
            log.warn("Invalid MFA context for request: {} - Errors: {}",
                    request.getRequestURI(), validation.getErrors());
            handleInvalidContext(request, response, validation);
            return;
        }

        // 경고 로깅
        if (validation.hasWarnings()) {
            log.warn("MFA context warnings for request: {} - Warnings: {}",
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

    /**
     * 개선: Repository 패턴 통합 - 무효한 컨텍스트 처리
     */
    private void handleInvalidContext(HttpServletRequest request, HttpServletResponse response,
                                      ValidationResult validation) throws IOException {
        // ✅ High 수정 2: Request Attribute에서 FactorContext 조회 (세션 조회 중복 제거)
        FactorContext ctx = (FactorContext) request.getAttribute(FACTOR_CONTEXT_ATTR);
        String oldSessionId = ctx != null ? ctx.getMfaSessionId() : sessionRepository.getSessionId(request);

        // ✅ Medium 수정 2: 세션이 실제로 존재하는 경우에만 정리
        if (oldSessionId != null && sessionRepository.existsSession(oldSessionId)) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, response);
                log.debug("Invalid session cleaned up: {}", oldSessionId);
            } catch (Exception e) {
                log.warn("Failed to cleanup invalid session: {}", oldSessionId, e);
            }
        } else if (oldSessionId != null) {
            log.debug("Session {} does not exist, skipping cleanup", oldSessionId);
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_SESSION_INVALID");
        errorResponse.put("message", "MFA 세션이 유효하지 않습니다.");
        errorResponse.put("errors", validation.getErrors());
        errorResponse.put("warnings", validation.getWarnings());
        errorResponse.put("redirectUrl", request.getContextPath() + authUrlProvider.getPrimaryLoginPage());
        errorResponse.put("repositoryType", sessionRepository.getRepositoryType());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "MFA_SESSION_INVALID", String.join(", ", validation.getErrors()),
                request.getRequestURI(), errorResponse);
    }
}
