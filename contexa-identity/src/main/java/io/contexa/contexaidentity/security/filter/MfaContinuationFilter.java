package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.validator.MfaContextValidator;
import io.contexa.contexaidentity.security.core.validator.ValidationResult;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.filter.handler.MfaRequestHandler;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.filter.handler.StateMachineAwareMfaRequestHandler;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import io.contexa.contexaidentity.security.filter.matcher.MfaUrlMatcher;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
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

    private final AuthResponseWriter responseWriter;
    private final MfaRequestHandler requestHandler;
    private final MfaUrlMatcher urlMatcher;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final MfaSessionRepository sessionRepository;

    public MfaContinuationFilter(MfaPolicyProvider mfaPolicyProvider,
                                 AuthContextProperties authContextProperties,
                                 AuthResponseWriter responseWriter,
                                 ApplicationContext applicationContext) {
        this.responseWriter = Objects.requireNonNull(responseWriter);

        this.urlMatcher = new MfaUrlMatcher(authContextProperties, applicationContext);
        this.stateMachineIntegrator = applicationContext.getBean(MfaStateMachineIntegrator.class);

        this.sessionRepository = applicationContext.getBean(MfaSessionRepository.class);

        this.requestHandler = new StateMachineAwareMfaRequestHandler(
                mfaPolicyProvider,
                authContextProperties,
                responseWriter,
                applicationContext,
                stateMachineIntegrator
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

        // 통합된 검증 로직 사용
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        ValidationResult validation = MfaContextValidator.validateFactorSelectionContext(ctx, sessionRepository);

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
        String oldSessionId = sessionRepository.getSessionId(request);
        if (oldSessionId != null) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, response);
            } catch (Exception e) {
                log.warn("Failed to cleanup invalid session: {}", oldSessionId, e);
            }
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_SESSION_INVALID");
        errorResponse.put("message", "MFA 세션이 유효하지 않습니다.");
        errorResponse.put("errors", validation.getErrors());
        errorResponse.put("warnings", validation.getWarnings());
        errorResponse.put("redirectUrl", request.getContextPath() + "/loginForm");
        errorResponse.put("repositoryType", sessionRepository.getRepositoryType());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "MFA_SESSION_INVALID", String.join(", ", validation.getErrors()),
                request.getRequestURI(), errorResponse);
    }

    private boolean isValidMfaContext(FactorContext ctx) {
        return ctx != null &&
                ctx.getMfaSessionId() != null &&
                AuthType.MFA.name().equalsIgnoreCase(ctx.getFlowTypeName());
    }
}