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
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
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

        if (!urlMatcher.isMfaRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (ctx != null) {
            request.setAttribute(FACTOR_CONTEXT_ATTR, ctx);
        }

        ValidationResult validation = MfaContextValidator.validateFactorSelectionContext(ctx, sessionRepository);
        request.setAttribute(VALIDATION_RESULT_ATTR, validation);

        if (validation.hasErrors()) {
            log.warn("Invalid MFA context for request: {} - Errors: {}",
                    request.getRequestURI(), validation.getErrors());
            handleInvalidContext(request, response, validation);
            return;
        }

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

    private void handleInvalidContext(HttpServletRequest request, HttpServletResponse response,
                                      ValidationResult validation) throws IOException {

        FactorContext ctx = (FactorContext) request.getAttribute(FACTOR_CONTEXT_ATTR);
        String oldSessionId = ctx != null ? ctx.getMfaSessionId() : sessionRepository.getSessionId(request);

        if (oldSessionId != null && sessionRepository.existsSession(oldSessionId)) {
            try {
                stateMachineIntegrator.releaseStateMachine(oldSessionId);
                sessionRepository.removeSession(oldSessionId, request, response);
            } catch (Exception e) {
                log.warn("Failed to cleanup invalid session: {}", oldSessionId, e);
            }
        } else if (oldSessionId != null) {
        }

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "MFA_SESSION_INVALID");
        errorResponse.put("message", "MFA session is invalid.");
        errorResponse.put("errors", validation.getErrors());
        errorResponse.put("warnings", validation.getWarnings());
        errorResponse.put("redirectUrl", request.getContextPath() + authUrlProvider.getPrimaryLoginPage());
        errorResponse.put("repositoryType", sessionRepository.getRepositoryType());

        responseWriter.writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                "MFA_SESSION_INVALID", String.join(", ", validation.getErrors()),
                request.getRequestURI(), errorResponse);
    }

    public void initializeUrlMatchers() {
        urlMatcher.initializeMatchers();
        initialized = true;
    }
}