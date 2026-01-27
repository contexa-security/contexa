package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import io.contexa.contexacommon.enums.AuthType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Filter that intercepts requests when Zero Trust security determines a CHALLENGE action.
 * Detects ROLE_MFA_REQUIRED authority and initializes MFA flow via ChallengeMfaInitializer.
 *
 * Supports content negotiation:
 * - Browser requests (Accept: text/html) -> HTTP 302 redirect to MFA page
 * - API requests (Accept: application/json) -> HTTP 403 with JSON response and special headers
 */
@Slf4j
public class ZeroTrustChallengeFilter extends OncePerRequestFilter {

    public static final String ROLE_MFA_REQUIRED = "ROLE_MFA_REQUIRED";
    public static final String HEADER_MFA_CHALLENGE_REQUIRED = "X-MFA-Challenge-Required";
    public static final String HEADER_MFA_SESSION_ID = "X-MFA-Session-Id";
    public static final String HEADER_MFA_REDIRECT_URL = "X-MFA-Redirect-Url";

    private final ChallengeMfaInitializer challengeMfaInitializer;
    private final AuthResponseWriter responseWriter;
    private final AuthUrlProvider authUrlProvider;
    private final MfaSessionRepository sessionRepository;
    private final MfaStateMachineIntegrator stateMachineIntegrator;

    public ZeroTrustChallengeFilter(
            ChallengeMfaInitializer challengeMfaInitializer,
            AuthResponseWriter responseWriter,
            AuthUrlProvider authUrlProvider,
            MfaSessionRepository sessionRepository,
            MfaStateMachineIntegrator stateMachineIntegrator) {
        this.challengeMfaInitializer = challengeMfaInitializer;
        this.responseWriter = responseWriter;
        this.authUrlProvider = authUrlProvider;
        this.sessionRepository = sessionRepository;
        this.stateMachineIntegrator = stateMachineIntegrator;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!hasAuthority(auth, ROLE_MFA_REQUIRED)) {
            filterChain.doFilter(request, response);
            return;
        }

        String existingSessionId = sessionRepository.getSessionId(request);
        if (existingSessionId != null && sessionRepository.existsSession(existingSessionId)) {
            FactorContext existingContext = stateMachineIntegrator.loadFactorContext(existingSessionId);

            if (existingContext != null) {
                Boolean isChallengeSession = existingContext.getBooleanAttribute("challengeInitiated");

                if (Boolean.TRUE.equals(isChallengeSession)) {
                    if (!existingContext.getCurrentState().isTerminal()) {
                        String mfaPageUrl = buildMfaPageUrl(existingContext, request);
                        if (isHtmlAccepted(request)) {
                            handleBrowserRequest(response, mfaPageUrl);
                        } else {
                            handleApiRequest(response, request, existingContext, mfaPageUrl);
                        }
                        return;
                    }
                    stateMachineIntegrator.cleanupSession(request, response);
                } else {
                    stateMachineIntegrator.cleanupSession(request, response);
                }
            } else {
                sessionRepository.removeSession(existingSessionId, request, response);
            }
        }

        try {
            FactorContext context = challengeMfaInitializer.initializeChallengeFlow(request, response, auth);

            String mfaPageUrl = buildMfaPageUrl(context, request);

            if (isHtmlAccepted(request)) {
                handleBrowserRequest(response, mfaPageUrl);
            } else {
                handleApiRequest(response, request, context, mfaPageUrl);
            }

        } catch (ChallengeMfaInitializer.ChallengeMfaInitializationException e) {
            log.error("Failed to initialize challenge MFA flow: {}", e.getMessage());
            handleInitializationError(response, request, e);
        } catch (Exception e) {
            log.error("Unexpected error in ZeroTrustChallengeFilter", e);
            handleInitializationError(response, request, e);
        }
    }

    private String buildMfaPageUrl(FactorContext context, HttpServletRequest request) {
        MfaState currentState = context.getCurrentState();
        String contextPath = request.getContextPath();

        if (currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            AuthType currentFactor = context.getCurrentProcessingFactor();
            if (currentFactor != null) {
                return switch (currentFactor) {
                    case OTT -> contextPath + authUrlProvider.getOttRequestCodeUi();
                    case PASSKEY -> contextPath + authUrlProvider.getPasskeyChallengeUi();
                    default -> contextPath + authUrlProvider.getMfaSelectFactor();
                };
            }
        }

        if (currentState == MfaState.AWAITING_FACTOR_SELECTION ||
            currentState == MfaState.PRIMARY_AUTHENTICATION_COMPLETED) {
            return contextPath + authUrlProvider.getMfaSelectFactor();
        }

        return contextPath + authUrlProvider.getMfaSelectFactor();
    }

    private void handleBrowserRequest(HttpServletResponse response, String mfaPageUrl) throws IOException {
        response.sendRedirect(mfaPageUrl);
    }

    private void handleApiRequest(HttpServletResponse response, HttpServletRequest request,
                                   FactorContext context, String mfaPageUrl) throws IOException {
        response.setHeader(HEADER_MFA_CHALLENGE_REQUIRED, "true");
        response.setHeader(HEADER_MFA_SESSION_ID, context.getMfaSessionId());
        response.setHeader(HEADER_MFA_REDIRECT_URL, mfaPageUrl);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", "MFA_CHALLENGE_REQUIRED");
        responseBody.put("message", "Additional verification required due to security policy");
        responseBody.put("mfaSessionId", context.getMfaSessionId());
        responseBody.put("nextStepUrl", mfaPageUrl);
        responseBody.put("challengeReason", "ZERO_TRUST_ADAPTIVE");
        responseBody.put("currentState", context.getCurrentState().name());

        AuthType nextFactor = context.getCurrentProcessingFactor();
        if (nextFactor != null) {
            responseBody.put("nextFactorType", nextFactor.name());
            responseBody.put("nextStepId", context.getCurrentStepId());
        }

        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_FORBIDDEN,
                "MFA_CHALLENGE_REQUIRED",
                "Additional verification required due to security policy",
                request.getRequestURI(),
                responseBody
        );
    }

    private void handleInitializationError(HttpServletResponse response, HttpServletRequest request,
                                           Exception e) throws IOException {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("error", "MFA_INIT_FAILED");
        errorDetails.put("message", "Failed to initialize MFA challenge flow");

        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_INIT_FAILED",
                "Failed to initialize MFA challenge",
                request.getRequestURI(),
                errorDetails
        );
    }

    private boolean hasAuthority(Authentication auth, String authority) {
        if (auth.getAuthorities() == null) {
            return false;
        }
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority::equals);
    }

    private boolean isHtmlAccepted(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        if (accept == null || accept.isEmpty()) {
            return true;
        }

        boolean acceptsHtml = accept.contains("text/html");
        boolean acceptsJson = accept.contains("application/json");

        if (acceptsHtml && !acceptsJson) {
            return true;
        }

        if (acceptsJson && !acceptsHtml) {
            return false;
        }

        if (acceptsHtml && acceptsJson) {
            int htmlIndex = accept.indexOf("text/html");
            int jsonIndex = accept.indexOf("application/json");
            return htmlIndex < jsonIndex;
        }

        return true;
    }
}
