package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.WebUtil;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexacommon.enums.AuthType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
public class ZeroTrustChallengeFilter extends OncePerRequestFilter {

    public static final String ROLE_MFA_REQUIRED = "ROLE_MFA_REQUIRED";

    private static final String LOCK_KEY_PREFIX = "mfa:challenge:init:";
    private static final Duration LOCK_TIMEOUT = Duration.ofSeconds(30);

    private final ChallengeMfaInitializer challengeMfaInitializer;
    private final AuthResponseWriter responseWriter;
    private final AuthUrlProvider authUrlProvider;
    private final MfaSessionRepository sessionRepository;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final RedisDistributedLockService lockService;

    public ZeroTrustChallengeFilter(
            ChallengeMfaInitializer challengeMfaInitializer,
            AuthResponseWriter responseWriter,
            AuthUrlProvider authUrlProvider,
            MfaSessionRepository sessionRepository,
            MfaStateMachineIntegrator stateMachineIntegrator,
            RedisDistributedLockService lockService) {
        this.challengeMfaInitializer = challengeMfaInitializer;
        this.responseWriter = responseWriter;
        this.authUrlProvider = authUrlProvider;
        this.sessionRepository = sessionRepository;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.lockService = lockService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (StringUtils.hasText(contextPath)) {
            requestUri = requestUri.substring(contextPath.length());
        }

        if (authUrlProvider.getMfaPageUrls().contains(requestUri)) {
            return true;
        }

        if (requestUri.startsWith("/mfa/challenge/")) {
            return true;
        }

        if (requestUri.startsWith("/api/mfa/")) {
            return true;
        }

        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated() || !hasAuthority(auth)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (handleExistingSession(request, response, filterChain)) {
            return;
        }

        String userId = extractUserId(auth);
        String lockKey = LOCK_KEY_PREFIX + userId;
        String lockOwner = Thread.currentThread().getName() + ":" + UUID.randomUUID();

        if (!lockService.tryLock(lockKey, lockOwner, LOCK_TIMEOUT)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            if (handleExistingChallengeSession(request, response, filterChain)) {
                return;
            }

            FactorContext context = challengeMfaInitializer.initializeChallengeFlow(request, response, auth);
            redirectToMfaPage(context, request, response);

        } catch (ChallengeMfaInitializer.ChallengeMfaInitializationException e) {
            log.error("Failed to initialize challenge MFA flow: {}", e.getMessage());
            handleInitializationError(response, request, e);
        } catch (Exception e) {
            log.error("Unexpected error in ZeroTrustChallengeFilter", e);
            handleInitializationError(response, request, e);
        } finally {
            lockService.unlock(lockKey, lockOwner);
        }
    }

    private boolean handleExistingSession(HttpServletRequest request,
                                          HttpServletResponse response,
                                          FilterChain filterChain) throws ServletException, IOException {
        String sessionId = sessionRepository.getSessionId(request);
        if (sessionId == null || !sessionRepository.existsSession(sessionId)) {
            return false;
        }

        FactorContext context = stateMachineIntegrator.loadFactorContext(sessionId);
        if (context == null) {
            sessionRepository.removeSession(sessionId, request, response);
            return false;
        }

        if (!context.getBooleanAttribute("challengeInitiated")) {
            stateMachineIntegrator.cleanupSession(request, response);
            return false;
        }

        if (context.getCurrentState().isTerminal()) {
            stateMachineIntegrator.cleanupSession(request, response);
            return false;
        }

        if (context.getBooleanAttribute("challengeRedirected")) {
            filterChain.doFilter(request, response);
            return true;
        }

        redirectToMfaPage(context, request, response);
        return true;
    }

    private boolean handleExistingChallengeSession(HttpServletRequest request,
                                                   HttpServletResponse response,
                                                   FilterChain filterChain) throws ServletException, IOException {
        String sessionId = sessionRepository.getSessionId(request);
        if (sessionId == null || !sessionRepository.existsSession(sessionId)) {
            return false;
        }

        FactorContext context = stateMachineIntegrator.loadFactorContext(sessionId);
        if (context == null || !context.getBooleanAttribute("challengeInitiated")) {
            return false;
        }

        if (context.getBooleanAttribute("challengeRedirected")) {
            filterChain.doFilter(request, response);
            return true;
        }

        redirectToMfaPage(context, request, response);
        return true;
    }

    private void redirectToMfaPage(FactorContext context,
                                   HttpServletRequest request,
                                   HttpServletResponse response) throws IOException {

        context.setAttribute("challengeRedirected", true);
        stateMachineIntegrator.saveFactorContext(context);
        String mfaPageUrl = buildMfaPageUrl(context, request);

        if (WebUtil.isApiOrAjaxRequest(request)) {
            writeMfaChallengeResponse(response, request, context, mfaPageUrl);
        } else {
            response.sendRedirect(mfaPageUrl);
        }
    }

    private void writeMfaChallengeResponse(HttpServletResponse response,
                                           HttpServletRequest request,
                                           FactorContext context,
                                           String mfaPageUrl) throws IOException {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("error", "MFA_CHALLENGE_REQUIRED");
        responseBody.put("message", "MFA verification required");
        responseBody.put("mfaUrl", mfaPageUrl);
        responseBody.put("sessionId", context.getMfaSessionId());
        responseBody.put("currentState", context.getCurrentState().name());

        AuthType currentFactor = context.getCurrentProcessingFactor();
        if (currentFactor != null) {
            responseBody.put("currentFactor", currentFactor.name());
        }

        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_UNAUTHORIZED,
                "MFA_CHALLENGE_REQUIRED",
                "MFA verification required",
                request.getRequestURI(),
                responseBody
        );
    }

    private String buildMfaPageUrl(FactorContext context, HttpServletRequest request) {
        MfaState currentState = context.getCurrentState();
        String contextPath = request.getContextPath();

        if (currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            AuthType currentFactor = context.getCurrentProcessingFactor();
            if (currentFactor != null) {
                return switch (currentFactor) {
                    case MFA_OTT -> contextPath + authUrlProvider.getOttRequestCodeUi();
                    case MFA_PASSKEY -> contextPath + authUrlProvider.getPasskeyChallengeUi();
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

    private boolean hasAuthority(Authentication auth) {
        if (auth.getAuthorities() == null) {
            return false;
        }
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(ZeroTrustChallengeFilter.ROLE_MFA_REQUIRED::equals);
    }

    private String extractUserId(Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return "unknown";
        }
        return auth.getName();
    }

}
