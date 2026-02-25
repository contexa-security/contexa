package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
public class ZeroTrustAccessControlFilter extends OncePerRequestFilter {

    public static final String ROLE_BLOCKED = "ROLE_BLOCKED";
    public static final String ROLE_REVIEW_REQUIRED = "ROLE_REVIEW_REQUIRED";
    public static final String BLOCK_MFA_FLOW_ATTRIBUTE = "BLOCK_MFA_FLOW";

    private static final String ESCALATE_RETRY_KEY_PREFIX = "security:escalate:retry:";
    private static final Duration ESCALATE_RETRY_TTL = Duration.ofMinutes(5);
    private static final Duration BLOCK_MFA_VERIFIED_TTL = Duration.ofHours(1);
    private static final int RETRY_AFTER_SECONDS = 30;

    private final ZeroTrustActionRedisRepository actionRedisRepository;
    private final AuthResponseWriter responseWriter;
    private final StringRedisTemplate stringRedisTemplate;
    private final IBlockedUserRecorder blockedUserRecorder;
    private final ChallengeMfaInitializer challengeMfaInitializer;
    private final AuthUrlProvider authUrlProvider;

    public ZeroTrustAccessControlFilter(
            ZeroTrustActionRedisRepository actionRedisRepository,
            AuthResponseWriter responseWriter,
            StringRedisTemplate stringRedisTemplate, IBlockedUserRecorder blockedUserRecorder, ChallengeMfaInitializer challengeMfaInitializer, AuthUrlProvider authUrlProvider) {
        this.actionRedisRepository = actionRedisRepository;
        this.responseWriter = responseWriter;
        this.stringRedisTemplate = stringRedisTemplate;
        this.blockedUserRecorder = blockedUserRecorder;
        this.challengeMfaInitializer = challengeMfaInitializer;
        this.authUrlProvider = authUrlProvider;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (StringUtils.hasText(contextPath)) {
            requestUri = requestUri.substring(contextPath.length());
        }

        return requestUri.startsWith("/logout")
                || requestUri.startsWith("/zero-trust")
                || requestUri.startsWith("/api/aiam/sse/zero-trust")
                || requestUri.startsWith("/api/aiam/zero-trust");
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

        boolean isBlocked = hasAuthority(auth, ROLE_BLOCKED);
        boolean isEscalated = hasAuthority(auth, ROLE_REVIEW_REQUIRED);

        if (!isBlocked && !isEscalated) {
            filterChain.doFilter(request, response);
            return;
        }

        String userId = extractUserId(auth);
        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        ZeroTrustAction currentAction = actionRedisRepository.getCurrentAction(userId, contextBindingHash);

        String requestUri = resolveRequestUri(request);

        switch (currentAction) {
            case BLOCK -> handleBlockWithMfa(request, response, filterChain, auth, userId, requestUri);
            case ESCALATE -> handleEscalate(request, response, userId);
            default -> filterChain.doFilter(request, response);
        }
    }

    private void handleBlockWithMfa(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain,
                                    Authentication auth,
                                    String userId,
                                    String requestUri) throws IOException, ServletException {

        if (isBlockMfaPending(userId)) {
            if (isMfaRelatedPath(requestUri)) {
                filterChain.doFilter(request, response);
                return;
            }

            if (challengeMfaInitializer != null) {
                initializeBlockMfa(request, response, auth, userId);
                return;
            }
        }

        handleBlocked(request, response, userId);
    }

    private boolean isBlockMfaPending(String userId) {
        try {
            String key = ZeroTrustRedisKeys.blockMfaPending(userId);
            return "true".equals(stringRedisTemplate.opsForValue().get(key));
        } catch (Exception e) {
            log.error("[ZeroTrustAccessControlFilter] Failed to check block-mfa-pending: userId={}", userId, e);
            return false;
        }
    }

    private boolean isMfaRelatedPath(String requestUri) {
        return requestUri.startsWith("/mfa/")
                || requestUri.startsWith("/api/mfa/");
    }

    private void initializeBlockMfa(HttpServletRequest request,
                                    HttpServletResponse response,
                                    Authentication auth,
                                    String userId) throws IOException {
        try {
            request.setAttribute(BLOCK_MFA_FLOW_ATTRIBUTE, true);

            FactorContext context = challengeMfaInitializer.initializeChallengeFlow(
                    request, response, auth);

            String mfaPageUrl = buildMfaPageUrl(context, request);
            if (WebUtil.isApiOrAjaxRequest(request)) {
                Map<String, Object> body = new HashMap<>();
                body.put("error", "BLOCK_MFA_REQUIRED");
                body.put("message", "MFA verification required for block resolution");
                body.put("mfaUrl", mfaPageUrl);

                responseWriter.writeErrorResponse(
                        response,
                        HttpServletResponse.SC_UNAUTHORIZED,
                        "BLOCK_MFA_REQUIRED",
                        "MFA verification required for block resolution",
                        request.getRequestURI(),
                        body);
            } else {
                response.sendRedirect(mfaPageUrl);
            }
        } catch (Exception e) {
            log.error("[ZeroTrustAccessControlFilter] Failed to initialize block MFA: userId={}", userId, e);
            handleBlocked(request, response, userId);
        }
    }

    private String buildMfaPageUrl(FactorContext context, HttpServletRequest request) {
        if (authUrlProvider == null) {
            return request.getContextPath() + "/mfa/select-factor";
        }

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

        return contextPath + authUrlProvider.getMfaSelectFactor();
    }

    private void handleBlocked(HttpServletRequest request,
                               HttpServletResponse response,
                               String userId) throws IOException {

        String redirectUrl = request.getContextPath() + "/zero-trust/blocked";

        Map<String, Object> body = new HashMap<>();
        body.put("error", "ACCOUNT_BLOCKED");
        body.put("message", "Your account has been blocked due to security concerns");
        body.put("adminReviewRequired", true);
        body.put("redirectUrl", redirectUrl);

        if (WebUtil.isApiOrAjaxRequest(request)) {
            responseWriter.writeErrorResponse(
                    response,
                    HttpServletResponse.SC_FORBIDDEN,
                    "ACCOUNT_BLOCKED",
                    "Your account has been blocked due to security concerns",
                    request.getRequestURI(),
                    body);
        } else {
            response.sendRedirect(redirectUrl);
        }
    }

    private void handleEscalate(HttpServletRequest request,
                                HttpServletResponse response,
                                String userId) throws IOException {

        ZeroTrustAction hashAction = actionRedisRepository.getActionFromHash(userId);
        String retryKey = ESCALATE_RETRY_KEY_PREFIX + userId;

        if (hashAction != null) {
            markEscalateRetry(retryKey);
            respondWithReviewInProgress(request, response);
            return;
        }

        try {
            Boolean retryExists = stringRedisTemplate.hasKey(retryKey);
            if (retryExists) {
                respondWithReviewInProgress(request, response);
                return;
            }
        } catch (Exception e) {
            log.error("[ZeroTrustAccessControlFilter] Failed to check escalate retry flag: userId={}", userId, e);
        }

        promoteEscalateToBlock(userId, request, response);
    }

    private void markEscalateRetry(String retryKey) {
        try {
            Boolean exists = stringRedisTemplate.hasKey(retryKey);
            if (!exists) {
                stringRedisTemplate.opsForValue().set(retryKey, "1", ESCALATE_RETRY_TTL);
            }
        } catch (Exception e) {
            log.error("[ZeroTrustAccessControlFilter] Failed to mark escalate retry: retryKey={}", retryKey, e);
        }
    }

    private void respondWithReviewInProgress(HttpServletRequest request,
                                             HttpServletResponse response) throws IOException {

        String returnUrl = URLEncoder.encode(request.getRequestURI(), StandardCharsets.UTF_8);
        String redirectUrl = request.getContextPath()
                + "/zero-trust/analysis-pending?returnUrl=" + returnUrl;

        Map<String, Object> body = new HashMap<>();
        body.put("error", "SECURITY_REVIEW_IN_PROGRESS");
        body.put("message", "Security analysis in progress");
        body.put("retryAfterSeconds", RETRY_AFTER_SECONDS);
        body.put("redirectUrl", redirectUrl);

        response.setHeader("Retry-After", String.valueOf(RETRY_AFTER_SECONDS));

        if (WebUtil.isApiOrAjaxRequest(request)) {
            responseWriter.writeErrorResponse(
                    response,
                    423,
                    "SECURITY_REVIEW_IN_PROGRESS",
                    "Security analysis in progress",
                    request.getRequestURI(),
                    body);
        } else {
            response.sendRedirect(redirectUrl);
        }
    }

    private void promoteEscalateToBlock(String userId,
                                        HttpServletRequest request,
                                        HttpServletResponse response) throws IOException {
        try {
            String requestId = UUID.randomUUID().toString();

            Map<String, Object> fields = new HashMap<>();
            fields.put("promotedFrom", "ESCALATE");
            fields.put("promotionReason", "ESCALATE TTL expired without resolution");

            actionRedisRepository.saveAction(userId, ZeroTrustAction.BLOCK, fields);
            actionRedisRepository.setBlockedFlag(userId);

            if (blockedUserRecorder != null) {
                blockedUserRecorder.recordBlock(
                        requestId, userId, null,
                        1.0, 0.0,
                        "Auto-promoted from ESCALATE: TTL expired without resolution",
                        request.getRemoteAddr(),
                        request.getHeader("User-Agent"));
            }

            log.error("[ZeroTrustAccessControlFilter] ESCALATE promoted to BLOCK: userId={}", userId);
        } catch (Exception e) {
            log.error("[ZeroTrustAccessControlFilter] Failed to promote ESCALATE to BLOCK: userId={}", userId, e);
        }

        handleBlocked(request, response, userId);
    }

    private String resolveRequestUri(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (StringUtils.hasText(contextPath)) {
            requestUri = requestUri.substring(contextPath.length());
        }
        return requestUri;
    }

    private boolean hasAuthority(Authentication auth, String authority) {
        if (auth.getAuthorities() == null) {
            return false;
        }
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority::equals);
    }

    private String extractUserId(Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return "unknown";
        }
        return auth.getName();
    }
}
