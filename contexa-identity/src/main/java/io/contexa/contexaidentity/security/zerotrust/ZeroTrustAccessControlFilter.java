package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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

    private static final String ESCALATE_RETRY_KEY_PREFIX = "security:escalate:retry:";
    private static final Duration ESCALATE_RETRY_TTL = Duration.ofMinutes(5);
    private static final int RETRY_AFTER_SECONDS = 30;

    private final ZeroTrustActionRedisRepository actionRedisRepository;
    private final AuthResponseWriter responseWriter;
    private final StringRedisTemplate stringRedisTemplate;

    @Setter
    @Autowired(required = false)
    private IBlockedUserRecorder blockedUserRecorder;

    @Setter
    @Autowired(required = false)
    private AdminOverrideService adminOverrideService;

    public ZeroTrustAccessControlFilter(
            ZeroTrustActionRedisRepository actionRedisRepository,
            AuthResponseWriter responseWriter,
            StringRedisTemplate stringRedisTemplate) {
        this.actionRedisRepository = actionRedisRepository;
        this.responseWriter = responseWriter;
        this.stringRedisTemplate = stringRedisTemplate;
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
        ZeroTrustAction currentAction = actionRedisRepository.getCurrentAction(userId);

        switch (currentAction) {
            case BLOCK -> handleBlocked(request, response, userId);
            case ESCALATE -> handleEscalate(request, response, userId);
            default -> filterChain.doFilter(request, response);
        }
    }

    private void handleBlocked(HttpServletRequest request,
                               HttpServletResponse response,
                               String userId) throws IOException {

        Map<String, Object> body = new HashMap<>();
        body.put("error", "ACCOUNT_BLOCKED");
        body.put("message", "Your account has been blocked due to security concerns");
        body.put("adminReviewRequired", true);

        if (WebUtil.isApiOrAjaxRequest(request)) {
            responseWriter.writeErrorResponse(
                    response,
                    HttpServletResponse.SC_FORBIDDEN,
                    "ACCOUNT_BLOCKED",
                    "Your account has been blocked due to security concerns",
                    request.getRequestURI(),
                    body);
        } else {
            response.sendRedirect("/zero-trust/blocked");
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

        Map<String, Object> body = new HashMap<>();
        body.put("error", "SECURITY_REVIEW_IN_PROGRESS");
        body.put("message", "Security analysis in progress");
        body.put("retryAfterSeconds", RETRY_AFTER_SECONDS);

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
            String returnUrl = URLEncoder.encode(request.getRequestURI(), StandardCharsets.UTF_8);
            response.sendRedirect("/zero-trust/analysis-pending?returnUrl=" + returnUrl);
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

            if (adminOverrideService != null) {
                adminOverrideService.addToPendingReview(
                        requestId, userId,
                        1.0, 0.0,
                        "Auto-promoted from ESCALATE: TTL expired without resolution");
            }

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
