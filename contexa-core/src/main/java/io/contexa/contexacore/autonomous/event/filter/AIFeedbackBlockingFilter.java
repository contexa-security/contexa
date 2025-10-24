package io.contexa.contexacore.autonomous.event.filter;

import io.contexa.contexacore.autonomous.utils.UserIdentificationStrategy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * AI Feedback Blocking Filter
 *
 * AI가 분석하고 확정한 위협만 차단합니다 (AINative Security Philosophy).
 *
 * 차단 조건:
 * 1. AI 확정 차단 목록 (Cold Path AI가 분석 후 설정)
 * 2. AI 학습 공격 패턴 (Cold Path AI가 학습한 패턴)
 * 3. Rate Limiting (시스템 보호)
 *
 * 위치: HCADFilter 이후, SecurityEventPublishingFilter 이전
 * Order: HIGHEST_PRECEDENCE + 2.5
 */
@Slf4j
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE + 2) // HCADFilter와 SecurityEventPublishingFilter 사이
public class AIFeedbackBlockingFilter extends OncePerRequestFilter {

    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    @Value("${security.ai.blocking.enabled:true}")
    private boolean aiBlockingEnabled;

    @Value("${security.rate.limit.requests:100}")
    private int rateLimitRequests;

    @Value("${security.rate.limit.window:60}")
    private int rateLimitWindowSeconds;

    // Redis 키 패턴
    private static final String AI_BLOCKLIST_PREFIX = "ai:blocklist:";
    private static final String AI_BLOCKLIST_IP_PREFIX = "ai:blocklist:ip:";
    private static final String AI_ATTACK_PATTERN_PREFIX = "ai:attack:patterns:";
    private static final String RATE_LIMIT_PREFIX = "rate:limit:";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (!aiBlockingEnabled) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String userId = getUserIdOrIp(request, auth);
        String clientIp = extractClientIp(request);

        // 1. AI 확정 차단 목록 체크 (AI가 Cold Path 에서 설정)
        if (isInAIConfirmedBlocklist(userId) || isInAIConfirmedBlocklist(clientIp)) {
            log.warn("[AIFeedbackBlocking] Request blocked - AI confirmed threat: userId={}, ip={}",
                    userId, clientIp);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("{\"error\":\"Access denied - AI detected threat pattern\"}");
            response.setContentType("application/json");
            return;
        }

        // 2. AI 학습 공격 패턴 체크 (Cold Path AI가 학습)
        if (matchesAILearnedAttackPattern(request, userId)) {
            log.warn("[AIFeedbackBlocking] Request blocked - Known attack pattern: userId={}, uri={}",
                    userId, request.getRequestURI());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("{\"error\":\"Access denied - Known attack pattern detected\"}");
            response.setContentType("application/json");
            return;
        }

        // 3. Rate Limiting (시스템 보호)
        if (!checkRateLimit(userId)) {
            log.warn("[AIFeedbackBlocking] Request blocked - Rate limit exceeded: userId={}", userId);
            response.setStatus(429); // Too Many Requests
            response.getWriter().write("{\"error\":\"Too many requests\"}");
            response.setContentType("application/json");
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * AI 확정 차단 목록 체크
     *
     * Redis key: "ai:blocklist:{userId}" 또는 "ai:blocklist:ip:{ip}"
     * Cold Path AI가 분석 후 설정하는 차단 목록
     */
    private boolean isInAIConfirmedBlocklist(String identifier) {
        if (identifier == null) {
            return false;
        }

        try {
            String key = identifier.startsWith("anonymous:")
                ? AI_BLOCKLIST_IP_PREFIX + identifier.replace("anonymous:", "")
                : AI_BLOCKLIST_PREFIX + identifier;

            Long blockTimestamp = (Long) redisTemplate.opsForValue().get(key);

            if (blockTimestamp != null) {
                // 24시간 이내 차단만 유효 (오래된 차단은 자동 해제)
                long hoursSinceBlock = (System.currentTimeMillis() - blockTimestamp) / (1000 * 60 * 60);
                if (hoursSinceBlock < 24) {
                    return true;
                } else {
                    // 오래된 차단 제거
                    redisTemplate.delete(key);
                }
            }
        } catch (Exception e) {
            log.error("[AIFeedbackBlocking] Failed to check AI blocklist", e);
        }

        return false;
    }

    /**
     * AI 학습 공격 패턴 매칭
     *
     * Redis key: "ai:attack:patterns:{userId}"
     * Cold Path AI가 학습한 공격 패턴 (Set)
     */
    private boolean matchesAILearnedAttackPattern(HttpServletRequest request, String userId) {
        if (userId == null) {
            return false;
        }

        try {
            String key = AI_ATTACK_PATTERN_PREFIX + userId;
            Set<Object> patterns = redisTemplate.opsForSet().members(key);

            if (patterns != null && !patterns.isEmpty()) {
                String requestUri = request.getRequestURI();
                String requestMethod = request.getMethod();
                String userAgent = request.getHeader("User-Agent");

                for (Object patternObj : patterns) {
                    String pattern = patternObj.toString();

                    // 단순 패턴 매칭 (실제로는 더 정교한 매칭 필요)
                    if (requestUri.contains(pattern) ||
                        (userAgent != null && userAgent.contains(pattern))) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            log.error("[AIFeedbackBlocking] Failed to check attack patterns", e);
        }

        return false;
    }

    /**
     * Rate Limiting 체크
     *
     * Redis key: "rate:limit:{userId}"
     * Sliding window 알고리즘 사용
     */
    private boolean checkRateLimit(String userId) {
        if (userId == null) {
            return true;
        }

        try {
            String key = RATE_LIMIT_PREFIX + userId;
            Long currentCount = redisTemplate.opsForValue().increment(key);

            if (currentCount == null) {
                return true;
            }

            // 첫 요청이면 TTL 설정
            if (currentCount == 1) {
                redisTemplate.expire(key, rateLimitWindowSeconds, TimeUnit.SECONDS);
            }

            // 제한 초과 체크
            return currentCount <= rateLimitRequests;

        } catch (Exception e) {
            log.error("[AIFeedbackBlocking] Failed to check rate limit", e);
            return true; // 에러 시 통과 (안전 측면)
        }
    }

    /**
     * 사용자 ID 또는 IP 추출
     */
    private String getUserIdOrIp(HttpServletRequest request, Authentication auth) {
        if (auth != null && trustResolver.isAuthenticated(auth)) {
            return UserIdentificationStrategy.getUserId(auth);
        }
        return "anonymous:" + extractClientIp(request);
    }

    /**
     * 클라이언트 IP 추출 (프록시 고려)
     */
    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}
