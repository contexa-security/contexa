package io.contexa.contexacore.hcad.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * HCAD 세션 위협 관리 서비스
 *
 * 세션 위협 상태 체크 및 세션 ID 추출/마스킹 로직 담당:
 * - Redis 기반 세션 위협 상태 조회
 * - Grace Period 관리
 * - 세션 ID 추출 (Cookie, Header, Bearer Token)
 * - 로깅용 세션 ID 마스킹
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class HCADSessionThreatService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${hcad.session.cookie-name:JSESSIONID}")
    private String sessionCookieName;

    @Value("${hcad.session.header-name:X-Session-Id}")
    private String sessionHeaderName;

    /**
     * 세션 위협 상태 체크
     *
     * Redis에서 세션 상태를 조회하여 Response Header에 위협 정보 설정:
     * - BLOCKED: 즉시 차단
     * - GRACE: 유예 기간 (재인증 필요)
     * - MONITORING: 모니터링 중
     */
    public void checkSessionThreatStatus(HttpServletRequest request, HttpServletResponse response) {
        String sessionId = extractSessionId(request);
        if (sessionId == null) {
            return;
        }

        try {
            String redisKeyPrefix = "security:session:threat:";
            String blockedKey = redisKeyPrefix + "blocked:" + sessionId;
            String graceKey = redisKeyPrefix + "grace:" + sessionId;
            String monitoringKey = redisKeyPrefix + "monitoring:" + sessionId;

            // 1. 차단 상태 체크
            Map<Object, Object> blockedData = redisTemplate.opsForHash().entries(blockedKey);
            if (!blockedData.isEmpty()) {
                response.setHeader("X-Session-Threat", "BLOCKED");
                response.setHeader("X-Session-Action", "TERMINATE");

                Object threatScore = blockedData.get("threatScore");
                if (threatScore != null) {
                    response.setHeader("X-Threat-Score", threatScore.toString());
                }

                log.warn("[HCAD] Blocked session detected - sessionId: {}", maskSessionId(sessionId));
                return;
            }

            // 2. Grace Period 상태 체크
            Map<Object, Object> graceData = redisTemplate.opsForHash().entries(graceKey);
            if (!graceData.isEmpty()) {
                Long ttl = redisTemplate.getExpire(graceKey, TimeUnit.SECONDS);
                if (ttl != null && ttl > 0) {
                    response.setHeader("X-Session-Threat", "HIGH");
                    response.setHeader("X-Grace-Period", String.valueOf(ttl));
                    response.setHeader("X-Session-Action", "REAUTHENTICATION_REQUIRED");
                    response.setHeader("X-Recovery-URL", "/auth/step-up");

                    Object threatScore = graceData.get("threatScore");
                    if (threatScore != null) {
                        response.setHeader("X-Threat-Score", threatScore.toString());
                    }

                    log.info("[HCAD] Session in grace period - sessionId: {}, TTL: {}s",
                        maskSessionId(sessionId), ttl);
                    return;
                }
            }

            // 3. 모니터링 상태 체크
            Map<Object, Object> monitoringData = redisTemplate.opsForHash().entries(monitoringKey);
            if (!monitoringData.isEmpty()) {
                response.setHeader("X-Session-Threat", "MEDIUM");
                response.setHeader("X-Session-Action", "MONITORING");

                Object threatScore = monitoringData.get("threatScore");
                if (threatScore != null) {
                    response.setHeader("X-Threat-Score", threatScore.toString());
                }

                if (log.isDebugEnabled()) {
                    log.debug("[HCAD] Session under monitoring - sessionId: {}", maskSessionId(sessionId));
                }
            }

        } catch (Exception e) {
            log.error("[HCAD] Failed to check session threat status", e);
            // 오류 발생 시 정상 진행 (fail-open)
        }
    }

    /**
     * HTTP 요청에서 세션 ID 추출
     * Cookie, Header, Bearer Token 순서로 시도
     */
    public String extractSessionId(HttpServletRequest request) {
        // 1. Cookie에서 추출
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (sessionCookieName.equals(cookie.getName())) {
                    String cookieValue = cookie.getValue();
                    if (cookieValue != null && !cookieValue.isEmpty()) {
                        return cookieValue;
                    }
                }
            }
        }

        // 2. Custom Header에서 추출
        String headerSession = request.getHeader(sessionHeaderName);
        if (headerSession != null && !headerSession.isEmpty()) {
            return headerSession.trim();
        }

        // 3. Authorization Bearer Token에서 추출
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String token = authorization.substring(7).trim();
            if (!token.isEmpty()) {
                // JWT인 경우 그대로 사용 (간단한 구현)
                return token;
            }
        }

        // 4. HttpSession에서 추출 (폴백)
        if (request.getSession(false) != null) {
            return request.getSession().getId();
        }

        return null;
    }

    /**
     * 세션 ID 마스킹 (로깅용)
     */
    public String maskSessionId(String sessionId) {
        if (sessionId == null || sessionId.length() < 8) {
            return "***";
        }
        return sessionId.substring(0, 4) + "..." + sessionId.substring(sessionId.length() - 4);
    }
}
