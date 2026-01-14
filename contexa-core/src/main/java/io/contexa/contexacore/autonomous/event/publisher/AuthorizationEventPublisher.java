package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
public class AuthorizationEventPublisher {

    private final KafkaSecurityEventPublisher kafkaPublisher;
    private final TieredStrategyProperties tieredStrategyProperties;
    private final RedisTemplate<String, Object> redisTemplate;

    private static final Duration ANALYSIS_LOCK_TTL = Duration.ofSeconds(30);

    public AuthorizationEventPublisher(
            KafkaSecurityEventPublisher kafkaPublisher,
            TieredStrategyProperties tieredStrategyProperties,
            RedisTemplate<String, Object> redisTemplate) {
        this.kafkaPublisher = kafkaPublisher;
        this.tieredStrategyProperties = tieredStrategyProperties;
        this.redisTemplate = redisTemplate;
    }

    public void publishWebAuthorizationDecision(
            Authentication authentication,
            HttpServletRequest request,
            AuthorizationDecision decision) {

        long startTime = System.currentTimeMillis();

        try {
            RequestInfo requestInfo = RequestInfo.from(request, tieredStrategyProperties.getSecurity());
            request.setAttribute("security.event.published", true);

            String userId = authentication != null ? authentication.getName() : null;
            if (shouldSkipPublishing(userId)) {
                return;
            }

            AuthorizationDecisionEvent event = buildAuthorizationEvent(authentication, requestInfo, decision);

            kafkaPublisher.publishAuthorizationEvent(event);

            long duration = System.currentTimeMillis() - startTime;
            log.debug("[AuthorizationEventPublisher] Web authorization event queued - eventId: {}, resource: {}, result: {}, duration: {}ms",
                    event.getEventId(), event.getResource(), event.getResult(), duration);


        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[AuthorizationEventPublisher] Failed to publish web authorization event - duration: {}ms", duration, e);
        }
    }

    private boolean shouldSkipPublishing(String userId) {
        if (userId == null || userId.isEmpty() || "anonymousUser".equals(userId)) {
            return true;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object existingAction = redisTemplate.opsForHash().get(analysisKey, "action");
            if (existingAction != null && !"PENDING_ANALYSIS".equals(existingAction.toString())) {
                log.debug("[AuthorizationEventPublisher] Phase 14: 유효한 분석 결과 존재 - userId: {}, action: {}",
                        userId, existingAction);
                return true;
            }

            String lockKey = ZeroTrustRedisKeys.analysisLock(userId);
            Boolean acquired = redisTemplate.opsForValue()
                    .setIfAbsent(lockKey, "1", ANALYSIS_LOCK_TTL);

            if (Boolean.TRUE.equals(acquired)) {
                log.debug("[AuthorizationEventPublisher] Phase 14: 분석 락 획득 성공 - userId: {}", userId);
                return false;
            } else {
                log.debug("[AuthorizationEventPublisher] Phase 14: 분석 락 획득 실패 (이미 분석 중) - userId: {}", userId);
                return true;
            }

        } catch (Exception e) {
            log.warn("[AuthorizationEventPublisher] Phase 14: 분석 락 확인 실패 - userId: {}, 분석 진행", userId, e);
            return false;
        }
    }

    private AuthorizationDecisionEvent buildAuthorizationEvent(
            Authentication authentication,
            RequestInfo requestInfo,
            AuthorizationDecision decision) {

        AuthorizationDecisionEvent.AuthorizationDecisionEventBuilder builder =
                AuthorizationDecisionEvent.builder();

        String userName = authentication != null ? authentication.getName() : null;
        builder.eventId(UUID.randomUUID().toString())
                .timestamp(Instant.now())
                .userId(userName)
                .resource(requestInfo.getRequestUri())
                .httpMethod(requestInfo.getMethod())
                .result(decision.isGranted() ?
                        AuthorizationDecisionEvent.AuthorizationResult.ALLOWED :
                        AuthorizationDecisionEvent.AuthorizationResult.DENIED)
                .clientIp(requestInfo.getClientIp())
                .userAgent(requestInfo.getUserAgent())
                .sessionId(requestInfo.getSessionId());

        builder.isNewSession(requestInfo.getIsNewSession())
                .isNewUser(requestInfo.getIsNewUser())
                .isNewDevice(requestInfo.getIsNewDevice())
                .recentRequestCount(requestInfo.getRecentRequestCount());

        Map<String, Object> metadata = extractWebMetadata(requestInfo, authentication);
        builder.metadata(metadata);

        return builder.build();
    }
    
    public void publishMethodAuthorizationDecisionAsync(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {

        long startTime = System.currentTimeMillis();

        try {
            RequestInfo requestInfo = null;
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                requestInfo = RequestInfo.from(request, tieredStrategyProperties.getSecurity());
                request.setAttribute("security.event.published", true);
            }
            String userId = authentication != null ? authentication.getName() : null;
            if (shouldSkipPublishing(userId)) {
                return;
            }

            AuthorizationDecisionEvent event = buildMethodAuthorizationEvent(methodInvocation, authentication, granted, requestInfo);

            kafkaPublisher.publishAuthorizationEvent(event);

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[AuthorizationEventPublisher] Failed to publish method authorization event - duration: {}ms", duration, e);
        }
    }

    private AuthorizationDecisionEvent buildMethodAuthorizationEvent(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            RequestInfo requestInfo) {

        String resource = methodInvocation.getMethod().getDeclaringClass().getSimpleName() +
                "." + methodInvocation.getMethod().getName();

        AuthorizationDecisionEvent.AuthorizationDecisionEventBuilder builder =
                AuthorizationDecisionEvent.builder();

        String userName = authentication != null ? authentication.getName() : null;
        builder.eventId(UUID.randomUUID().toString())
                .timestamp(Instant.now())
                .userId(userName)
                .resource(resource)
                .result(granted ?
                        AuthorizationDecisionEvent.AuthorizationResult.ALLOWED :
                        AuthorizationDecisionEvent.AuthorizationResult.DENIED);

        if (requestInfo != null) {
            builder.clientIp(requestInfo.getClientIp())
                    .sessionId(requestInfo.getSessionId())
                    .userAgent(requestInfo.getUserAgent())
                    .httpMethod(requestInfo.getMethod());

            builder.isNewSession(requestInfo.getIsNewSession())
                    .isNewUser(requestInfo.getIsNewUser())
                    .isNewDevice(requestInfo.getIsNewDevice())
                    .recentRequestCount(requestInfo.getRecentRequestCount());
        }

        return builder.build();
    }
    
    private Map<String, Object> extractWebMetadata(RequestInfo requestInfo, Authentication authentication) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("queryString", requestInfo.getQueryString());
        metadata.put("secure", requestInfo.isSecure());

        if (authentication != null) {
            metadata.put("authorities", authentication.getAuthorities().toString());
        }

        return metadata;
    }

    @Builder
    @Getter
    public static class RequestInfo {
        private final String requestUri;
        private final String method;
        private final String clientIp;
        private final String userAgent;
        private final String sessionId;
        private final String requestId;
        private final String servletPath;
        private final String queryString;
        private final String remoteHost;
        private final String protocol;
        private final boolean secure;

        private final Boolean isNewSession;
        private final Boolean isNewUser;
        private final Boolean isNewDevice;
        private final Integer recentRequestCount;

        public static RequestInfo from(HttpServletRequest request, TieredStrategyProperties.Security security) {
            return RequestInfo.builder()
                    .requestUri(request.getRequestURI())
                    .method(request.getMethod())
                    .clientIp(extractClientIpStatic(request, security))
                    .userAgent(extractUserAgentStatic(request))
                    .sessionId(request.getSession(false) != null ?
                            request.getSession(false).getId() : null)
                    .requestId(extractRequestIdStatic(request))
                    .servletPath(request.getServletPath())
                    .queryString(request.getQueryString())
                    .remoteHost(request.getRemoteHost())
                    .protocol(request.getProtocol())
                    .secure(request.isSecure())
                    .isNewSession((Boolean) request.getAttribute("hcad.is_new_session"))
                    .isNewUser((Boolean) request.getAttribute("hcad.is_new_user"))
                    .isNewDevice((Boolean) request.getAttribute("hcad.is_new_device"))
                    .recentRequestCount((Integer) request.getAttribute("hcad.recent_request_count"))
                    .build();
        }

        private static String extractClientIpStatic(HttpServletRequest request, TieredStrategyProperties.Security security) {
            String remoteAddr = request.getRemoteAddr();

            if (security == null || !security.isTrustedProxyValidationEnabled()) {
                return extractClientIpLegacy(request);
            }

            List<String> trustedProxies = security.getTrustedProxies();

            // 신뢰 프록시 목록이 비어있으면 X-Forwarded-For 사용 안 함 (가장 안전)
            if (trustedProxies == null || trustedProxies.isEmpty()) {
                log.debug("[D1][Zero Trust] No trusted proxies configured, using remoteAddr: {}", remoteAddr);
                return remoteAddr;
            }

            // remoteAddr이 신뢰 프록시 목록에 있는지 확인
            if (isTrustedProxy(remoteAddr, trustedProxies)) {
                // 신뢰 프록시에서 온 요청 → X-Forwarded-For 사용
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                    String clientIp = xForwardedFor.split(",")[0].trim();
                    log.debug("[D1][Zero Trust] Trusted proxy {}, using X-Forwarded-For: {}", remoteAddr, clientIp);
                    return clientIp;
                }

                String xRealIp = request.getHeader("X-Real-IP");
                if (xRealIp != null && !xRealIp.isEmpty()) {
                    log.debug("[D1][Zero Trust] Trusted proxy {}, using X-Real-IP: {}", remoteAddr, xRealIp);
                    return xRealIp;
                }
            } else {
                // 신뢰 프록시가 아닌 곳에서 온 요청 → remoteAddr 사용
                // X-Forwarded-For가 있어도 무시 (스푸핑 방지)
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                    log.warn("[D1][Zero Trust] Untrusted source {} sent X-Forwarded-For header (ignored): {}",
                            remoteAddr, xForwardedFor);
                }
            }

            return remoteAddr;
        }

        private static String extractClientIpLegacy(HttpServletRequest request) {
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

        private static boolean isTrustedProxy(String ip, List<String> trustedProxies) {
            if (ip == null || trustedProxies == null) {
                return false;
            }

            for (String trusted : trustedProxies) {
                if (trusted == null || trusted.isEmpty()) {
                    continue;
                }

                try {
                    if (trusted.contains("/")) {
                        if (isIpInCidr(ip, trusted)) {
                            return true;
                        }
                    } else {
                        if (trusted.equals(ip)) {
                            return true;
                        }
                    }
                } catch (Exception e) {
                    log.warn("[D1] Invalid trusted proxy format: {}", trusted, e);
                }
            }

            return false;
        }

        private static boolean isIpInCidr(String ip, String cidr) {
            try {
                String[] parts = cidr.split("/");
                if (parts.length != 2) {
                    return false;
                }

                String networkAddress = parts[0];
                int prefixLength = Integer.parseInt(parts[1]);

                InetAddress inetIp = InetAddress.getByName(ip);
                InetAddress inetNetwork = InetAddress.getByName(networkAddress);

                byte[] ipBytes = inetIp.getAddress();
                byte[] networkBytes = inetNetwork.getAddress();

                // IPv4와 IPv6 호환성 확인
                if (ipBytes.length != networkBytes.length) {
                    return false;
                }

                // 네트워크 마스크 생성 및 비교
                int fullBytes = prefixLength / 8;
                int remainingBits = prefixLength % 8;

                // 전체 바이트 비교
                for (int i = 0; i < fullBytes; i++) {
                    if (ipBytes[i] != networkBytes[i]) {
                        return false;
                    }
                }

                // 남은 비트 비교
                if (remainingBits > 0 && fullBytes < ipBytes.length) {
                    int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                    return (ipBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
                }

                return true;
            } catch (Exception e) {
                log.debug("[D1] CIDR check failed for ip={}, cidr={}: {}", ip, cidr, e.getMessage());
                return false;
            }
        }

        private static String extractUserAgentStatic(HttpServletRequest request) {
            String userAgent = request.getHeader("X-Simulated-User-Agent");
            if (userAgent != null && !userAgent.isEmpty()) {
                return userAgent;
            }
            userAgent = request.getHeader("User-Agent");
            return userAgent != null ? userAgent : "unknown";
        }

        private static String extractRequestIdStatic(HttpServletRequest request) {
            String requestId = request.getHeader("X-Request-ID");
            return (requestId != null && !requestId.isEmpty()) ?
                    requestId : UUID.randomUUID().toString();
        }
    }
}