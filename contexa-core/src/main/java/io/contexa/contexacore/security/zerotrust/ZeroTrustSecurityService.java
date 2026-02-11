package io.contexa.contexacore.security.zerotrust;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.UserSecurityContext;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;

import io.contexa.contexacommon.security.UnifiedCustomUserDetails;

import java.net.InetAddress;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class ZeroTrustSecurityService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ThreatScoreOrchestrator threatScoreOrchestrator;
    private final ObjectMapper objectMapper;

    @Value("${zerotrust.enabled:true}")
    private boolean zeroTrustEnabled;

    @Value("${zerotrust.threat.initial:0.3}")
    private double initialThreatScore;

    @Value("${zerotrust.cache.ttl.hours:24}")
    private long cacheTtlHours;

    @Value("${zerotrust.session.tracking.enabled:true}")
    private boolean sessionTrackingEnabled;

    public void applyZeroTrustToContext(SecurityContext context, String userId, String sessionId, HttpServletRequest request) {
        if (!zeroTrustEnabled || context == null || userId == null) {
            return;
        }
        try {

            String action = getLatestAction(userId);
            double threatScore = threatScoreOrchestrator.getThreatScore(userId);
            double trustScore = 1.0 - threatScore;

            UserSecurityContext userContext = getUserContext(userId);
            if (userContext == null) {
                userContext = createInitialUserContext(userId, sessionId);
            }

            if (sessionTrackingEnabled && sessionId != null) {
                trackUserSession(userId, sessionId);
            }

            adjustAuthoritiesByAction(context, action, userId, request);
            setZeroTrustMetadata(context, trustScore, threatScore, userContext, action);

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to apply Zero Trust to context for user: {}", userId, e);
        }
    }

    public void invalidateSession(String sessionId, String userId, String reason) {
        if (sessionId == null) {
            return;
        }
        try {
            String invalidKey = ZeroTrustRedisKeys.invalidSession(sessionId);

            Map<String, Object> invalidationRecord = new HashMap<>();
            invalidationRecord.put("sessionId", sessionId);
            invalidationRecord.put("userId", userId);
            invalidationRecord.put("reason", reason);
            invalidationRecord.put("timestamp", System.currentTimeMillis());

            redisTemplate.opsForValue().set(invalidKey, invalidationRecord, Duration.ofHours(cacheTtlHours));
            if (sessionTrackingEnabled && userId != null) {
                removeUserSession(userId, sessionId);
            }

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to invalidate session: {}", sessionId, e);
        }
    }

    public boolean isSessionInvalidated(String sessionId) {
        if (sessionId == null) {
            return false;
        }

        try {
            String invalidKey = ZeroTrustRedisKeys.invalidSession(sessionId);
            return redisTemplate.hasKey(invalidKey);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to check session invalidation: {}", sessionId, e);
            return false;
        }
    }

    public void invalidateAllUserSessions(String userId, String reason) {
        if (userId == null) {
            return;
        }

        try {
            Set<String> userSessions = getUserSessions(userId);

            for (String sessionId : userSessions) {
                invalidateSession(sessionId, userId, reason);
            }

            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.delete(sessionsKey);

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to invalidate all sessions for user: {}", userId, e);
        }
    }

    private String getLatestAction(String userId) {
        try {

            String blockKey = ZeroTrustRedisKeys.userBlocked(userId);
            Boolean isBlocked = (Boolean) redisTemplate.opsForValue().get(blockKey);
            if (Boolean.TRUE.equals(isBlocked)) {
                return "BLOCK";
            }

            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object action = redisTemplate.opsForHash().get(analysisKey, "action");
            if (action != null) {
                return action.toString();
            }

            return "PENDING_ANALYSIS";

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to get action for user: {}", userId, e);

            return "PENDING_ANALYSIS";
        }
    }

    private void adjustAuthoritiesByAction(SecurityContext context, String action, String userId, HttpServletRequest request) {
        Authentication auth = context.getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return;
        }

        Collection<? extends GrantedAuthority> currentAuthorities = auth.getAuthorities();

        Set<GrantedAuthority> adjustedAuthorities = new HashSet<>();

        switch (action) {
            case "ALLOW" -> {
                Object principal = auth.getPrincipal();
                if (principal instanceof UnifiedCustomUserDetails userDetails) {
                    adjustedAuthorities.addAll(userDetails.getOriginalAuthorities());
                } else {
                    adjustedAuthorities.addAll(currentAuthorities);
                }
            }
            case "BLOCK" -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_BLOCKED"));
                log.warn("[ZeroTrust][AI Native] User BLOCKED (CRITICAL RISK): {}", userId);
            }
            case "CHALLENGE" -> {
                adjustedAuthorities.addAll(currentAuthorities);
//                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_MFA_REQUIRED"));
            }
            case "ESCALATE" -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_REVIEW_REQUIRED"));
                log.warn("[ZeroTrust][AI Native] Security REVIEW required (ESCALATE): {}", userId);
            }
            case "PENDING_ANALYSIS" -> {
                if (auth.getPrincipal() instanceof UnifiedCustomUserDetails userDetails) {
                    adjustedAuthorities.addAll(userDetails.getOriginalAuthorities());
                }
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_PENDING_ANALYSIS"));
            }
            default -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_LIMITED"));
                log.warn("[ZeroTrust][AI Native] Unknown action '{}', limited to ROLE_USER: {}", action, userId);
            }
        }

        if (!adjustedAuthorities.equals(new HashSet<>(currentAuthorities))) {
            double trustScore = 1.0 - threatScoreOrchestrator.getThreatScore(userId);
            double threatScore = threatScoreOrchestrator.getThreatScore(userId);

            Authentication adjustedAuth = new ZeroTrustAuthenticationToken(
                    auth.getPrincipal(),
                    auth.getCredentials(),
                    adjustedAuthorities,
                    trustScore,
                    threatScore
            );
            context.setAuthentication(adjustedAuth);
        }
    }

    private void setZeroTrustMetadata(SecurityContext context, double trustScore,
                                      double threatScore, UserSecurityContext userContext, String action) {
        if (context.getAuthentication() instanceof ZeroTrustAuthenticationToken zeroTrustAuth) {

            zeroTrustAuth.setTrustScore(trustScore);
            zeroTrustAuth.setThreatScore(threatScore);
            zeroTrustAuth.setUserContext(userContext);
            zeroTrustAuth.setLastEvaluated(LocalDateTime.now());

            Map<String, Object> details = new HashMap<>();
            details.put("action", action);
            details.put("trustScore", trustScore);
            details.put("threatScore", threatScore);
            zeroTrustAuth.setDetails(details);
        }
    }

    private UserSecurityContext getUserContext(String userId) {
        try {
            String contextKey = ZeroTrustRedisKeys.userContext(userId);
            Object stored = redisTemplate.opsForValue().get(contextKey);

            if (stored instanceof UserSecurityContext) {
                return (UserSecurityContext) stored;
            } else if (stored instanceof Map) {
                return objectMapper.convertValue(stored, UserSecurityContext.class);
            }

            return null;
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to get user context for: {}", userId, e);
            return null;
        }
    }

    private UserSecurityContext createInitialUserContext(String userId, String sessionId) {
        UserSecurityContext context = UserSecurityContext.builder()
                .userId(userId)
                .currentThreatScore(initialThreatScore)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        if (sessionId != null) {

            UserSecurityContext.SessionContext sessionContext = UserSecurityContext.SessionContext.builder()
                    .sessionId(sessionId)
                    .startTime(LocalDateTime.now())
                    .lastAccessTime(LocalDateTime.now())
                    .active(true)
                    .build();
            context.addSession(sessionContext);
        }

        try {
            String contextKey = ZeroTrustRedisKeys.userContext(userId);
            redisTemplate.opsForValue().set(contextKey, context,
                    Duration.ofHours(cacheTtlHours));
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to save initial user context for: {}", userId, e);
        }

        return context;
    }

    private void trackUserSession(String userId, String sessionId) {
        try {
            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().add(sessionsKey, sessionId);
            redisTemplate.expire(sessionsKey, cacheTtlHours, TimeUnit.HOURS);

            String sessionUserKey = ZeroTrustRedisKeys.sessionUser(sessionId);
            redisTemplate.opsForValue().set(sessionUserKey, userId,
                    Duration.ofHours(cacheTtlHours));

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to track user session: {} -> {}", userId, sessionId, e);
        }
    }

    private void removeUserSession(String userId, String sessionId) {
        try {
            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().remove(sessionsKey, sessionId);

            String sessionUserKey = ZeroTrustRedisKeys.sessionUser(sessionId);
            redisTemplate.delete(sessionUserKey);

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to remove user session: {} -> {}", userId, sessionId, e);
        }
    }

    private Set<String> getUserSessions(String userId) {
        try {
            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            Set<Object> sessions = redisTemplate.opsForSet().members(sessionsKey);

            if (sessions != null) {
                return sessions.stream()
                        .map(Object::toString)
                        .collect(Collectors.toSet());
            }
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to get user sessions for: {}", userId, e);
        }
        return new HashSet<>();
    }

    public double getThreatScore(String userId) {
        return threatScoreOrchestrator.getThreatScore(userId);
    }
}