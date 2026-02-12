package io.contexa.contexacore.security.zerotrust;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.UserSecurityContext;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import jakarta.servlet.http.HttpServletRequest;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;

import io.contexa.contexacommon.security.UnifiedCustomUserDetails;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class ZeroTrustSecurityService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ThreatScoreUtil threatScoreUtil;
    private final ObjectMapper objectMapper;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private final ZeroTrustActionRedisRepository actionRedisRepository;

    public void applyZeroTrustToContext(SecurityContext context, String userId, String sessionId, HttpServletRequest request) {
        if (!securityZeroTrustProperties.isEnabled() || context == null || userId == null) {
            return;
        }
        try {

            ZeroTrustAction action = getLatestAction(userId);
            double threatScore = threatScoreUtil.getThreatScore(userId);
            double trustScore = 1.0 - threatScore;

            UserSecurityContext userContext = getUserContext(userId);
            if (userContext == null) {
                userContext = createInitialUserContext(userId, sessionId);
            }

            if (securityZeroTrustProperties.getSession().isTrackingEnabled() && sessionId != null) {
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

            redisTemplate.opsForValue().set(invalidKey, invalidationRecord, Duration.ofHours(securityZeroTrustProperties.getCache().getTtlHours()));
            if (securityZeroTrustProperties.getSession().isTrackingEnabled() && userId != null) {
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

    private ZeroTrustAction getLatestAction(String userId) {
        return actionRedisRepository.getCurrentAction(userId);
    }

    private void adjustAuthoritiesByAction(SecurityContext context, ZeroTrustAction action, String userId, HttpServletRequest request) {
        Authentication auth = context.getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return;
        }

        Collection<? extends GrantedAuthority> currentAuthorities = auth.getAuthorities();

        Set<GrantedAuthority> adjustedAuthorities = new HashSet<>();

        switch (action) {
            case ALLOW -> {
                Object principal = auth.getPrincipal();
                if (principal instanceof UnifiedCustomUserDetails userDetails) {
                    adjustedAuthorities.addAll(userDetails.getOriginalAuthorities());
                } else {
                    adjustedAuthorities.addAll(currentAuthorities);
                }
            }
            case BLOCK -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_BLOCKED"));
                log.error("[ZeroTrust][AI Native] User BLOCKED (CRITICAL RISK): {}", userId);
            }
            case CHALLENGE -> {
                adjustedAuthorities.addAll(currentAuthorities);
            }
            case ESCALATE -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_REVIEW_REQUIRED"));
                log.error("[ZeroTrust][AI Native] Security REVIEW required (ESCALATE): {}", userId);
            }
            case PENDING_ANALYSIS -> {
                if (auth.getPrincipal() instanceof UnifiedCustomUserDetails userDetails) {
                    adjustedAuthorities.addAll(userDetails.getOriginalAuthorities());
                }
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_PENDING_ANALYSIS"));
            }
        }

        if (!adjustedAuthorities.equals(new HashSet<>(currentAuthorities))) {
            double trustScore = 1.0 - threatScoreUtil.getThreatScore(userId);
            double threatScore = threatScoreUtil.getThreatScore(userId);

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
                                      double threatScore, UserSecurityContext userContext, ZeroTrustAction action) {
        if (context.getAuthentication() instanceof ZeroTrustAuthenticationToken zeroTrustAuth) {

            zeroTrustAuth.setTrustScore(trustScore);
            zeroTrustAuth.setThreatScore(threatScore);
            zeroTrustAuth.setUserContext(userContext);
            zeroTrustAuth.setLastEvaluated(LocalDateTime.now());

            Map<String, Object> details = new HashMap<>();
            details.put("action", action.name());
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
                .currentThreatScore(securityZeroTrustProperties.getThreat().getInitial())
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
                    Duration.ofHours(securityZeroTrustProperties.getCache().getTtlHours()));
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to save initial user context for: {}", userId, e);
        }

        return context;
    }

    private void trackUserSession(String userId, String sessionId) {
        try {
            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            redisTemplate.opsForSet().add(sessionsKey, sessionId);
            redisTemplate.expire(sessionsKey, securityZeroTrustProperties.getCache().getTtlHours(), TimeUnit.HOURS);

            String sessionUserKey = ZeroTrustRedisKeys.sessionUser(sessionId);
            redisTemplate.opsForValue().set(sessionUserKey, userId,
                    Duration.ofHours(securityZeroTrustProperties.getCache().getTtlHours()));

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
        return threatScoreUtil.getThreatScore(userId);
    }
}