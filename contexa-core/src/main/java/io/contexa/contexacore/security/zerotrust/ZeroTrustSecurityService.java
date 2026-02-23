package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
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
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class ZeroTrustSecurityService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ThreatScoreUtil threatScoreUtil;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private final ZeroTrustActionRedisRepository actionRedisRepository;

    public void applyZeroTrustToContext(SecurityContext context, String userId, String sessionId, HttpServletRequest request) {
        if (!securityZeroTrustProperties.isEnabled() || context == null || userId == null) {
            return;
        }
        try {
            String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
            ZeroTrustAction action = actionRedisRepository.getCurrentAction(userId, contextBindingHash);
            double threatScore = threatScoreUtil.getThreatScore(userId);
            double trustScore = 1.0 - threatScore;

            adjustAuthoritiesByAction(context, action, userId, trustScore, threatScore);

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to apply Zero Trust to context for user: {}", userId, e);
            throw e;
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

            redisTemplate.opsForValue().set(invalidKey, invalidationRecord,
                    Duration.ofHours(securityZeroTrustProperties.getCache().getTtlHours()));

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
            String sessionsKey = ZeroTrustRedisKeys.userSessions(userId);
            Set<Object> sessions = redisTemplate.opsForSet().members(sessionsKey);

            if (sessions != null) {
                for (Object sessionObj : sessions) {
                    invalidateSession(sessionObj.toString(), userId, reason);
                }
            }

            redisTemplate.delete(sessionsKey);

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to invalidate all sessions for user: {}", userId, e);
        }
    }

    private void adjustAuthoritiesByAction(SecurityContext context, ZeroTrustAction action,
                                           String userId, double trustScore, double threatScore) {
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
                adjustedAuthorities.add(new SimpleGrantedAuthority("ROLE_MFA_REQUIRED"));
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
}
