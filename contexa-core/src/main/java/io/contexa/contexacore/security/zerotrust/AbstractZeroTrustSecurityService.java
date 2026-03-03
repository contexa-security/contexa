package io.contexa.contexacore.security.zerotrust;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;

import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Slf4j
public abstract class AbstractZeroTrustSecurityService implements ZeroTrustSecurityService {

    private static final String ZERO_TRUST_ACTION_ATTR = "contexa.zeroTrustAction";

    protected final ThreatScoreUtil threatScoreUtil;
    protected final SecurityZeroTrustProperties securityZeroTrustProperties;
    protected final ZeroTrustActionRepository actionRepository;
    protected BlockingSignalBroadcaster blockingSignalBroadcaster;

    private final Cache<String, CachedZeroTrustDecision> decisionCache;
    private final Set<String> registeredSessions = ConcurrentHashMap.newKeySet();

    protected AbstractZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository) {
        this.threatScoreUtil = threatScoreUtil;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
        this.actionRepository = actionRepository;
        this.decisionCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(5, TimeUnit.SECONDS)
                .build();
    }

    @Override
    public void applyZeroTrustToContext(SecurityContext context, String userId, String sessionId, HttpServletRequest request) {
        if (!securityZeroTrustProperties.isEnabled() || context == null || userId == null) {
            return;
        }
        try {
            String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);

            ZeroTrustAction action;
            double threatScore;

            CachedZeroTrustDecision cached = decisionCache.getIfPresent(userId);
            if (cached != null && Objects.equals(cached.contextBindingHash, contextBindingHash)) {
                action = cached.action;
                threatScore = cached.threatScore;
            } else {
                action = actionRepository.getCurrentAction(userId, contextBindingHash);
                threatScore = threatScoreUtil.getThreatScore(userId);
                decisionCache.put(userId, new CachedZeroTrustDecision(action, threatScore, contextBindingHash));
            }

            double trustScore = 1.0 - threatScore;
            adjustAuthoritiesByAction(context, action, userId, trustScore, threatScore);

            if (sessionId != null && registeredSessions.add(sessionId)) {
                doRegisterSession(userId, sessionId);
            }

            if (request != null) {
                request.setAttribute(ZERO_TRUST_ACTION_ATTR, action);
            }

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to apply Zero Trust to context for user: {}", userId, e);
            throw e;
        }
    }

    @Override
    public void cleanupOnLogout(String userId, String sessionId) {
        if (userId == null) {
            return;
        }

        try {
            actionRepository.removeAllUserData(userId);
            if (blockingSignalBroadcaster != null) {
                blockingSignalBroadcaster.registerUnblock(userId);
            }

            decisionCache.invalidate(userId);
            if (sessionId != null) {
                registeredSessions.remove(sessionId);
            }
            doCleanupSessionData(userId, sessionId);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to cleanup on logout: userId={}", userId, e);
        }
    }

    protected abstract void doRegisterSession(String userId, String sessionId);

    protected abstract void doCleanupSessionData(String userId, String sessionId);

    protected void adjustAuthoritiesByAction(SecurityContext context, ZeroTrustAction action,
                                              String userId, double trustScore, double threatScore) {
        Authentication auth = context.getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return;
        }

        if (auth instanceof ZeroTrustAuthenticationToken ztToken && ztToken.getAction() == action) {
            return;
        }

        Collection<? extends GrantedAuthority> currentAuthorities = auth.getAuthorities();
        Set<GrantedAuthority> adjustedAuthorities = new HashSet<>();

        switch (action) {
            case ALLOW -> {
                addOriginalOrCurrentAuthorities(auth, adjustedAuthorities, currentAuthorities);
            }
            case BLOCK -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
                log.error("[ZeroTrust][AI Native] User BLOCKED (CRITICAL RISK): {}", userId);
            }
            case CHALLENGE -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
            }
            case ESCALATE -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
                log.error("[ZeroTrust][AI Native] Security REVIEW required (ESCALATE): {}", userId);
            }
            case PENDING_ANALYSIS -> {
                addOriginalOrCurrentAuthorities(auth, adjustedAuthorities, currentAuthorities);
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
            }
        }

        if (!adjustedAuthorities.equals(new HashSet<>(currentAuthorities))) {
            Authentication adjustedAuth = new ZeroTrustAuthenticationToken(
                    auth.getPrincipal(),
                    auth.getCredentials(),
                    adjustedAuthorities,
                    trustScore,
                    threatScore,
                    action
            );
            context.setAuthentication(adjustedAuth);
        }
    }

    private void addOriginalOrCurrentAuthorities(Authentication auth,
                                                  Set<GrantedAuthority> target,
                                                  Collection<? extends GrantedAuthority> current) {
        Object principal = auth.getPrincipal();
        if (principal instanceof UnifiedCustomUserDetails userDetails) {
            target.addAll(userDetails.getOriginalAuthorities());
        } else {
            target.addAll(current);
        }
    }

    private record CachedZeroTrustDecision(ZeroTrustAction action, double threatScore, String contextBindingHash) {}
}
