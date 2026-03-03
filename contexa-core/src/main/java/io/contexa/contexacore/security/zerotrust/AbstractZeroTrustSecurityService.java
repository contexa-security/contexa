package io.contexa.contexacore.security.zerotrust;

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
import java.util.Set;

@Slf4j
public abstract class AbstractZeroTrustSecurityService implements ZeroTrustSecurityService {

    protected final ThreatScoreUtil threatScoreUtil;
    protected final SecurityZeroTrustProperties securityZeroTrustProperties;
    protected final ZeroTrustActionRepository actionRepository;
    protected BlockingSignalBroadcaster blockingSignalBroadcaster;

    protected AbstractZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository) {
        this.threatScoreUtil = threatScoreUtil;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
        this.actionRepository = actionRepository;
    }

    @Override
    public void applyZeroTrustToContext(SecurityContext context, String userId, String sessionId, HttpServletRequest request) {
        if (!securityZeroTrustProperties.isEnabled() || context == null || userId == null) {
            return;
        }
        try {
            String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
            ZeroTrustAction action = actionRepository.getCurrentAction(userId, contextBindingHash);
            double threatScore = threatScoreUtil.getThreatScore(userId);
            double trustScore = 1.0 - threatScore;

            adjustAuthoritiesByAction(context, action, userId, trustScore, threatScore);

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

            doCleanupSessionData(userId, sessionId);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to cleanup on logout: userId={}", userId, e);
        }
    }

    protected abstract void doCleanupSessionData(String userId, String sessionId);

    protected void adjustAuthoritiesByAction(SecurityContext context, ZeroTrustAction action,
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
