package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;

import java.util.Arrays;

@Slf4j
public abstract class AbstractAISecurityExpressionRoot extends SecurityExpressionRoot {

    protected final AuthorizationContext authorizationContext;
    protected final AuditLogRepository auditLogRepository;
    protected final ZeroTrustActionRedisRepository actionRedisRepository;

    protected AbstractAISecurityExpressionRoot(Authentication authentication,
                                               AuthorizationContext authorizationContext,
                                               AuditLogRepository auditLogRepository,
                                               ZeroTrustActionRedisRepository actionRedisRepository) {
        super(authentication);
        this.authorizationContext = authorizationContext;
        this.auditLogRepository = auditLogRepository;
        this.actionRedisRepository = actionRedisRepository;
    }

    protected String extractUserId() {
        Authentication authentication = getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        return authentication.getName();
    }

    protected ZeroTrustAction getCurrentAction() {
        String userId = extractUserId();
        if (userId == null) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }
        return actionRedisRepository.getCurrentAction(userId);
    }

    public boolean isAllowed() {
        return getCurrentAction() == ZeroTrustAction.ALLOW;
    }

    public boolean isBlocked() {
        return getCurrentAction() == ZeroTrustAction.BLOCK;
    }

    public boolean needsChallenge() {
        return getCurrentAction() == ZeroTrustAction.CHALLENGE;
    }

    public boolean needsEscalation() {
        return getCurrentAction() == ZeroTrustAction.ESCALATE;
    }

    public boolean isPendingAnalysis() {
        return getCurrentAction() == ZeroTrustAction.PENDING_ANALYSIS;
    }

    public boolean hasAction(String expectedAction) {
        return ZeroTrustAction.fromString(expectedAction) == getCurrentAction();
    }

    public boolean hasActionIn(String... allowedActions) {
        ZeroTrustAction action = getCurrentAction();
        return Arrays.stream(allowedActions)
                .anyMatch(a -> ZeroTrustAction.fromString(a) == action);
    }

    public boolean hasActionOrDefault(String defaultAction, String... allowedActions) {
        ZeroTrustAction action = getCurrentAction();
        if (action == ZeroTrustAction.PENDING_ANALYSIS) {
            action = ZeroTrustAction.fromString(defaultAction);
        }

        final ZeroTrustAction finalAction = action;
        return Arrays.stream(allowedActions)
                .anyMatch(a -> ZeroTrustAction.fromString(a) == finalAction);
    }
}