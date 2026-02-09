package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;

import java.util.Arrays;

@Slf4j
public abstract class AbstractAISecurityExpressionRoot extends SecurityExpressionRoot {

    protected final AuthorizationContext authorizationContext;
    protected final AuditLogRepository auditLogRepository;
    protected final StringRedisTemplate stringRedisTemplate;

    protected AbstractAISecurityExpressionRoot(Authentication authentication,
                                               AuthorizationContext authorizationContext,
                                               AuditLogRepository auditLogRepository,
                                               StringRedisTemplate stringRedisTemplate) {
        super(authentication);
        this.authorizationContext = authorizationContext;
        this.auditLogRepository = auditLogRepository;
        this.stringRedisTemplate = stringRedisTemplate;
    }

    protected String extractUserId() {
        Authentication authentication = getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        return authentication.getName();
    }

    protected String getCurrentAction() {
        String userId = extractUserId();
        if (userId == null) {
            return "PENDING_ANALYSIS";
        }
        String redisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
        return getActionFromRedisHash(userId, redisKey, stringRedisTemplate);
    }

    public boolean isAllowed() {
        return hasAction("ALLOW");
    }

    public boolean isBlocked() {
        return hasAction("BLOCK");
    }

    public boolean needsChallenge() {
        return hasAction("CHALLENGE");
    }

    public boolean needsEscalation() {
        return hasAction("ESCALATE");
    }

    public boolean isPendingAnalysis() {
        String action = getCurrentAction();
        return action == null || action.isEmpty() || "PENDING_ANALYSIS".equalsIgnoreCase(action);
    }

    public boolean hasAction(String expectedAction) {
        String action = getCurrentAction();

        if (action == null || action.isEmpty()) {
            return false;
        }
        return expectedAction.equalsIgnoreCase(action);
    }

    public boolean hasActionIn(String... allowedActions) {
        String action = getCurrentAction();

        if (action == null || action.isEmpty()) {
            return false;
        }
        return Arrays.stream(allowedActions)
                .anyMatch(a -> a.equalsIgnoreCase(action));
    }

    public boolean hasActionOrDefault(String defaultAction, String... allowedActions) {
        String action = getCurrentAction();
        if (action == null || action.isEmpty() || "PENDING_ANALYSIS".equalsIgnoreCase(action)) {

            action = defaultAction;
        }

        final String finalAction = action;
        return Arrays.stream(allowedActions)
                .anyMatch(a -> a.equalsIgnoreCase(finalAction));
    }

    protected String getActionFromRedisHash(String userId, String redisKey,
                                            StringRedisTemplate stringRedisTemplate) {
        if (userId == null || redisKey == null || stringRedisTemplate == null) {
            return "PENDING_ANALYSIS";
        }

        try {
            Object actionValue = stringRedisTemplate.opsForHash().get(redisKey, "action");

            if (actionValue != null) {
                return actionValue.toString();
            } else {
                return "PENDING_ANALYSIS";
            }
        } catch (Exception e) {
            log.error("getActionFromRedisHash: Redis lookup failed - userId: {}, returning PENDING_ANALYSIS", userId, e);
            return "PENDING_ANALYSIS";
        }
    }
}