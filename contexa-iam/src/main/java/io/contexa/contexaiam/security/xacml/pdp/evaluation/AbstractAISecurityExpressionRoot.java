package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;

import java.util.Arrays;
import java.util.List;

@Slf4j
public abstract class AbstractAISecurityExpressionRoot extends SecurityExpressionRoot {

    protected final AuthorizationContext authorizationContext;
    protected final AuditLogRepository auditLogRepository;

    protected AbstractAISecurityExpressionRoot(Authentication authentication,
                                               AuthorizationContext authorizationContext,
                                               AuditLogRepository auditLogRepository) {
        super(authentication);
        this.authorizationContext = authorizationContext;
        this.auditLogRepository = auditLogRepository;

    }

    protected String getRemoteIp() {
        if (authorizationContext != null && authorizationContext.environment() != null) {
            jakarta.servlet.http.HttpServletRequest request = authorizationContext.environment().request();
            if (request != null) {

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
            return authorizationContext.environment().remoteIp();
        }
        return "unknown";
    }

    protected String extractUserId() {
        Authentication authentication = getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        return authentication.getName();
    }

    private boolean isInternalIP(String ip) {
        if (ip == null) return false;
        return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.") || ip.equals("127.0.0.1");
    }
    protected void storeActionAsTrustAssessment(String action) {
        if (authorizationContext == null) {
            return;
        }

        if (authorizationContext.attributes().containsKey("ai_assessment")) {
            return;
        }

        double score = switch (action != null ? action.toUpperCase() : "PENDING_ANALYSIS") {
            case "ALLOW" -> 1.0;
            case "CHALLENGE" -> 0.5;
            case "ESCALATE" -> 0.3;
            case "BLOCK" -> 0.0;
            default -> 0.5;
        };

        List<String> riskTags = List.of("LLM_ACTION", action != null ? action : "PENDING_ANALYSIS");
        String summary = "Redis LLM Action: " + (action != null ? action : "PENDING_ANALYSIS");

        TrustAssessment assessment = new TrustAssessment(score, riskTags, summary);
        authorizationContext.attributes().put("ai_assessment", assessment);

    }

    protected abstract String getCurrentAction();

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

        storeActionAsTrustAssessment(action);

        return action == null || action.isEmpty() || "PENDING_ANALYSIS".equalsIgnoreCase(action);
    }

    public boolean hasAction(String expectedAction) {
        String action = getCurrentAction();

        storeActionAsTrustAssessment(action);

        if (action == null || action.isEmpty()) {
            return false;
        }
        return expectedAction.equalsIgnoreCase(action);
    }

    public boolean hasActionIn(String... allowedActions) {
        String action = getCurrentAction();

        storeActionAsTrustAssessment(action);

        if (action == null || action.isEmpty()) {
            return false;
        }
        return Arrays.stream(allowedActions)
                .anyMatch(a -> a.equalsIgnoreCase(action));
    }

    public boolean isAnalysisComplete() {
        String action = getCurrentAction();
        return action != null
                && !action.isEmpty()
                && !"PENDING_ANALYSIS".equalsIgnoreCase(action);
    }

    public boolean requiresAnalysis() {
        boolean complete = isAnalysisComplete();
        if (!complete) {
            log.warn("분석 필수 리소스 접근 시도 - 분석 미완료 상태");
        }
        return complete;
    }

    public boolean requiresAnalysisWithAction(String... allowedActions) {
        if (!isAnalysisComplete()) {
            log.warn("분석 필수 리소스 접근 시도 - 분석 미완료 상태");
            return false;
        }
        boolean hasAllowedAction = hasActionIn(allowedActions);
        if (!hasAllowedAction) {
            log.warn("분석 완료 but 허용되지 않은 action - current: {}, allowed: {}",
                    getCurrentAction(), Arrays.toString(allowedActions));
        }
        return hasAllowedAction;
    }

    public boolean hasActionOrDefault(String defaultAction, String... allowedActions) {
        String action = getCurrentAction();
        if (action == null || action.isEmpty() || "PENDING_ANALYSIS".equalsIgnoreCase(action)) {

            action = defaultAction;
        }

        storeActionAsTrustAssessment(action);

        final String finalAction = action;
        return Arrays.stream(allowedActions)
                .anyMatch(a -> a.equalsIgnoreCase(finalAction));
    }

    protected static class ContextExtractionResult {
        public final String remoteIp;
        public final String userAgent;
        public final String resourceIdentifier;
        public final String actionType;

        public ContextExtractionResult(String remoteIp, String userAgent,
                                       String resourceIdentifier, String actionType) {
            this.remoteIp = remoteIp;
            this.userAgent = userAgent;
            this.resourceIdentifier = resourceIdentifier;
            this.actionType = actionType;
        }
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
            log.error("getActionFromRedisHash: Redis 조회 실패 - userId: {}, PENDING_ANALYSIS 반환", userId, e);
            return "PENDING_ANALYSIS";
        }
    }

    protected ContextExtractionResult extractContextFromAuthorizationContext() {
        String remoteIp = getRemoteIp();
        String userAgent = "";
        String resourceIdentifier = "";
        String actionType = "";

        if (authorizationContext != null) {
            if (authorizationContext.environment() != null && authorizationContext.environment().request() != null) {
                userAgent = authorizationContext.environment().request().getHeader("User-Agent");
                if (userAgent == null) {
                    userAgent = "";
                }
            }
            if (authorizationContext.resource() != null) {
                resourceIdentifier = authorizationContext.resource().identifier();
            }
            actionType = authorizationContext.action();
        }

        return new ContextExtractionResult(remoteIp, userAgent, resourceIdentifier, actionType);
    }

    protected String calculateContextHashFromAuthorizationContext() {
        StringBuilder sb = new StringBuilder();
        if (authorizationContext != null) {
            if (authorizationContext.resource() != null) {
                sb.append(authorizationContext.resource().identifier());
            }
            sb.append(authorizationContext.action());
            if (authorizationContext.subjectEntity() != null) {
                sb.append(authorizationContext.subjectEntity().getId());
            }
        }
        sb.append(System.currentTimeMillis());
        return Integer.toHexString(sb.toString().hashCode());
    }
} 