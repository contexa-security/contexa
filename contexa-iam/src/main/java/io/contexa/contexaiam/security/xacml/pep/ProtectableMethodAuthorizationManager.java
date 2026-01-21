package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexacommon.annotation.AnalysisRequirement;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.exception.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.interceptor.ZeroTrustResponseInterceptor;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Arrays;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class ProtectableMethodAuthorizationManager {

    private final MethodSecurityExpressionHandler expressionHandler;
    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final CustomDynamicAuthorizationManager dynamicAuthorizationManager;
    private final RedisTemplate<String, Object> redisTemplate;
    private final ZeroTrustResponseInterceptor zeroTrustResponseInterceptor;

    private static final long POLLING_INTERVAL_MS = 100;

    private static final Duration ANALYSIS_CACHE_TTL = Duration.ofSeconds(30);

    private static final Duration ANALYSIS_LOCK_TTL = Duration.ofSeconds(30);

    private static final Set<String> ALLOWED_ACTIONS = Set.of("ALLOW");

    public void protectable(Supplier<Authentication> authentication, MethodInvocation mi) {
        
        Protectable protectable = findProtectableAnnotation(mi);

        if (protectable != null) {
            String userId = extractUserId(authentication.get());
            String resourceId = getResourceId(mi);

            handleAnalysisRequirement(protectable, userId, resourceId);

            if (protectable.enableRuntimeInterception()) {
                enableRuntimeInterception();
            }
        }

        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);

        Object protectableRuleObj = ctx.lookupVariable("protectableRule");
        if (protectableRuleObj instanceof Expression protectableRule) {
            boolean result = ExpressionUtils.evaluateAsBoolean(protectableRule, ctx);
            if (!result) {
                                throw new AccessDeniedException("Access is denied");
            }
                    } else {
            
            log.warn("[ZeroTrust] preAuthorize - preAuthorizeRule 변수가 없거나 Expression 타입이 아님: {}",
                    protectableRuleObj != null ? protectableRuleObj.getClass().getSimpleName() : "null");
            throw new AccessDeniedException("Access is denied - preAuthorizeRule not found");
        }
    }

    private Protectable findProtectableAnnotation(MethodInvocation mi) {
        Method method = mi.getMethod();

        Protectable protectable = method.getAnnotation(Protectable.class);
        if (protectable != null) {
            return protectable;
        }

        return method.getDeclaringClass().getAnnotation(Protectable.class);
    }

    private void handleAnalysisRequirement(Protectable protectable, String userId, String resourceId) {
        AnalysisRequirement requirement = protectable.analysisRequirement();

        switch (requirement) {
            case NOT_REQUIRED -> {
                
                            }

            case PREFERRED -> {
                
                String action = getCurrentAction(userId);
                if ("PENDING_ANALYSIS".equals(action)) {
                    String defaultAction = protectable.defaultAction();
                                        
                    if ("BLOCK".equalsIgnoreCase(defaultAction)) {
                        throw ZeroTrustAccessDeniedException.blocked(resourceId, 0.5);
                    }
                    
                } else {
                    
                    validateAction(action, resourceId);
                }
            }

            case REQUIRED -> {
                
                long timeoutMs = protectable.analysisTimeout();
                waitForAnalysis(userId, resourceId, timeoutMs);

                String action = getCurrentAction(userId);
                validateAction(action, resourceId);
            }

            case STRICT -> {
                
                long timeoutMs = protectable.analysisTimeout();
                waitForAnalysis(userId, resourceId, timeoutMs);

                String action = getCurrentAction(userId);
                if (!"ALLOW".equalsIgnoreCase(action)) {
                    log.warn("[ZeroTrust] STRICT 리소스에서 ALLOW가 아닌 action: {} - 거부", action);
                    throw new ZeroTrustAccessDeniedException(
                        action,
                        resourceId,
                        0.7,
                        "STRICT 리소스는 ALLOW action만 허용됨"
                    );
                }
            }
        }
    }

    private void waitForAnalysis(String userId, String resourceId, long timeoutMs) {
        long startTime = System.currentTimeMillis();

        while (true) {
            String action = getCurrentAction(userId);
            if (!"PENDING_ANALYSIS".equals(action)) {
                                return;
            }

            if (System.currentTimeMillis() - startTime > timeoutMs) {
                log.warn("[ZeroTrust] 분석 타임아웃 - userId: {}, timeout: {}ms", userId, timeoutMs);
                throw ZeroTrustAccessDeniedException.analysisTimeout(resourceId, timeoutMs);
            }

            try {
                Thread.sleep(POLLING_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ZeroTrustAccessDeniedException(
                    "PENDING_ANALYSIS",
                    resourceId,
                    0.5,
                    "분석 대기 중 인터럽트 발생"
                );
            }
        }
    }

    private void validateAction(String action, String resourceId) {
        if (action == null || ALLOWED_ACTIONS.contains(action.toUpperCase())) {
            return; 
        }

        switch (action.toUpperCase()) {
            case "BLOCK" -> throw ZeroTrustAccessDeniedException.blocked(resourceId, 0.8);
            case "CHALLENGE" -> throw ZeroTrustAccessDeniedException.challengeRequired(resourceId, 0.6);
            case "ESCALATE" -> throw ZeroTrustAccessDeniedException.pendingReview(resourceId, 0.7);
            default -> {
                log.warn("[ZeroTrust] 알 수 없는 action: {} - 거부", action);
                throw new ZeroTrustAccessDeniedException(
                    action,
                    resourceId,
                    0.5,
                    "알 수 없는 action: " + action
                );
            }
        }
    }

    private String getCurrentAction(String userId) {
        if (userId == null || userId.isEmpty()) {
            return "PENDING_ANALYSIS";
        }

        try {
            
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object action = redisTemplate.opsForHash().get(analysisKey, "action");
            if (action != null) {
                return action.toString();
            }

            return "PENDING_ANALYSIS";

        } catch (Exception e) {
            log.error("[ZeroTrust] action 조회 실패 - userId: {}", userId, e);
            return "PENDING_ANALYSIS";
        }
    }

    private String getResourceId(MethodInvocation mi) {
        Method method = mi.getMethod();
        String paramTypes = Arrays.stream(method.getParameterTypes())
            .map(Class::getSimpleName)
            .collect(Collectors.joining(","));
        return method.getDeclaringClass().getName() + "." + method.getName() + "(" + paramTypes + ")";
    }

    private String extractUserId(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return "anonymous";
        }
        return authentication.getName();
    }

    private void enableRuntimeInterception() {
        String requestId = getCurrentRequestId();
        if (requestId != null && zeroTrustResponseInterceptor != null) {
            zeroTrustResponseInterceptor.enableRuntimeInterception(requestId);
                    }
    }

    private String getCurrentRequestId() {
        try {
            ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                Object requestId = request.getAttribute("zeroTrustRequestId");
                return requestId != null ? requestId.toString() : null;
            }
        } catch (Exception e) {
                    }
        return null;
    }
}