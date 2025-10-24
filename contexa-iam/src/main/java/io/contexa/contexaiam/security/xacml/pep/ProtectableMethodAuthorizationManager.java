package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Spring Security 표준 방식 AOP - 단순하고 명확
 * 
 * 역할:
 * - SpEL 표현식 평가만 담당
 * - hasPermission 메서드에서 모든 권한 검증 처리
 * - @Protectable 애노테이션 정보는 CustomPermissionEvaluator에서 자동 처리
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ProtectableMethodAuthorizationManager {
    private final MethodSecurityExpressionHandler expressionHandler;
    private final PolicyRetrievalPoint policyRetrievalPoint;
    private final CustomDynamicAuthorizationManager dynamicAuthorizationManager;

    public void preAuthorize(Supplier<Authentication> authentication, MethodInvocation mi) {
        String finalExpression = getDynamicExpression(mi, "PRE_AUTHORIZE");
        if (!StringUtils.hasText(finalExpression)) {
            return;
        }
        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);
        if (!evaluate(finalExpression, ctx)) {
            throw new AccessDeniedException("Access is denied");
        }
    }

    public void postAuthorize(Supplier<Authentication> authentication, MethodInvocation mi, Object returnObject) {
        String finalExpression = getDynamicExpression(mi, "POST_AUTHORIZE");
        if (!StringUtils.hasText(finalExpression)) {
            return;
        }
        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);
        expressionHandler.setReturnObject(returnObject, ctx);
        if (!evaluate(finalExpression, ctx)) {
            throw new AccessDeniedException("Access is denied");
        }
    }

    private boolean evaluate(String expressionString, EvaluationContext context) {
        try {
            Expression expression = expressionHandler.getExpressionParser().parseExpression(expressionString);
            return ExpressionUtils.evaluateAsBoolean(expression, context);
        } catch (Exception e) {
            log.error("Error evaluating SpEL expression: {}", expressionString, e);
            return false;
        }
    }

    private String getDynamicExpression(MethodInvocation mi, String phase) {
        Method method = mi.getMethod();
        String paramTypes = Arrays.stream(method.getParameterTypes()).map(Class::getSimpleName).collect(Collectors.joining(","));
        String methodIdentifier = method.getDeclaringClass().getName() + "." + method.getName() + "(" + paramTypes + ")";

        List<Policy> policies = policyRetrievalPoint.findMethodPolicies(methodIdentifier, phase);
        if (CollectionUtils.isEmpty(policies)) {
            return null;
        }
        return dynamicAuthorizationManager.getExpressionFromPolicies(policies);
    }
}