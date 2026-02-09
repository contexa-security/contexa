package io.contexa.contexaiam.security.xacml.pep;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;

import java.util.function.Supplier;

@Slf4j
@RequiredArgsConstructor
public class ProtectableMethodAuthorizationManager {

    private final MethodSecurityExpressionHandler expressionHandler;

    public void protectable(Supplier<Authentication> authentication, MethodInvocation mi) {

        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);

        Object protectableRuleObj = ctx.lookupVariable("protectableRule");
        if (protectableRuleObj instanceof Expression protectableRule) {
            boolean result = ExpressionUtils.evaluateAsBoolean(protectableRule, ctx);
            if (!result) {
                throw new AuthorizationDeniedException("Access is denied");
            }
        } else {
            log.warn("[ZeroTrust] preAuthorize - preAuthorizeRule 변수가 없거나 Expression 타입이 아님: {}",
                    protectableRuleObj != null ? protectableRuleObj.getClass().getSimpleName() : "null");
            throw new AuthorizationDeniedException("Access is denied - preAuthorizeRule not found");
        }
    }
}