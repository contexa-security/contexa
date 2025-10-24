package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.ExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.WebSpelExpressionEvaluator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class ExpressionAuthorizationManagerResolver {

    private final List<ExpressionEvaluator> evaluators;
    private final SecurityExpressionHandler<RequestAuthorizationContext> customWebSecurityExpressionHandler;

    public AuthorizationManager<RequestAuthorizationContext> resolve(String expression) {
        for (ExpressionEvaluator evaluator : evaluators) {
            if (evaluator.supports(expression)) {
                // 'WebSpelExpressionEvaluator' 가 선택되면...
                if (evaluator instanceof WebSpelExpressionEvaluator) {
                    WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager(expression);
                    // 이 manager는 내부적으로 createSecurityExpressionRoot를 호출하여 #riskScore 변수가 주입된 컨텍스트를 사용하게 된다.
                    manager.setExpressionHandler(customWebSecurityExpressionHandler);
                    return manager;
                }
                return evaluator.createManager(expression);
            }
        }
        throw new IllegalArgumentException("No evaluator found for expression: " + expression);
    }
}