package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.ExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.WebSpelExpressionEvaluator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.List;

@RequiredArgsConstructor
public class ExpressionAuthorizationManagerResolver {

    private final List<ExpressionEvaluator> evaluators;
    private final SecurityExpressionHandler<RequestAuthorizationContext> customWebSecurityExpressionHandler;

    public AuthorizationManager<RequestAuthorizationContext> resolve(String expression) {
        for (ExpressionEvaluator evaluator : evaluators) {
            if (evaluator.supports(expression)) {
                if (evaluator instanceof WebSpelExpressionEvaluator) {
                    WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager(expression);
                    manager.setExpressionHandler(customWebSecurityExpressionHandler);
                    return manager;
                }
                return evaluator.createManager(expression);
            }
        }
        throw new IllegalArgumentException("No evaluator found for expression: " + expression);
    }
}