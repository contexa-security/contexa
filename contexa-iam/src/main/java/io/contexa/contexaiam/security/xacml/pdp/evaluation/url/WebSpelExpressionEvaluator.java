package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

@Order(2)
public class WebSpelExpressionEvaluator implements ExpressionEvaluator {

    @Override
    public boolean supports(String expression) {
        return true;
    }

    @Override
    public AuthorizationManager<RequestAuthorizationContext> createManager(String expression) {

        return new WebExpressionAuthorizationManager(expression);
    }
}