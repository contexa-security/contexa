package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

@Order(0)
public class AuthenticatedExpressionEvaluator implements ExpressionEvaluator {
    @Override
    public boolean supports(String expression) {
        return "isAuthenticated()".equals(expression) || "isFullyAuthenticated()".equals(expression);
    }

    @Override
    public AuthorizationManager<RequestAuthorizationContext> createManager(String expression) {
        if ("isAuthenticated()".equals(expression)) {
            return AuthenticatedAuthorizationManager.authenticated();
        }
        return AuthenticatedAuthorizationManager.fullyAuthenticated();
    }
}