package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.regex.Pattern;

@Order(1)
public class AuthorityExpressionEvaluator implements ExpressionEvaluator {
    private static final Pattern AUTHORITY_PATTERN = Pattern.compile("^[A-Z_]+$");

    @Override
    public boolean supports(String expression) {
        return AUTHORITY_PATTERN.matcher(expression).matches();
    }

    @Override
    public AuthorizationManager<RequestAuthorizationContext> createManager(String expression) {
        return AuthorityAuthorizationManager.hasAuthority(expression);
    }
}