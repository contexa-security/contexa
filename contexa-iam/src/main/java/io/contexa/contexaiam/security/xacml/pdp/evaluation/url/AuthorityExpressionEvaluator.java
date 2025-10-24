package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class AuthorityExpressionEvaluator implements ExpressionEvaluator {
    // SpEL 문법이 없는 순수 권한 문자열을 확인하는 정규식
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