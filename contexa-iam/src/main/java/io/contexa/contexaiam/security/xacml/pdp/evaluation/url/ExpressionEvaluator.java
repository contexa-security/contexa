package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;


public interface ExpressionEvaluator {
    
    boolean supports(String expression);

    
    AuthorizationManager<RequestAuthorizationContext> createManager(String expression);
}