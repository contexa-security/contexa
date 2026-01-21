package io.contexa.contexaiam.security.xacml.pip.context;

import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInvocation; 
import org.springframework.security.core.Authentication;

public interface ContextHandler {
    
    AuthorizationContext create(Authentication authentication, HttpServletRequest request);

    AuthorizationContext create(Authentication authentication, MethodInvocation invocation);

}
