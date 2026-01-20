package io.contexa.contexaidentity.security.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.util.Map;


public interface PlatformAuthenticationFailureHandler extends AuthenticationFailureHandler {

    
    default void onAuthenticationFailure(HttpServletRequest request,
                                 HttpServletResponse response,
                                 AuthenticationException exception,
                                 @Nullable FactorContext factorContext,
                                 FailureType failureType,
                                 Map<String, Object> errorDetails) throws IOException, ServletException {

    }

    
    @Override
    default void onAuthenticationFailure(HttpServletRequest request,
                                         HttpServletResponse response,
                                         AuthenticationException exception) throws IOException, ServletException {
        
    }

    
    enum FailureType {
        PRIMARY_AUTH_FAILED,        
        MFA_FACTOR_FAILED,         
        MFA_MAX_ATTEMPTS_EXCEEDED, 
        MFA_SESSION_NOT_FOUND,     
        MFA_GLOBAL_FAILURE         
    }
}