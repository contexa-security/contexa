package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.io.IOException;


@Slf4j
public class RestAuthenticationFilter extends BaseAuthenticationFilter {

    public RestAuthenticationFilter(RequestMatcher requestMatcher,
                                    AuthenticationManager authenticationManager,
                                    AuthContextProperties properties,
                                    TokenService tokenService,
                                    AuthResponseWriter responseWriter) {
        super(requestMatcher, authenticationManager, properties);

        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(properties, "properties cannot be null");
        Assert.notNull(tokenService, "tokenService cannot be null");
        Assert.notNull(responseWriter, "responseWriter cannot be null");

        log.info("RestAuthenticationFilter initialized with OAuth2 token-based handlers");
    }

    
    @Override
    public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authentication) throws IOException, ServletException {

        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        log.info("REST authentication successful for user: {}", authentication.getName());
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    
    @Override
    public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();

        log.warn("REST authentication failed from IP: {}. Error: {}",
                getClientIpAddress(request),
                failed.getMessage());

        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
