package io.contexa.contexaidentity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.domain.LoginRequest;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public abstract class BaseAuthenticationFilter extends OncePerRequestFilter {

    protected final AuthenticationManager authenticationManager;
    protected final AuthContextProperties properties;
    protected final ObjectMapper mapper = new ObjectMapper();

    protected SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    protected RequestMatcher requestMatcher;
    protected PlatformAuthenticationSuccessHandler successHandler;
    protected PlatformAuthenticationFailureHandler failureHandler;
    protected SecurityContextRepository securityContextRepository;

    protected BaseAuthenticationFilter(RequestMatcher requestMatcher, AuthenticationManager authenticationManager,
                                       AuthContextProperties properties) {
        this.requestMatcher = requestMatcher;
        this.authenticationManager = authenticationManager;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        long startTime = System.currentTimeMillis();

        try {
            Authentication authResult = attemptAuthentication(request, response);
            if (authResult == null) {
                ensureMinimumDelay(startTime);
                filterChain.doFilter(request, response);
                return;
            }

            successfulAuthentication(request, response, filterChain, authResult);

        } catch (AuthenticationException ex) {
            ensureMinimumDelay(startTime);
            unsuccessfulAuthentication(request, response, ex);
        }
    }

    /**
     * 인증 시도 - 공통
     */
    protected Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            LoginRequest login = mapper.readValue(request.getInputStream(), LoginRequest.class);
            validateLoginRequest(login);

            RestAuthenticationToken authRequest =
                    new RestAuthenticationToken(login.username(), login.password());
            return authenticationManager.authenticate(authRequest);

        } catch (IOException e) {
            throw new RuntimeException("Authentication request body read failed", e);
        }
    }

    /**
     * 인증 성공 처리 - 하위 클래스에서 구현
     */
    protected abstract void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                     FilterChain chain, Authentication authentication)
            throws IOException, ServletException;

    /**
     * 인증 실패 처리 - 공통
     */
    protected abstract void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed)
            throws IOException, ServletException;


    protected void ensureMinimumDelay(long startTime) {
        long elapsed = System.currentTimeMillis() - startTime;
        long authDelay = properties.getMfa().getMinimumDelayMs();
        if (elapsed < authDelay) {
            try {
                Thread.sleep(authDelay - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    protected void validateLoginRequest(LoginRequest login) {
        if (!StringUtils.hasText(login.username()) || !StringUtils.hasText(login.password())) {
            throw new IllegalArgumentException("Username and password must not be empty");
        }
        if (login.username().length() > 100) {
            throw new IllegalArgumentException("Username too long");
        }
        if (login.password().length() > 200) {
            throw new IllegalArgumentException("Password too long");
        }
    }

    protected String getClientIpAddress(HttpServletRequest request) {
        String[] headers = {
                "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED", "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED", "HTTP_VIA", "REMOTE_ADDR"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        this.requestMatcher = requestMatcher;
    }

    public void setSuccessHandler(PlatformAuthenticationSuccessHandler successHandler) {
        Assert.notNull(successHandler, "successHandler cannot be null");
        this.successHandler = successHandler;
    }

    public void setFailureHandler(PlatformAuthenticationFailureHandler failureHandler) {
        Assert.notNull(failureHandler, "failureHandler cannot be null");
        this.failureHandler = failureHandler;
    }

    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
        this.securityContextRepository = securityContextRepository;
    }

    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }
}
