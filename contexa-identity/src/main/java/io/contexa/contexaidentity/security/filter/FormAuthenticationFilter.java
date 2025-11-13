package io.contexa.contexaidentity.security.filter;

import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.io.IOException;

/**
 * 단일 Form 인증 필터 (MFA 없음)
 *
 * Spring Security 표준 Form 인증 처리
 * - Form 파라미터에서 username/password 읽기
 * - UsernamePasswordAuthenticationToken 사용
 * - MFA 로직 없음 (FactorContext, State Machine 제외)
 */
@Slf4j
public class FormAuthenticationFilter extends BaseAuthenticationFilter {

    // Form 파라미터 필드
    private String usernameParameter = "username";
    private String passwordParameter = "password";

    public FormAuthenticationFilter(RequestMatcher requestMatcher,
                                    AuthenticationManager authenticationManager,
                                    AuthContextProperties properties) {
        super(requestMatcher, authenticationManager, properties);

        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(properties, "properties cannot be null");

        log.info("FormAuthenticationFilter initialized for single-factor authentication");
    }

    /**
     * Form 파라미터에서 인증 정보 읽기
     */
    @Override
    protected Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        String username = request.getParameter(usernameParameter);
        String password = request.getParameter(passwordParameter);

        if (username == null) {
            username = "";
        }
        if (password == null) {
            password = "";
        }

        username = username.trim();

        // Form 인증은 UsernamePasswordAuthenticationToken 사용
        UsernamePasswordAuthenticationToken authRequest =
                UsernamePasswordAuthenticationToken.unauthenticated(username, password);

        return authenticationManager.authenticate(authRequest);
    }

    /**
     * 인증 성공 처리 - 단순 Security Context 저장 (MFA 없음)
     */
    @Override
    public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authentication) throws IOException, ServletException {

        // Security Context 설정
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        log.info("Form authentication successful for user: {}", authentication.getName());

        // Success Handler 호출
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    /**
     * 인증 실패 처리
     */
    @Override
    public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException failed) throws IOException, ServletException {
        securityContextHolderStrategy.clearContext();

        log.warn("Form authentication failed from IP: {}. Error: {}",
                getClientIpAddress(request),
                failed.getMessage());

        failureHandler.onAuthenticationFailure(request, response, failed);
    }

    // Setter 메서드들
    public void setUsernameParameter(String usernameParameter) {
        Assert.hasText(usernameParameter, "usernameParameter cannot be empty");
        this.usernameParameter = usernameParameter;
    }

    public void setPasswordParameter(String passwordParameter) {
        Assert.hasText(passwordParameter, "passwordParameter cannot be empty");
        this.passwordParameter = passwordParameter;
    }
}
