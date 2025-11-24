package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.filter.BaseAuthenticationFilter;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexacommon.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.util.Objects;

/**
 * Form 인증 설정을 위한 추상 기반 클래스 (MFA 전용)
 * 공통 기능을 제공하고 템플릿 메서드 패턴을 사용하여 확장 가능
 *
 * Note: Single Form 인증은 Spring Security 기본 FormLoginConfigurer 사용
 */
public abstract class AbstractFormAuthenticationConfigurer<T extends AbstractFormAuthenticationConfigurer<T, H>, H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<T, H> {

    protected String loginProcessingUrl = "/login";
    protected String usernameParameter = "username";
    protected String passwordParameter = "password";
    protected String loginPage;
    protected String failureUrl;
    protected boolean permitAll = false;
    protected RequestMatcher requestMatcher;
    protected PlatformAuthenticationSuccessHandler successHandler;
    protected PlatformAuthenticationFailureHandler failureHandler;
    protected SecurityContextRepository securityContextRepository;
    protected AuthContextProperties properties;

    protected AbstractFormAuthenticationConfigurer() {
        this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, loginProcessingUrl);
    }

    @Override
    public void configure(H http) {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        Assert.notNull(authenticationManager, "AuthenticationManager cannot be null (is it shared from HttpSecurity?)");

        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        properties = applicationContext.getBean(AuthContextProperties.class);

        if (this.requestMatcher == null) {
            this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, loginProcessingUrl);
        }

        BaseAuthenticationFilter filter = createAuthenticationFilter(http, authenticationManager, applicationContext, properties);
        configureFilter(filter, (HttpSecurity) http);
        http.addFilterBefore(postProcess(filter), UsernamePasswordAuthenticationFilter.class);
    }

    /**
     * 하위 클래스에서 구현해야 할 추상 메서드
     * 특정 타입의 인증 필터를 생성
     */
    protected abstract BaseAuthenticationFilter createAuthenticationFilter(
            H http,
            AuthenticationManager authenticationManager,
            ApplicationContext applicationContext,
            AuthContextProperties properties);

    /**
     * 필터에 공통 설정을 적용하는 메서드
     */
    protected void configureFilter(BaseAuthenticationFilter filter, HttpSecurity http) {
        if (successHandler != null) {
            filter.setSuccessHandler(successHandler);
        }
        if (failureHandler != null) {
            filter.setFailureHandler(failureHandler);
        }

        // SecurityContextRepository 결정 우선순위:
        // 1. HttpSecurity SharedObject (Adapter에서 설정)
        // 2. Configurer 필드 (사용자가 명시적으로 설정)
        // 3. 기본값 (RequestAttributeSecurityContextRepository)
        SecurityContextRepository resolvedRepository = http.getSharedObject(SecurityContextRepository.class);
        if (resolvedRepository == null) {
            resolvedRepository = this.securityContextRepository;
        }
        if (resolvedRepository == null) {
            resolvedRepository = new RequestAttributeSecurityContextRepository();
        }

        filter.setSecurityContextRepository(resolvedRepository);
    }

    public T loginProcessingUrl(String loginProcessingUrl) {
        Assert.hasText(loginProcessingUrl, "loginProcessingUrl must not be null or empty");
        this.loginProcessingUrl = loginProcessingUrl;
        this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, loginProcessingUrl);
        return (T) this;
    }

    public T usernameParameter(String usernameParameter) {
        Assert.hasText(usernameParameter, "usernameParameter must not be null or empty");
        this.usernameParameter = usernameParameter;
        return (T) this;
    }

    public T passwordParameter(String passwordParameter) {
        Assert.hasText(passwordParameter, "passwordParameter must not be null or empty");
        this.passwordParameter = passwordParameter;
        return (T) this;
    }

    public T loginPage(String loginPage) {
        Assert.hasText(loginPage, "loginPage must not be null or empty");
        this.loginPage = loginPage;
        return (T) this;
    }

    public T failureUrl(String failureUrl) {
        Assert.hasText(failureUrl, "failureUrl must not be null or empty");
        this.failureUrl = failureUrl;
        return (T) this;
    }

    public T permitAll(boolean permitAll) {
        this.permitAll = permitAll;
        return (T) this;
    }

    public T successHandler(PlatformAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return (T) this;
    }

    public T failureHandler(PlatformAuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return (T) this;
    }

    public T securityContextRepository(SecurityContextRepository repository) {
        this.securityContextRepository = repository;
        return (T) this;
    }
}
