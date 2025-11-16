package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.filter.BaseAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.RestAuthenticationProvider;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.util.Objects;

/**
 * REST 인증 설정을 위한 추상 기반 클래스
 * 공통 기능을 제공하고 템플릿 메서드 패턴을 사용하여 확장 가능
 */
public abstract class AbstractRestAuthenticationConfigurer<T extends AbstractRestAuthenticationConfigurer<T, H>, H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<T, H> {

    protected String loginProcessingUrl = "/api/auth/login";
    protected RequestMatcher requestMatcher;
    protected PlatformAuthenticationSuccessHandler successHandler;
    protected PlatformAuthenticationFailureHandler failureHandler;
    protected SecurityContextRepository securityContextRepository;
    protected AuthContextProperties properties;

    protected AbstractRestAuthenticationConfigurer() {
        this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, loginProcessingUrl);
        ;
    }

    @Override
    public void configure(H http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        Assert.notNull(authenticationManager, "AuthenticationManager cannot be null (is it shared from HttpSecurity?)");

        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        properties = applicationContext.getBean(AuthContextProperties.class);
        UserDetailsService userDetailsService = applicationContext.getBean(UserDetailsService.class);
        PasswordEncoder passwordEncoder = applicationContext.getBean(PasswordEncoder.class);

        if (this.requestMatcher == null) {
            this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, loginProcessingUrl);
        }

        // 템플릿 메서드 - 하위 클래스에서 필터 생성
        BaseAuthenticationFilter filter = createAuthenticationFilter(http, authenticationManager, applicationContext, properties);
        http.authenticationProvider(new RestAuthenticationProvider(userDetailsService, passwordEncoder));
        // 공통 설정 적용
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
            AuthContextProperties properties) throws Exception;

    /**
     * 필터에 공통 설정을 적용하는 메서드
     * 리플렉션을 사용하여 필터 타입에 관계없이 설정 적용
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