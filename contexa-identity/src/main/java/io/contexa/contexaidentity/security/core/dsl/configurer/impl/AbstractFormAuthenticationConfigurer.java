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

    protected abstract BaseAuthenticationFilter createAuthenticationFilter(
            H http,
            AuthenticationManager authenticationManager,
            ApplicationContext applicationContext,
            AuthContextProperties properties);

    protected void configureFilter(BaseAuthenticationFilter filter, HttpSecurity http) {
        if (successHandler != null) {
            filter.setSuccessHandler(successHandler);
        }
        if (failureHandler != null) {
            filter.setFailureHandler(failureHandler);
        }

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
