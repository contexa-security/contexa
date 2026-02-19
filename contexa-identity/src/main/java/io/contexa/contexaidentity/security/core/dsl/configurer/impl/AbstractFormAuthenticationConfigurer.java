package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.util.Assert;

import java.util.Objects;

public abstract class AbstractFormAuthenticationConfigurer<T extends AbstractFormAuthenticationConfigurer<T, H>, H extends HttpSecurityBuilder<H>>
        extends AbstractAuthenticationConfigurer<T, H> {

    protected String usernameParameter = "username";
    protected String passwordParameter = "password";
    protected String loginPage;
    protected String successUrl;
    protected boolean alwaysUse;
    protected String failureUrl;
    protected boolean permitAll = false;

    protected AbstractFormAuthenticationConfigurer() {
        super("/login");
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

    public T successUrl(String successUrl) {
        Assert.hasText(successUrl, "loginPage must not be null or empty");
        this.successUrl = successUrl;
        return (T) this;
    }

    public T successUrl(String successUrl, boolean alwaysUse) {
        Assert.hasText(successUrl, "loginPage must not be null or empty");
        this.successUrl = successUrl;
        this.alwaysUse = alwaysUse;
        return (T) this;
    }

    public T permitAll(boolean permitAll) {
        this.permitAll = permitAll;
        return (T) this;
    }

    @Override
    public T successHandler(PlatformAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        this.successHandler.setDefaultTargetUrl(this.successUrl);
        this.successHandler.setAlwaysUse(alwaysUse);
        return (T) this;
    }

    @Override
    public T failureHandler(PlatformAuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        this.failureHandler.setDefaultTargetUrl(Objects.requireNonNullElse(this.failureUrl, "/login?error"));
        return (T) this;
    }
}
