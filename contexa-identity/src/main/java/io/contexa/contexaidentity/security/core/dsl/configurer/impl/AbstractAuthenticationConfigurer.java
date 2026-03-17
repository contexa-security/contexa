package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.filter.BaseAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.MfaFormAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.MfaRestAuthenticationFilter;
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
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

public abstract class AbstractAuthenticationConfigurer<T extends AbstractAuthenticationConfigurer<T, H>, H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<T, H> {

    protected String loginProcessingUrl;
    protected RequestMatcher requestMatcher;
    protected PlatformAuthenticationSuccessHandler successHandler;
    protected PlatformAuthenticationFailureHandler failureHandler;
    protected SecurityContextRepository securityContextRepository;
    protected AuthContextProperties properties;

    protected AbstractAuthenticationConfigurer(String defaultLoginProcessingUrl) {
        this.loginProcessingUrl = defaultLoginProcessingUrl;
        this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, defaultLoginProcessingUrl);
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

        beforeFilterCreation(http, authenticationManager, applicationContext);

        BaseAuthenticationFilter filter = createAuthenticationFilter(http, authenticationManager, applicationContext, properties);
        configureFilter(filter, (HttpSecurity) http);
        http.addFilterBefore(postProcess(filter), UsernamePasswordAuthenticationFilter.class);
    }

    protected void beforeFilterCreation(H http, AuthenticationManager authenticationManager, ApplicationContext applicationContext) {
        // no-op by default
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

        if (securityContextRepository != null) {
            filter.setSecurityContextRepository(securityContextRepository);
        } else {
            SecurityContextRepository resolvedRepository = http.getSharedObject(SecurityContextRepository.class);
            filter.setSecurityContextRepository(resolvedRepository);
        }

        // Propagate flowTypeName to MFA primary auth filters for Multi MFA support
        AuthenticationFlowConfig flowConfig = http.getSharedObject(AuthenticationFlowConfig.class);
        if (flowConfig != null) {
            if (filter instanceof MfaFormAuthenticationFilter mfaFormFilter) {
                mfaFormFilter.setFlowTypeName(flowConfig.getTypeName());
            } else if (filter instanceof MfaRestAuthenticationFilter mfaRestFilter) {
                mfaRestFilter.setFlowTypeName(flowConfig.getTypeName());
            }
        }
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
