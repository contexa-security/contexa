package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.filter.BaseAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.MfaRestAuthenticationFilter;
import io.contexa.contexacommon.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public final class MfaRestAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractRestAuthenticationConfigurer<MfaRestAuthenticationConfigurer<H>, H> {

    private String mfaInitiateUrl;

    @Override
    public void init(H http){
        
        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        if (platformContext != null) {
            AuthContextProperties authProps = platformContext.getShared(AuthContextProperties.class);
            if (authProps != null && authProps.getMfa() != null && StringUtils.hasText(authProps.getMfa().getUrls().getInitiate())) {
                this.mfaInitiateUrl = authProps.getMfa().getUrls().getInitiate();
            }
        }
        if (this.mfaInitiateUrl == null) {
            this.mfaInitiateUrl = "/mfa"; 
        }
    }

    @Override
    protected BaseAuthenticationFilter createAuthenticationFilter(
            H http,
            AuthenticationManager authenticationManager,
            ApplicationContext applicationContext,
            AuthContextProperties properties) {

        Assert.notNull(this.mfaInitiateUrl, "mfaInitiateUrl must be configured or have a default value.");

        return new MfaRestAuthenticationFilter(
                authenticationManager,
                applicationContext,
                properties,
                requestMatcher
        );
    }

    public MfaRestAuthenticationConfigurer<H> mfaInitiateUrl(String mfaInitiateUrl) {
        Assert.hasText(mfaInitiateUrl, "mfaInitiateUrl must not be empty");
        this.mfaInitiateUrl = mfaInitiateUrl;
        return this;
    }
}