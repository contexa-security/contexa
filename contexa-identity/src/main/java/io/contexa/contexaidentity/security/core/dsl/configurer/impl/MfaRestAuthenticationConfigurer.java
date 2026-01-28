package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.filter.BaseAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.MfaRestAuthenticationFilter;
import io.contexa.contexacommon.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.util.Assert;

public final class MfaRestAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractRestAuthenticationConfigurer<MfaRestAuthenticationConfigurer<H>, H> {

    private String mfaInitiateUrl = "/mfa";

    @Override
    public void init(H http){
        // mfaInitiateUrl uses default value "/mfa"
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