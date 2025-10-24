package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.filter.BaseAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.MfaRestAuthenticationFilter;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * MFA(Multi-Factor Authentication)를 지원하는 REST 인증 설정 클래스
 */
public final class MfaRestAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractRestAuthenticationConfigurer<MfaRestAuthenticationConfigurer<H>, H> {

    private String mfaInitiateUrl;

    @Override
    public void init(H http) throws Exception {
        // MFA 설정 초기화
        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        if (platformContext != null) {
            AuthContextProperties authProps = platformContext.getShared(AuthContextProperties.class);
            if (authProps != null && authProps.getMfa() != null && StringUtils.hasText(authProps.getMfa().getInitiateUrl())) {
                this.mfaInitiateUrl = authProps.getMfa().getInitiateUrl();
            }
        }
        if (this.mfaInitiateUrl == null) {
            this.mfaInitiateUrl = "/mfa"; // 기본값 설정
        }
    }

    @Override
    protected BaseAuthenticationFilter createAuthenticationFilter(
            H http,
            AuthenticationManager authenticationManager,
            ApplicationContext applicationContext,
            AuthContextProperties properties) throws Exception {

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