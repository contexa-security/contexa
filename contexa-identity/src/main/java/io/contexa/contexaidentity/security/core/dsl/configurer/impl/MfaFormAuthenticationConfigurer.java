package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.filter.BaseAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.MfaFormAuthenticationFilter;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * MFA(Multi-Factor Authentication)를 지원하는 Form 인증 설정 클래스
 */
public final class MfaFormAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractFormAuthenticationConfigurer<MfaFormAuthenticationConfigurer<H>, H> {

    private String mfaInitiateUrl;

    @Override
    public void init(H http) {
        // MFA 설정 초기화
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
            AuthContextProperties properties){

        Assert.notNull(this.mfaInitiateUrl, "mfaInitiateUrl must be configured or have a default value.");

        MfaFormAuthenticationFilter filter = new MfaFormAuthenticationFilter(
                authenticationManager,
                applicationContext,
                properties,
                requestMatcher
        );

        // Form 전용 파라미터 설정
        filter.setUsernameParameter(usernameParameter);
        filter.setPasswordParameter(passwordParameter);

        return filter;
    }

    public MfaFormAuthenticationConfigurer<H> mfaInitiateUrl(String mfaInitiateUrl) {
        Assert.hasText(mfaInitiateUrl, "mfaInitiateUrl must not be empty");
        this.mfaInitiateUrl = mfaInitiateUrl;
        return this;
    }
}
