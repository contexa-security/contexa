package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.service.IdentityUserDetailsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationProvider;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

/**
 * OTT 인증 어댑터 기반 클래스
 *
 * 단일 인증과 MFA 모두 동일한 Spring Security OneTimeTokenAuthenticationFilter를 사용합니다.
 */
@Slf4j
public abstract class BaseOttAuthenticationAdapter extends AbstractAuthenticationAdapter<OttOptions> {

    @Override
    protected void configureHttpSecurity(HttpSecurity http, OttOptions options,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {
        throw new UnsupportedOperationException(
                "BaseOttAuthenticationAdapter uses OneTimeTokenGenerationSuccessHandler. Call configureHttpSecurityForOtt instead."
        );
    }

    @Override
    public void configureHttpSecurityForOtt(HttpSecurity http, OttOptions opts,
                                            OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler,
                                            PlatformAuthenticationSuccessHandler successHandler,
                                            PlatformAuthenticationFailureHandler failureHandler) throws Exception {

        String loginProcessingUrl = opts.getLoginProcessingUrl();
        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        ApplicationContext appContext = platformContext.applicationContext();
        UserDetailsService userDetailsService = appContext.getBean(IdentityUserDetailsService.class);
        OneTimeTokenService oneTimeTokenService = appContext.getBean(OneTimeTokenService.class);

        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl())
                    .loginProcessingUrl(loginProcessingUrl)
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl())
                    .tokenService(opts.getOneTimeTokenService())
                    .tokenGenerationSuccessHandler(opts.getTokenGenerationSuccessHandler() == null ?
                            tokenGenerationSuccessHandler : opts.getTokenGenerationSuccessHandler())
                    .authenticationProvider(new OneTimeTokenAuthenticationProvider(oneTimeTokenService, userDetailsService));

            if (successHandler != null) ott.successHandler(successHandler);
            else if (opts.getSuccessHandler() != null) ott.successHandler(opts.getSuccessHandler());

            if (failureHandler != null) ott.failureHandler(failureHandler);
            else if (opts.getFailureHandler() != null) ott.failureHandler(opts.getFailureHandler());
        });
    }
}
