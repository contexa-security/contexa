package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationProvider;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

@Slf4j
public class OttAuthenticationAdapter extends AbstractAuthenticationAdapter<OttOptions> {

    @Override
    public String getId() {
        return AuthType.OTT.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 300;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, OttOptions options,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler  successHandler, // 이 메소드는 Ott에서는 사용 안 함
                                         PlatformAuthenticationFailureHandler  failureHandler) throws Exception {
        throw new UnsupportedOperationException(
                "OttAuthenticationAdapter uses OneTimeTokenGenerationSuccessHandler. Call configureHttpSecurityForOtt instead."
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
        UserDetailsService userDetailsService = appContext.getBean(UserDetailsService.class);
        OneTimeTokenService oneTimeTokenService = appContext.getBean(OneTimeTokenService.class);

        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl())
                    .loginProcessingUrl(loginProcessingUrl)
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl())
                    .tokenService(opts.getOneTimeTokenService())
                    .tokenGenerationSuccessHandler(opts.getTokenGenerationSuccessHandler() == null ?
                            tokenGenerationSuccessHandler:opts.getTokenGenerationSuccessHandler())
                    .authenticationProvider(new OneTimeTokenAuthenticationProvider(oneTimeTokenService, userDetailsService));

            if (successHandler != null)  ott.successHandler(successHandler);
            else if (opts.getSuccessHandler() != null) ott.successHandler(opts.getSuccessHandler());

            if (failureHandler != null) ott.failureHandler(failureHandler);
            else if (opts.getFailureHandler() != null) ott.failureHandler(opts.getFailureHandler());

        });
    }
}
