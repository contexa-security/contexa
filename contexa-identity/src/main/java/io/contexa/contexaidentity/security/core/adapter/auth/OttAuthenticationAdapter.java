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
                                            PlatformAuthenticationSuccessHandler successHandler,// 코드 생성 성공 핸들러
                                            PlatformAuthenticationFailureHandler failureHandler) throws Exception { // 코드 검증 실패 핸들러

        String getRequestUrlForForwardingFilter = opts.getLoginProcessingUrl(); // 예: /login/ott 또는 /login/mfa-ott
        String postProcessingUrlForAuthFilter = opts.getLoginProcessingUrl();   // 이 URL로 자동 POST

        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        ApplicationContext appContext = platformContext.applicationContext();
        UserDetailsService userDetailsService = appContext.getBean(UserDetailsService.class);
        OneTimeTokenService oneTimeTokenService = appContext.getBean(OneTimeTokenService.class);

        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl()) // 사용자가 직접 코드 입력하는 페이지 (선택적)
                    .loginProcessingUrl(postProcessingUrlForAuthFilter) // 코드 "검증"을 처리할 POST URL
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl()) // 코드 "생성/발송"을 처리할 POST URL (GenerateOneTimeTokenFilter가 처리)
                    .tokenService(opts.getOneTimeTokenService())
                    .tokenGenerationSuccessHandler(opts.getTokenGenerationSuccessHandler() == null ?
                            tokenGenerationSuccessHandler:opts.getTokenGenerationSuccessHandler())
                    .successHandler(successHandler)
                    .failureHandler(failureHandler)
                    .authenticationProvider(new OneTimeTokenAuthenticationProvider(oneTimeTokenService, userDetailsService));
        });
        log.info("OttAuthenticationAdapter: Configured OttForwardingFilter for GET {} and OneTimeTokenLogin for POST {} (Generation at {})",
                getRequestUrlForForwardingFilter, postProcessingUrlForAuthFilter, opts.getTokenGeneratingUrl());
    }
}
