package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * REST 인증 어댑터 기반 클래스
 * @param <T> Configurer 타입
 */
public abstract class BaseRestAuthenticationAdapter<T extends AbstractHttpConfigurer<T, HttpSecurity>>
        extends AbstractAuthenticationAdapter<RestOptions> {

    @Override
    public int getOrder() {
        return 200;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, RestOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler  successHandler,
                                         PlatformAuthenticationFailureHandler  failureHandler) throws Exception {

        T configurer = createConfigurer();

        http.with(configurer, config -> {
            configureRestAuthentication(config, opts, successHandler, failureHandler);

            if (opts.getSecurityContextRepository() != null) {
                configureSecurityContext(config, opts);
            }
        });
    }

    /**
     * Configurer 인스턴스 생성
     */
    protected abstract T createConfigurer();

    /**
     * REST 인증 설정
     */
    protected abstract void configureRestAuthentication(T configurer, RestOptions opts,
                                                        PlatformAuthenticationSuccessHandler  successHandler,
                                                        PlatformAuthenticationFailureHandler failureHandler);

    /**
     * Security Context 설정
     */
    protected abstract void configureSecurityContext(T configurer, RestOptions opts);
}