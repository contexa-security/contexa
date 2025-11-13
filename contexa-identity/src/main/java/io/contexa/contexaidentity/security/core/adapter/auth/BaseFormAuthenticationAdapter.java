package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * Form 인증 어댑터 기반 클래스
 * @param <T> Configurer 타입
 */
public abstract class BaseFormAuthenticationAdapter<T extends AbstractHttpConfigurer<T, HttpSecurity>>
        extends AbstractAuthenticationAdapter<FormOptions> {

    @Override
    public int getOrder() {
        return 100; // Form은 REST(200)보다 우선순위 높음
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, FormOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {

        T configurer = createConfigurer();

        http.with(configurer, config -> {
            configureFormAuthentication(config, opts, successHandler, failureHandler);

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
     * Form 인증 설정
     */
    protected abstract void configureFormAuthentication(T configurer, FormOptions opts,
                                                        PlatformAuthenticationSuccessHandler successHandler,
                                                        PlatformAuthenticationFailureHandler failureHandler);

    /**
     * Security Context 설정
     */
    protected abstract void configureSecurityContext(T configurer, FormOptions opts);
}
