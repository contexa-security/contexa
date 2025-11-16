package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.enums.StateType;
import io.contexa.contexaidentity.security.handler.OAuth2SingleAuthFailureHandler;
import io.contexa.contexaidentity.security.handler.OAuth2SingleAuthSuccessHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.handler.SessionSingleAuthFailureHandler;
import io.contexa.contexaidentity.security.handler.SessionSingleAuthSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.util.List;

/**
 * REST 인증 어댑터 기반 클래스
 *
 * REST는 자체 플랫폼 방식으로 Spring Security 기본 핸들러가 없으므로
 * SESSION 모드에서도 명시적 핸들러 필요
 *
 * @param <T> Configurer 타입
 */
@Slf4j
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
     * REST 인증용 Success Handler 결정
     *
     * REST는 자체 플랫폼 방식이므로 SESSION 모드에서도 SessionSingleAuth* 핸들러 사용
     * Spring Security 기본 핸들러를 사용하지 않음
     */
    @Override
    protected PlatformAuthenticationSuccessHandler resolveSuccessHandler(
            RestOptions options,
            @Nullable AuthenticationFlowConfig currentFlow,
            AuthenticationStepConfig myStepConfig,
            @Nullable List<AuthenticationStepConfig> allSteps,
            @Nullable StateConfig stateConfig,
            ApplicationContext appContext) {

        StateType stateType = determineStateType(stateConfig, appContext);
        boolean isMfaFlow = (currentFlow != null && AuthType.MFA.name().equalsIgnoreCase(currentFlow.getTypeName()));

        log.debug("AuthenticationFeature [REST]: Resolving success handler - MFA: {}, StateType: {}",
                isMfaFlow, stateType);

        if (isMfaFlow) {
            // MFA 인증은 부모 클래스 로직 사용
            return super.resolveSuccessHandler(options, currentFlow, myStepConfig, allSteps, stateConfig, appContext);
        } else {
            // 단일 인증 - REST는 SESSION 모드에서도 명시적 핸들러 필요
            if (stateType == StateType.SESSION) {
                log.debug("AuthenticationFeature [REST]: Single auth + SESSION mode - using SessionSingleAuthSuccessHandler");
                return appContext.getBean(SessionSingleAuthSuccessHandler.class);
            } else {
                // OAuth2 또는 JWT 모드
                log.debug("AuthenticationFeature [REST]: Single auth + OAuth2/JWT mode - using OAuth2SingleAuthSuccessHandler");
                return appContext.getBean(OAuth2SingleAuthSuccessHandler.class);
            }
        }
    }

    /**
     * REST 인증용 Failure Handler 결정
     *
     * REST는 자체 플랫폼 방식이므로 SESSION 모드에서도 SessionSingleAuth* 핸들러 사용
     * Spring Security 기본 핸들러를 사용하지 않음
     */
    @Override
    protected PlatformAuthenticationFailureHandler resolveFailureHandler(
            RestOptions options,
            @Nullable AuthenticationFlowConfig currentFlow,
            @Nullable StateConfig stateConfig,
            ApplicationContext appContext) {

        StateType stateType = determineStateType(stateConfig, appContext);
        boolean isMfaFlow = (currentFlow != null && AuthType.MFA.name().equalsIgnoreCase(currentFlow.getTypeName()));

        log.debug("AuthenticationFeature [REST]: Resolving failure handler - MFA: {}, StateType: {}",
                isMfaFlow, stateType);

        if (isMfaFlow) {
            // MFA 인증은 부모 클래스 로직 사용
            return super.resolveFailureHandler(options, currentFlow, stateConfig, appContext);
        } else {
            // 단일 인증 - REST는 SESSION 모드에서도 명시적 핸들러 필요
            if (stateType == StateType.SESSION) {
                log.debug("AuthenticationFeature [REST]: Single auth + SESSION mode - using SessionSingleAuthFailureHandler");
                return appContext.getBean(SessionSingleAuthFailureHandler.class);
            } else {
                // OAuth2 또는 JWT 모드
                log.debug("AuthenticationFeature [REST]: Single auth + OAuth2/JWT mode - using OAuth2SingleAuthFailureHandler");
                return appContext.getBean(OAuth2SingleAuthFailureHandler.class);
            }
        }
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
