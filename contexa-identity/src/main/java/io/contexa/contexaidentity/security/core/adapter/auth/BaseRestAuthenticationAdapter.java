package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.StateType;
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
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {

        T configurer = createConfigurer();

        http.with(configurer, config -> {
            configureRestAuthentication(config, opts, successHandler, failureHandler);

            if (opts.getSecurityContextRepository() != null) {
                configureSecurityContext(config, opts);
            }
        });
    }

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

        if (isMfaFlow) {
            return super.resolveSuccessHandler(options, currentFlow, myStepConfig, allSteps, stateConfig, appContext);
        } else {
            if (stateType == StateType.SESSION) {
                return appContext.getBean(SessionSingleAuthSuccessHandler.class);
            } else {
                return appContext.getBean(OAuth2SingleAuthSuccessHandler.class);
            }
        }
    }

    @Override
    protected PlatformAuthenticationFailureHandler resolveFailureHandler(
            RestOptions options,
            @Nullable AuthenticationFlowConfig currentFlow,
            @Nullable StateConfig stateConfig,
            ApplicationContext appContext) {

        StateType stateType = determineStateType(stateConfig, appContext);
        boolean isMfaFlow = (currentFlow != null && AuthType.MFA.name().equalsIgnoreCase(currentFlow.getTypeName()));

        if (isMfaFlow) {

            return super.resolveFailureHandler(options, currentFlow, stateConfig, appContext);
        } else {

            if (stateType == StateType.SESSION) {
                return appContext.getBean(SessionSingleAuthFailureHandler.class);
            } else {

                return appContext.getBean(OAuth2SingleAuthFailureHandler.class);
            }
        }
    }

    protected abstract T createConfigurer();

    protected abstract void configureRestAuthentication(T configurer, RestOptions opts,
                                                        PlatformAuthenticationSuccessHandler successHandler,
                                                        PlatformAuthenticationFailureHandler failureHandler);

    protected abstract void configureSecurityContext(T configurer, RestOptions opts);
}
