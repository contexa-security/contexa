/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexaidentity.security.handler.OAuth2SingleAuthFailureHandler;
import io.contexa.contexaidentity.security.handler.OAuth2SingleAuthSuccessHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.handler.SessionSingleAuthFailureHandler;
import io.contexa.contexaidentity.security.handler.SessionSingleAuthSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

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
    protected PlatformAuthenticationSuccessHandler resolveNonMfaSuccessHandler(StateType stateType, ApplicationContext appContext) {
        if (stateType == StateType.SESSION) {
            return appContext.getBean(SessionSingleAuthSuccessHandler.class);
        }
        return appContext.getBean(OAuth2SingleAuthSuccessHandler.class);
    }

    @Override
    protected PlatformAuthenticationFailureHandler resolveNonMfaFailureHandler(StateType stateType, ApplicationContext appContext) {
        if (stateType == StateType.SESSION) {
            return appContext.getBean(SessionSingleAuthFailureHandler.class);
        }
        return appContext.getBean(OAuth2SingleAuthFailureHandler.class);
    }

    protected abstract T createConfigurer();

    protected abstract void configureRestAuthentication(T configurer, RestOptions opts,
                                                        PlatformAuthenticationSuccessHandler successHandler,
                                                        PlatformAuthenticationFailureHandler failureHandler);

    protected abstract void configureSecurityContext(T configurer, RestOptions opts);
}
