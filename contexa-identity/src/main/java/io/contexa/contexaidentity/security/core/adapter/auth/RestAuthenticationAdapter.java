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

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.configurer.impl.RestAuthenticationConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.filter.DefaultRestLoginPageGeneratingFilter;
import io.contexa.contexaidentity.security.filter.RestAuthenticationFilter;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import java.util.Objects;
import org.springframework.context.ApplicationContext;
import org.springframework.context.MessageSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public final class RestAuthenticationAdapter extends BaseRestAuthenticationAdapter<RestAuthenticationConfigurer<HttpSecurity>> {

    @Override
    public String getId() {
        return AuthType.REST.name().toLowerCase();
    }

    @Override
    protected RestAuthenticationConfigurer createConfigurer() {
        return new RestAuthenticationConfigurer();
    }

    @Override
    protected void configureRestAuthentication(RestAuthenticationConfigurer configurer,
                                               RestOptions opts,
                                               PlatformAuthenticationSuccessHandler successHandler,
                                               PlatformAuthenticationFailureHandler failureHandler) {

        configurer.loginProcessingUrl(opts.getLoginProcessingUrl());

        if (opts.getSuccessHandler() != null) {
            configurer.successHandler(opts.getSuccessHandler());

        } else if (successHandler != null) {
            configurer.successHandler(successHandler);
            successHandler.setDefaultTargetUrl(opts.getDefaultSuccessUrl());
            successHandler.setAlwaysUse(opts.isAlwaysUseDefaultSuccessUrl());
        }
        if (opts.getFailureHandler() != null) {
            configurer.failureHandler(opts.getFailureHandler());

        } else if (failureHandler != null) {
            configurer.failureHandler(failureHandler);
            failureHandler.setDefaultTargetUrl(Objects.requireNonNullElse(opts.getFailureUrl(), "/login?error"));
        }
    }

    @Override
    protected void configureSecurityContext(RestAuthenticationConfigurer configurer,
                                            RestOptions opts) {
        configurer.securityContextRepository(opts.getSecurityContextRepository());
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, RestOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {
        super.configureHttpSecurity(http, opts, currentFlow, successHandler, failureHandler);

        String loginPageUrl = currentFlow.getUrlPrefix() != null
                ? currentFlow.getUrlPrefix() + "/api/login" : "/api/login";
        DefaultRestLoginPageGeneratingFilter loginPageFilter = new DefaultRestLoginPageGeneratingFilter(loginPageUrl);
        MessageSource messageSource = http.getSharedObject(ApplicationContext.class)
                .getBean(MessageSource.class);
        loginPageFilter.setMessageSource(messageSource);
        http.addFilterBefore(loginPageFilter, UsernamePasswordAuthenticationFilter.class);
    }
}