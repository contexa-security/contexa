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

import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.Objects;

public final class FormAuthenticationAdapter extends BaseFormAuthenticationAdapter<FormLoginConfigurer<HttpSecurity>> {

    @Override
    public String getId() {
        return AuthType.FORM.name().toLowerCase();
    }

    @Override
    protected FormLoginConfigurer<HttpSecurity> createConfigurer() {
        return new FormLoginConfigurer<>();
    }

    @Override
    protected void configureFormAuthentication(FormLoginConfigurer<HttpSecurity> configurer,
                                               FormOptions opts,
                                               PlatformAuthenticationSuccessHandler successHandler,
                                               PlatformAuthenticationFailureHandler failureHandler) {
        configurer
                .loginProcessingUrl(opts.getLoginProcessingUrl());

        if (opts.getUsernameParameter() != null) {
            configurer.usernameParameter(opts.getUsernameParameter());
        }
        if (opts.getPasswordParameter() != null) {
            configurer.passwordParameter(opts.getPasswordParameter());
        }
        if (opts.isPermitAll()) {
            configurer.permitAll();
        }
        if (opts.getLoginPage() != null) {
            configurer.loginPage(opts.getLoginPage());
        }
        if (opts.getFailureUrl() != null) {
            configurer.failureUrl(opts.getFailureUrl());
        }

        if (opts.getDefaultSuccessUrl() != null) {
            configurer.defaultSuccessUrl(opts.getDefaultSuccessUrl());
        }

        if (opts.getDefaultSuccessUrl() != null && opts.isAlwaysUseDefaultSuccessUrl()) {
            configurer.defaultSuccessUrl(opts.getDefaultSuccessUrl(), true);
        }

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

        SafeHttpFormLoginCustomizer rawLogin = opts.getRawFormLoginCustomizer();
        if (rawLogin != null) {
            try {
                rawLogin.customize(configurer);
            } catch (Exception e) {
                throw new RuntimeException("Error customizing raw form login for " + getId(), e);
            }
        }
    }

    @Override
    protected void applySecurityContextRepository(FormLoginConfigurer<HttpSecurity> configurer, SecurityContextRepository repository) {
        configurer.securityContextRepository(repository);
    }
}
