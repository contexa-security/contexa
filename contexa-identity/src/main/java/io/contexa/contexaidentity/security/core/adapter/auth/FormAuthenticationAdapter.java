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

import java.util.Locale;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.handler.login.LoginFactsRecorder;
import io.contexa.contexacommon.security.bridge.AuthenticationMethodReferences;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.web.context.SecurityContextRepository;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;

public final class FormAuthenticationAdapter extends BaseFormAuthenticationAdapter<FormLoginConfigurer<HttpSecurity>> {

    /** The page Spring generates and posts to when the flow names no login page. */
    private static final String DEFAULT_LOGIN_PAGE = "/login";

    @Override
    public String getId() {
        return AuthType.FORM.name().toLowerCase(Locale.ROOT);
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
                .loginProcessingUrl(opts.getLoginProcessingUrl())
                .authenticationDetailsSource(LoginFactsRecorder.detailsSource(AuthenticationMethodReferences.PASSWORD));

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
            failureHandler.setDefaultTargetUrl(failureAddress(opts));
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
    protected void configureHttpSecurity(HttpSecurity http, FormOptions opts, AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {
        super.configureHttpSecurity(http, opts, currentFlow, successHandler, failureHandler);
        if (opts.getFailureHandler() == null && failureHandler != null && opts.getLoginPage() == null) {
            // Contexa answers the failures (the token state) and sends a page to the generated login page's error
            // address, which that page knows only when it is told.
            LoginPageErrorAddress.register(http, failureAddress(opts));
        }
    }

    /** Where a failed page sign-in goes: the flow's failureUrl, else its login page with ?error, as in Spring. */
    private static String failureAddress(FormOptions opts) {
        if (opts.getFailureUrl() != null) {
            return opts.getFailureUrl();
        }
        return (opts.getLoginPage() != null ? opts.getLoginPage() : DEFAULT_LOGIN_PAGE) + "?error";
    }

    @Override
    protected void applySecurityContextRepository(FormLoginConfigurer<HttpSecurity> configurer, SecurityContextRepository repository) {
        configurer.securityContextRepository(repository);
    }
}
