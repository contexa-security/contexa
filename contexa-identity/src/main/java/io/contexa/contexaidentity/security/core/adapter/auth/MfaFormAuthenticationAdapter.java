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

import io.contexa.contexaidentity.security.core.dsl.configurer.impl.MfaFormAuthenticationConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextRepository;

public final class MfaFormAuthenticationAdapter extends BaseFormAuthenticationAdapter<MfaFormAuthenticationConfigurer<HttpSecurity>> {

    @Override
    public String getId() {
        return AuthType.MFA_FORM.name().toLowerCase();
    }

    @Override
    protected MfaFormAuthenticationConfigurer<HttpSecurity> createConfigurer() {
        return new MfaFormAuthenticationConfigurer<>();
    }

    @Override
    protected void configureFormAuthentication(MfaFormAuthenticationConfigurer<HttpSecurity> configurer,
                                               FormOptions opts,
                                               PlatformAuthenticationSuccessHandler successHandler,
                                               PlatformAuthenticationFailureHandler failureHandler) {
        String effectiveLoginPage = opts.getEffectiveLoginPage();
        configurer
                .loginProcessingUrl(opts.getLoginProcessingUrl())
                .usernameParameter(opts.getUsernameParameter())
                .passwordParameter(opts.getPasswordParameter())
                .loginPage(effectiveLoginPage)
                .failureUrl(opts.getFailureUrl())
                .successUrl(opts.getDefaultSuccessUrl())
                .successUrl(opts.getDefaultSuccessUrl(), opts.isAlwaysUseDefaultSuccessUrl())
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .permitAll(opts.isPermitAll());
    }

    @Override
    protected void applySecurityContextRepository(MfaFormAuthenticationConfigurer<HttpSecurity> configurer, SecurityContextRepository repository) {
        configurer.securityContextRepository(repository);
    }
}
