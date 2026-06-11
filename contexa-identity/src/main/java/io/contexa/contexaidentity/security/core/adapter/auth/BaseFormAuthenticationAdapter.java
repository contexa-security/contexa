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

import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

public abstract class BaseFormAuthenticationAdapter<T extends AbstractHttpConfigurer<T, HttpSecurity>>
        extends AbstractAuthenticationAdapter<FormOptions> {

    @Override
    public int getOrder() {
        return 100;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, FormOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {

        T configurer = createConfigurer();

        http.with(configurer, config -> {
            configureFormAuthentication(config, opts, successHandler, failureHandler);
            configureSecurityContext(config, opts, http);
        });
    }

    protected abstract T createConfigurer();

    protected abstract void configureFormAuthentication(T configurer, FormOptions opts,
                                                        PlatformAuthenticationSuccessHandler successHandler,
                                                        PlatformAuthenticationFailureHandler failureHandler);

    /**
     * Common security context configuration for all form-based adapters.
     * Subclasses can override applySecurityContextRepository to bridge different configurer APIs.
     */
    protected void configureSecurityContext(T configurer, FormOptions opts, HttpSecurity http) {
        SecurityContextRepository existing = http.getSharedObject(SecurityContextRepository.class);
        if (existing instanceof AISessionSecurityContextRepository) {
            applySecurityContextRepository(configurer, existing);
        } else if (opts.getSecurityContextRepository() != null) {
            applySecurityContextRepository(configurer, opts.getSecurityContextRepository());
        } else {
            applySecurityContextRepository(configurer, new HttpSessionSecurityContextRepository());
        }
    }

    protected abstract void applySecurityContextRepository(T configurer, SecurityContextRepository repository);
}
