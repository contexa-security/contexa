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
package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaidentity.security.filter.RestAuthenticationProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public abstract class AbstractRestAuthenticationConfigurer<T extends AbstractRestAuthenticationConfigurer<T, H>, H extends HttpSecurityBuilder<H>>
        extends AbstractAuthenticationConfigurer<T, H> {

    protected AbstractRestAuthenticationConfigurer() {
        super("/api/login");
    }

    @Override
    protected void beforeFilterCreation(H http, AuthenticationManager authenticationManager, ApplicationContext applicationContext) {
        UserDetailsService userDetailsService = applicationContext.getBean(UserDetailsService.class);
        PasswordEncoder passwordEncoder = applicationContext.getBean(PasswordEncoder.class);
        LoginPolicyHandler loginPolicyHandler = null;
        try {
            loginPolicyHandler = applicationContext.getBean(LoginPolicyHandler.class);
        } catch (Exception ignored) {
        }
        http.authenticationProvider(new RestAuthenticationProvider(userDetailsService, passwordEncoder, loginPolicyHandler));
    }
}
