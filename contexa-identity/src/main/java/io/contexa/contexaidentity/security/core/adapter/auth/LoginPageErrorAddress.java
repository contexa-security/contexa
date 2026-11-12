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

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

/**
 * Tells the login page Spring generates which address is its error page. A flow that answers its failures with a
 * Contexa handler (the token state) leaves Spring's login settings without a failure address, so the generated page
 * did not answer {@code /login?error} and a failed page sign-in ended on a 404. Spring sets that address on the page
 * while its configurers initialize; this one sets it afterwards, while the configurers configure.
 */
final class LoginPageErrorAddress extends AbstractHttpConfigurer<LoginPageErrorAddress, HttpSecurity> {

    private final String errorAddress;

    LoginPageErrorAddress(String errorAddress) {
        this.errorAddress = errorAddress;
    }

    /**
     * @param http         the flow's chain
     * @param errorAddress the address a failed page sign-in is sent to, without the context path
     */
    static void register(HttpSecurity http, String errorAddress) throws Exception {
        http.with(new LoginPageErrorAddress(errorAddress), Customizer.withDefaults());
    }

    @Override
    public void configure(HttpSecurity http) {
        DefaultLoginPageGeneratingFilter page = http.getSharedObject(DefaultLoginPageGeneratingFilter.class);
        if (page != null) {
            page.setFailureUrl(errorAddress);
        }
    }
}
