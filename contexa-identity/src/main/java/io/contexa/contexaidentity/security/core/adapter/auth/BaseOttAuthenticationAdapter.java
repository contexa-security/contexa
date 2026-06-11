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
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationProvider;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import io.contexa.contexaidentity.security.service.ott.EmailGenerateOneTimeTokenRequest;

@Slf4j
public abstract class BaseOttAuthenticationAdapter extends AbstractAuthenticationAdapter<OttOptions> {

    @Override
    protected void configureHttpSecurity(HttpSecurity http, OttOptions options,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {
        throw new UnsupportedOperationException(
                "BaseOttAuthenticationAdapter uses OneTimeTokenGenerationSuccessHandler. Call configureHttpSecurityForOtt instead."
        );
    }

    @Override
    public void configureHttpSecurityForOtt(HttpSecurity http, OttOptions opts,
                                            OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler,
                                            PlatformAuthenticationSuccessHandler successHandler,
                                            PlatformAuthenticationFailureHandler failureHandler) throws Exception {

        String loginProcessingUrl = opts.getLoginProcessingUrl();
        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        ApplicationContext appContext = platformContext.applicationContext();
        UserDetailsService userDetailsService = appContext.getBean(UserDetailsService.class);
        OneTimeTokenService oneTimeTokenService = appContext.getBean(OneTimeTokenService.class);

        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl())
                    .loginProcessingUrl(loginProcessingUrl)
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl())
                    .tokenService(opts.getOneTimeTokenService())
                    .tokenGenerationSuccessHandler(opts.getTokenGenerationSuccessHandler() == null ?
                            tokenGenerationSuccessHandler : opts.getTokenGenerationSuccessHandler())
                    .generateRequestResolver(request -> {
                        String username = request.getParameter("username");
                        if (username == null || username.isBlank()) {
                            return null;
                        }
                        String email = request.getParameter("email");
                        if (email != null && !email.isBlank()) {
                            return new EmailGenerateOneTimeTokenRequest(username, email);
                        }
                        return new GenerateOneTimeTokenRequest(username);
                    })
                    .authenticationProvider(new OneTimeTokenAuthenticationProvider(oneTimeTokenService, userDetailsService));

            if (successHandler != null) ott.successHandler(successHandler);
            else if (opts.getSuccessHandler() != null) ott.successHandler(opts.getSuccessHandler());

            if (failureHandler != null) ott.failureHandler(failureHandler);
            else if (opts.getFailureHandler() != null) ott.failureHandler(opts.getFailureHandler());
        });
    }
}
