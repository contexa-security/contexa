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

import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.handler.OneTimeTokenCreationSuccessHandler;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.filter.OneTimeTokenAddressRefusalFilter;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.handler.login.LoginFactsAuthenticationProvider;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.ott.ContexaOneTimeTokens;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationProvider;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.ott.FlowBoundOneTimeTokenRequestResolver;

@Slf4j
public abstract class BaseOttAuthenticationAdapter extends AbstractAuthenticationAdapter<OttOptions> {

    /** The page that asks for the code of this kind of sign-in. */
    protected String codeRequestPage(AuthUrlProvider urls) {
        return urls.getSingleOttRequestEmail();
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, OttOptions options,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {
        throw new UnsupportedOperationException(
                "BaseOttAuthenticationAdapter uses OneTimeTokenGenerationSuccessHandler. Call configureHttpSecurityForOtt instead."
        );
    }

    /**
     * The handler all flows share does not know which flow a request belongs to, and a sign-in by code alone leaves no
     * flow record to ask. So each flow hands the page it takes its code at to the handler with the request: the page the
     * DSL named ({@code defaultSubmitPageUrl}), which is where the browser goes once the code is mailed.
     */
    private static OneTimeTokenGenerationSuccessHandler naming(String submitPageUrl,
                                                               OneTimeTokenGenerationSuccessHandler shared) {
        if (shared == null) {
            return null;
        }
        return (request, response, token) -> {
            request.setAttribute(OneTimeTokenCreationSuccessHandler.SUBMIT_PAGE_ATTRIBUTE, submitPageUrl);
            shared.handle(request, response, token);
        };
    }

    @Override
    public void configureHttpSecurityForOtt(HttpSecurity http, OttOptions opts,
                                            OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler,
                                            PlatformAuthenticationSuccessHandler successHandler,
                                            PlatformAuthenticationFailureHandler failureHandler) throws Exception {

        String loginProcessingUrl = opts.getLoginProcessingUrl();
        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        ApplicationContext appContext = platformContext.applicationContext();
        UserDetailsService userDetailsService = ContexaUserStore.forSignIn(appContext);
        OneTimeTokenService oneTimeTokenService = appContext.getBean(ContexaOneTimeTokens.BEAN_NAME, ContexaOneTimeTokens.class).service();

        http.addFilterBefore(new OneTimeTokenAddressRefusalFilter(appContext.getBean(AuthResponseWriter.class),
                codeRequestPage(appContext.getBean(AuthUrlProvider.class))), GenerateOneTimeTokenFilter.class);

        http.oneTimeTokenLogin(ott -> {
            ott.defaultSubmitPageUrl(opts.getDefaultSubmitPageUrl())
                    .loginProcessingUrl(loginProcessingUrl)
                    .showDefaultSubmitPage(opts.isShowDefaultSubmitPage())
                    .tokenGeneratingUrl(opts.getTokenGeneratingUrl())
                    .tokenService(opts.getOneTimeTokenService())
                    .tokenGenerationSuccessHandler(opts.getTokenGenerationSuccessHandler() == null ?
                            naming(opts.getDefaultSubmitPageUrl(), tokenGenerationSuccessHandler)
                            : opts.getTokenGenerationSuccessHandler())
                    .generateRequestResolver(new FlowBoundOneTimeTokenRequestResolver(request -> {
                        MfaStateMachineIntegrator flows = appContext.getBeanProvider(MfaStateMachineIntegrator.class).getIfAvailable();
                        return flows != null ? flows.loadFactorContextFromRequest(request) : null;
                    }))
                    // Spring's provider takes the account the code names as it is: the store refuses a locked or disabled one
                    .authenticationProvider(new LoginFactsAuthenticationProvider(new OneTimeTokenAuthenticationProvider(
                            oneTimeTokenService, new AccountStateCheckingUserDetailsService(userDetailsService))));

            if (successHandler != null) ott.successHandler(successHandler);
            else if (opts.getSuccessHandler() != null) ott.successHandler(opts.getSuccessHandler());

            if (failureHandler != null) ott.failureHandler(failureHandler);
            else if (opts.getFailureHandler() != null) ott.failureHandler(opts.getFailureHandler());
        });
    }
}
