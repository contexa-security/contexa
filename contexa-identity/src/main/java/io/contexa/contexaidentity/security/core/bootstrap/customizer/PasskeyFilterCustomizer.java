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
package io.contexa.contexaidentity.security.core.bootstrap.customizer;

import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.filter.ContexaWebAuthnRegistrationPageFilter;
import io.contexa.contexaidentity.security.filter.ContexaWebAuthnResourceFilter;
import io.contexa.contexaidentity.security.handler.*;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.Filter;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.ui.DefaultResourcesFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsFilter;
import org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter;
import org.springframework.util.StringUtils;

/**
 * Applies per-flow URL prefix to WebAuthn (Passkey) filters.
 * Also handles WebAuthn handler replacement and registration page replacement.
 *
 * Targets: WebAuthnAuthenticationFilter, PublicKeyCredentialRequestOptionsFilter,
 *          PublicKeyCredentialCreationOptionsFilter, WebAuthnRegistrationFilter
 */
@Slf4j
public class PasskeyFilterCustomizer extends AbstractFilterCustomizer {

    /**
     * Apply per-flow URLs to all WebAuthn filters.
     *
     * @param context PasskeyCustomizerContext containing passkeyOpts and authProps
     */
    @Override
    public void customize(DefaultSecurityFilterChain builtChain, AuthUrlProvider flowUrlProvider, Object context) {
        PasskeyCustomizerContext ctx = (PasskeyCustomizerContext) context;

        for (Filter filter : getFilters(builtChain)) {

            if (filter instanceof AbstractAuthenticationProcessingFilter authFilter && isWebAuthnAuth(filter)) {
                setMatcherIfPresent(authFilter, resolveLoginProcessing(flowUrlProvider, ctx.passkeyOpts(), ctx.authProps()));
            }

            if (filter instanceof PublicKeyCredentialRequestOptionsFilter optionsFilter) {
                String url = resolveAssertionOptions(flowUrlProvider, ctx.passkeyOpts(), ctx.authProps());
                if (StringUtils.hasText(url)) {
                    optionsFilter.setRequestMatcher(createPostMatcher(url));
                }
            }

            if (filter instanceof PublicKeyCredentialCreationOptionsFilter creationFilter) {
                String url = flowUrlProvider.getPasskeyRegistrationOptions();
                if (StringUtils.hasText(url)) {
                    creationFilter.setRequestMatcher(createPostMatcher(url));
                }
            }

            if (filter instanceof WebAuthnRegistrationFilter regFilter) {
                String url = flowUrlProvider.getPasskeyRegistrationProcessing();
                if (StringUtils.hasText(url)) {
                    regFilter.setRegisterCredentialMatcher(createPostMatcher(url));
                    regFilter.setRemoveCredentialMatcher(
                            PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.DELETE, url + "/{id}"));
                }
            }

            if (filter instanceof ContexaWebAuthnRegistrationPageFilter pageFilter) {
                String pageUrl = flowUrlProvider.getPasskeyRegistrationPage();
                if (StringUtils.hasText(pageUrl)) {
                    pageFilter.setRequestMatcher(createGetMatcher(pageUrl));
                }
                String regUrl = flowUrlProvider.getPasskeyRegistrationProcessing();
                if (StringUtils.hasText(regUrl)) {
                    pageFilter.setDeleteActionBase(regUrl);
                    String jsPath = regUrl.replace("/webauthn/register", "/login/webauthn.js");
                    pageFilter.setWebauthnJsPath(jsPath);
                    String urlPrefix = regUrl.replace("/webauthn/register", "");
                    if (StringUtils.hasText(urlPrefix)) {
                        pageFilter.setWebauthnContextPath(urlPrefix);
                    }
                }
            }

            if (filter instanceof DefaultResourcesFilter resFilter
                    && resFilter.toString().contains("spring-security-webauthn.js")) {
                String regUrl = flowUrlProvider.getPasskeyRegistrationProcessing();
                if (StringUtils.hasText(regUrl)) {
                    String jsServingPath = regUrl.replace("/webauthn/register", "/login/webauthn.js");
                    int idx = getFilters(builtChain).indexOf(filter);
                    if (idx >= 0) {
                        getFilters(builtChain).set(idx, ContexaWebAuthnResourceFilter.create(jsServingPath));
                    }
                }
            }
        }
    }

    /**
     * Replace WebAuthn authentication handlers (success/failure).
     */
    public void replaceHandlers(DefaultSecurityFilterChain builtChain,
                                 AuthenticationFlowConfig flowConfig,
                                 ApplicationContext appContext,
                                 boolean isMfaFlow) {

        for (Filter filter : getFilters(builtChain)) {
            if (filter instanceof AbstractAuthenticationProcessingFilter authFilter && isWebAuthnAuth(filter)) {
                try {
                    AuthContextProperties authProps = appContext.getBean(AuthContextProperties.class);
                    StateType stateType = (flowConfig.getStateConfig() != null && flowConfig.getStateConfig().stateType() != null) ?
                            flowConfig.getStateConfig().stateType() : authProps.getStateType();

                    PlatformAuthenticationSuccessHandler successHandler;
                    PlatformAuthenticationFailureHandler failureHandler;

                    if (isMfaFlow) {
                        successHandler = appContext.getBean(MfaFactorProcessingSuccessHandler.class);
                        failureHandler = appContext.getBean(UnifiedAuthenticationFailureHandler.class);
                    } else {
                        if (stateType == StateType.SESSION) {
                            successHandler = null;
                            failureHandler = null;
                        } else {
                            successHandler = appContext.getBean(OAuth2SingleAuthSuccessHandler.class);
                            failureHandler = appContext.getBean(OAuth2SingleAuthFailureHandler.class);
                        }
                    }

                    if (successHandler != null) {
                        authFilter.setAuthenticationSuccessHandler(successHandler);
                    }
                    if (failureHandler != null) {
                        authFilter.setAuthenticationFailureHandler(failureHandler);
                    }
                    return;

                } catch (Exception e) {
                    log.error("Failed to replace WebAuthn handlers for flow: {}", flowConfig.getTypeName(), e);
                }
            }
        }

        log.error("WebAuthnAuthenticationFilter not found in filter chain for flow: {}. " +
                        "Passkey authentication may not work properly without custom handlers.",
                flowConfig.getTypeName());
    }

    /**
     * Replace DefaultWebAuthnRegistrationPageGeneratingFilter with Contexa version.
     */
    public void replaceRegistrationPage(DefaultSecurityFilterChain builtChain, ApplicationContext appContext) {
        try {
            PublicKeyCredentialUserEntityRepository userEntities =
                    appContext.getBean(PublicKeyCredentialUserEntityRepository.class);
            UserCredentialRepository userCredentials =
                    appContext.getBean(UserCredentialRepository.class);

            ContexaWebAuthnRegistrationPageFilter contexaFilter =
                    new ContexaWebAuthnRegistrationPageFilter(userEntities, userCredentials);
            try {
                MessageSource messageSource =
                        appContext.getBean(MessageSource.class);
                contexaFilter.setMessageSource(messageSource);
            } catch (Exception ignored) {
            }

            List<Filter> filters = builtChain.getFilters();
            for (int i = 0; i < filters.size(); i++) {
                if (filters.get(i).getClass().getSimpleName().equals("DefaultWebAuthnRegistrationPageGeneratingFilter")) {
                    filters.set(i, contexaFilter);
                    return;
                }
            }
        } catch (Exception e) {
            log.error("Failed to replace DefaultWebAuthnRegistrationPageGeneratingFilter with Contexa version", e);
        }
    }

    private boolean isWebAuthnAuth(Filter filter) {
        String name = filter.getClass().getSimpleName();
        return name.contains("WebAuthn") && !name.contains("Registration");
    }

    private String resolveLoginProcessing(AuthUrlProvider flowProvider, PasskeyOptions opts, AuthContextProperties props) {
        if (flowProvider != null) return flowProvider.getPasskeyLoginProcessing();
        if (opts != null && StringUtils.hasText(opts.getLoginProcessingUrl())) return opts.getLoginProcessingUrl();
        return props.getUrls().getFactors().getPasskey().getLoginProcessing();
    }

    private String resolveAssertionOptions(AuthUrlProvider flowProvider, PasskeyOptions opts, AuthContextProperties props) {
        if (flowProvider != null) return flowProvider.getPasskeyAssertionOptions();
        if (opts != null && StringUtils.hasText(opts.getAssertionOptionsEndpoint())) return opts.getAssertionOptionsEndpoint();
        return props.getUrls().getFactors().getPasskey().getAssertionOptions();
    }

    public record PasskeyCustomizerContext(PasskeyOptions passkeyOpts, AuthContextProperties authProps) {}
}
