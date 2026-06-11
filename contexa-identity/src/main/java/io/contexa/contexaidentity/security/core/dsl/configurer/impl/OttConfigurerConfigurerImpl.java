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

import io.contexa.contexaidentity.security.core.asep.dsl.OttAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.configurer.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.OttConfigurerConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
public final class OttConfigurerConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<OttConfigurerConfigurerImpl, OttOptions, OttOptions.Builder, OttConfigurerConfigurer>
        implements OttConfigurerConfigurer {

    public OttConfigurerConfigurerImpl(ApplicationContext applicationContext) {
        super(OttOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    public OttConfigurerConfigurerImpl(ApplicationContext applicationContext, boolean isMfaMode) {
        super(isMfaMode ?
            OttOptions.builderForMfa(applicationContext) :
            OttOptions.builder(applicationContext)
        );
        setApplicationContext(applicationContext);
    }

    @Override
    public OttConfigurerConfigurer order(int order) {
        getOptionsBuilder().order(order);
        return self();
    }

    @Override
    public OttConfigurerConfigurer loginProcessingUrl(String url) {
        getOptionsBuilder().loginProcessingUrl(url);
        return self();
    }

    @Override
    public OttConfigurerConfigurer successHandler(PlatformAuthenticationSuccessHandler successHandler) {
        getOptionsBuilder().successHandler(successHandler);
        return self();
    }

    @Override
    public OttConfigurerConfigurer failureHandler(PlatformAuthenticationFailureHandler failureHandler) {
        getOptionsBuilder().failureHandler(failureHandler);
        return self();
    }

    @Override
    public OttConfigurerConfigurer securityContextRepository(SecurityContextRepository repository) {
        getOptionsBuilder().securityContextRepository(repository);
        return self();
    }

    @Override
    public OttConfigurerConfigurer defaultSubmitPageUrl(String url) {
        getOptionsBuilder().defaultSubmitPageUrl(url);
        return self();
    }

    @Override
    public OttConfigurerConfigurer tokenGeneratingUrl(String url) {
        getOptionsBuilder().tokenGeneratingUrl(url);
        return self();
    }

    @Override
    public OttConfigurerConfigurer showDefaultSubmitPage(boolean show) {
        getOptionsBuilder().showDefaultSubmitPage(show);
        return self();
    }

    @Override
    public OttConfigurerConfigurer tokenService(OneTimeTokenService service) {
        getOptionsBuilder().oneTimeTokenService(service); 
        return self();
    }

    @Override
    public OttConfigurerConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
        getOptionsBuilder().tokenGenerationSuccessHandler(handler); 
        return self();
    }

    @Override
    public OttConfigurerConfigurer asep(Customizer<OttAsepAttributes> ottAsepAttributesCustomizer) {

        OttAsepAttributes attributes = new OttAsepAttributes();
        if (ottAsepAttributesCustomizer != null) {
            ottAsepAttributesCustomizer.customize(attributes);
        }
        
        getOptionsBuilder().asepAttributes(attributes); 
                return self();
    }

    @Override
    protected OttConfigurerConfigurerImpl self() {
        return this;
    }
}

