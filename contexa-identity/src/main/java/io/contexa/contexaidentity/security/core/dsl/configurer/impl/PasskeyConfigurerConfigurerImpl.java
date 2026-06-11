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

import io.contexa.contexaidentity.security.core.asep.dsl.PasskeyAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.configurer.AbstractOptionsBuilderConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.PasskeyConfigurerConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;

import java.util.List;
import java.util.Set;

@Slf4j
public final class PasskeyConfigurerConfigurerImpl
        extends AbstractOptionsBuilderConfigurer<PasskeyConfigurerConfigurerImpl, PasskeyOptions, PasskeyOptions.Builder, PasskeyConfigurerConfigurer>
        implements PasskeyConfigurerConfigurer {

    public PasskeyConfigurerConfigurerImpl(ApplicationContext applicationContext) {
        super(PasskeyOptions.builder(applicationContext));
        setApplicationContext(applicationContext);
    }

    public PasskeyConfigurerConfigurerImpl(ApplicationContext applicationContext, boolean isMfaMode) {
        super(isMfaMode ?
            PasskeyOptions.builderForMfa(applicationContext) :
            PasskeyOptions.builder(applicationContext)
        );
        setApplicationContext(applicationContext);
    }

    @Override
    public PasskeyConfigurerConfigurer order(int order) {
        getOptionsBuilder().order(order); 
        return self();
    }

    @Override
    public PasskeyConfigurerConfigurer loginProcessingUrl(String url) {
        super.loginProcessingUrl(url); 
        return self();
    }

    @Override
    public PasskeyConfigurerConfigurer assertionOptionsEndpoint(String url) {
        getOptionsBuilder().assertionOptionsEndpoint(url);
        return self();
    }

    @Override
    public PasskeyConfigurerConfigurer rpName(String rpName) {
        getOptionsBuilder().rpName(rpName);
        return self();
    }

    @Override
    public PasskeyConfigurerConfigurer rpId(String rpId) {
        getOptionsBuilder().rpId(rpId);
        return self();
    }

    @Override
    public PasskeyConfigurerConfigurer allowedOrigins(List<String> origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyConfigurerConfigurer allowedOrigins(String... origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyConfigurerConfigurer allowedOrigins(Set<String> origins) {
        getOptionsBuilder().allowedOrigins(origins);
        return self();
    }

    @Override
    public PasskeyConfigurerConfigurer asep(Customizer<PasskeyAsepAttributes> passkeyAsepAttributesCustomizer){

        PasskeyAsepAttributes attributes = new PasskeyAsepAttributes();
        if (passkeyAsepAttributesCustomizer != null) {
            passkeyAsepAttributesCustomizer.customize(attributes);
        }
        getOptionsBuilder().asepAttributes(attributes);
                return self();
    }

    @Override
    protected PasskeyConfigurerConfigurerImpl self() {
        return this;
    }
}
