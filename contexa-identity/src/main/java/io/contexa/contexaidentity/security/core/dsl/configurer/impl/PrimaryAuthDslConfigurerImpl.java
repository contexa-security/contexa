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

import io.contexa.contexaidentity.security.core.dsl.configurer.FormConfigurerConfigurer;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.core.dsl.configurer.PrimaryAuthDslConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.RestConfigurerConfigurer;
import io.contexa.contexaidentity.security.core.dsl.factory.AuthMethodConfigurerFactory;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.util.Assert;

import java.util.Objects;

@Slf4j
@Getter
public final class PrimaryAuthDslConfigurerImpl<H extends HttpSecurityBuilder<H>>
        implements PrimaryAuthDslConfigurer {

    private Customizer<FormConfigurerConfigurer> formLoginCustomizer;
    private Customizer<RestConfigurerConfigurer> restLoginCustomizer;
    private final ApplicationContext applicationContext;

    public PrimaryAuthDslConfigurerImpl(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
    }

    @Override
    public PrimaryAuthDslConfigurer formLogin(Customizer<FormConfigurerConfigurer> formLoginCustomizer) {
        Assert.notNull(formLoginCustomizer, "formLoginCustomizer cannot be null");
        // Both written, the later one replaced the other without a word.
        Assert.state(this.restLoginCustomizer == null,
                "primaryAuthentication takes formLogin(...) or restLogin(...), not both");
        this.formLoginCustomizer = formLoginCustomizer;
        return this;
    }

    @Override
    public PrimaryAuthDslConfigurer restLogin(Customizer<RestConfigurerConfigurer> restLoginCustomizer) {
        Assert.notNull(restLoginCustomizer, "restLoginCustomizer cannot be null");
        Assert.state(this.formLoginCustomizer == null,
                "primaryAuthentication takes formLogin(...) or restLogin(...), not both");
        this.restLoginCustomizer = restLoginCustomizer;
        return this;
    }

    private static void warnOrderHasNoEffect(boolean orderSet, int order) {
        if (orderSet) {
            log.warn("order({}) inside the primary step of an MFA flow has no effect: the flow's place among the chains "
                    + "is mfa.order(...)", order);
        }
    }

    @Override
    public PrimaryAuthenticationOptions buildOptions() {
        PrimaryAuthenticationOptions.Builder optionsBuilder = PrimaryAuthenticationOptions.builder();
        String determinedLoginProcessingUrl = null;

        AuthMethodConfigurerFactory factory = new AuthMethodConfigurerFactory(this.applicationContext);

        if (formLoginCustomizer != null) {
            
            FormConfigurerConfigurerImpl formDslBuilder = (FormConfigurerConfigurerImpl) factory.createFactorConfigurer(
                AuthType.MFA_FORM, FormConfigurerConfigurer.class
            );
            formLoginCustomizer.customize(formDslBuilder);
            FormOptions builtFormOptions = formDslBuilder.buildConcreteOptions();
            warnOrderHasNoEffect(builtFormOptions.isOrderSet(), builtFormOptions.getOrder());

            optionsBuilder.formOptions(builtFormOptions);
            determinedLoginProcessingUrl = builtFormOptions.getLoginProcessingUrl();
            
        } else if (restLoginCustomizer != null) {
            
            RestConfigurerConfigurerImpl restDslBuilder = (RestConfigurerConfigurerImpl) factory.createFactorConfigurer(
                AuthType.MFA_REST, RestConfigurerConfigurer.class
            );
            restLoginCustomizer.customize(restDslBuilder);
            RestOptions builtRestOptions = restDslBuilder.buildConcreteOptions();
            warnOrderHasNoEffect(builtRestOptions.isOrderSet(), builtRestOptions.getOrder());

            optionsBuilder.restOptions(builtRestOptions);
            // A REST primary step names no sign-in page of its own: its page is the configured one
            // (contexa.auth.urls.primary.form-login-page), as the form step's default.
            optionsBuilder.loginPage(applicationContext.getBean(AuthUrlProvider.class).getPrimaryLoginPage());
            determinedLoginProcessingUrl = builtRestOptions.getLoginProcessingUrl();
                    } else {

            throw new DslConfigurationException("Neither formLogin nor restLogin was configured for primary authentication, but buildOptions was called.");
        }

        Assert.hasText(determinedLoginProcessingUrl,
                "loginProcessingUrl could not be determined from FormLogin or RestLogin configuration.");
        optionsBuilder.loginProcessingUrl(determinedLoginProcessingUrl);

        return optionsBuilder.build();
    }
}