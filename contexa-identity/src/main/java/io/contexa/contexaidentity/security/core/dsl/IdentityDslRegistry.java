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
package io.contexa.contexaidentity.security.core.dsl;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpCustomizer;
import io.contexa.contexaidentity.security.core.dsl.configurer.*;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexaidentity.security.exception.DslConfigurationException;
import io.contexa.contexaidentity.security.webauthn.PasskeyLibrary;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.Objects;

@Slf4j
public final class IdentityDslRegistry<H extends HttpSecurityBuilder<H>> 
        extends AbstractFlowRegistrar<H> implements IdentityAuthDsl {

    public IdentityDslRegistry(ApplicationContext applicationContext) {
        super(PlatformConfig.builder(),
                Objects.requireNonNull(applicationContext, "applicationContext cannot be null")
        );
            }

    @Override
    public IdentityAuthDsl global(SafeHttpCustomizer<HttpSecurity> customizer) {
        Objects.requireNonNull(customizer, "global customizer cannot be null");
        platformBuilder.global(customizer); 
                return this;
    }

    @Override
    public IdentityStateDsl form(Customizer<FormConfigurerConfigurer> customizer) throws Exception {
                return registerAuthenticationMethod(AuthType.FORM, customizer, 100, FormConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl rest(Customizer<RestConfigurerConfigurer> customizer) throws Exception {
                return registerAuthenticationMethod(AuthType.REST, customizer, 200, RestConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl ott(Customizer<OttConfigurerConfigurer> customizer) throws Exception {
                return registerAuthenticationMethod(AuthType.OTT, customizer, 300, OttConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl passkey(Customizer<PasskeyConfigurerConfigurer> customizer) throws Exception {
        if (!PasskeyLibrary.available(applicationContext.getClassLoader())) {
            // A flow that signs in by passkey alone has nothing to fall back on: it is refused, not started without it.
            throw new DslConfigurationException("passkey() declares a sign-in by passkey, but webauthn4j is not on the "
                    + "class path. Put webauthn4j back on the class path, or sign in with another method.");
        }
                return registerAuthenticationMethod(AuthType.PASSKEY, customizer, 400, PasskeyConfigurerConfigurer.class);
    }

    @Override
    public IdentityStateDsl mfa(Customizer<MfaDslConfigurer> customizer) throws Exception {
                return registerMultiStepFlow(customizer);
    }

    @Override
    public PlatformConfig build() {
        return platformBuilder.build();
    }
}
