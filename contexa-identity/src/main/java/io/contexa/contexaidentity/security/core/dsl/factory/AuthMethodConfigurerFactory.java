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
package io.contexa.contexaidentity.security.core.dsl.factory;

import io.contexa.contexaidentity.security.core.asep.dsl.BaseAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.configurer.AuthenticationFactorConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.impl.*;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexacommon.enums.AuthType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

import java.util.Objects;

@Slf4j
public final class AuthMethodConfigurerFactory {

    private final ApplicationContext applicationContext;

    public AuthMethodConfigurerFactory(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null");
    }

    public <O extends AuthenticationProcessingOptions,
            A extends BaseAsepAttributes,
            S extends AuthenticationFactorConfigurer<O, A, S>>
    S createFactorConfigurer(AuthType authType, Class<S> configurerInterfaceType) { 
        Objects.requireNonNull(authType, "AuthType cannot be null");
        Objects.requireNonNull(configurerInterfaceType, "ConfigurerInterfaceType cannot be null");

        Object concreteConfigurerLogic = switch (authType) {
            case FORM -> {
                yield new FormConfigurerConfigurerImpl(this.applicationContext);
            }
            case MFA_FORM -> {
                yield new FormConfigurerConfigurerImpl(this.applicationContext, true);
            }
            case REST -> {
                yield new RestConfigurerConfigurerImpl(this.applicationContext);
            }
            case MFA_REST -> {
                yield new RestConfigurerConfigurerImpl(this.applicationContext, true);
            }

            case OTT -> {
                yield new OttConfigurerConfigurerImpl(this.applicationContext);
            }
            case MFA_OTT -> {
                yield new OttConfigurerConfigurerImpl(this.applicationContext, true);
            }
            case PASSKEY -> {
                yield new PasskeyConfigurerConfigurerImpl(this.applicationContext);
            }
            case MFA_PASSKEY -> {
                yield new PasskeyConfigurerConfigurerImpl(this.applicationContext, true);
            }
            
            default -> {
                log.error("AuthMethodConfigurerFactory: Unsupported AuthType for AuthenticationFactorConfigurer: {}", authType);
                throw new IllegalArgumentException("Unsupported AuthType for AuthenticationFactorConfigurer: " + authType);
            }
        };

        if (configurerInterfaceType.isInstance(concreteConfigurerLogic)) {
            return configurerInterfaceType.cast(concreteConfigurerLogic);
        } else {
            log.error("AuthMethodConfigurerFactory: Created configurer of type {} is not assignable to expected interface {}.",
                    concreteConfigurerLogic.getClass().getName(), configurerInterfaceType.getSimpleName());
            throw new IllegalArgumentException("Created configurer type mismatch. Expected: " +
                    configurerInterfaceType.getSimpleName() + ", Actual: " + concreteConfigurerLogic.getClass().getName());
        }
    }

    public <H extends HttpSecurityBuilder<H>> PrimaryAuthDslConfigurerImpl<H> createPrimaryAuthConfigurer(ApplicationContext context) {
        return new PrimaryAuthDslConfigurerImpl<>(context); 
    }

    public <H extends HttpSecurityBuilder<H>> MfaDslConfigurerImpl<H> createMfaConfigurer(ApplicationContext context) {
        return new MfaDslConfigurerImpl<>(context); 
    }
}