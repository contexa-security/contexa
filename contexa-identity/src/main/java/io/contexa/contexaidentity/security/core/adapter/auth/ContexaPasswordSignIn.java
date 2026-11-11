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

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.ObjectPostProcessor;

/**
 * The authentication manager of Contexa's own password sign-in (the form and the first step of MFA) where Contexa owns the
 * sign-in: Contexa's provider over Contexa's store, and nothing else.
 * <p>
 * The chain's manager asks Spring's global one, whose password provider Spring picks from the beans it finds: with
 * several user stores and providers of the application's it picks none, and nobody could sign in; where the application
 * configures the global manager or declares one, the application's answers. A manager with a parent also asks the parent
 * again after its own provider refused, so a password refused by Contexa would be checked twice. This manager has no
 * parent. It publishes its events and is observed as the chain's manager is; the global manager and the application's
 * beans stay as they are. The sign-ins by token (REST), code and passkey already have providers of their own.
 */
public final class ContexaPasswordSignIn {

    /** The bean of Contexa's password provider, which exists only where Contexa owns the sign-in. */
    public static final String PROVIDER_BEAN = "contexaCustomAuthenticationProvider";

    private ContexaPasswordSignIn() {
    }

    /**
     * Returns the manager of Contexa's own password provider, or {@code null} where the application owns the sign-in or
     * there is no such provider: the filter then keeps the chain's manager, as before.
     */
    @Nullable
    public static AuthenticationManager manager(ApplicationContext context) {
        if (!context.containsBean(PROVIDER_BEAN)
                || ContexaOperatingProfile.resolve(context.getEnvironment()).ownership() != SecurityOwnershipMode.CONTEXA_OWNED) {
            return null;
        }
        ProviderManager manager = new ProviderManager(context.getBean(PROVIDER_BEAN, AuthenticationProvider.class));
        manager.setAuthenticationEventPublisher(eventPublisher(context));
        manager.setMessageSource(context);
        // As the chain's manager: what the post-processor returns may wrap the manager, so it is typed as the interface
        AuthenticationManager signIn = manager;
        return observed(context).postProcess(signIn);
    }

    /** The publisher the chain's manager is given (HttpSecurityConfiguration), so the sign-in events reach the same listeners. */
    private static AuthenticationEventPublisher eventPublisher(ApplicationContext context) {
        if (context.getBeanNamesForType(AuthenticationEventPublisher.class).length > 0) {
            return context.getBean(AuthenticationEventPublisher.class);
        }
        return new DefaultAuthenticationEventPublisher(context);
    }

    /** What HttpSecurity applies to the chain's manager: the observation of its sign-ins, when one is configured. */
    private static ObjectPostProcessor<AuthenticationManager> observed(ApplicationContext context) {
        ObjectProvider<ObjectPostProcessor<AuthenticationManager>> postProcessor = context.getBeanProvider(
                ResolvableType.forClassWithGenerics(ObjectPostProcessor.class, AuthenticationManager.class));
        return postProcessor.getIfUnique(ObjectPostProcessor::identity);
    }
}
