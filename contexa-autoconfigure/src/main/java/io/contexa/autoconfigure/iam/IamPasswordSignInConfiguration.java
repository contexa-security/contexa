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
package io.contexa.autoconfigure.iam;

import io.contexa.autoconfigure.core.ContexaOwnBeans;
import io.contexa.contexacommon.operating.ConditionalOnMode;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexacore.security.UnifiedUserDetailsService;
import io.contexa.contexaiam.security.core.CustomAuthenticationProvider;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaPasswordSignIn;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * The provider of Contexa's password sign-in, in every way of running Contexa: the form and MFA filters of a flow that signs
 * Contexa's accounts in authenticate with it alone ({@link ContexaPasswordSignIn}). It is a provider bean only where
 * Contexa's main chain signs the application's users in and the application has no store or provider of its own; elsewhere
 * it is held, as Spring's global authentication manager counts every provider bean and takes none of two (R-17 of
 * docs/agent/운영모드-정상화-구현계획.md).
 */
@Configuration(proxyBeanMethods = false)
public class IamPasswordSignInConfiguration {

    @Bean(name = "contexaCustomAuthenticationProvider")
    @ConditionalOnMode(SecurityMode.FULL)
    @ConditionalOnMissingBean(value = {UserDetailsService.class, AuthenticationProvider.class}, ignored = UnifiedUserDetailsService.class)
    public CustomAuthenticationProvider customAuthenticationProvider(BeanFactory beanFactory,
                                                                    LoginPolicyHandler contexaLoginPolicyHandler) {
        return provider(beanFactory, contexaLoginPolicyHandler);
    }

    @Bean(name = "contexaCustomAuthenticationProvider")
    @ConditionalOnMissingBean(name = ContexaPasswordSignIn.PROVIDER_BEAN)
    public HeldBean<AuthenticationProvider> heldCustomAuthenticationProvider(BeanFactory beanFactory,
                                                                            LoginPolicyHandler contexaLoginPolicyHandler) {
        return new HeldBean<>(provider(beanFactory, contexaLoginPolicyHandler));
    }

    private static CustomAuthenticationProvider provider(BeanFactory beanFactory, LoginPolicyHandler loginPolicy) {
        return new CustomAuthenticationProvider(ContexaUserStore.forSignIn(beanFactory), ContexaOwnBeans.passwordEncoder(beanFactory),
                loginPolicy);
    }
}
