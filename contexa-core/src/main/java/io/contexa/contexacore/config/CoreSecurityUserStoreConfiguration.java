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
package io.contexa.contexacore.config;

import io.contexa.contexacommon.operating.ConditionalOnMode;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexacommon.security.authority.AuthorityResolver;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexacore.security.UnifiedUserDetailsService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Contexa's user store, in every way of running Contexa: its administrators sign in from it wherever they sign in
 * ({@link ContexaUserStore} takes it by its name). It is offered to the application by type only where Contexa's main chain
 * signs the application's users in and the application has no store of its own (R-17 of docs/agent/운영모드-정상화-구현계획.md).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "contexa.core.security.unified", name = "enabled", havingValue = "true", matchIfMissing = true)
public class CoreSecurityUserStoreConfiguration {

    /** Mode FULL without a store of the application's: whatever asks for a UserDetailsService gets Contexa's. */
    @Bean(name = "contexaUnifiedUserDetailsService")
    @Primary
    @ConditionalOnMode(SecurityMode.FULL)
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UnifiedUserDetailsService unifiedUserDetailsService(UserRepository userRepository,
                                                               AuthorityResolver contexaAuthorityResolver) {
        return new UnifiedUserDetailsService(userRepository, contexaAuthorityResolver);
    }

    /**
     * Elsewhere it is held, of no type Spring looks up for the application: Spring's global authentication manager counts
     * every UserDetailsService bean, a standby one too, and with two it takes none, so the application's sign-in would fail.
     */
    @Bean(name = "contexaUnifiedUserDetailsService")
    @ConditionalOnMissingBean(name = ContexaUserStore.BEAN_NAME)
    public HeldBean<UserDetailsService> heldUnifiedUserDetailsService(UserRepository userRepository,
                                                                     AuthorityResolver contexaAuthorityResolver) {
        return new HeldBean<>(new UnifiedUserDetailsService(userRepository, contexaAuthorityResolver));
    }
}
