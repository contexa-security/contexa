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

import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.authority.AuthorityResolver;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacore.security.UnifiedUserDetailsService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetailsService;

/** Contexa's user store serves the sign-in only where Contexa owns it; {@link ContexaUserStore} says when it is the one in use. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnOwnership(SecurityOwnershipMode.CONTEXA_OWNED)
public class CoreSecurityContexaOwnedConfiguration {

    /** An application without a store of its own: whatever asks for a UserDetailsService gets Contexa's. */
    @Bean(name = "contexaUnifiedUserDetailsService")
    @Primary
    @ConditionalOnProperty(
            prefix = "contexa.core.security.unified",
            name = "enabled",
            havingValue = "true",
            matchIfMissing = true
    )
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UnifiedUserDetailsService unifiedUserDetailsService(
            UserRepository userRepository,
            AuthorityResolver contexaAuthorityResolver) {
        return new UnifiedUserDetailsService(userRepository, contexaAuthorityResolver);
    }

    /** Beside the application's own stores it stays out of their way, for the sign-in to fall back on when they leave no choice. */
    @Bean(name = "contexaUnifiedUserDetailsService", defaultCandidate = false)
    @ConditionalOnProperty(
            prefix = "contexa.core.security.unified",
            name = "enabled",
            havingValue = "true",
            matchIfMissing = true
    )
    @ConditionalOnMissingBean(name = "contexaUnifiedUserDetailsService")
    public UnifiedUserDetailsService standbyUnifiedUserDetailsService(
            UserRepository userRepository,
            AuthorityResolver contexaAuthorityResolver) {
        return new UnifiedUserDetailsService(userRepository, contexaAuthorityResolver);
    }
}
