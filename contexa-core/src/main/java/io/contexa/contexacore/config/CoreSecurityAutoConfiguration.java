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

import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.beans.factory.BeanFactory;
import io.contexa.contexacommon.repository.GroupRolePermissionRepository;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexacommon.repository.RolePermissionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
import io.contexa.contexacommon.security.authority.AuthorityResolver;
import io.contexa.contexacore.security.UnifiedUserDetailsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.userdetails.UserDetailsService;

@Slf4j
@AutoConfiguration
@ConditionalOnProperty(
        prefix = "contexa.core.security",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class CoreSecurityAutoConfiguration {

    public CoreSecurityAutoConfiguration() {}

    @Bean(name = "contexaAuthorityResolver")
    @ConditionalOnMissingBean
    public AuthorityResolver authorityResolver(
            UserRolePermissionRepository userRolePermissionRepository,
            GroupRolePermissionRepository groupRolePermissionRepository,
            RolePermissionRepository rolePermissionRepository,
            BeanFactory beanFactory) {
        // Contexa's own hierarchy (hidden from lookups by type); an application's own RoleHierarchy is neither used nor made ambiguous
        RoleHierarchy roleHierarchy = beanFactory.containsBean("contexaRoleHierarchy")
                && beanFactory.getBean("contexaRoleHierarchy") instanceof HeldBean<?> held
                && held.get() instanceof RoleHierarchy contexaOwn
                ? contexaOwn
                : new RoleHierarchyImpl();
        return new AuthorityResolver(userRolePermissionRepository, groupRolePermissionRepository,
                rolePermissionRepository, roleHierarchy);
    }

    @Bean(name = "contexaUnifiedUserDetailsService")
    @Primary
    @ConditionalOnProperty(
            prefix = "contexa.core.security.unified",
            name = "enabled",
            havingValue = "true",
            matchIfMissing = true
    )
    @ConditionalOnProperty(
            prefix = "contexa.bridge",
            name = "ownership",
            havingValue = "CONTEXA_OWNED"
    )
    @ConditionalOnMissingBean(UserDetailsService.class)
        public UnifiedUserDetailsService unifiedUserDetailsService(
                UserRepository userRepository,
                AuthorityResolver contexaAuthorityResolver) {
            return new UnifiedUserDetailsService(userRepository, contexaAuthorityResolver);
        }
    }
