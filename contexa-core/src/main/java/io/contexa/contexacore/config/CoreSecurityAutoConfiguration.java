package io.contexa.contexacore.config;

import io.contexa.contexacommon.repository.GroupRolePermissionRepository;
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

    @Bean
    @ConditionalOnMissingBean
    public AuthorityResolver authorityResolver(
            UserRolePermissionRepository userRolePermissionRepository,
            GroupRolePermissionRepository groupRolePermissionRepository,
            RoleHierarchy roleHierarchy) {
        return new AuthorityResolver(userRolePermissionRepository, groupRolePermissionRepository, roleHierarchy);
    }

    @Bean
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
                AuthorityResolver authorityResolver) {
            return new UnifiedUserDetailsService(userRepository, authorityResolver);
        }
    }
