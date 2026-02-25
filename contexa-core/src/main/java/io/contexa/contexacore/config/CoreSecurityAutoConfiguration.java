package io.contexa.contexacore.config;

import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.security.UnifiedUserDetailsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
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
    @Primary
    @ConditionalOnProperty(
        prefix = "contexa.core.security.unified",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UnifiedUserDetailsService unifiedUserDetailsService(
            UserRepository userRepository) {

        return new UnifiedUserDetailsService(
                userRepository
        );
    }
}
