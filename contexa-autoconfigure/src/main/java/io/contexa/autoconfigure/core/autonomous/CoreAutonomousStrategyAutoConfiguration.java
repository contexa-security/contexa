package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.security.identification.UserIdentificationService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.autonomous", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ContexaProperties.class)
public class CoreAutonomousStrategyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public UserIdentificationService userIdentificationService() {
        return new UserIdentificationService();
    }
}
