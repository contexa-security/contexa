package io.contexa.contexaidentity.security.config;

import io.contexa.contexacore.std.operations.AICoreOperations;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.SearchStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Slf4j
@Configuration
@RequiredArgsConstructor
@ConditionalOnProperty(
    prefix = "aidc.security.ai",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true 
)
public class AIAuthenticationConfiguration {
    
    
    @Bean
    @ConditionalOnBean(value = {AICoreOperations.class},
                       search = SearchStrategy.ALL)
    public AIAuthenticationStatusLogger aiAuthenticationStatusLogger() {
        return new AIAuthenticationStatusLogger();
    }
    
    
    @Slf4j
    public static class AIAuthenticationStatusLogger {
        public AIAuthenticationStatusLogger() {
            log.info("===================================================");
            log.info("AI Adaptive Authentication Status:");
            log.info("  - Configuration: ENABLED");
            log.info("  - RiskAssessmentLab: AVAILABLE");
            log.info("  - BehavioralAnalysisLab: AVAILABLE");
            log.info("  - Status: ACTIVE");
            log.info("===================================================");
        }
    }
}