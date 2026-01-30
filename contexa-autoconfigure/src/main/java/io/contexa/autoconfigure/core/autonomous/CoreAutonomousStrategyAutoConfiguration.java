package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.monitor.PolicyEffectivenessMonitor;
import io.contexa.contexacore.autonomous.monitor.PolicyProposalAnalytics;
import io.contexa.contexacore.autonomous.security.identification.UserIdentificationService;
import io.contexa.contexacore.repository.PolicyEvolutionProposalRepository;
import io.contexa.contexacore.repository.PolicyProposalRepository;
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
    public PolicyEffectivenessMonitor policyEffectivenessMonitor(
            PolicyProposalRepository policyProposalRepository) {
        return new PolicyEffectivenessMonitor(policyProposalRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyProposalAnalytics policyProposalAnalytics(
            PolicyEvolutionProposalRepository policyEvolutionProposalRepository,
            PolicyEffectivenessMonitor policyEffectivenessMonitor) {
        return new PolicyProposalAnalytics(policyEvolutionProposalRepository, policyEffectivenessMonitor);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserIdentificationService userIdentificationService() {
        return new UserIdentificationService();
    }
}
