package io.contexa.autoconfigure.core.autonomous;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.monitor.PolicyEffectivenessMonitor;
import io.contexa.contexacore.autonomous.monitor.PolicyProposalAnalytics;
import io.contexa.contexacore.repository.PolicyEvolutionProposalRepository;
import io.contexa.contexacore.autonomous.safety.EmergencyKillSwitch;
import io.contexa.contexacore.autonomous.safety.PolicyConflictDetector;
import io.contexa.contexacore.autonomous.safety.PolicyVersionManager;
import io.contexa.contexacore.autonomous.security.identification.UserIdentificationService;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.autonomous.state.DistributedStateManager;
import io.contexa.contexacore.autonomous.strategy.CompositeEvaluationStrategy;
import io.contexa.contexacore.autonomous.strategy.DefaultThreatEvaluationStrategy;
import io.contexa.contexacore.autonomous.strategy.SessionThreatEvaluationStrategy;
import io.contexa.contexacore.autonomous.strategy.VectorStoreEvaluationStrategy;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.autonomous", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ContexaProperties.class)
public class CoreAutonomousStrategyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public CompositeEvaluationStrategy compositeEvaluationStrategy() {
        return new CompositeEvaluationStrategy();
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultThreatEvaluationStrategy defaultThreatEvaluationStrategy() {
        return new DefaultThreatEvaluationStrategy();
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionThreatEvaluationStrategy sessionThreatEvaluationStrategy(
            RedisTemplate<String, Object> redisTemplate,
            ObjectMapper objectMapper) {
        return new SessionThreatEvaluationStrategy(redisTemplate, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public VectorStoreEvaluationStrategy vectorStoreEvaluationStrategy() {
        return new VectorStoreEvaluationStrategy();
    }

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
    public EmergencyKillSwitch emergencyKillSwitch() {
        return new EmergencyKillSwitch();
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyConflictDetector policyConflictDetector() {
        return new PolicyConflictDetector();
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyVersionManager policyVersionManager() {
        return new PolicyVersionManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public DistributedStateManager distributedStateManager(
            RedisTemplate<String, Object> redisTemplate,
            RedisDistributedLockService redisDistributedLockService,
            ObjectMapper objectMapper) {
        return new DistributedStateManager(redisTemplate, redisDistributedLockService, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserIdentificationService userIdentificationService() {
        return new UserIdentificationService();
    }
}
