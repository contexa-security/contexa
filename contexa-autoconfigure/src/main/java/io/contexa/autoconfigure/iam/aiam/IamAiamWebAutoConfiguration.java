package io.contexa.autoconfigure.iam.aiam;

import io.contexa.contexacore.autonomous.event.publisher.KafkaSecurityEventPublisher;
import io.contexa.contexacore.repository.AttackResultRepository;
import io.contexa.contexacore.simulation.analyzer.SimulationResultAnalyzer;
import io.contexa.contexacore.simulation.tracker.DataBreachTracker;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.aiam.protocol.context.SecurityCopilotContext;
import io.contexa.contexaiam.aiam.service.ProtectableDataService;
import io.contexa.contexaiam.aiam.service.SecurityCopilotMessageProvider;
import io.contexa.contexaiam.aiam.service.SecurityCopilotValidationService;
import io.contexa.contexaiam.aiam.service.SoarActionService;
import io.contexa.contexaiam.aiam.web.*;
import io.contexa.contexaiam.security.core.AIReactiveUserDetailsService;
import io.contexa.contexaiam.properties.SecurityStepUpProperties;
import io.contexa.contexaiam.service.PolicyService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * IAM AIAM Web Controllers AutoConfiguration
 */
@AutoConfiguration
@EnableConfigurationProperties(SecurityStepUpProperties.class)
public class IamAiamWebAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecurityCopilotController securityCopilotController(
            AICoreOperations<SecurityCopilotContext> aiNativeProcessor,
            SecurityCopilotValidationService validationService,
            SecurityCopilotMessageProvider messageProvider) {
        return new SecurityCopilotController(aiNativeProcessor, validationService, messageProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityPlaneController securityPlaneController() {
        return new SecurityPlaneController();
    }

    @Bean
    @ConditionalOnMissingBean
    public AttackEventHelper attackEventHelper(
            KafkaSecurityEventPublisher eventPublisher,
            ProtectableDataService protectableDataService,
            DataBreachTracker dataBreachTracker) {
        return new AttackEventHelper(eventPublisher, protectableDataService, dataBreachTracker);
    }

    @Bean
    @ConditionalOnMissingBean
    public WebSocketTestMessageController webSocketTestMessageController(
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new WebSocketTestMessageController(brokerTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public StepUpAuthController stepUpAuthController(
            RedisTemplate<String, Object> redisTemplate,
            PasswordEncoder passwordEncoder,
            AIReactiveUserDetailsService aiReactiveUserDetailsService) {
        return new StepUpAuthController(redisTemplate, passwordEncoder, aiReactiveUserDetailsService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarActionController soarActionController(SoarActionService soarActionService) {
        return new SoarActionController(soarActionService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SimulationResultController simulationResultController(
            SimulationResultAnalyzer resultAnalyzer,
            AttackResultRepository attackResultRepository) {
        return new SimulationResultController(resultAnalyzer, attackResultRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public DualModeSimulationViewController dualModeSimulationViewController() {
        return new DualModeSimulationViewController();
    }

    @Bean
    @ConditionalOnMissingBean
    public AIPolicyApprovalViewController aiPolicyApprovalViewController() {
        return new AIPolicyApprovalViewController();
    }

    @Bean
    @ConditionalOnMissingBean
    public AIPolicyApprovalController aiPolicyApprovalController(PolicyService policyService) {
        return new AIPolicyApprovalController(policyService);
    }
}
