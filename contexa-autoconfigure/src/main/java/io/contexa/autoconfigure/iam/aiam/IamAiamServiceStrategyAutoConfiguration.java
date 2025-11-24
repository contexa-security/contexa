package io.contexa.autoconfigure.iam.aiam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.repository.SoarIncidentRepository;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacoreenterprise.soar.service.SoarToolCallingService;
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.labs.policy.AdvancedPolicyGenerationLab;
import io.contexa.contexaiam.aiam.service.*;
import io.contexa.contexaiam.aiam.strategy.*;
import io.contexa.contexaiam.repository.BehaviorAnomalyEventRepository;
import io.contexa.contexaiam.repository.BehaviorBasedPermissionRepository;
import io.contexa.contexaiam.repository.BehaviorRealtimeCacheRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexacore.repository.CustomerDataRepository;
import io.contexa.contexacommon.repository.UserBehaviorProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.simp.SimpMessagingTemplate;

/**
 * IAM AIAM Service and Strategy AutoConfiguration
 */
@AutoConfiguration
public class IamAiamServiceStrategyAutoConfiguration {

    // Services
    @Bean
    @ConditionalOnMissingBean
    public SoarActionService soarActionService(ApprovalService approvalService) {
        return new SoarActionService(approvalService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityCopilotMessageProvider securityCopilotMessageProvider() {
        return new SecurityCopilotMessageProvider();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityCopilotValidationService securityCopilotValidationService(
            SecurityCopilotMessageProvider messageProvider) {
        return new SecurityCopilotValidationService(messageProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public ProtectableDataService protectableDataService(
            CustomerDataRepository customerDataRepository) {
        return new ProtectableDataService(customerDataRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public BehaviorProfileService behaviorProfileService(
            UserRepository userRepository,
            UserBehaviorProfileRepository behaviorProfileRepository,
            BehaviorAnomalyEventRepository anomalyEventRepository,
            BehaviorBasedPermissionRepository permissionRepository) {
        return new BehaviorProfileService(
                userRepository, behaviorProfileRepository, anomalyEventRepository, permissionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public DataIngestionServiceImpl dataIngestionService(
            VectorStore vectorStore,
            PolicyRepository policyRepository,
            ObjectMapper objectMapper) {
        return new DataIngestionServiceImpl(vectorStore, policyRepository, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public RealTimeBehaviorMonitor realTimeBehaviorMonitor(
            BehaviorRealtimeCacheRepository realtimeCacheRepository,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new RealTimeBehaviorMonitor(realtimeCacheRepository, brokerTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarIncidentService soarIncidentService(
            SoarIncidentRepository incidentRepository,
            ApplicationEventPublisher eventPublisher) {
        return new SoarIncidentService(incidentRepository, eventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarSimulationService soarSimulationService(
            SoarToolCallingService soarToolCallingService,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new SoarSimulationService(soarToolCallingService, brokerTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public StaticAccessOptimizationService staticAccessOptimizationService(
            AdvancedPolicyGenerationLab policyGenerationLab,
            IAMDataCollectionService dataCollectionService,
            MeterRegistry meterRegistry) {
        return new StaticAccessOptimizationService(
                policyGenerationLab, dataCollectionService, meterRegistry);
    }

    // Strategies
    @Bean
    @ConditionalOnMissingBean
    public AccessGovernanceDiagnosisStrategy accessGovernanceDiagnosisStrategy(AILabFactory labFactory) {
        return new AccessGovernanceDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConditionTemplateDiagnosisStrategy conditionTemplateDiagnosisStrategy(AILabFactory labFactory) {
        return new ConditionTemplateDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public DynamicThreatResponseSynthesisStrategy dynamicThreatResponseSynthesisStrategy(AILabFactory labFactory) {
        return new DynamicThreatResponseSynthesisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public PolicyGenerationDiagnosisStrategy policyGenerationDiagnosisStrategy(AILabFactory labFactory) {
        return new PolicyGenerationDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResourceNamingDiagnosisStrategy resourceNamingDiagnosisStrategy(AILabFactory labFactory) {
        return new ResourceNamingDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityCopilotDiagnosisStrategy securityCopilotDiagnosisStrategy(AILabFactory labFactory) {
        return new SecurityCopilotDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public StudioQueryDiagnosisStrategy studioQueryDiagnosisStrategy(AILabFactory labFactory) {
        return new StudioQueryDiagnosisStrategy(labFactory);
    }
}
