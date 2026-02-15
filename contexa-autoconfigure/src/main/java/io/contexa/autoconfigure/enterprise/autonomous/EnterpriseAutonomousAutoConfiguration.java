package io.contexa.autoconfigure.enterprise.autonomous;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.IPolicyProposalManagementService;
import io.contexa.contexacore.autonomous.PolicyActivationService;
import io.contexa.contexacore.autonomous.monitor.PolicyProposalAnalytics;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.repository.PolicyEvolutionProposalRepository;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacoreenterprise.autonomous.PolicyProposalManagementService;
import io.contexa.contexacoreenterprise.autonomous.controller.PolicyWorkbenchController;
import io.contexa.contexacoreenterprise.autonomous.evolution.*;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyApprovalService;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyEvolutionGovernance;
import io.contexa.contexacoreenterprise.autonomous.helper.DistributedStateManager;
import io.contexa.contexacoreenterprise.autonomous.helper.LearningEngineHelper;
import io.contexa.contexacoreenterprise.autonomous.helper.MemorySystemHelper;
import io.contexa.contexacoreenterprise.autonomous.helper.PolicyEvolutionHelper;
import io.contexa.contexacoreenterprise.autonomous.intelligence.AITuningService;
import io.contexa.contexacoreenterprise.autonomous.labs.PolicyEvolutionLab;
import io.contexa.contexacoreenterprise.autonomous.monitor.PolicyAuditLogger;
import io.contexa.contexacoreenterprise.autonomous.notification.DefaultNotificationService;
import io.contexa.contexacoreenterprise.autonomous.service.impl.SoarNotifierImpl;
import io.contexa.contexacoreenterprise.autonomous.validation.SpelValidationService;
import io.contexa.contexacoreenterprise.dashboard.metrics.evolution.EvolutionMetricsCollector;
import io.contexa.contexacoreenterprise.properties.AiTuningProperties;
import io.contexa.contexacoreenterprise.properties.GovernanceProperties;
import io.contexa.contexacoreenterprise.properties.LearningEngineProperties;
import io.contexa.contexacoreenterprise.properties.MemoryProperties;
import io.contexa.contexacoreenterprise.properties.PolicyEvolutionProperties;
import io.contexa.contexacoreenterprise.properties.SecurityAutonomousProperties;
import io.contexa.contexacoreenterprise.properties.SecurityEvaluatorProperties;
import io.contexa.contexacoreenterprise.properties.StateProperties;
import io.contexa.contexacoreenterprise.repository.SynthesisPolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
@ConditionalOnClass(name = "io.contexa.contexacoreenterprise.autonomous.PolicyProposalManagementService")
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "true", matchIfMissing = false)
@EnableConfigurationProperties({ ContexaProperties.class, SecurityAutonomousProperties.class,
        SecurityEvaluatorProperties.class, PolicyEvolutionProperties.class, GovernanceProperties.class,
        AiTuningProperties.class, LearningEngineProperties.class,
        MemoryProperties.class, StateProperties.class })
public class EnterpriseAutonomousAutoConfiguration {

    public EnterpriseAutonomousAutoConfiguration() {

    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyApprovalService policyApprovalService(
            PolicyProposalRepository proposalRepository,
            ApplicationEventPublisher eventPublisher,
            @Autowired(required = false) PolicyActivationService policyActivationService) {
        return new PolicyApprovalService(proposalRepository, eventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyEvolutionEngine policyEvolutionEngine(
            ChatModel chatModel,
            UnifiedVectorService unifiedVectorService,
            AITuningService tuningService,
            PolicyEvolutionProperties policyEvolutionProperties,
            RedisTemplate<String, PolicyEvolutionProposal> policyEvolutionRedisTemplate,
            RedisTemplate<String, String> stringRedisTemplate) {
        return new PolicyEvolutionEngine(
                chatModel, unifiedVectorService, tuningService,
                policyEvolutionProperties, policyEvolutionRedisTemplate, stringRedisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyEvolutionGovernance policyEvolutionGovernance(
            PolicyProposalRepository proposalRepository,
            PolicyActivationService activationService,
            PolicyApprovalService approvalService,
            ApplicationEventPublisher eventPublisher,
            GovernanceProperties governanceProperties) {
        return new PolicyEvolutionGovernance(
                proposalRepository, activationService, approvalService, eventPublisher, governanceProperties);
    }

    @Bean
    @ConditionalOnMissingBean(PolicyActivationService.class)
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyActivationService policyActivationService() {
        return new PolicyActivationServiceImpl();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AutonomousLearningCoordinator autonomousLearningCoordinator(
            PolicyEvolutionEngine evolutionEngine,
            AITuningService tuningService,
            PolicyProposalRepository proposalRepository,
            EvolutionMetricsCollector evolutionMetricsCollector,
            SecurityAutonomousProperties securityAutonomousProperties) {
        return new AutonomousLearningCoordinator(evolutionEngine, tuningService, proposalRepository, evolutionMetricsCollector, securityAutonomousProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AITuningService aiTuningService(
            VectorStore vectorStore,
            RedisTemplate<String, Object> redisTemplate,
            AiTuningProperties aiTuningProperties) {
        return new AITuningService(vectorStore, redisTemplate, aiTuningProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyEvolutionLab policyEvolutionLab(
            ChatModel chatModel,
            PolicyEvolutionHelper policyEvolutionHelper,
            LearningEngineHelper learningEngineHelper,
            MemorySystemHelper memorySystemHelper) {
        return new PolicyEvolutionLab(chatModel, policyEvolutionHelper, learningEngineHelper,
                memorySystemHelper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyEvolutionHelper policyEvolutionHelper(
            UnifiedVectorService unifiedVectorService,
            PolicyEvolutionProperties policyEvolutionProperties) {
        return new PolicyEvolutionHelper(unifiedVectorService, policyEvolutionProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public LearningEngineHelper learningEngineHelper(
            AITuningService tuningService,
            DistributedStateManager stateManager,
            LearningEngineProperties learningEngineProperties) {
        return new LearningEngineHelper(tuningService, stateManager, learningEngineProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public MemorySystemHelper memorySystemHelper(
            UnifiedVectorService unifiedVectorService,
            DistributedStateManager stateManager,
            RedisTemplate<String, Object> redisTemplate,
            MemoryProperties memoryProperties) {
        return new MemorySystemHelper(unifiedVectorService, stateManager, redisTemplate, memoryProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyAuditLogger policyAuditLogger(
            SynthesisPolicyRepository synthesisPolicyRepository) {
        return new PolicyAuditLogger(synthesisPolicyRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public DefaultNotificationService defaultNotificationService() {
        return new DefaultNotificationService();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarNotifierImpl soarNotifierImpl() {
        return new SoarNotifierImpl();
    }

    @Bean
    @ConditionalOnMissingBean(IPolicyProposalManagementService.class)
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public IPolicyProposalManagementService policyProposalManagementService(
            PolicyEvolutionProposalRepository proposalRepository,
            PolicyEvolutionGovernance governance,
            PolicyAuditLogger auditLogger,
            ApplicationEventPublisher eventPublisher) {
        return new PolicyProposalManagementService(proposalRepository, governance, auditLogger, eventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyWorkbenchController policyWorkbenchController(
            PolicyProposalRepository proposalRepository,
            PolicyActivationService activationService,
            PolicyApprovalService approvalService,
            PolicyEvolutionGovernance governanceService,
            SynthesisPolicyRepository synthesisPolicyRepository,
            PolicyProposalAnalytics analyticsService) {
        return new PolicyWorkbenchController(
                proposalRepository, activationService, approvalService,
                governanceService, synthesisPolicyRepository, analyticsService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ProposalToPolicyConverter proposalToPolicyConverter() {
        return new ProposalToPolicyConverter();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnClass(name = "io.contexa.contexaiam.security.xacml.pap.service.PolicyService")
    public PolicyActivationEventListener policyActivationEventListener(
            PolicyProposalRepository proposalRepository,
            ProposalToPolicyConverter proposalToPolicyConverter,
            PolicyService policyService,
            PolicyRetrievalPoint policyRetrievalPoint,
            CustomDynamicAuthorizationManager authorizationManager) {
        return new PolicyActivationEventListener(
                proposalRepository,
                proposalToPolicyConverter,
                policyService,
                policyRetrievalPoint,
                authorizationManager);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SpelValidationService spelValidationService() {
        return new SpelValidationService();
    }

    @Bean
    @ConditionalOnMissingBean
    public DistributedStateManager distributedStateManager(
            RedisTemplate<String, Object> redisTemplate,
            RedisDistributedLockService redisDistributedLockService,
            ObjectMapper objectMapper,
            StateProperties stateProperties) {
        return new DistributedStateManager(redisTemplate, redisDistributedLockService, objectMapper, stateProperties);
    }
}
