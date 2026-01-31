package io.contexa.autoconfigure.enterprise.autonomous;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexacore.autonomous.IPolicyProposalManagementService;
import io.contexa.contexacore.autonomous.ISecurityPlaneAgent;
import io.contexa.contexacore.autonomous.PolicyActivationService;
import io.contexa.contexacore.autonomous.monitor.PolicyEffectivenessMonitor;
import io.contexa.contexacore.autonomous.monitor.PolicyProposalAnalytics;
import io.contexa.contexacore.autonomous.notification.NotificationService;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacore.repository.PolicyEvolutionProposalRepository;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacoreenterprise.autonomous.PolicyProposalManagementService;
import io.contexa.contexacoreenterprise.autonomous.controller.PolicyWorkbenchController;
import io.contexa.contexacoreenterprise.autonomous.event.listener.PolicyChangeEventListener;
import io.contexa.contexacoreenterprise.autonomous.evolution.*;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyApprovalService;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyEvolutionGovernance;
import io.contexa.contexacoreenterprise.autonomous.helper.DistributedStateManager;
import io.contexa.contexacoreenterprise.autonomous.helper.LearningEngineHelper;
import io.contexa.contexacoreenterprise.autonomous.helper.MemorySystemHelper;
import io.contexa.contexacoreenterprise.autonomous.helper.PolicyEvolutionHelper;
import io.contexa.contexacoreenterprise.autonomous.intelligence.AITuningService;
import io.contexa.contexacoreenterprise.autonomous.intelligence.XAIReportingService;
import io.contexa.contexacoreenterprise.autonomous.labs.PolicyEvolutionLab;
import io.contexa.contexacoreenterprise.autonomous.metrics.PolicyUsageMetricsService;
import io.contexa.contexacoreenterprise.autonomous.monitor.PolicyAuditLogger;
import io.contexa.contexacoreenterprise.autonomous.notification.DefaultNotificationService;
import io.contexa.contexacoreenterprise.autonomous.notification.SlackNotificationAdapter;
import io.contexa.contexacoreenterprise.autonomous.notification.SmsNotificationAdapter;
import io.contexa.contexacoreenterprise.autonomous.notification.UnifiedNotificationService;
import io.contexa.contexacoreenterprise.autonomous.scheduler.StaticAnalysisScheduler;
import io.contexa.contexacoreenterprise.autonomous.service.AsyncResultDeliveryService;
import io.contexa.contexacoreenterprise.autonomous.service.impl.SoarNotifierImpl;
import io.contexa.contexacoreenterprise.autonomous.validation.SpelValidationService;
import io.contexa.contexacoreenterprise.autonomous.workflow.ApprovalWorkflow;
import io.contexa.contexacoreenterprise.properties.SecurityAutonomousProperties;
import io.contexa.contexacoreenterprise.properties.SecurityEvaluatorProperties;
import io.contexa.contexacoreenterprise.repository.SynthesisPolicyRepository;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacoreenterprise.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacoreenterprise.soar.notification.SoarEmailService;
import io.contexa.contexacoreenterprise.tool.authorization.ToolAuthorizationService;
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
import org.springframework.messaging.simp.SimpMessagingTemplate;

@AutoConfiguration
@ConditionalOnClass(name = "io.contexa.contexacoreenterprise.autonomous.PolicyProposalManagementService")
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "true", matchIfMissing = false)
@EnableConfigurationProperties({ ContexaProperties.class, SecurityAutonomousProperties.class,
        SecurityEvaluatorProperties.class })
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
            RedisTemplate<String, PolicyEvolutionProposal> policyEvolutionRedisTemplate,
            RedisTemplate<String, String> stringRedisTemplate) {
        return new PolicyEvolutionEngine(
                chatModel, unifiedVectorService, tuningService,
                policyEvolutionRedisTemplate, stringRedisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyEvolutionGovernance policyEvolutionGovernance(
            PolicyProposalRepository proposalRepository,
            PolicyActivationService activationService,
            PolicyApprovalService approvalService,
            ApplicationEventPublisher eventPublisher) {
        return new PolicyEvolutionGovernance(
                proposalRepository, activationService, approvalService, eventPublisher);
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
            ISecurityPlaneAgent securityPlaneAgent,
            PolicyEvolutionEngine evolutionEngine,
            AITuningService tuningService,
            PolicyProposalRepository proposalRepository,
            ApplicationEventPublisher eventPublisher) {
        return new AutonomousLearningCoordinator(
                securityPlaneAgent, evolutionEngine, tuningService,
                proposalRepository, eventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AITuningService aiTuningService(
            VectorStore vectorStore,
            RedisTemplate<String, Object> redisTemplate) {
        return new AITuningService(vectorStore, redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AccessGovernanceLabConnector accessGovernanceLabConnector() {
        return new AccessGovernanceLabConnector();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public BehavioralAnalysisLabConnector behavioralAnalysisLabConnector() {
        return new BehavioralAnalysisLabConnector();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyEvolutionLabIntegration policyEvolutionLabIntegration(
            IPolicyProposalManagementService proposalManagementService,
            ApplicationEventPublisher eventPublisher) {
        return new PolicyEvolutionLabIntegration(proposalManagementService, eventPublisher);
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
            AITuningService tuningService) {
        return new PolicyEvolutionHelper(unifiedVectorService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public LearningEngineHelper learningEngineHelper(
            AITuningService tuningService,
            DistributedStateManager stateManager) {
        return new LearningEngineHelper(tuningService, stateManager);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public MemorySystemHelper memorySystemHelper(
            UnifiedVectorService unifiedVectorService,
            DistributedStateManager stateManager,
            RedisTemplate<String, Object> redisTemplate) {
        return new MemorySystemHelper(unifiedVectorService, stateManager, redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public XAIReportingService xaiReportingService(
            RedisTemplate<String, Object> redisTemplate) {
        return new XAIReportingService(redisTemplate);
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
    public PolicyUsageMetricsService policyUsageMetricsService(
            PolicyProposalRepository proposalRepository,
            ContexaCacheService cacheService) {
        return new PolicyUsageMetricsService(proposalRepository, cacheService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SlackNotificationAdapter slackNotificationAdapter(
            ObjectMapper objectMapper) {
        return new SlackNotificationAdapter(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SmsNotificationAdapter smsNotificationAdapter(
            ObjectMapper objectMapper) {
        return new SmsNotificationAdapter(objectMapper);
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
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public UnifiedNotificationService unifiedNotificationService(
            SoarEmailService emailService,
            McpApprovalNotificationService websocketService,
            SlackNotificationAdapter slackAdapter,
            SmsNotificationAdapter smsAdapter,
            RedisTemplate<String, Object> redisTemplate) {
        return new UnifiedNotificationService(emailService, websocketService, slackAdapter, smsAdapter, redisTemplate);
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
    public ApprovalWorkflow approvalWorkflow(
            RedisTemplate<String, Object> redisTemplate,
            ToolAuthorizationService authService) {
        return new ApprovalWorkflow(redisTemplate, authService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AsyncResultDeliveryService asyncResultDeliveryService(
            ToolExecutionContextRepository executionRepository,
            RedisEventPublisher eventPublisher,
            UnifiedNotificationService notificationService,
            RedisTemplate<String, Object> redisTemplate,
            SimpMessagingTemplate messagingTemplate,
            ObjectMapper objectMapper) {
        return new AsyncResultDeliveryService(
                executionRepository, eventPublisher, notificationService,
                redisTemplate, messagingTemplate, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyChangeEventListener policyChangeEventListener(
            PolicyEvolutionEngine policyEvolutionEngine,
            PolicyApprovalService approvalService,
            NotificationService notificationService) {
        return new PolicyChangeEventListener(
                policyEvolutionEngine, approvalService, notificationService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.autonomous.policy-evolution", name = "enabled", havingValue = "true", matchIfMissing = true)
    public StaticAnalysisScheduler staticAnalysisScheduler(
            IPolicyProposalManagementService proposalManagementService,
            PolicyEvolutionProposalRepository proposalRepository,
            SynthesisPolicyRepository synthesisPolicyRepository,
            PolicyEffectivenessMonitor effectivenessMonitor,
            PolicyProposalAnalytics proposalAnalytics,
            PolicyAuditLogger auditLogger) {
        return new StaticAnalysisScheduler(
                proposalManagementService, proposalRepository, synthesisPolicyRepository);
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
            ObjectMapper objectMapper) {
        return new DistributedStateManager(redisTemplate, redisDistributedLockService, objectMapper);
    }
}
