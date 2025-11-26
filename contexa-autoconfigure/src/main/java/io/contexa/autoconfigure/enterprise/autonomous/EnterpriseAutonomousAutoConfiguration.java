package io.contexa.autoconfigure.enterprise.autonomous;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacoreenterprise.properties.SecurityAutonomousProperties;
import io.contexa.contexacoreenterprise.properties.SecurityEvaluatorProperties;
import io.contexa.contexacore.autonomous.ISecurityPlaneAgent;
import io.contexa.contexacore.autonomous.PolicyActivationService;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacoreenterprise.autonomous.evolution.AutonomousLearningCoordinator;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyActivationServiceImpl;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyEvolutionEngine;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyApprovalService;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyEvolutionGovernance;
import io.contexa.contexacoreenterprise.autonomous.intelligence.AITuningService;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import io.contexa.contexacore.infra.redis.RedisAtomicOperations;
import io.contexa.contexacore.autonomous.state.DistributedStateManager;
import io.contexa.contexacore.repository.PolicyEvolutionProposalRepository;
import io.contexa.contexacoreenterprise.repository.SynthesisPolicyRepository;
import io.contexa.contexacoreenterprise.autonomous.evolution.AccessGovernanceLabConnector;
import io.contexa.contexacoreenterprise.autonomous.evolution.BehavioralAnalysisLabConnector;
import io.contexa.contexacoreenterprise.autonomous.evolution.IntegratedThreatEvaluator;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyEvolutionLabIntegration;
import io.contexa.contexacoreenterprise.autonomous.labs.PolicyEvolutionLab;
import io.contexa.contexacoreenterprise.autonomous.helper.PolicyEvolutionHelper;
import io.contexa.contexacoreenterprise.autonomous.helper.LearningEngineHelper;
import io.contexa.contexacoreenterprise.autonomous.helper.MemorySystemHelper;
import io.contexa.contexacoreenterprise.autonomous.intelligence.XAIReportingService;
import io.contexa.contexacoreenterprise.autonomous.monitor.PolicyAuditLogger;
import io.contexa.contexacore.autonomous.monitor.PolicyEffectivenessMonitor;
import io.contexa.contexacore.autonomous.monitor.PolicyProposalAnalytics;
import io.contexa.contexacoreenterprise.autonomous.metrics.PolicyUsageMetricsService;
import io.contexa.contexacoreenterprise.autonomous.notification.SlackNotificationAdapter;
import io.contexa.contexacoreenterprise.autonomous.notification.SmsNotificationAdapter;
import io.contexa.contexacoreenterprise.autonomous.notification.DefaultNotificationService;
import io.contexa.contexacoreenterprise.autonomous.notification.UnifiedNotificationService;
import io.contexa.contexacoreenterprise.autonomous.service.impl.SoarNotifierImpl;
import io.contexa.contexacoreenterprise.autonomous.service.AsyncResultDeliveryService;
import io.contexa.contexacoreenterprise.autonomous.orchestrator.strategy.AwaitApprovalStrategy;
import io.contexa.contexacoreenterprise.autonomous.workflow.ApprovalWorkflow;
import io.contexa.contexacore.autonomous.IPolicyProposalManagementService;
import io.contexa.contexacoreenterprise.autonomous.PolicyProposalManagementService;
import io.contexa.contexacoreenterprise.autonomous.scheduler.VectorLearningScheduler;
import io.contexa.contexacoreenterprise.autonomous.event.listener.PolicyChangeEventListener;
import io.contexa.contexacoreenterprise.autonomous.scheduler.PolicyEvolutionScheduler;
import io.contexa.contexacoreenterprise.autonomous.scheduler.StaticAnalysisScheduler;
import io.contexa.contexacoreenterprise.autonomous.controller.PolicyWorkbenchController;
import io.contexa.contexacore.autonomous.notification.NotificationService;
import io.contexa.contexacoreenterprise.soar.notification.SoarEmailService;
import io.contexa.contexacoreenterprise.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacoreenterprise.tool.authorization.ToolAuthorizationService;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacore.hcad.service.HCADVectorIntegrationService;
import io.opentelemetry.api.trace.Tracer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.ai.chat.model.ChatModel;
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

/**
 * Enterprise Autonomous AutoConfiguration
 *
 * Contexa Enterprise 모듈의 Autonomous Policy Evolution 자동 구성을 제공합니다.
 * @Bean 방식으로 Enterprise Autonomous 서비스들을 명시적으로 등록합니다.
 *
 * 포함된 컴포넌트 (27개):
 * Level 1-4: Core Services (5개)
 * - PolicyApprovalService, PolicyEvolutionEngine, PolicyEvolutionGovernance
 * - PolicyActivationServiceImpl, AutonomousLearningCoordinator
 *
 * Level 5: Evolution Lab Integration (6개)
 * - AITuningService, AccessGovernanceLabConnector, BehavioralAnalysisLabConnector
 * - IntegratedThreatEvaluator, PolicyEvolutionLabIntegration, PolicyEvolutionLab
 *
 * Level 6: Helper Classes (3개)
 * - PolicyEvolutionHelper, LearningEngineHelper, MemorySystemHelper
 *
 * Level 7: Independent Services (8개)
 * - XAIReportingService, PolicyAuditLogger, PolicyUsageMetricsService
 * - SlackNotificationAdapter, SmsNotificationAdapter, DefaultNotificationService
 * - SoarNotifierImpl, AwaitApprovalStrategy
 *
 * Level 8: Intermediate Services (3개)
 * - UnifiedNotificationService, PolicyProposalManagementService, ApprovalWorkflow
 *
 * Level 9: Service & Scheduler (2개)
 * - AsyncResultDeliveryService, VectorLearningScheduler
 *
 * 활성화 조건:
 * contexa:
 *   enterprise:
 *     enabled: true
 *   autonomous:
 *     policy-evolution:
 *       enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnClass(name = "io.contexa.contexacoreenterprise.autonomous.PolicyProposalManagementService")
@ConditionalOnProperty(
    prefix = "contexa.enterprise",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = false
)
@EnableConfigurationProperties({ContexaProperties.class, SecurityAutonomousProperties.class, SecurityEvaluatorProperties.class})
public class EnterpriseAutonomousAutoConfiguration {

    public EnterpriseAutonomousAutoConfiguration() {
        // @Bean 방식으로 Enterprise Autonomous 서비스 등록
    }

    // ========== Level 1: 독립적 서비스 (2개) ==========

    /**
     * 1-1. PolicyApprovalService - 정책 승인 워크플로우 관리
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyApprovalService policyApprovalService(
            PolicyProposalRepository proposalRepository,
            ApplicationEventPublisher eventPublisher,
            @Autowired(required = false) PolicyActivationService policyActivationService) {
        return new PolicyApprovalService(proposalRepository, eventPublisher);
    }

    /**
     * 1-2. PolicyEvolutionEngine - 정책 진화 엔진
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyEvolutionEngine policyEvolutionEngine(
            ChatModel chatModel,
            UnifiedVectorService unifiedVectorService,
            AITuningService tuningService,
            RedisTemplate<String, PolicyEvolutionProposal> policyEvolutionRedisTemplate,
            RedisTemplate<String, String> stringRedisTemplate) {
        return new PolicyEvolutionEngine(
            chatModel, unifiedVectorService, tuningService,
            policyEvolutionRedisTemplate, stringRedisTemplate
        );
    }

    // ========== Level 2: Level 1 의존 (1개) ==========

    /**
     * 2-1. PolicyEvolutionGovernance - 정책 진화 거버넌스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyEvolutionGovernance policyEvolutionGovernance(
            PolicyProposalRepository proposalRepository,
            PolicyActivationService activationService,
            PolicyApprovalService approvalService,
            ApplicationEventPublisher eventPublisher) {
        return new PolicyEvolutionGovernance(
            proposalRepository, activationService, approvalService, eventPublisher
        );
    }

    // ========== Level 3: PolicyActivationService 구현체 (1개) ==========

    /**
     * 3-1. PolicyActivationServiceImpl - 정책 활성화 서비스
     */
    @Bean
    @ConditionalOnMissingBean(PolicyActivationService.class)
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyActivationService policyActivationService() {
        return new PolicyActivationServiceImpl();
    }

    // ========== Level 4: 최상위 코디네이터 (1개) ==========

    /**
     * 4-1. AutonomousLearningCoordinator - 자율 학습 코디네이터
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AutonomousLearningCoordinator autonomousLearningCoordinator(
            ISecurityPlaneAgent securityPlaneAgent,
            PolicyEvolutionEngine evolutionEngine,
            AITuningService tuningService,
            PolicyProposalRepository proposalRepository,
            ApplicationEventPublisher eventPublisher) {
        return new AutonomousLearningCoordinator(
            securityPlaneAgent, evolutionEngine, tuningService,
            proposalRepository, eventPublisher
        );
    }

    // ========== Level 5: Evolution Lab 연동 및 Intelligence (6개) ==========

    /**
     * 5-1. AITuningService - AI 모델 자동 튜닝 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AITuningService aiTuningService(
            StandardVectorStoreService vectorStore,
            RedisTemplate<String, Object> redisTemplate) {
        return new AITuningService(vectorStore, redisTemplate);
    }

    /**
     * 5-2. AccessGovernanceLabConnector - Access Governance Lab 연동 커넥터
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AccessGovernanceLabConnector accessGovernanceLabConnector() {
        return new AccessGovernanceLabConnector();
    }

    /**
     * 5-3. BehavioralAnalysisLabConnector - Behavioral Analysis Lab 연동 커넥터
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public BehavioralAnalysisLabConnector behavioralAnalysisLabConnector() {
        return new BehavioralAnalysisLabConnector();
    }

    /**
     * 5-4. IntegratedThreatEvaluator - 통합 위협 평가기
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public IntegratedThreatEvaluator integratedThreatEvaluator(
            RedisAtomicOperations redisAtomicOperations,
            RedisTemplate<String, Object> redisTemplate) {
        return new IntegratedThreatEvaluator(redisAtomicOperations, redisTemplate);
    }

    /**
     * 5-5. PolicyEvolutionLabIntegration - Policy Evolution Lab 통합
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyEvolutionLabIntegration policyEvolutionLabIntegration(
            IPolicyProposalManagementService proposalManagementService,
            ApplicationEventPublisher eventPublisher) {
        return new PolicyEvolutionLabIntegration(proposalManagementService, eventPublisher);
    }

    /**
     * 5-6. PolicyEvolutionLab - Policy Evolution Lab (Enterprise AI Lab)
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyEvolutionLab policyEvolutionLab(
            Tracer tracer,
            ChatModel chatModel,
            PolicyEvolutionHelper policyEvolutionHelper,
            LearningEngineHelper learningEngineHelper,
            MemorySystemHelper memorySystemHelper) {
        return new PolicyEvolutionLab(tracer, chatModel, policyEvolutionHelper, learningEngineHelper, memorySystemHelper);
    }

    // ========== Level 6: Helper 클래스 (3개) ==========

    /**
     * 6-1. PolicyEvolutionHelper - 정책 진화 헬퍼
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyEvolutionHelper policyEvolutionHelper(
            UnifiedVectorService unifiedVectorService,
            AITuningService tuningService) {
        return new PolicyEvolutionHelper(unifiedVectorService, tuningService);
    }

    /**
     * 6-2. LearningEngineHelper - 학습 엔진 헬퍼
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public LearningEngineHelper learningEngineHelper(
            AITuningService tuningService,
            DistributedStateManager stateManager) {
        return new LearningEngineHelper(tuningService, stateManager);
    }

    /**
     * 6-3. MemorySystemHelper - 메모리 시스템 헬퍼
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public MemorySystemHelper memorySystemHelper(
            UnifiedVectorService unifiedVectorService,
            StandardVectorStoreService standardVectorStoreService,
            DistributedStateManager stateManager,
            RedisTemplate<String, Object> redisTemplate) {
        return new MemorySystemHelper(unifiedVectorService, standardVectorStoreService, stateManager, redisTemplate);
    }

    // ========== Level 7: 독립적/낮은 의존성 클래스 (8개) ==========

    /**
     * 7-1. XAIReportingService - 설명 가능한 AI 리포팅
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public XAIReportingService xaiReportingService(
            StandardVectorStoreService vectorStore,
            RedisTemplate<String, Object> redisTemplate) {
        return new XAIReportingService(vectorStore, redisTemplate);
    }

    /**
     * 7-2. PolicyAuditLogger - 정책 감사 로거
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyAuditLogger policyAuditLogger(
            SynthesisPolicyRepository synthesisPolicyRepository) {
        return new PolicyAuditLogger(synthesisPolicyRepository);
    }

    /**
     * 7-3. PolicyUsageMetricsService - 정책 사용 메트릭
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyUsageMetricsService policyUsageMetricsService(
            PolicyProposalRepository proposalRepository) {
        return new PolicyUsageMetricsService(proposalRepository);
    }

    /**
     * 7-4. SlackNotificationAdapter - Slack 알림 어댑터
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SlackNotificationAdapter slackNotificationAdapter(
            ObjectMapper objectMapper) {
        return new SlackNotificationAdapter(objectMapper);
    }

    /**
     * 7-5. SmsNotificationAdapter - SMS 알림 어댑터
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SmsNotificationAdapter smsNotificationAdapter(
            ObjectMapper objectMapper) {
        return new SmsNotificationAdapter(objectMapper);
    }

    /**
     * 7-6. DefaultNotificationService - 기본 알림 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public DefaultNotificationService defaultNotificationService() {
        return new DefaultNotificationService();
    }

    /**
     * 7-7. SoarNotifierImpl - SOAR 알림 구현체
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarNotifierImpl soarNotifierImpl() {
        return new SoarNotifierImpl();
    }

    /**
     * 7-8. AwaitApprovalStrategy - 승인 대기 전략
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AwaitApprovalStrategy awaitApprovalStrategy(
            RedisTemplate<String, Object> redisTemplate,
            ApplicationEventPublisher eventPublisher) {
        return new AwaitApprovalStrategy(redisTemplate, eventPublisher);
    }

    // ========== Level 8: 중간 의존성 클래스 (3개) ==========

    /**
     * 8-1. UnifiedNotificationService - 통합 알림 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public UnifiedNotificationService unifiedNotificationService(
            SoarEmailService emailService,
            McpApprovalNotificationService websocketService,
            SlackNotificationAdapter slackAdapter,
            SmsNotificationAdapter smsAdapter,
            RedisTemplate<String, Object> redisTemplate) {
        return new UnifiedNotificationService(emailService, websocketService, slackAdapter, smsAdapter, redisTemplate);
    }

    /**
     * 8-2. PolicyProposalManagementService - 정책 제안 관리 서비스
     * IPolicyProposalManagementService 인터페이스로 빈 등록
     */
    @Bean
    @ConditionalOnMissingBean(IPolicyProposalManagementService.class)
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public IPolicyProposalManagementService policyProposalManagementService(
            PolicyEvolutionProposalRepository proposalRepository,
            PolicyEvolutionGovernance governance,
            PolicyAuditLogger auditLogger,
            ApplicationEventPublisher eventPublisher) {
        return new PolicyProposalManagementService(proposalRepository, governance, auditLogger, eventPublisher);
    }

    /**
     * 8-3. ApprovalWorkflow - 승인 워크플로우
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ApprovalWorkflow approvalWorkflow(
            RedisTemplate<String, Object> redisTemplate,
            ToolAuthorizationService authService) {
        return new ApprovalWorkflow(redisTemplate, authService);
    }

    // ========== Level 9: Service 및 Scheduler (2개) ==========

    /**
     * 9-1. AsyncResultDeliveryService - 비동기 결과 전달 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AsyncResultDeliveryService asyncResultDeliveryService(
            ToolExecutionContextRepository executionRepository,
            RedisEventPublisher eventPublisher,
            UnifiedNotificationService notificationService,
            RedisTemplate<String, Object> redisTemplate,
            SimpMessagingTemplate messagingTemplate,
            ObjectMapper objectMapper) {
        return new AsyncResultDeliveryService(
            executionRepository, eventPublisher, notificationService,
            redisTemplate, messagingTemplate, objectMapper
        );
    }

    /**
     * 9-2. VectorLearningScheduler - 벡터 학습 스케줄러
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public VectorLearningScheduler vectorLearningScheduler(
            @Autowired(required = false) HCADVectorIntegrationService hcadVectorService,
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate) {
        return new VectorLearningScheduler(hcadVectorService, redisTemplate);
    }

    /**
     * 9-3. PolicyChangeEventListener - 정책 변경 이벤트 리스너
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyChangeEventListener policyChangeEventListener(
            PolicyEvolutionEngine policyEvolutionEngine,
            PolicyApprovalService approvalService,
            NotificationService notificationService) {
        return new PolicyChangeEventListener(
            policyEvolutionEngine, approvalService, notificationService
        );
    }

    /**
     * 9-4. PolicyEvolutionScheduler - 정책 진화 스케줄러
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyEvolutionScheduler policyEvolutionScheduler(
            IPolicyProposalManagementService proposalManagementService,
            PolicyEvolutionProposalRepository proposalRepository,
            PolicyEffectivenessMonitor effectivenessMonitor,
            PolicyProposalAnalytics proposalAnalytics) {
        return new PolicyEvolutionScheduler(
            proposalManagementService, proposalRepository,
            effectivenessMonitor, proposalAnalytics
        );
    }

    /**
     * 9-5. StaticAnalysisScheduler - 정적 분석 스케줄러
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public StaticAnalysisScheduler staticAnalysisScheduler(
            IPolicyProposalManagementService proposalManagementService,
            PolicyEvolutionProposalRepository proposalRepository,
            SynthesisPolicyRepository synthesisPolicyRepository,
            PolicyEffectivenessMonitor effectivenessMonitor,
            PolicyProposalAnalytics proposalAnalytics,
            PolicyAuditLogger auditLogger) {
        return new StaticAnalysisScheduler(
            proposalManagementService, proposalRepository, synthesisPolicyRepository,
            effectivenessMonitor, proposalAnalytics, auditLogger
        );
    }

    // ========== Level 10: Controller (1개) ==========

    /**
     * 10-1. PolicyWorkbenchController - 정책 워크벤치 컨트롤러
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.autonomous.policy-evolution",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PolicyWorkbenchController policyWorkbenchController(
            PolicyProposalRepository proposalRepository,
            PolicyActivationService activationService,
            PolicyApprovalService approvalService,
            PolicyEvolutionGovernance governanceService,
            SynthesisPolicyRepository synthesisPolicyRepository,
            PolicyProposalAnalytics analyticsService) {
        return new PolicyWorkbenchController(
            proposalRepository, activationService, approvalService,
            governanceService, synthesisPolicyRepository, analyticsService
        );
    }
}
