package io.contexa.autoconfigure.enterprise.soar;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacoreenterprise.soar.tool.provider.SoarToolIntegrationProvider;
import io.contexa.contexacoreenterprise.soar.strategy.SoarDiagnosisStrategy;
import io.contexa.contexacoreenterprise.soar.service.SoarToolExecutionService;
import io.contexa.contexacoreenterprise.soar.service.SoarToolCallingService;
import io.contexa.contexacoreenterprise.soar.retriever.SoarContextRetriever;
import io.contexa.contexacoreenterprise.soar.prompt.SoarPromptTemplate;
import io.contexa.contexacoreenterprise.soar.notification.SoarApprovalNotifierImpl;
import io.contexa.contexacoreenterprise.soar.manager.SoarInteractionManager;
import io.contexa.contexacoreenterprise.soar.lab.SoarLabImpl;
import io.contexa.contexacoreenterprise.soar.helper.WebSocketConfigHelper;
import io.contexa.contexacoreenterprise.soar.helper.ToolCallDetectionHelper;
import io.contexa.contexacoreenterprise.soar.event.RedisApprovalSubscriber;
import io.contexa.contexacoreenterprise.soar.event.ApprovalEventListener;
import io.contexa.contexacoreenterprise.soar.event.WebSocketApprovalHandler;
import io.contexa.contexacoreenterprise.tool.pipeline.PipelineSoarToolExecutionStep;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalAwareToolCallingManagerDecorator;
import io.contexa.contexacoreenterprise.soar.approval.UnifiedApprovalService;
import io.contexa.contexacoreenterprise.soar.approval.ToolApprovalService;
import io.contexa.contexacoreenterprise.soar.approval.ConversationHistoryBuilder;
import io.contexa.contexacoreenterprise.soar.approval.AsyncToolExecutionService;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalRequestValidator;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalStateManager;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalRequestFactory;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacoreenterprise.mcp.tool.resolution.ChainedToolResolver;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacoreenterprise.soar.notification.SoarEmailService;
import io.contexa.contexacoreenterprise.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacoreenterprise.config.NotificationConfig.NotificationTargetManager;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.repository.SoarApprovalRequestRepository;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacore.repository.ApprovalPolicyRepository;
import io.contexa.contexacore.autonomous.notification.SoarApprovalNotifier;
import io.opentelemetry.api.trace.Tracer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.messaging.simp.SimpMessagingTemplate;

/**
 * Enterprise SOAR AutoConfiguration
 *
 * Contexa Enterprise 모듈의 SOAR (Security Orchestration, Automation and Response) 자동 구성을 제공합니다.
 * @Bean 방식으로 Enterprise SOAR 서비스들을 명시적으로 등록합니다.
 *
 * 포함된 컴포넌트 (22개):
 * Level 1: Helper/Utility (4개)
 * - WebSocketConfigHelper, ToolCallDetectionHelper, ConversationHistoryBuilder, ToolApprovalService
 *
 * Level 2: Simple Services (6개)
 * - SoarPromptTemplate, ApprovalRequestFactory, ApprovalRequestValidator, ApprovalStateManager
 * - SoarEmailService, McpApprovalNotificationService
 *
 * Level 3: Medium Services (7개)
 * - SoarToolIntegrationProvider, SoarDiagnosisStrategy, SoarToolExecutionService
 * - SoarContextRetriever, ApprovalEventListener, RedisApprovalSubscriber, SoarLabImpl
 *
 * Level 4: Complex Services (4개)
 * - SoarToolCallingService, SoarApprovalNotifierImpl, SoarInteractionManager, AsyncToolExecutionService
 *
 * Level 5: Highest Services (1개)
 * - UnifiedApprovalService
 *
 * 활성화 조건:
 * contexa:
 *   enterprise:
 *     enabled: true
 *   soar:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.enterprise",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContexaProperties.class)
public class EnterpriseSoarAutoConfiguration {

    public EnterpriseSoarAutoConfiguration() {
        // @Bean 방식으로 Enterprise SOAR 서비스 등록
    }

    // ========== Level 1: Helper/Utility 클래스 (4개) ==========

    /**
     * 1. WebSocketConfigHelper - WebSocket 설정 헬퍼
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public WebSocketConfigHelper webSocketConfigHelper() {
        return new WebSocketConfigHelper();
    }

    /**
     * 2. ToolCallDetectionHelper - 도구 호출 감지 헬퍼
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ToolCallDetectionHelper toolCallDetectionHelper() {
        return new ToolCallDetectionHelper();
    }

    /**
     * 3. ConversationHistoryBuilder - Conversation History 빌더
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ConversationHistoryBuilder conversationHistoryBuilder() {
        return new ConversationHistoryBuilder();
    }

    /**
     * 4. ToolApprovalService - Tool 승인 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ToolApprovalService toolApprovalService() {
        return new ToolApprovalService();
    }

    // ========== Level 2: Simple Services (4개) ==========

    /**
     * 5. SoarPromptTemplate - SOAR 프롬프트 템플릿
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarPromptTemplate soarPromptTemplate() {
        return new SoarPromptTemplate();
    }

    /**
     * 6. ApprovalRequestFactory - 승인 요청 팩토리
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ApprovalRequestFactory approvalRequestFactory() {
        return new ApprovalRequestFactory();
    }

    /**
     * 7. ApprovalRequestValidator - 승인 요청 검증기
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ApprovalRequestValidator approvalRequestValidator() {
        return new ApprovalRequestValidator();
    }

    /**
     * 8. ApprovalStateManager - 승인 상태 관리자
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ApprovalStateManager approvalStateManager(
            ApplicationEventPublisher eventPublisher) {
        return new ApprovalStateManager(eventPublisher);
    }

    /**
     * 9. SoarEmailService - SOAR 이메일 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarEmailService soarEmailService(
            org.springframework.mail.javamail.JavaMailSender mailSender,
            org.thymeleaf.TemplateEngine templateEngine) {
        return new SoarEmailService(mailSender, templateEngine);
    }

    /**
     * 10. McpApprovalNotificationService - MCP 승인 알림 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public McpApprovalNotificationService mcpApprovalNotificationService(
            ApplicationEventPublisher eventPublisher,
            ObjectMapper objectMapper,
            io.contexa.contexacore.repository.ApprovalNotificationRepository notificationRepository) {
        return new McpApprovalNotificationService(eventPublisher, objectMapper, notificationRepository);
    }

    // ========== Level 3: Medium Services (7개) ==========

    /**
     * 9. SoarToolIntegrationProvider - SOAR Tool Integration Provider
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarToolIntegrationProvider soarToolIntegrationProvider() {
        return new SoarToolIntegrationProvider();
    }

    /**
     * 10. SoarDiagnosisStrategy - SOAR 진단 전략
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarDiagnosisStrategy soarDiagnosisStrategy(
            AILabFactory labFactory) {
        return new SoarDiagnosisStrategy(labFactory);
    }

    /**
     * 11. SoarToolExecutionService - SOAR Tool 실행 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarToolExecutionService soarToolExecutionService(
            ToolCapableLLMClient toolCapableLLMClient,
            ChainedToolResolver toolResolver) {
        return new SoarToolExecutionService(toolCapableLLMClient, toolResolver);
    }

    /**
     * 12. SoarContextRetriever - SOAR 컨텍스트 검색기
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarContextRetriever soarContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry) {
        return new SoarContextRetriever(vectorStore, registry);
    }

    /**
     * 13. ApprovalEventListener - 승인 이벤트 리스너
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ApprovalEventListener approvalEventListener(
            ApprovalService approvalService) {
        return new ApprovalEventListener(approvalService);
    }

    /**
     * 14. RedisApprovalSubscriber - Redis 승인 구독자
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public RedisApprovalSubscriber redisApprovalSubscriber() {
        return new RedisApprovalSubscriber();
    }

    /**
     * 15. SoarLabImpl - SOAR Lab 구현체
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarLabImpl soarLabImpl(
            Tracer tracer,
            PipelineOrchestrator orchestrator) {
        return new SoarLabImpl(tracer, orchestrator);
    }

    // ========== Level 4: Complex Services (4개) ==========

    /**
     * 16. SoarToolCallingService - SOAR Tool Calling 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarToolCallingService soarToolCallingService(
            AICoreOperations<SoarContext> aiNativeProcessor,
            SoarInteractionManager interactionManager,
            ChainedToolResolver toolResolver,
            UnifiedApprovalService unifiedApprovalService) {
        return new SoarToolCallingService(
            aiNativeProcessor, interactionManager, toolResolver, unifiedApprovalService
        );
    }

    /**
     * 17. SoarApprovalNotifierImpl - SOAR 승인 알림 구현체
     * IMPORTANT: @Qualifier("brokerMessagingTemplate") 패턴 반드시 사용
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarApprovalNotifierImpl soarApprovalNotifierImpl(
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerMessagingTemplate,
            SoarEmailService emailService,
            McpApprovalNotificationService mcpNotificationService,
            NotificationTargetManager targetManager) {
        return new SoarApprovalNotifierImpl(
            brokerMessagingTemplate, emailService, mcpNotificationService, targetManager
        );
    }

    /**
     * 18. SoarInteractionManager - SOAR 상호작용 관리자
     * IMPORTANT: @Qualifier("brokerMessagingTemplate") 패턴 반드시 사용
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SoarInteractionManager soarInteractionManager(
            RedisTemplate<String, Object> redisTemplate,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate,
            ApprovalService approvalService) {
        return new SoarInteractionManager(redisTemplate, brokerTemplate, approvalService);
    }

    /**
     * 19. AsyncToolExecutionService - 비동기 Tool 실행 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AsyncToolExecutionService asyncToolExecutionService(
            ToolExecutionContextRepository contextRepository,
            ObjectMapper objectMapper,
            ChainedToolResolver chainedToolResolver) {
        return new AsyncToolExecutionService(contextRepository, objectMapper, chainedToolResolver);
    }

    // ========== Level 5: Highest Services (1개) ==========

    /**
     * 20. UnifiedApprovalService - 통합 승인 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public UnifiedApprovalService unifiedApprovalService(
            SoarApprovalRequestRepository repository,
            ApprovalRequestFactory approvalRequestFactory,
            ToolExecutionContextRepository executionContextRepository,
            ApprovalPolicyRepository policyRepository,
            SoarApprovalNotifier soarNotifier,
            ApplicationEventPublisher eventPublisher,
            StringRedisTemplate redisTemplate) {
        return new UnifiedApprovalService(
            repository, approvalRequestFactory, executionContextRepository,
            policyRepository, soarNotifier, eventPublisher, redisTemplate
        );
    }

    /**
     * 21. WebSocketApprovalHandler - WebSocket 승인 핸들러
     * IMPORTANT: @Qualifier("brokerMessagingTemplate") 패턴 반드시 사용
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public WebSocketApprovalHandler webSocketApprovalHandler(
            ObjectMapper objectMapper,
            UnifiedApprovalService unifiedApprovalService,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new WebSocketApprovalHandler(
            objectMapper, unifiedApprovalService, brokerTemplate
        );
    }

    /**
     * 22. PipelineSoarToolExecutionStep - 파이프라인 SOAR Tool 실행 단계
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public PipelineSoarToolExecutionStep pipelineSoarToolExecutionStep(
            ToolCapableLLMClient toolCapableLLMClient,
            ApprovalAwareToolCallingManagerDecorator approvalAwareToolCallingManager,
            ToolCallDetectionHelper toolCallDetectionHelper,
            ChainedToolResolver chainedToolResolver) {
        return new PipelineSoarToolExecutionStep(
            toolCapableLLMClient, approvalAwareToolCallingManager,
            toolCallDetectionHelper, chainedToolResolver
        );
    }
}
