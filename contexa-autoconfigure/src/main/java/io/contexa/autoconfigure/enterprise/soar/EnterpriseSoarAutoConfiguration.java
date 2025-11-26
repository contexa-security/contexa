package io.contexa.autoconfigure.enterprise.soar;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacoreenterprise.properties.SoarProperties;
import io.contexa.contexacoreenterprise.properties.ToolProperties;
import io.contexa.contexacoreenterprise.config.NotificationConfig;
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
import io.contexa.contexacoreenterprise.soar.controller.ToolApprovalController;
import io.contexa.contexacoreenterprise.soar.controller.SoarApprovalController;
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
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.retry.annotation.EnableRetry;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

/**
 * Enterprise SOAR AutoConfiguration
 *
 * <p>
 * Contexa Enterprise 모듈의 SOAR (Security Orchestration, Automation and Response) 자동 구성을 제공합니다.
 * @Bean 방식으로 Enterprise SOAR 서비스들을 명시적으로 등록합니다.
 * </p>
 *
 * <h3>포함된 컴포넌트 (27개):</h3>
 * <ul>
 *   <li><strong>Level 0: Infrastructure (3개)</strong> - JavaMailSender, TemplateEngine, NotificationTargetManager</li>
 *   <li><strong>Level 1: Helper/Utility (4개)</strong> - WebSocketConfigHelper, ToolCallDetectionHelper, ConversationHistoryBuilder, ToolApprovalService</li>
 *   <li><strong>Level 2: Simple Services (6개)</strong> - SoarPromptTemplate, ApprovalRequestFactory, ApprovalRequestValidator, ApprovalStateManager, SoarEmailService, McpApprovalNotificationService</li>
 *   <li><strong>Level 3: Medium Services (7개)</strong> - SoarToolIntegrationProvider, SoarDiagnosisStrategy, SoarToolExecutionService, SoarContextRetriever, ApprovalEventListener, RedisApprovalSubscriber, SoarLabImpl</li>
 *   <li><strong>Level 4: Complex Services (4개)</strong> - SoarToolCallingService, SoarApprovalNotifierImpl, SoarInteractionManager, AsyncToolExecutionService</li>
 *   <li><strong>Level 5: Highest Services (1개)</strong> - UnifiedApprovalService</li>
 *   <li><strong>Level 6: Controllers (2개)</strong> - ToolApprovalController, SoarApprovalController</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * contexa:
 *   enterprise:
 *     enabled: true
 *   soar:
 *     enabled: true  (기본값)
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnClass(name = "io.contexa.contexacoreenterprise.soar.approval.UnifiedApprovalService")
@ConditionalOnProperty(
    prefix = "contexa.enterprise",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = false
)
@EnableConfigurationProperties({ContexaProperties.class, SoarProperties.class, ToolProperties.class})
@EnableRetry
public class EnterpriseSoarAutoConfiguration {

    public EnterpriseSoarAutoConfiguration() {
        // @Bean 방식으로 Enterprise SOAR 서비스 등록
    }

    // ========== Level 0: Infrastructure (3개) ==========

    /**
     * JavaMailSender - 이메일 발송 서비스
     *
     * <p>
     * Spring Boot의 자동 구성을 사용하지만, 필요시 커스터마이징 가능합니다.
     * 실제 메일 설정 값은 application.yml에서 주입됩니다.
     * </p>
     *
     * @return JavaMailSender
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(name = "soar.notification.email.enabled", havingValue = "true", matchIfMissing = true)
    public JavaMailSender javaMailSender() {
        return new JavaMailSenderImpl();
    }

    /**
     * 이메일 템플릿 엔진
     *
     * <p>
     * Thymeleaf 기반 이메일 템플릿 처리를 제공합니다.
     * </p>
     *
     * @return TemplateEngine
     */
    @Bean
    @ConditionalOnMissingBean(name = "emailTemplateEngine")
    public TemplateEngine emailTemplateEngine() {
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();

        // 이메일 템플릿 리졸버 설정
        ClassLoaderTemplateResolver templateResolver = new ClassLoaderTemplateResolver();
        templateResolver.setPrefix("templates/");
        templateResolver.setSuffix(".html");
        templateResolver.setTemplateMode(TemplateMode.HTML);
        templateResolver.setCharacterEncoding("UTF-8");
        templateResolver.setCacheable(false);
        templateResolver.setOrder(1);

        templateEngine.addTemplateResolver(templateResolver);
        return templateEngine;
    }

    /**
     * 알림 타겟 관리자
     *
     * <p>
     * 사용자별 알림 채널 선호도와 연결 상태를 관리합니다.
     * </p>
     *
     * @return NotificationTargetManager
     */
    @Bean
    @ConditionalOnMissingBean
    public NotificationConfig.NotificationTargetManager notificationTargetManager() {
        return new NotificationConfig.NotificationTargetManager();
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
     * ApprovalService 인터페이스 타입으로 빈 등록
     */
    @Bean
    @ConditionalOnMissingBean(ApprovalService.class)
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ApprovalService unifiedApprovalService(
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

    // ========== Controllers (2개) ==========

    /**
     * 23. ToolApprovalController - Tool 승인 컨트롤러
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.soar",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ToolApprovalController toolApprovalController(
            ToolApprovalService approvalService) {
        return new ToolApprovalController(approvalService);
    }

    /**
     * 24. SoarApprovalController - SOAR 승인 컨트롤러
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
    public SoarApprovalController soarApprovalController(
            ApprovalService approvalService,
            SoarToolExecutionService soarToolExecutionService,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new SoarApprovalController(
            approvalService, soarToolExecutionService, brokerTemplate
        );
    }
}
