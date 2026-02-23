package io.contexa.autoconfigure.enterprise.soar;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacoreenterprise.mcp.tool.provider.McpClientProvider;
import io.contexa.contexacoreenterprise.properties.SoarProperties;
import io.contexa.contexacoreenterprise.properties.ToolProperties;
import io.contexa.contexacoreenterprise.soar.controller.SoarActionController;
import io.contexa.contexacoreenterprise.soar.controller.SoarSimulationController;
import io.contexa.contexacoreenterprise.soar.service.SoarActionService;
import io.contexa.contexacoreenterprise.soar.service.SoarSimulationService;
import io.contexa.contexacoreenterprise.soar.tool.provider.SoarToolIntegrationProvider;
import io.contexa.contexacoreenterprise.soar.strategy.SoarDiagnosisStrategy;
import io.contexa.contexacoreenterprise.soar.service.SoarToolCallingService;
import io.contexa.contexacoreenterprise.soar.retriever.SoarContextRetriever;
import io.contexa.contexacoreenterprise.soar.prompt.SoarPromptTemplate;
import io.contexa.contexacoreenterprise.soar.notification.SoarApprovalNotifierImpl;
import io.contexa.contexacoreenterprise.soar.manager.SoarInteractionManager;
import io.contexa.contexacoreenterprise.soar.lab.SoarLabImpl;
import io.contexa.contexacoreenterprise.soar.helper.ToolCallDetectionHelper;
import io.contexa.contexacoreenterprise.soar.event.ApprovalEventListener;
import io.contexa.contexacoreenterprise.soar.event.WebSocketApprovalHandler;
import io.contexa.contexacoreenterprise.soar.tool.PipelineSoarToolExecutionStep;
import io.contexa.contexacoreenterprise.soar.controller.SoarApprovalController;
import io.contexa.contexacoreenterprise.soar.approval.UnifiedApprovalService;
import io.contexa.contexacoreenterprise.soar.approval.AsyncToolExecutionService;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalRequestValidator;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalRequestFactory;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacoreenterprise.mcp.tool.resolution.ChainedToolResolver;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacoreenterprise.soar.notification.SoarEmailService;
import io.contexa.contexacoreenterprise.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacoreenterprise.soar.notification.NotificationTargetManager;
import io.contexa.contexacore.soar.approval.ApprovalService;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.repository.SoarApprovalRequestRepository;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacore.repository.ApprovalPolicyRepository;
import io.contexa.contexacore.autonomous.notification.SoarApprovalNotifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "true", matchIfMissing = false)
@EnableConfigurationProperties({ ContexaProperties.class, SoarProperties.class, ToolProperties.class })
@EnableRetry
public class EnterpriseSoarAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(name = "soar.notification.email.enabled", havingValue = "true", matchIfMissing = true)
    public JavaMailSender javaMailSender() {
        return new JavaMailSenderImpl();
    }

    @Bean
    @ConditionalOnMissingBean(name = "emailTemplateEngine")
    public TemplateEngine emailTemplateEngine() {
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();

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

    @Bean
    @ConditionalOnMissingBean
    public NotificationTargetManager notificationTargetManager() {
        return new NotificationTargetManager();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ToolCallDetectionHelper toolCallDetectionHelper() {
        return new ToolCallDetectionHelper();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarPromptTemplate soarPromptTemplate() {
        return new SoarPromptTemplate();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ApprovalRequestFactory approvalRequestFactory() {
        return new ApprovalRequestFactory();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ApprovalRequestValidator approvalRequestValidator() {
        return new ApprovalRequestValidator();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarEmailService soarEmailService(
            org.springframework.mail.javamail.JavaMailSender mailSender,
            org.thymeleaf.TemplateEngine templateEngine,
            SoarProperties soarProperties) {
        return new SoarEmailService(mailSender, templateEngine, soarProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpApprovalNotificationService mcpApprovalNotificationService(
            ApplicationEventPublisher eventPublisher,
            ObjectMapper objectMapper,
            io.contexa.contexacore.repository.ApprovalNotificationRepository notificationRepository) {
        return new McpApprovalNotificationService(eventPublisher, objectMapper, notificationRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarToolIntegrationProvider soarToolIntegrationProvider() {
        return new SoarToolIntegrationProvider();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarDiagnosisStrategy soarDiagnosisStrategy(
            AILabFactory labFactory) {
        return new SoarDiagnosisStrategy(labFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarContextRetriever soarContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry,
            SoarProperties soarProperties) {
        return new SoarContextRetriever(vectorStore, registry, soarProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ApprovalEventListener approvalEventListener(
            ApprovalService approvalService) {
        return new ApprovalEventListener(approvalService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarLabImpl soarLabImpl(PipelineOrchestrator orchestrator) {
        return new SoarLabImpl(orchestrator);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarToolCallingService soarToolCallingService(
            AICoreOperations<SoarContext> aiNativeProcessor,
            SoarInteractionManager interactionManager,
            ChainedToolResolver toolResolver,
            ObjectMapper objectMapper) {
        return new SoarToolCallingService(aiNativeProcessor, interactionManager, toolResolver, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarSimulationController soarSimulationController(
            SoarSimulationService simulationService,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new SoarSimulationController(simulationService,brokerTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarSimulationService soarSimulationService(
            SoarToolCallingService soarToolCallingService,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate,
            McpClientProvider mcpClientProvider) {
        return new SoarSimulationService(soarToolCallingService, brokerTemplate, mcpClientProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarActionController soarActionController(SoarActionService soarActionService) {
        return new SoarActionController(soarActionService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SoarActionService soarActionService(
            @Autowired(required = false) ApprovalService approvalService) {
        return new SoarActionService(approvalService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarApprovalNotifierImpl soarApprovalNotifierImpl(
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerMessagingTemplate,
            SoarEmailService emailService,
            McpApprovalNotificationService mcpNotificationService,
            NotificationTargetManager targetManager,
            SoarProperties soarProperties) {
        return new SoarApprovalNotifierImpl(
                brokerMessagingTemplate, emailService, mcpNotificationService, targetManager, soarProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarInteractionManager soarInteractionManager(
            RedisTemplate<String, Object> redisTemplate,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate,
            ApprovalService approvalService) {
        return new SoarInteractionManager(redisTemplate, brokerTemplate, approvalService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public AsyncToolExecutionService asyncToolExecutionService(
            ToolExecutionContextRepository contextRepository,
            ObjectMapper objectMapper,
            ChainedToolResolver chainedToolResolver) {
        return new AsyncToolExecutionService(contextRepository, objectMapper, chainedToolResolver);
    }

    @Bean
    @ConditionalOnMissingBean(ApprovalService.class)
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
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
                policyRepository, soarNotifier, eventPublisher, redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public WebSocketApprovalHandler webSocketApprovalHandler(
            ObjectMapper objectMapper,
            UnifiedApprovalService unifiedApprovalService,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new WebSocketApprovalHandler(
                objectMapper, unifiedApprovalService, brokerTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PipelineSoarToolExecutionStep pipelineSoarToolExecutionStep(
            ToolCapableLLMClient toolCapableLLMClient,
            ToolCallingManager toolCallingManager,
            ToolCallDetectionHelper toolCallDetectionHelper,
            ChainedToolResolver chainedToolResolver,
            ObjectMapper objectMapper,
            SoarProperties soarProperties) {
        return new PipelineSoarToolExecutionStep(
                toolCapableLLMClient, toolCallingManager,
                toolCallDetectionHelper, chainedToolResolver, objectMapper, soarProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SoarApprovalController soarApprovalController(
            ApprovalService approvalService,
            SoarToolCallingService soarToolCallingService,
            ChainedToolResolver chainedToolResolver,
            @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate) {
        return new SoarApprovalController(
                approvalService, soarToolCallingService, chainedToolResolver, brokerTemplate);
    }
}
