package io.contexa.autoconfigure.enterprise.tool;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.ThreatEvaluator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.soar.SoarLab;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacoreenterprise.autonomous.evolution.IntegratedThreatEvaluator;
import io.contexa.contexacoreenterprise.dashboard.metrics.mcp.MCPToolMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.soar.ToolExecutionMetrics;
import io.contexa.contexacoreenterprise.mcp.cache.ToolResultCache;
import io.contexa.contexacoreenterprise.mcp.event.ToolEventPublisher;
import io.contexa.contexacoreenterprise.mcp.integration.*;
import io.contexa.contexacoreenterprise.mcp.tool.provider.McpClientProvider;
import io.contexa.contexacoreenterprise.mcp.tool.provider.McpClientProviderImpl;
import io.contexa.contexacoreenterprise.mcp.tool.resolution.*;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalAwareToolCallingManagerDecorator;
import io.contexa.contexacoreenterprise.soar.approval.AsyncToolExecutionService;
import io.contexa.contexacoreenterprise.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacoreenterprise.soar.approval.UnifiedApprovalService;
import io.contexa.contexacoreenterprise.soar.config.ToolApprovalPolicyManager;
import io.contexa.contexacoreenterprise.soar.helper.ToolCallDetectionHelper;
import io.contexa.contexacoreenterprise.soar.lab.SoarLabImpl;
import io.contexa.contexacoreenterprise.soar.tool.exception.SoarToolExecutionExceptionProcessor;
import io.contexa.contexacoreenterprise.tool.authorization.ToolAuthorizationService;
import io.contexa.contexacoreenterprise.tool.pipeline.PipelineSoarToolExecutionStep;
import io.micrometer.core.instrument.MeterRegistry;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientSseClientTransport;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.model.tool.DefaultToolCallingManager;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.resolution.DelegatingToolCallbackResolver;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.EnableAsync;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.*;


@Slf4j
@AutoConfiguration
@EnableAsync(proxyTargetClass = true)
@EnableAspectJAutoProxy(proxyTargetClass = true, exposeProxy = true)
@ConditionalOnClass(name = "io.contexa.contexacoreenterprise.soar.lab.SoarLabImpl")
@ConditionalOnProperty(
    prefix = "contexa.enterprise",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = false
)
@EnableConfigurationProperties(ContexaProperties.class)
public class EnterpriseToolAutoConfiguration {

    
    
    

    @Bean
    @ConditionalOnMissingBean
    public SoarLab soarLab(@Autowired(required = false) SoarLabImpl impl) {
        if (impl != null) {
            log.info("SoarLab export 완료");
            return request -> impl.processAsync(request);
        }
        return null;
    }

    @Bean
    @ConditionalOnMissingBean
    public ThreatEvaluator threatEvaluator(@Autowired(required = false) IntegratedThreatEvaluator evaluator) {
        if (evaluator != null) {
            log.info("ThreatEvaluator export 완료");
            return evaluator::evaluateIntegrated;
        }
        return null;
    }

    
    
    

    @Bean
    @ConditionalOnMissingBean(name = "defaultToolCallingManager")
    public DefaultToolCallingManager defaultToolCallingManager(
            ToolCallbackResolver chainedToolResolver,
            SoarToolExecutionExceptionProcessor toolExecutionExceptionProcessor) {

        log.info("Spring AI DefaultToolCallingManager 생성");

        return DefaultToolCallingManager.builder()
            .toolCallbackResolver(chainedToolResolver)
            .toolExecutionExceptionProcessor(toolExecutionExceptionProcessor)
            .build();
    }

    @Bean
    @Primary
    @ConditionalOnProperty(
        prefix = "spring.ai.soar.approval",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ToolCallingManager approvalAwareToolCallingManager(
            DefaultToolCallingManager defaultToolCallingManager,
            UnifiedApprovalService unifiedApprovalService,
            ToolApprovalPolicyManager policyManager,
            ToolExecutionMetrics executionMetrics,
            McpApprovalNotificationService notificationService,
            ToolExecutionContextRepository contextRepository,
            AsyncToolExecutionService asyncExecutionService,
            ObjectMapper objectMapper) {

        log.info("ApprovalAwareToolCallingManager 생성 (Decorator 패턴)");

        return new ApprovalAwareToolCallingManagerDecorator(
            defaultToolCallingManager,
            unifiedApprovalService,
            policyManager,
            executionMetrics,
            notificationService,
            contextRepository,
            asyncExecutionService,
            objectMapper
        );
    }

    @Bean
    @Primary
    @ConditionalOnProperty(
        prefix = "spring.ai.soar.approval",
        name = "enabled",
        havingValue = "false"
    )
    public ToolCallingManager standardToolCallingManager(
            DefaultToolCallingManager defaultToolCallingManager) {

        log.info("표준 DefaultToolCallingManager 사용 (승인 기능 비활성화)");
        return defaultToolCallingManager;
    }

    @Bean
    @ConditionalOnMissingBean(ToolCallbackResolver.class)
    public ToolCallbackResolver toolCallbackResolver(
            List<ToolCallbackResolver> resolvers) {

        log.info("🔗 ToolCallbackResolver 체인 구성: {} 개", resolvers.size());

        
        return new DelegatingToolCallbackResolver(resolvers);
    }

    @Bean
    @ConditionalOnMissingBean
    public ChainedToolResolver chainedToolResolver(
            SpringBeanToolCallbackResolver springBeanResolver,
            McpToolResolver mcpToolResolver,
            StaticToolCallbackResolver staticToolResolver,
            FallbackToolResolver fallbackToolResolver,
            MCPToolMetrics metricsCollector) {

        log.info("ChainedToolResolver 생성 (향상된 기능)");

        List<ToolCallbackResolver> resolvers = Arrays.asList(
            mcpToolResolver,           
            springBeanResolver,        
            staticToolResolver,        
            fallbackToolResolver       
        );

        ChainedToolResolver chainedResolver = new ChainedToolResolver(
            metricsCollector,
            springBeanResolver,
            mcpToolResolver,
            staticToolResolver,
            fallbackToolResolver
        );

        log.info("ChainedToolResolver 초기화 완료");
        return chainedResolver;
    }

    @Bean
    @ConditionalOnMissingBean(SpringBeanToolCallbackResolver.class)
    public SpringBeanToolCallbackResolver springBeanToolCallbackResolver(
            ApplicationContext applicationContext) {

        log.info("🌱 SpringBeanToolCallbackResolver 생성");
        return new SpringBeanToolCallbackResolver(applicationContext);
    }

    @Bean
    @ConditionalOnMissingBean
    public McpToolResolver mcpToolResolver(
            Optional<McpClientProvider> mcpClientProvider,
            Optional<McpFunctionCallbackProvider> mcpFunctionProvider) {

        if (mcpClientProvider.isPresent() && mcpFunctionProvider.isPresent()) {
            log.info("McpToolResolver 생성 (MCP 활성화)");
            return new McpToolResolver(mcpClientProvider.get(), mcpFunctionProvider.get());
        } else {
            log.warn("MCP 프로바이더를 찾을 수 없음. 빈 McpToolResolver 생성");
            return new McpToolResolver(null, null);
        }
    }

    @Bean
    @ConditionalOnMissingBean(StaticToolCallbackResolver.class)
    public StaticToolCallbackResolver staticToolCallbackResolver() {
        log.info("StaticToolCallbackResolver 생성");
        return new StaticToolCallbackResolver();
    }

    @Bean
    @ConditionalOnMissingBean(FallbackToolResolver.class)
    public FallbackToolResolver fallbackToolResolver() {
        log.info("FallbackToolResolver 생성");
        return new FallbackToolResolver();
    }

    @Bean
    @ConditionalOnMissingBean(MCPToolMetrics.class)
    public MCPToolMetrics metricsCollector(
            @Autowired(required = false) MeterRegistry meterRegistry) {
        log.info("MCPToolMetrics 생성");
        return new MCPToolMetrics(meterRegistry);
    }

    @Bean
    @ConditionalOnMissingBean
    public ToolInventoryLogger toolInventoryLogger(
            Optional<ChainedToolResolver> chainedResolver,
            Optional<McpFunctionCallbackProvider> mcpProvider) {

        return new ToolInventoryLogger() {
            @jakarta.annotation.PostConstruct
            public void logToolInventory() {
                log.info("========== 도구 인벤토리 ==========");

                
                if (chainedResolver.isPresent()) {
                    Set<String> toolNames = chainedResolver.get().getRegisteredToolNames();
                    log.info("등록된 도구 총 {} 개", toolNames.size());

                    if (log.isDebugEnabled()) {
                        toolNames.forEach(name -> log.debug("  - {}", name));
                    }
                }

                
                if (mcpProvider.isPresent()) {
                    Map<String, Object> stats = mcpProvider.get().getMcpToolStatistics();
                    log.info("MCP 도구 통계: {}", stats);
                }

                log.info("=====================================");
            }
        };
    }

    private interface ToolInventoryLogger {
        
    }

    
    
    

    @Bean
    @ConditionalOnMissingBean
    public ToolEventPublisher toolEventPublisher(ApplicationEventPublisher eventPublisher) {
        log.info("Tool Event Publisher Bean 생성");
        return new ToolEventPublisher(eventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpFunctionCallbackProvider mcpFunctionCallbackProvider(
            McpSyncClient braveSearchMcpClient,
            McpSyncClient securityMcpClient) {
        log.info("MCP Function Callback Provider Bean 생성");
        return new McpFunctionCallbackProvider(braveSearchMcpClient, securityMcpClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpPromptIntegrator mcpPromptIntegrator(
            McpSyncClient braveSearchMcpClient,
            McpSyncClient securityMcpClient) {
        log.info("MCP Prompt Integrator Bean 생성");
        return new McpPromptIntegrator(braveSearchMcpClient, securityMcpClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpResourceProvider mcpResourceProvider(
            McpSyncClient braveSearchMcpClient,
            McpSyncClient securityMcpClient) {
        log.info("MCP Resource Provider Bean 생성");
        return new McpResourceProvider(braveSearchMcpClient, securityMcpClient);
    }

    @Bean("mcpToolIntegrationAdapter")
    @ConditionalOnMissingBean(name = "mcpToolIntegrationAdapter")
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpToolIntegrationAdapter mcpToolIntegrationAdapter(
            McpFunctionCallbackProvider mcpProvider) {
        log.info("MCP Tool Integration Adapter Bean 생성");
        return new McpToolIntegrationAdapter(mcpProvider);
    }

    @Bean("unifiedToolCallbackProvider")
    @ConditionalOnMissingBean(name = "unifiedToolCallbackProvider")
    public UnifiedToolCallbackProvider unifiedToolCallbackProvider() {
        log.info("Unified Tool Callback Provider Bean 생성");
        return new UnifiedToolCallbackProvider();
    }

    @Bean
    @ConditionalOnMissingBean
    public McpClientProviderImpl mcpClientProvider(
            @Autowired(required = false) List<McpSyncClient> mcpClients,
            @Autowired(required = false) McpSyncClient braveSearchMcpClient,
            @Autowired(required = false) McpSyncClient securityMcpClient) {
        log.info("MCP Client Provider Impl Bean 생성");
        return new McpClientProviderImpl(mcpClients, braveSearchMcpClient, securityMcpClient);
    }

    
    
    

    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client.brave-search", name = "enabled", havingValue = "true", matchIfMissing = false)
    public McpSyncClient braveSearchMcpClient(
            @Value("${spring.ai.mcp.client.request-timeout:30}") long requestTimeoutSeconds) {
        log.info("Brave Search MCP 클라이언트 초기화");

        try {
            
            var stdioParams = ServerParameters.builder("npx")
                    .args("-y", "@modelcontextprotocol/server-brave-search")
                    .build();

            
            var mcpClient = McpClient.sync(new StdioClientTransport(stdioParams, null))
                    .requestTimeout(Duration.ofSeconds(requestTimeoutSeconds))
                    .build();

            var init = mcpClient.initialize();
            log.info("Brave Search MCP 초기화 완료: {}", init != null ? init.serverInfo() : "server info unavailable");

            return mcpClient;

        } catch (Exception e) {
            log.warn("Brave Search MCP 클라이언트 생성 실패: {}", e.getMessage());
            
            return createFallbackMcpClient();
        }
    }

    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client.local-security", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpSyncClient securityMcpClient(
            @Value("${spring.ai.mcp.client.sse.connections.local-server.url:http://localhost:9000}") String serverUrl,
            @Value("${spring.ai.mcp.client.request-timeout:30}") long requestTimeoutSeconds) {
        log.info("contexa MCP 클라이언트 초기화 (SSE Transport)");

        try {
            
            HttpClientSseClientTransport transport = HttpClientSseClientTransport.builder(serverUrl)
                    .sseEndpoint("/sse")
                    .build();

            McpSyncClient mcpClient = McpClient.sync(transport)
                    .requestTimeout(Duration.ofSeconds(requestTimeoutSeconds))
                    .build();

            
            try {
                var init = mcpClient.initialize();
                log.info("contexa MCP 초기화 완료: {}", init != null ? init.serverInfo() : "server info unavailable");
            } catch (Exception initEx) {
                log.warn("contexa MCP 서버 초기화 실패 (서버가 아직 시작되지 않음): {}", initEx.getMessage());
            }

            log.info("contexa MCP 클라이언트 생성 완료 (SSE URL: {})", serverUrl);
            return mcpClient;

        } catch (Exception e) {
            log.warn("contexa MCP 클라이언트 생성 실패: {}", e.getMessage());
            
            return createFallbackMcpClient();
        }
    }

    private McpSyncClient createFallbackMcpClient() {
        try {
            log.info("Fallback MCP 클라이언트 생성");
            var dummyParams = ServerParameters.builder("echo")
                    .args("Fallback MCP Client")
                    .build();
            return McpClient.sync(new StdioClientTransport(dummyParams, null))
                    .requestTimeout(Duration.ofSeconds(5))
                    .build();
        } catch (Exception e) {
            log.error("Fallback MCP 클라이언트 생성도 실패", e);
            
            return null;
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public Map<String, Object> mcpClientStatus(List<McpSyncClient> mcpSyncClients) {
        if (mcpSyncClients == null) {
            return Map.of(
                    "totalClients", 0,
                    "activeClients", 0,
                    "status", "no_clients",
                    "timestamp", System.currentTimeMillis()
            );
        }

        return Map.of(
                "totalClients", mcpSyncClients.size(),
                "activeClients", mcpSyncClients.stream().filter(c -> c != null).count(),
                "status", "configured",
                "timestamp", System.currentTimeMillis()
        );
    }

    
    
    

    @Bean
    @ConditionalOnMissingBean(name = "toolEnabledChatClient")
    @ConditionalOnProperty(prefix = "contexa.tools", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ChatClient toolEnabledChatClient(
            @Autowired(required = false) @Qualifier("advisorEnabledChatClientBuilder") ChatClient.Builder advisorBuilder,
            @Autowired(required = false) @Qualifier("chatClientBuilder") ChatClient.Builder basicBuilder,
            @Autowired(required = false) ChainedToolResolver toolResolver,
            @Value("${contexa.tools.enabled:true}") boolean toolsEnabled) {

        log.info("🛠️ 도구 활성화 ChatClient 생성 시작");

        
        ChatClient.Builder builder = advisorBuilder != null ? advisorBuilder : basicBuilder;

        if (builder == null) {
            log.error("ChatClient.Builder를 찾을 수 없습니다");
            throw new IllegalStateException("ChatClient.Builder not found. Check LlmConfig and AdvisorAutoConfiguration.");
        }

        
        if (toolsEnabled && toolResolver != null) {
            try {
                ToolCallback[] tools = toolResolver.getAllToolCallbacks();

                if (tools.length > 0) {
                    builder = builder.defaultToolCallbacks(tools);
                    log.info("{} 개의 도구가 ChatClient에 통합되었습니다", tools.length);

                    
                    if (log.isDebugEnabled()) {
                        for (ToolCallback tool : tools) {
                            log.debug("  - {}: {}",
                                tool.getToolDefinition().name(),
                                tool.getToolDefinition().description());
                        }
                    }
                } else {
                    log.warn("사용 가능한 도구가 없습니다");
                }
            } catch (Exception e) {
                log.error("도구 통합 실패", e);
                
            }
        } else if (!toolsEnabled) {
            log.info("도구가 비활성화되어 있습니다");
        } else {
            log.warn("ChainedToolResolver를 찾을 수 없습니다");
        }

        
        if (toolsEnabled) {
            builder = builder.defaultSystem("""
                You are an AI Assistant with access to integrated security tools.

                🛠️ TOOL CAPABILITIES:
                - SOAR Tools: Direct security response actions with risk-based approval
                - MCP Tools: External services and search capabilities
                - All tools are managed through a unified resolution system

                TOOL USAGE GUIDELINES:
                1. Tools are automatically available based on context
                2. High-risk tools require approval before execution
                3. Tool results should be used to provide evidence-based responses
                4. Chain multiple tools for comprehensive analysis when needed

                BEST PRACTICES:
                - Use appropriate tools for the task at hand
                - Respect approval workflows for sensitive operations
                - Provide clear explanations of tool usage and results
                - Fallback gracefully when tools are unavailable
                """);
        }

        ChatClient chatClient = builder.build();
        log.info("도구 활성화 ChatClient 생성 완료");

        return chatClient;
    }

    @Bean
    @ConditionalOnMissingBean
    public ToolIntegrationStatus toolIntegrationStatus(
            @Autowired(required = false) ChainedToolResolver toolResolver,
            @Value("${contexa.tools.enabled:true}") boolean toolsEnabled) {

        int toolCount = 0;
        String status = "not_configured";

        if (toolResolver != null) {
            try {
                ToolCallback[] tools = toolResolver.getAllToolCallbacks();
                toolCount = tools.length;
                status = toolCount > 0 ? "active" : "no_tools";
            } catch (Exception e) {
                status = "error";
                log.error("도구 상태 확인 실패", e);
            }
        }

        return new ToolIntegrationStatus(toolsEnabled, status, toolCount);
    }

    public record ToolIntegrationStatus(
        boolean enabled,
        String status,
        int toolCount
    ) {}

    
    
    

    @Bean
    @ConditionalOnMissingBean(ToolResultCache.class)
    public ToolResultCache toolResultCache(RedisTemplate<String, Object> redisTemplate) {
        log.info("Tool Result Cache 구성");
        return new ToolResultCache(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean(ToolAuthorizationService.class)
    public ToolAuthorizationService toolAuthorizationService() {
        log.info("Tool Authorization Service 구성");
        return new ToolAuthorizationService();
    }

    @Bean
    @ConditionalOnMissingBean
    public ToolExecutionConfigurationLogger configurationLogger() {
        return new ToolExecutionConfigurationLogger();
    }

    public static class ToolExecutionConfigurationLogger {
        public ToolExecutionConfigurationLogger() {
            log.info("════════════════════════════════════════════════════");
            log.info("Tool Execution Configuration 초기화 완료");
            log.info("MCP 통합 도구 실행 시스템 활성화");
            log.info("보안 검증 및 승인 메커니즘 통합 완료");
            log.info("════════════════════════════════════════════════════");
        }
    }

    
    
    

    @Bean(name = "soarToolCallingManager")
    @ConditionalOnMissingBean
    public ToolCallingManager soarToolCallingManager() {
        log.info("SOAR ToolCallingManager Bean 생성");

        
        return DefaultToolCallingManager.builder().build();
    }

    @Bean
    @ConditionalOnMissingBean
    public ToolApprovalPolicyManager toolApprovalPolicyManager() {
        log.info("Tool Approval Policy Manager Bean 생성");
        return new ToolApprovalPolicyManager();
    }

    @Bean
    @Primary
    @ConditionalOnMissingBean
    public SoarToolExecutionExceptionProcessor toolExecutionExceptionProcessor(
            @Value("${spring.ai.tools.throw-exception-on-error:false}") boolean throwOnError) {
        log.info("SOAR Tool Execution Exception Processor Bean 생성 (throwOnError: {})", throwOnError);
        return new SoarToolExecutionExceptionProcessor(throwOnError);
    }

    @Bean
    @Qualifier("pipelineSoarToolExecutionStep")
    @ConditionalOnMissingBean(name = "pipelineSoarToolExecutionStep")
    public PipelineSoarToolExecutionStep pipelineSoarToolExecutionStep(
            ToolCapableLLMClient toolCapableLLMClient,
            ApprovalAwareToolCallingManagerDecorator approvalAwareToolCallingManager,
            ToolCallDetectionHelper toolCallDetectionHelper,
            ChainedToolResolver chainedToolResolver) {
        log.info("Pipeline SOAR Tool Execution Step Bean 생성");
        return new PipelineSoarToolExecutionStep(
            toolCapableLLMClient,
            approvalAwareToolCallingManager,
            toolCallDetectionHelper,
            chainedToolResolver
        );
    }

    
    public EnterpriseToolAutoConfiguration() {
        log.info("=".repeat(80));
        log.info("Enterprise Tool AutoConfiguration 초기화");
        log.info("32개 빈 등록 시작 (7개 레벨)");
        log.info("  - Level 1: Enterprise Core (2개)");
        log.info("  - Level 2: Tool Calling (11개)");
        log.info("  - Level 3: MCP Integration (7개)");
        log.info("  - Level 4: MCP Clients (3개)");
        log.info("  - Level 5: Tool Configuration (2개)");
        log.info("  - Level 6: Tool Execution (3개)");
        log.info("  - Level 7: SOAR Tools (4개)");
        log.info("=".repeat(80));
    }
}
