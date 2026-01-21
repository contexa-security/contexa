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
                        return request -> impl.processAsync(request);
        }
        return null;
    }

    @Bean
    @ConditionalOnMissingBean
    public ThreatEvaluator threatEvaluator(@Autowired(required = false) IntegratedThreatEvaluator evaluator) {
        if (evaluator != null) {
                        return evaluator::evaluateIntegrated;
        }
        return null;
    }

    
    
    

    @Bean
    @ConditionalOnMissingBean(name = "defaultToolCallingManager")
    public DefaultToolCallingManager defaultToolCallingManager(
            ToolCallbackResolver chainedToolResolver,
            SoarToolExecutionExceptionProcessor toolExecutionExceptionProcessor) {

        
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

                return defaultToolCallingManager;
    }

    @Bean
    @ConditionalOnMissingBean(ToolCallbackResolver.class)
    public ToolCallbackResolver toolCallbackResolver(
            List<ToolCallbackResolver> resolvers) {

        
        
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

                return chainedResolver;
    }

    @Bean
    @ConditionalOnMissingBean(SpringBeanToolCallbackResolver.class)
    public SpringBeanToolCallbackResolver springBeanToolCallbackResolver(
            ApplicationContext applicationContext) {

                return new SpringBeanToolCallbackResolver(applicationContext);
    }

    @Bean
    @ConditionalOnMissingBean
    public McpToolResolver mcpToolResolver(
            Optional<McpClientProvider> mcpClientProvider,
            Optional<McpFunctionCallbackProvider> mcpFunctionProvider) {

        if (mcpClientProvider.isPresent() && mcpFunctionProvider.isPresent()) {
                        return new McpToolResolver(mcpClientProvider.get(), mcpFunctionProvider.get());
        } else {
            log.warn("MCP 프로바이더를 찾을 수 없음. 빈 McpToolResolver 생성");
            return new McpToolResolver(null, null);
        }
    }

    @Bean
    @ConditionalOnMissingBean(StaticToolCallbackResolver.class)
    public StaticToolCallbackResolver staticToolCallbackResolver() {
                return new StaticToolCallbackResolver();
    }

    @Bean
    @ConditionalOnMissingBean(FallbackToolResolver.class)
    public FallbackToolResolver fallbackToolResolver() {
                return new FallbackToolResolver();
    }

    @Bean
    @ConditionalOnMissingBean(MCPToolMetrics.class)
    public MCPToolMetrics metricsCollector(
            @Autowired(required = false) MeterRegistry meterRegistry) {
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
                
                
                if (chainedResolver.isPresent()) {
                    Set<String> toolNames = chainedResolver.get().getRegisteredToolNames();
                }

                
                if (mcpProvider.isPresent()) {
                    Map<String, Object> stats = mcpProvider.get().getMcpToolStatistics();
                                    }

                            }
        };
    }

    private interface ToolInventoryLogger {
        
    }

    
    
    

    @Bean
    @ConditionalOnMissingBean
    public ToolEventPublisher toolEventPublisher(ApplicationEventPublisher eventPublisher) {
                return new ToolEventPublisher(eventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpFunctionCallbackProvider mcpFunctionCallbackProvider(
            McpSyncClient braveSearchMcpClient,
            McpSyncClient securityMcpClient) {
                return new McpFunctionCallbackProvider(braveSearchMcpClient, securityMcpClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpPromptIntegrator mcpPromptIntegrator(
            McpSyncClient braveSearchMcpClient,
            McpSyncClient securityMcpClient) {
                return new McpPromptIntegrator(braveSearchMcpClient, securityMcpClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpResourceProvider mcpResourceProvider(
            McpSyncClient braveSearchMcpClient,
            McpSyncClient securityMcpClient) {
                return new McpResourceProvider(braveSearchMcpClient, securityMcpClient);
    }

    @Bean("mcpToolIntegrationAdapter")
    @ConditionalOnMissingBean(name = "mcpToolIntegrationAdapter")
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpToolIntegrationAdapter mcpToolIntegrationAdapter(
            McpFunctionCallbackProvider mcpProvider) {
                return new McpToolIntegrationAdapter(mcpProvider);
    }

    @Bean("unifiedToolCallbackProvider")
    @ConditionalOnMissingBean(name = "unifiedToolCallbackProvider")
    public UnifiedToolCallbackProvider unifiedToolCallbackProvider() {
                return new UnifiedToolCallbackProvider();
    }

    @Bean
    @ConditionalOnMissingBean
    public McpClientProviderImpl mcpClientProvider(
            @Autowired(required = false) List<McpSyncClient> mcpClients,
            @Autowired(required = false) McpSyncClient braveSearchMcpClient,
            @Autowired(required = false) McpSyncClient securityMcpClient) {
                return new McpClientProviderImpl(mcpClients, braveSearchMcpClient, securityMcpClient);
    }

    
    
    

    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client.brave-search", name = "enabled", havingValue = "true", matchIfMissing = false)
    public McpSyncClient braveSearchMcpClient(
            @Value("${spring.ai.mcp.client.request-timeout:30}") long requestTimeoutSeconds) {
        
        try {
            
            var stdioParams = ServerParameters.builder("npx")
                    .args("-y", "@modelcontextprotocol/server-brave-search")
                    .build();

            
            var mcpClient = McpClient.sync(new StdioClientTransport(stdioParams, null))
                    .requestTimeout(Duration.ofSeconds(requestTimeoutSeconds))
                    .build();

            var init = mcpClient.initialize();
            
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
        
        try {
            
            HttpClientSseClientTransport transport = HttpClientSseClientTransport.builder(serverUrl)
                    .sseEndpoint("/sse")
                    .build();

            McpSyncClient mcpClient = McpClient.sync(transport)
                    .requestTimeout(Duration.ofSeconds(requestTimeoutSeconds))
                    .build();

            
            try {
                var init = mcpClient.initialize();
                            } catch (Exception initEx) {
                log.warn("contexa MCP 서버 초기화 실패 (서버가 아직 시작되지 않음): {}", initEx.getMessage());
            }

                        return mcpClient;

        } catch (Exception e) {
            log.warn("contexa MCP 클라이언트 생성 실패: {}", e.getMessage());
            
            return createFallbackMcpClient();
        }
    }

    private McpSyncClient createFallbackMcpClient() {
        try {
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
                    
                    
                    if (log.isDebugEnabled()) {
                        for (ToolCallback tool : tools) {
                                                    }
                    }
                } else {
                    log.warn("사용 가능한 도구가 없습니다");
                }
            } catch (Exception e) {
                log.error("도구 통합 실패", e);
                
            }
        } else if (!toolsEnabled) {
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
                return new ToolResultCache(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean(ToolAuthorizationService.class)
    public ToolAuthorizationService toolAuthorizationService() {
                return new ToolAuthorizationService();
    }

    @Bean
    @ConditionalOnMissingBean
    public ToolExecutionConfigurationLogger configurationLogger() {
        return new ToolExecutionConfigurationLogger();
    }

    public static class ToolExecutionConfigurationLogger {
        public ToolExecutionConfigurationLogger() {
                                                                    }
    }

    
    
    

    @Bean(name = "soarToolCallingManager")
    @ConditionalOnMissingBean
    public ToolCallingManager soarToolCallingManager() {
        
        
        return DefaultToolCallingManager.builder().build();
    }

    @Bean
    @ConditionalOnMissingBean
    public ToolApprovalPolicyManager toolApprovalPolicyManager() {
                return new ToolApprovalPolicyManager();
    }

    @Bean
    @Primary
    @ConditionalOnMissingBean
    public SoarToolExecutionExceptionProcessor toolExecutionExceptionProcessor(
            @Value("${spring.ai.tools.throw-exception-on-error:false}") boolean throwOnError) {
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
                return new PipelineSoarToolExecutionStep(
            toolCapableLLMClient,
            approvalAwareToolCallingManager,
            toolCallDetectionHelper,
            chainedToolResolver
        );
    }

    
    public EnterpriseToolAutoConfiguration() {
                                                                                            }
}
