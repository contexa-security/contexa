package io.contexa.contexacore.config;

import io.micrometer.core.instrument.MeterRegistry;
import io.contexa.contexacore.mcp.integration.McpFunctionCallbackProvider;
import io.contexa.contexacore.dashboard.metrics.mcp.MCPToolMetrics;
import io.contexa.contexacore.mcp.tool.provider.McpClientProvider;
import io.contexa.contexacore.mcp.tool.resolution.*;
import io.contexa.contexacore.soar.approval.*;
import io.contexa.contexacore.soar.config.ToolApprovalPolicyManager;
import io.contexa.contexacore.dashboard.metrics.soar.ToolExecutionMetrics;
import io.contexa.contexacore.repository.ToolExecutionContextRepository;
import io.contexa.contexacore.soar.approval.AsyncToolExecutionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.soar.tool.exception.SoarToolExecutionExceptionProcessor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.model.tool.DefaultToolCallingManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.execution.ToolExecutionExceptionProcessor;
import org.springframework.ai.tool.resolution.DelegatingToolCallbackResolver;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Spring AI Tool Calling Configuration
 * 
 * Spring AI 표준에 완벽하게 준수하는 Tool Calling 시스템을 구성합니다.
 * DefaultToolCallingManager를 기반으로 하며, 승인 메커니즘을 Decorator 패턴으로 추가합니다.
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class ToolCallingConfiguration {

    /**
     * Spring AI 표준 DefaultToolCallingManager Bean
     * 
     * 이것이 실제 도구 실행을 담당하는 핵심 매니저입니다.
     * ApprovalAwareToolCallingManager는 이것을 래핑하여 승인 로직만 추가합니다.
     */
    @Bean
    @ConditionalOnMissingBean(name = "defaultToolCallingManager")
    public DefaultToolCallingManager defaultToolCallingManager(
            ToolCallbackResolver chainedToolResolver,
            ToolExecutionExceptionProcessor toolExecutionExceptionProcessor) {
        
        log.info("Spring AI DefaultToolCallingManager 생성");
        
        return DefaultToolCallingManager.builder()
            .toolCallbackResolver(chainedToolResolver)
            .toolExecutionExceptionProcessor(toolExecutionExceptionProcessor)
            .build();
    }
    
    /**
     * Approval 기능이 추가된 ToolCallingManager
     * 
     * DefaultToolCallingManager를 Decorator 패턴으로 래핑하여
     * 고위험 도구 실행 시 승인 메커니즘을 추가합니다.
     */
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
    
    /**
     * 승인 기능이 비활성화된 경우 기본 ToolCallingManager 사용
     */
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
    
    /**
     * Spring AI 표준 DelegatingToolCallbackResolver
     * 
     * 여러 Resolver를 체인으로 연결하여 도구를 검색합니다.
     * ChainedToolResolver가 이것을 확장합니다.
     */
    @Bean
    @ConditionalOnMissingBean(ToolCallbackResolver.class)
    public ToolCallbackResolver toolCallbackResolver(
            List<ToolCallbackResolver> resolvers) {
        
        log.info("🔗 ToolCallbackResolver 체인 구성: {} 개", resolvers.size());
        
        // Spring AI 표준 DelegatingToolCallbackResolver 사용
        return new DelegatingToolCallbackResolver(resolvers);
    }
    
    /**
     * 향상된 ChainedToolResolver
     * 
     * DelegatingToolCallbackResolver를 확장하여
     * 캐싱, Circuit Breaker, 메트릭 수집 등을 추가합니다.
     */
    @Bean
    public ChainedToolResolver chainedToolResolver(
            SpringBeanToolCallbackResolver springBeanResolver,
            McpToolResolver mcpToolResolver,
            StaticToolCallbackResolver staticToolResolver,
            FallbackToolResolver fallbackToolResolver,
            MCPToolMetrics metricsCollector) {
        
        log.info("ChainedToolResolver 생성 (향상된 기능)");
        
        List<ToolCallbackResolver> resolvers = Arrays.asList(
            mcpToolResolver,           // MCP 도구 우선
            springBeanResolver,        // Spring Bean 도구
            staticToolResolver,        // 정적 도구
            fallbackToolResolver       // Fallback
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
    
    /**
     * Spring Bean 기반 도구 Resolver
     */
    @Bean
    @ConditionalOnMissingBean(SpringBeanToolCallbackResolver.class)
    public SpringBeanToolCallbackResolver springBeanToolCallbackResolver(
            ApplicationContext applicationContext) {
        
        log.info("🌱 SpringBeanToolCallbackResolver 생성");
        return new SpringBeanToolCallbackResolver(applicationContext);
    }
    
    /**
     * MCP 도구 Resolver
     */
    @Bean
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
    
    /**
     * 정적 도구 Resolver
     */
    @Bean
    @ConditionalOnMissingBean(StaticToolCallbackResolver.class)
    public StaticToolCallbackResolver staticToolCallbackResolver() {
        log.info("StaticToolCallbackResolver 생성");
        return new StaticToolCallbackResolver();
    }
    
    /**
     * Fallback 도구 Resolver
     */
    @Bean
    @ConditionalOnMissingBean(FallbackToolResolver.class)
    public FallbackToolResolver fallbackToolResolver() {
        log.info("FallbackToolResolver 생성");
        return new FallbackToolResolver();
    }
    
    
    /**
     * 메트릭 수집기
     */
    @Bean
    @ConditionalOnMissingBean(MCPToolMetrics.class)
    public MCPToolMetrics metricsCollector(
            @Autowired(required = false) MeterRegistry meterRegistry) {
        log.info("MCPToolMetrics 생성");
        return new MCPToolMetrics(meterRegistry);
    }
    
    /**
     * 도구 목록 로깅 (디버깅용)
     */
    @Bean
    public ToolInventoryLogger toolInventoryLogger(
            Optional<ChainedToolResolver> chainedResolver,
            Optional<McpFunctionCallbackProvider> mcpProvider) {
        
        return new ToolInventoryLogger() {
            @jakarta.annotation.PostConstruct
            public void logToolInventory() {
                log.info("========== 도구 인벤토리 ==========");
                
                // ChainedToolResolver에서 도구 수집
                if (chainedResolver.isPresent()) {
                    Set<String> toolNames = chainedResolver.get().getRegisteredToolNames();
                    log.info("등록된 도구 총 {} 개", toolNames.size());
                    
                    if (log.isDebugEnabled()) {
                        toolNames.forEach(name -> log.debug("  - {}", name));
                    }
                }
                
                // MCP 도구 통계
                if (mcpProvider.isPresent()) {
                    Map<String, Object> stats = mcpProvider.get().getMcpToolStatistics();
                    log.info("MCP 도구 통계: {}", stats);
                }
                
                log.info("=====================================");
            }
        };
    }
    
    /**
     * 도구 인벤토리 로거 인터페이스 (내부용)
     */
    private interface ToolInventoryLogger {
        // Marker interface for inventory logging bean
    }
    
    /**
     * Configuration 정보 로깅
     */
    @jakarta.annotation.PostConstruct
    public void logConfiguration() {
        log.info("Spring AI Tool Calling Configuration 초기화 완료");
        log.info("  - DefaultToolCallingManager: 활성화");
        log.info("  - ApprovalAwareToolCallingManager: Decorator 패턴 적용");
        log.info("  - ChainedToolResolver: 향상된 기능 포함");
        log.info("  - MCP 지원: 조건부 활성화");
        log.info("  - 예외 처리: SOAR 특화 프로세서");
    }
}