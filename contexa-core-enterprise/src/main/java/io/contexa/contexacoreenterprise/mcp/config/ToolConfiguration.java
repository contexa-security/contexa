package io.contexa.contexacoreenterprise.mcp.config;

import io.contexa.contexacoreenterprise.mcp.tool.resolution.ChainedToolResolver;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.contexa.contexacore.std.advisor.config.AdvisorConfiguration;
import io.contexa.contexacore.std.llm.config.TieredSecurityLLMConfiguration;

/**
 * ChatClient 통합 설정
 *
 * TieredSecurityLLMConfiguration과 AdvisorConfiguration 이후에 실행되어
 * 도구가 통합된 ChatClient를 제공합니다.
 */
@Slf4j
@Configuration
@AutoConfigureAfter({TieredSecurityLLMConfiguration.class, AdvisorConfiguration.class})
public class ToolConfiguration {
    
    @Value("${contexa.tools.enabled:true}")
    private boolean toolsEnabled;
    
    /**
     * 도구가 활성화된 ChatClient
     * 
     * ChainedToolResolver를 통해 모든 도구(SOAR + MCP)를 통합합니다.
     * Advisor가 활성화된 경우 Advisor가 적용된 Builder를 사용합니다.
     */
    @Bean
    @ConditionalOnMissingBean(name = "toolEnabledChatClient")
    @ConditionalOnProperty(prefix = "contexa.tools", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ChatClient toolEnabledChatClient(
            @Autowired(required = false) @Qualifier("advisorEnabledChatClientBuilder") ChatClient.Builder advisorBuilder,
            @Autowired(required = false) @Qualifier("chatClientBuilder") ChatClient.Builder basicBuilder,
            @Autowired(required = false) ChainedToolResolver toolResolver) {
        
        log.info("🛠️ 도구 활성화 ChatClient 생성 시작");
        
        // Builder 선택: Advisor가 있으면 우선 사용
        ChatClient.Builder builder = advisorBuilder != null ? advisorBuilder : basicBuilder;
        
        if (builder == null) {
            log.error("ChatClient.Builder를 찾을 수 없습니다");
            throw new IllegalStateException("ChatClient.Builder not found. Check LlmConfig and AdvisorAutoConfiguration.");
        }
        
        // 도구 통합
        if (toolsEnabled && toolResolver != null) {
            try {
                ToolCallback[] tools = toolResolver.getAllToolCallbacks();
                
                if (tools.length > 0) {
                    builder = builder.defaultToolCallbacks(tools);
                    log.info("{} 개의 도구가 ChatClient에 통합되었습니다", tools.length);
                    
                    // 도구 목록 로깅 (디버그 레벨)
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
                // 도구 통합 실패해도 기본 ChatClient는 생성
            }
        } else if (!toolsEnabled) {
            log.info("도구가 비활성화되어 있습니다");
        } else {
            log.warn("ChainedToolResolver를 찾을 수 없습니다");
        }
        
        // 도구 관련 시스템 프롬프트 추가
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
    
    /**
     * 도구 통합 상태 정보
     * 
     * 디버깅 및 모니터링을 위한 상태 정보를 제공합니다.
     */
    @Bean
    public ToolIntegrationStatus toolIntegrationStatus(
            @Autowired(required = false) ChainedToolResolver toolResolver) {
        
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
    
    /**
     * 도구 통합 상태 정보 클래스
     */
    public record ToolIntegrationStatus(
        boolean enabled,
        String status,
        int toolCount
    ) {}
}