package io.contexa.contexacoreenterprise.mcp.config;

import io.contexa.contexacoreenterprise.mcp.event.ToolEventPublisher;
import io.contexa.contexacoreenterprise.mcp.integration.*;
import io.contexa.contexacoreenterprise.mcp.tool.provider.McpClientProviderImpl;
import io.modelcontextprotocol.client.McpSyncClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * MCP Integration Configuration
 *
 * MCP 통합 컴포넌트들을 Bean으로 등록합니다.
 *
 * 등록되는 Bean (7개):
 * - ToolEventPublisher - 도구 실행 이벤트 발행
 * - McpFunctionCallbackProvider - MCP 함수 콜백 제공
 * - McpPromptIntegrator - MCP 프롬프트 통합
 * - McpResourceProvider - MCP 리소스 제공
 * - McpToolIntegrationAdapter - MCP 도구 통합 어댑터
 * - UnifiedToolCallbackProvider - 통합 도구 콜백 프로바이더
 * - McpClientProviderImpl - MCP 클라이언트 프로바이더 구현체
 */
@Slf4j
@Configuration
public class McpIntegrationConfiguration {

    /**
     * 도구 이벤트 발행자
     *
     * 도구 실행 관련 이벤트를 Spring의 ApplicationEvent 시스템을 통해 발행합니다.
     */
    @Bean
    @ConditionalOnMissingBean
    public ToolEventPublisher toolEventPublisher(ApplicationEventPublisher eventPublisher) {
        log.info("Tool Event Publisher Bean 생성");
        return new ToolEventPublisher(eventPublisher);
    }

    /**
     * MCP 함수 콜백 프로바이더
     *
     * MCP 클라이언트의 도구들을 Spring AI 표준 ToolCallback으로 변환하여 제공합니다.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpFunctionCallbackProvider mcpFunctionCallbackProvider(
            McpSyncClient braveSearchMcpClient,
            McpSyncClient securityMcpClient) {
        log.info("MCP Function Callback Provider Bean 생성");
        return new McpFunctionCallbackProvider(braveSearchMcpClient, securityMcpClient);
    }

    /**
     * MCP 프롬프트 통합자
     *
     * MCP 클라이언트의 프롬프트들을 Spring AI Prompt와 통합합니다.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpPromptIntegrator mcpPromptIntegrator(
            McpSyncClient braveSearchMcpClient,
            McpSyncClient securityMcpClient) {
        log.info("MCP Prompt Integrator Bean 생성");
        return new McpPromptIntegrator(braveSearchMcpClient, securityMcpClient);
    }

    /**
     * MCP 리소스 프로바이더
     *
     * MCP 클라이언트의 리소스들을 관리하고 제공합니다.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpResourceProvider mcpResourceProvider(
            McpSyncClient braveSearchMcpClient,
            McpSyncClient securityMcpClient) {
        log.info("MCP Resource Provider Bean 생성");
        return new McpResourceProvider(braveSearchMcpClient, securityMcpClient);
    }

    /**
     * MCP 도구 통합 어댑터
     *
     * McpFunctionCallbackProvider를 ToolIntegrationProvider 인터페이스로 어댑팅합니다.
     * 순환 의존성 없이 MCP 도구를 통합할 수 있습니다.
     */
    @Bean("mcpToolIntegrationAdapter")
    @ConditionalOnMissingBean(name = "mcpToolIntegrationAdapter")
    @ConditionalOnProperty(prefix = "spring.ai.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public McpToolIntegrationAdapter mcpToolIntegrationAdapter(
            McpFunctionCallbackProvider mcpProvider) {
        log.info("MCP Tool Integration Adapter Bean 생성");
        return new McpToolIntegrationAdapter(mcpProvider);
    }

    /**
     * 통합 도구 콜백 프로바이더
     *
     * MCP와 SOAR 도구들을 완전히 통합하여 관리하는 통합 Provider입니다.
     * @PostConstruct를 통해 초기화되므로 필드 주입 방식을 사용합니다.
     */
    @Bean("unifiedToolCallbackProvider")
    @ConditionalOnMissingBean(name = "unifiedToolCallbackProvider")
    public UnifiedToolCallbackProvider unifiedToolCallbackProvider() {
        log.info("Unified Tool Callback Provider Bean 생성");
        return new UnifiedToolCallbackProvider();
    }

    /**
     * MCP 클라이언트 프로바이더 구현체
     *
     * StandardMcpClientConfiguration에서 생성된 MCP 클라이언트들을 관리합니다.
     * 기본적으로 항상 활성화됩니다.
     */
    @Bean
    public McpClientProviderImpl mcpClientProvider(
            @Autowired(required = false) List<McpSyncClient> mcpClients,
            @Autowired(required = false) McpSyncClient braveSearchMcpClient,
            @Autowired(required = false) McpSyncClient securityMcpClient) {
        log.info("MCP Client Provider Impl Bean 생성");
        return new McpClientProviderImpl(mcpClients, braveSearchMcpClient, securityMcpClient);
    }
}
