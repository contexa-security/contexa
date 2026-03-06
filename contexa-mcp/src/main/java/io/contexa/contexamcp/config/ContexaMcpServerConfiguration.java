package io.contexa.contexamcp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexamcp.adapter.ExternalFirewallAdapter;
import io.contexa.contexamcp.adapter.NoOpFirewallAdapter;
import io.contexa.contexamcp.adapter.NoOpThreatIntelligenceAdapter;
import io.contexa.contexamcp.adapter.ThreatIntelligenceAdapter;
import io.contexa.contexamcp.security.HighRiskToolAuthorizationService;
import io.contexa.contexamcp.service.InMemoryIpBlockingService;
import io.contexa.contexamcp.service.InMemoryUserSessionService;
import io.contexa.contexamcp.service.IpBlockingService;
import io.contexa.contexamcp.service.McpAuditLogService;
import io.contexa.contexamcp.service.RedisIpBlockingService;
import io.contexa.contexamcp.service.RedisUserSessionService;
import io.contexa.contexamcp.service.UserSessionService;
import io.contexa.contexamcp.tools.AuditLogQueryTool;
import io.contexa.contexamcp.tools.IpBlockingTool;
import io.contexa.contexamcp.tools.LogAnalysisTool;
import io.contexa.contexamcp.tools.SessionTerminationTool;
import io.contexa.contexamcp.tools.ThreatIntelligenceTool;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import io.contexa.contexacommon.soar.event.SecurityActionEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.List;

@AutoConfiguration
@ConditionalOnProperty(prefix = "spring.ai.mcp.server", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ContexaMcpServerConfiguration {

    // --- Service Beans ---

    @Bean
    @ConditionalOnMissingBean
    public HighRiskToolAuthorizationService highRiskToolAuthorizationService(Environment environment) {
        return new HighRiskToolAuthorizationService(environment);
    }

    @Bean
    @ConditionalOnMissingBean
    public McpAuditLogService mcpAuditLogService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        return new McpAuditLogService(jdbcTemplate, objectMapper);
    }

    @Configuration
    @ConditionalOnBean(RedisTemplate.class)
    static class DistributedMcpServiceConfig {

        @Bean
        @ConditionalOnMissingBean(UserSessionService.class)
        public RedisUserSessionService redisUserSessionService(RedisTemplate<String, Object> redisTemplate) {
            return new RedisUserSessionService(redisTemplate);
        }

        @Bean
        @ConditionalOnMissingBean(IpBlockingService.class)
        public RedisIpBlockingService redisIpBlockingService(RedisTemplate<String, Object> redisTemplate) {
            return new RedisIpBlockingService(redisTemplate);
        }
    }

    @Configuration
    @ConditionalOnMissingBean(RedisTemplate.class)
    static class StandaloneMcpServiceConfig {

        @Bean
        @ConditionalOnMissingBean(UserSessionService.class)
        public InMemoryUserSessionService inMemoryUserSessionService() {
            return new InMemoryUserSessionService();
        }

        @Bean
        @ConditionalOnMissingBean(IpBlockingService.class)
        public InMemoryIpBlockingService inMemoryIpBlockingService() {
            return new InMemoryIpBlockingService();
        }
    }

    // --- Adapter Beans (Override with vendor-specific implementations for production) ---

    @Bean
    @ConditionalOnMissingBean
    public ExternalFirewallAdapter externalFirewallAdapter() {
        return new NoOpFirewallAdapter();
    }

    @Bean
    @ConditionalOnMissingBean
    public ThreatIntelligenceAdapter threatIntelligenceAdapter() {
        return new NoOpThreatIntelligenceAdapter();
    }

    // --- Tool Beans ---

    @Bean
    @ConditionalOnMissingBean
    public LogAnalysisTool logAnalysisTool() {
        return new LogAnalysisTool();
    }

    @Bean
    @ConditionalOnMissingBean
    public ThreatIntelligenceTool threatIntelligenceTool(
            ThreatIntelligenceAdapter threatIntelligenceAdapter) {
        return new ThreatIntelligenceTool(threatIntelligenceAdapter);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditLogQueryTool auditLogQueryTool(McpAuditLogService mcpAuditLogService) {
        return new AuditLogQueryTool(mcpAuditLogService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(IpBlockingService.class)
    public IpBlockingTool ipBlockingTool(
            IpBlockingService ipBlockingService,
            HighRiskToolAuthorizationService authorizationService,
            ExternalFirewallAdapter externalFirewallAdapter,
            SecurityActionEventPublisher securityActionEventPublisher) {
        return new IpBlockingTool(ipBlockingService, authorizationService,
                externalFirewallAdapter, securityActionEventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(UserSessionService.class)
    public SessionTerminationTool sessionTerminationTool(
            UserSessionService userSessionService,
            HighRiskToolAuthorizationService authorizationService,
            SecurityActionEventPublisher securityActionEventPublisher) {
        return new SessionTerminationTool(userSessionService, authorizationService, securityActionEventPublisher);
    }

    @Bean
    @ConditionalOnMissingBean
    public ToolCallbackProvider mcpToolProvider(
            LogAnalysisTool logAnalysisTool,
            ThreatIntelligenceTool threatIntelligenceTool,
            AuditLogQueryTool auditLogQueryTool,
            ObjectProvider<IpBlockingTool> ipBlockingToolProvider,
            ObjectProvider<SessionTerminationTool> sessionTerminationToolProvider) {

        List<Object> tools = new ArrayList<>();
        tools.add(logAnalysisTool);
        tools.add(threatIntelligenceTool);
        tools.add(auditLogQueryTool);

        IpBlockingTool ipBlockingTool = ipBlockingToolProvider.getIfAvailable();
        if (ipBlockingTool != null) {
            tools.add(ipBlockingTool);
        }

        SessionTerminationTool sessionTerminationTool = sessionTerminationToolProvider.getIfAvailable();
        if (sessionTerminationTool != null) {
            tools.add(sessionTerminationTool);
        }

        return MethodToolCallbackProvider.builder()
                .toolObjects(tools.toArray())
                .build();
    }
}
