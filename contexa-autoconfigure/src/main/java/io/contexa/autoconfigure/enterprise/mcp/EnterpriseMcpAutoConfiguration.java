package io.contexa.autoconfigure.enterprise.mcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.properties.ContexaEnterpriseProperties;
import io.contexa.contexacoreenterprise.mcp.tool.execution.config.ToolExecutionProperties;
import io.contexa.contexamcp.completions.SecurityCommandCompletion;
import io.contexa.contexamcp.prompts.SecurityAnalysisPrompts;
import io.contexa.contexamcp.resources.SecurityLogResource;
import io.contexa.contexamcp.resources.SystemInfoResource;
import io.contexa.contexamcp.service.AuditLogService;
import io.contexa.contexamcp.service.IpBlockingService;
import io.contexa.contexamcp.service.UserSessionService;
import io.contexa.contexamcp.tools.*;
import io.modelcontextprotocol.server.McpServerFeatures;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@AutoConfiguration
@ConditionalOnClass(name = "io.contexa.contexamcp.tools.NetworkScanTool")
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "true", matchIfMissing = false)
@ConditionalOnProperty(prefix = "spring.ai.mcp.server", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({
        ContexaEnterpriseProperties.class,
        ToolExecutionProperties.class
})
public class EnterpriseMcpAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public NetworkScanTool networkScanTool() {
        return new NetworkScanTool();
    }

    @Bean
    @ConditionalOnMissingBean
    public LogAnalysisTool logAnalysisTool() {
        return new LogAnalysisTool();
    }

    @Bean
    @ConditionalOnMissingBean
    public ThreatIntelligenceTool threatIntelligenceTool() {
        return new ThreatIntelligenceTool();
    }

    @Bean
    @ConditionalOnMissingBean
    public FileQuarantineTool fileQuarantineTool() {
        return new FileQuarantineTool();
    }

    @Bean
    @ConditionalOnMissingBean
    public ProcessKillTool processKillTool() {
        return new ProcessKillTool();
    }

    @Bean
    @ConditionalOnMissingBean
    public NetworkIsolationTool networkIsolationTool() {
        return new NetworkIsolationTool();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditLogQueryTool auditLogQueryTool(AuditLogService auditLogService) {
        return new AuditLogQueryTool(auditLogService);
    }

    @Bean
    @ConditionalOnMissingBean
    public IpBlockingTool ipBlockingTool(IpBlockingService ipBlockingService) {
        return new IpBlockingTool(ipBlockingService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionTerminationTool sessionTerminationTool(UserSessionService userSessionService) {
        return new SessionTerminationTool(userSessionService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityLogResource securityLogResource(ObjectMapper objectMapper) {
        return new SecurityLogResource(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public SystemInfoResource systemInfoResource(ObjectMapper objectMapper) {
        return new SystemInfoResource(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityAnalysisPrompts securityAnalysisPrompts() {
        return new SecurityAnalysisPrompts();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityCommandCompletion securityCommandCompletion() {
        return new SecurityCommandCompletion();
    }

    @Bean
    @ConditionalOnMissingBean
    public ToolCallbackProvider mcpToolProvider(
            NetworkScanTool networkScanTool,
            LogAnalysisTool logAnalysisTool,
            ThreatIntelligenceTool threatIntelligenceTool,
            FileQuarantineTool fileQuarantineTool,
            ProcessKillTool processKillTool,
            NetworkIsolationTool networkIsolationTool,
            AuditLogQueryTool auditLogQueryTool,
            IpBlockingTool ipBlockingTool,
            SessionTerminationTool sessionTerminationTool) {

        ToolCallbackProvider provider = MethodToolCallbackProvider.builder()
                .toolObjects(
                        networkScanTool,
                        logAnalysisTool,
                        threatIntelligenceTool,
                        fileQuarantineTool,
                        processKillTool,
                        networkIsolationTool,
                        auditLogQueryTool,
                        ipBlockingTool,
                        sessionTerminationTool)
                .build();

        return provider;
    }

    @Bean
    @ConditionalOnMissingBean(name = "mcpResources")
    public List<McpServerFeatures.SyncResourceSpecification> mcpResources(
            SecurityLogResource securityLogResource,
            SystemInfoResource systemInfoResource) {

        List<McpServerFeatures.SyncResourceSpecification> resources = new ArrayList<>();
        resources.add(securityLogResource.createSpecification());
        resources.add(systemInfoResource.createSpecification());

        return resources;
    }

    @Bean
    @ConditionalOnMissingBean(name = "mcpPrompts")
    public List<McpServerFeatures.SyncPromptSpecification> mcpPrompts(
            SecurityAnalysisPrompts securityAnalysisPrompts) {

        List<McpServerFeatures.SyncPromptSpecification> prompts = new ArrayList<>();
        prompts.add(securityAnalysisPrompts.createLogAnalysisSpec());
        prompts.add(securityAnalysisPrompts.createThreatAssessmentSpec());

        return prompts;
    }

    @Bean
    @ConditionalOnMissingBean(name = "mcpCompletions")
    public List<McpServerFeatures.SyncCompletionSpecification> mcpCompletions(
            SecurityCommandCompletion securityCommandCompletion) {

        List<McpServerFeatures.SyncCompletionSpecification> completions = new ArrayList<>();

        var completionInfo = securityCommandCompletion.createCompletionSpecification();
        if (completionInfo != null) {
            // TODO: Convert completion specification to SyncCompletionSpecification type
            log.error("Completion spec created but type conversion not implemented");
        } else {
            log.error("Failed to generate Completion info");
        }

        return completions;
    }

    @Bean
    @ConditionalOnMissingBean
    public McpServerInfoLogger mcpServerInfoLogger() {
        return new McpServerInfoLogger();
    }

    public static class McpServerInfoLogger {
        public McpServerInfoLogger() {
        }
    }
}
