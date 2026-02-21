package io.contexa.contexamcp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexamcp.prompts.SecurityAnalysisPrompts;
import io.contexa.contexamcp.resources.SecurityLogResource;
import io.contexa.contexamcp.resources.SystemInfoResource;
import io.contexa.contexamcp.security.HighRiskToolAuthorizationService;
import io.contexa.contexamcp.service.AuditLogService;
import io.contexa.contexamcp.service.IpBlockingService;
import io.contexa.contexamcp.service.UserSessionService;
import io.contexa.contexamcp.tools.AuditLogQueryTool;
import io.contexa.contexamcp.tools.FileQuarantineTool;
import io.contexa.contexamcp.tools.IpBlockingTool;
import io.contexa.contexamcp.tools.LogAnalysisTool;
import io.contexa.contexamcp.tools.NetworkIsolationTool;
import io.contexa.contexamcp.tools.NetworkScanTool;
import io.contexa.contexamcp.tools.ProcessKillTool;
import io.contexa.contexamcp.tools.SessionTerminationTool;
import io.contexa.contexamcp.tools.ThreatIntelligenceTool;
import io.modelcontextprotocol.server.McpServerFeatures;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import java.util.ArrayList;
import java.util.List;

@AutoConfiguration
@ConditionalOnProperty(prefix = "spring.ai.mcp.server", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ContexaMcpServerConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public HighRiskToolAuthorizationService highRiskToolAuthorizationService(Environment environment) {
        return new HighRiskToolAuthorizationService(environment);
    }

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
    public FileQuarantineTool fileQuarantineTool(HighRiskToolAuthorizationService authorizationService) {
        return new FileQuarantineTool(authorizationService);
    }

    @Bean
    @ConditionalOnMissingBean
    public ProcessKillTool processKillTool(HighRiskToolAuthorizationService authorizationService) {
        return new ProcessKillTool(authorizationService);
    }

    @Bean
    @ConditionalOnMissingBean
    public NetworkIsolationTool networkIsolationTool(HighRiskToolAuthorizationService authorizationService) {
        return new NetworkIsolationTool(authorizationService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuditLogQueryTool auditLogQueryTool(AuditLogService auditLogService) {
        return new AuditLogQueryTool(auditLogService);
    }

    @Bean
    @ConditionalOnMissingBean
    public IpBlockingTool ipBlockingTool(IpBlockingService ipBlockingService,
                                         HighRiskToolAuthorizationService authorizationService) {
        return new IpBlockingTool(ipBlockingService, authorizationService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionTerminationTool sessionTerminationTool(UserSessionService userSessionService,
                                                         HighRiskToolAuthorizationService authorizationService) {
        return new SessionTerminationTool(userSessionService, authorizationService);
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

        return MethodToolCallbackProvider.builder()
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
    }

    @Bean(name = "mcpResources")
    @ConditionalOnMissingBean(name = "mcpResources")
    public List<McpServerFeatures.SyncResourceSpecification> mcpResources(
            SecurityLogResource securityLogResource,
            SystemInfoResource systemInfoResource) {
        List<McpServerFeatures.SyncResourceSpecification> resources = new ArrayList<>();
        resources.add(securityLogResource.createSpecification());
        resources.add(systemInfoResource.createSpecification());
        return resources;
    }

    @Bean(name = "mcpPrompts")
    @ConditionalOnMissingBean(name = "mcpPrompts")
    public List<McpServerFeatures.SyncPromptSpecification> mcpPrompts(
            SecurityAnalysisPrompts securityAnalysisPrompts) {
        List<McpServerFeatures.SyncPromptSpecification> prompts = new ArrayList<>();
        prompts.add(securityAnalysisPrompts.createLogAnalysisSpec());
        prompts.add(securityAnalysisPrompts.createThreatAssessmentSpec());
        return prompts;
    }
}
